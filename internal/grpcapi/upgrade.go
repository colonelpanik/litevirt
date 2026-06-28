package grpcapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/upgrade"
)

// UpgradeHost receives a new binary over gRPC streaming, swaps it in,
// and triggers a re-exec of the daemon process.
func (s *Server) UpgradeHost(stream grpc.ClientStreamingServer[pb.UpgradeHostRequest, pb.UpgradeHostResponse]) error {
	if err := RequireRole(stream.Context(), "admin"); err != nil {
		return err
	}

	// Receive the first message to get target_host and checksum.
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "receive first chunk: %v", err)
	}

	// Forward to peer if target_host differs.
	if first.TargetHost != "" && first.TargetHost != s.hostName {
		return s.forwardUpgrade(stream, first)
	}

	// Pre-flight: block on in-flight work unless --force was passed.
	// Warn-level findings are logged but not blocking either way.
	if !first.Force {
		pre, err := s.PreflightUpgrade(stream.Context(), &pb.PreflightUpgradeRequest{TargetHost: s.hostName})
		if err != nil {
			slog.Warn("upgrade: preflight failed (continuing — set --force to acknowledge)", "error", err)
		} else {
			for _, f := range pre.Findings {
				slog.Warn("upgrade preflight",
					"severity", f.Severity, "code", f.Code, "message", f.Message)
			}
			if !pre.Ok {
				return status.Errorf(codes.FailedPrecondition,
					"upgrade pre-flight blocked %d condition(s); pass --force to override or address them first",
					countBlocking(pre.Findings))
			}
		}
	}

	binaryPath := s.daemonBinary()

	// Write binary to staging path + verify checksum (shared with PreStageUpgrade).
	stagingPath := binaryPath + ".new"
	if err := receiveBinaryToStaging(stream, first, stagingPath); err != nil {
		os.Remove(stagingPath)
		return err
	}

	if err := s.applyStagedBinary(stream.Context(), stagingPath); err != nil {
		os.Remove(stagingPath)
		return status.Errorf(codes.Internal, "apply binary: %v", err)
	}
	slog.Info("binary upgraded (push), signalling re-exec", "checksum", first.Checksum)

	resp := &pb.UpgradeHostResponse{
		HostName:   s.hostName,
		OldVersion: s.version,
		NewVersion: "pending-reexec",
		Status:     "ok",
	}
	if err := stream.SendAndClose(resp); err != nil {
		return err
	}
	s.signalReExec()
	return nil
}

// applyStagedBinary backs up the current binary to `.old`, atomically swaps in
// the staged binary, marks this host `upgrading` (so peers don't fence the
// restart window), and refreshes the systemd unit. It does NOT signal the
// re-exec — the caller does that after replying. Shared by the push UpgradeHost
// and the pull self-upgrade.
func (s *Server) applyStagedBinary(ctx context.Context, stagingPath string) error {
	binaryPath := s.daemonBinary()
	if err := copyFile(binaryPath, binaryPath+".old"); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}
	// Arm the post-upgrade health-watchdog sentinel BEFORE swapping the binary in.
	// The sentinel is the safety mechanism — without it the re-exec'd new binary
	// would mark itself active with NO health check — so this is fail-CLOSED: if we
	// can't arm it, we do NOT swap (the old binary keeps running). A sentinel
	// sitting next to the still-current binary is harmless: if we crash before the
	// swap, the current binary just self-confirms healthy and clears it.
	if err := upgrade.Arm(binaryPath, s.version); err != nil {
		return fmt.Errorf("arm health-watchdog sentinel: %w", err)
	}
	if err := os.Rename(stagingPath, binaryPath); err != nil {
		upgrade.Clear(binaryPath) // no new binary was installed → nothing to watch
		return fmt.Errorf("swap binary: %w", err)
	}
	// The new binary's startup transitions back to `active` once the watchdog
	// confirms the local gRPC is healthy.
	if err := corrosion.UpdateHostState(ctx, s.db, s.hostName, "upgrading"); err != nil {
		slog.Warn("upgrade: failed to mark host upgrading", "error", err)
	}
	updateSystemdUnit()
	return nil
}

// signalReExec asks the daemon main loop to re-exec the (now-swapped) binary.
func (s *Server) signalReExec() {
	select {
	case s.ReExecCh <- struct{}{}:
	default:
	}
}

// forwardUpgrade relays an UpgradeHost stream to a remote peer.
func (s *Server) forwardUpgrade(incoming grpc.ClientStreamingServer[pb.UpgradeHostRequest, pb.UpgradeHostResponse], first *pb.UpgradeHostRequest) error {
	ctx := incoming.Context()
	client, conn, err := s.peerClient(ctx, first.TargetHost)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", first.TargetHost, err)
	}
	defer conn.Close()

	remote, err := client.UpgradeHost(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "open remote upgrade stream: %v", err)
	}

	// Forward first message (clear target_host so remote processes it locally).
	first.TargetHost = ""
	if err := remote.Send(first); err != nil {
		return err
	}

	// Forward remaining chunks.
	for {
		msg, err := incoming.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := remote.Send(msg); err != nil {
			return err
		}
	}

	resp, err := remote.CloseAndRecv()
	if err != nil {
		return err
	}
	return incoming.SendAndClose(resp)
}

// litevirtUnit is the canonical systemd unit file for litevirtd.
// Kept here so upgrades can refresh it without a full `lv host init`.
//
// Notable hardening:
//   - KillMode=process: only the daemon is killed on stop, NOT child
//     QEMU processes. A regression here kills every running VM on stop.
//   - StartLimitBurst/StartLimitIntervalSec: a panicking new binary will
//     be restarted at most 3 times in 10 minutes; further failures put
//     the unit in `failed` state instead of looping forever (which would
//     hammer the cluster with rejoin attempts and grow mutation_log).
//   - Delegate=no: prevents litevirtd from being granted its own cgroup
//     subtree where a future `KillMode=control-group` accident could
//     reach into QEMU children.
//   - OnFailure=litevirt-rollback.service: when StartLimitBurst is
//     exceeded (i.e. the new binary keeps panicking), the rollback unit
//     fires automatically and restores the `.old` binary.
const litevirtUnit = `[Unit]
Description=litevirt daemon
After=network-online.target libvirtd.service
Wants=network-online.target
Wants=libvirtd.service
StartLimitBurst=3
StartLimitIntervalSec=600
OnFailure=litevirt-rollback.service

[Service]
Type=simple
ExecStart=/usr/local/bin/litevirt daemon
KillMode=process
Delegate=no
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

// litevirtRollbackUnit is the companion oneshot that systemd fires when
// the main litevirtd unit enters a failed state (i.e. StartLimitBurst
// exceeded). It restores `.old` over the current binary, clears the
// failed state, and restarts the main service.
//
// The journal-tagged log line is intentionally loud — operators should
// notice in `journalctl -u litevirt-rollback` that something rolled back.
const litevirtRollbackUnit = `[Unit]
Description=litevirt daemon rollback (auto-restore previous binary on failed upgrade)

[Service]
Type=oneshot
ExecStart=/bin/sh -c '\
  if [ -f /usr/local/bin/litevirt.old ]; then \
    logger -t litevirt-rollback "RESTORING previous litevirt binary after failed upgrade"; \
    mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt; \
    systemctl reset-failed litevirt.service; \
    systemctl start litevirt.service; \
  else \
    logger -t litevirt-rollback "no .old binary to roll back to; leaving litevirt in failed state"; \
    exit 1; \
  fi'
`

const rollbackUnitPath = "/etc/systemd/system/litevirt-rollback.service"

const unitPath = "/etc/systemd/system/litevirt.service"

// updateSystemdUnit writes the current unit file templates (main + rollback
// companion) and reloads systemd if anything changed on disk. Best-effort —
// failures are logged, not fatal.
func updateSystemdUnit() {
	changed := false
	if existing, err := os.ReadFile(unitPath); err != nil || string(existing) != litevirtUnit {
		if err := os.WriteFile(unitPath, []byte(litevirtUnit), 0644); err != nil {
			slog.Warn("failed to update systemd unit", "error", err)
			return
		}
		changed = true
	}
	if existing, err := os.ReadFile(rollbackUnitPath); err != nil || string(existing) != litevirtRollbackUnit {
		if err := os.WriteFile(rollbackUnitPath, []byte(litevirtRollbackUnit), 0644); err != nil {
			slog.Warn("failed to update rollback unit", "error", err)
			// don't return — the main unit still works, just without auto-rollback
		} else {
			changed = true
		}
	}
	if !changed {
		return
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		slog.Warn("systemctl daemon-reload failed", "error", err, "output", string(out))
		return
	}
	slog.Info("systemd units updated (main + rollback)")
}

// countBlocking returns how many findings are severity="block".
func countBlocking(findings []*pb.PreflightFinding) int {
	n := 0
	for _, f := range findings {
		if f.Severity == "block" {
			n++
		}
	}
	return n
}

// copyFile copies src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
