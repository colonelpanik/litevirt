package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/upgrade"
)

// startUpgradeWatchdog arms the post-upgrade health watchdog when a prior upgrade
// staged this binary and left a sentinel next to it. It runs independently and is
// armed FIRST in Run (before any potentially-hanging init), so a boot that hangs
// before the gRPC server can serve is still caught.
//
// Scope: only binary-INTRINSIC faults trigger a rollback — the new binary cannot
// make local gRPC answer Ping. Environmental faults (libvirt down, replication
// backlog, broken PKI) are deliberately NOT gated here: they'd break the previous
// binary equally, so rolling back would just flap. systemd's existing
// OnFailure=litevirt-rollback.service still handles crash-loops (a binary that
// exits non-zero); this fills the gap where the binary stays up but is dead.
func (d *Daemon) startUpgradeWatchdog(ctx context.Context) {
	if !d.cfg.UpgradeWatchdogEnabled || os.Getenv("LITEVIRT_UNSAFE_NO_UPGRADE_WATCHDOG") == "1" {
		return
	}
	binaryPath := upgrade.ResolveBinaryPath()
	sentinel, ok := upgrade.Read(binaryPath)
	if !ok {
		return // normal boot — nothing to verify
	}
	d.upgradePending = true // gate the host's upgrading→active flip on confirmation

	deadline := time.Duration(d.cfg.UpgradeHealthDeadlineSec) * time.Second
	if deadline <= 0 {
		deadline = 120 * time.Second
	}
	go d.runUpgradeWatchdog(ctx, binaryPath, sentinel, deadline)
}

// watchdogOutcome is the decision the watchdog reaches after probing health.
type watchdogOutcome int

const (
	wdConfirm  watchdogOutcome = iota // healthy → clear sentinel, mark active
	wdShutdown                        // daemon stopping before confirm → leave sentinel, no rollback
	wdGiveUp                          // unhealthy but can't safely roll back → defer to systemd/operator
	wdRollback                        // unhealthy, rollback available → restore .old + exit
)

// decideWatchdog maps the probe result to an action. Pure + unit-tested. A
// rollback happens ONLY when the new binary never became pingable, the daemon
// isn't shutting down, no rollback has been made yet (flap guard), and a .old
// binary exists to restore.
func decideWatchdog(pingOK, shuttingDown, oldExists bool, attempt int) watchdogOutcome {
	switch {
	case pingOK:
		return wdConfirm
	case shuttingDown:
		return wdShutdown
	case attempt >= 1 || !oldExists:
		return wdGiveUp
	default:
		return wdRollback
	}
}

func (d *Daemon) runUpgradeWatchdog(ctx context.Context, binaryPath string, sentinel upgrade.Sentinel, deadline time.Duration) {
	slog.Info("post-upgrade watchdog armed",
		"deadline", deadline, "prev_version", sentinel.PrevVersion, "attempt", sentinel.Attempt)

	client, conn, err := d.localGRPCClient()
	if err != nil {
		// A PKI/TLS-config failure is environmental (shared with .old), so do NOT
		// roll back on it — just skip the health check.
		slog.Warn("post-upgrade watchdog: cannot build local gRPC client; skipping health check (NOT rolling back)", "error", err)
		return
	}
	defer conn.Close()

	dctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	pingOK := pingUntil(dctx, client)

	switch decideWatchdog(pingOK, ctx.Err() != nil, fileExists(binaryPath+".old"), sentinel.Attempt) {
	case wdConfirm:
		d.confirmUpgradeHealthy(binaryPath)
	case wdShutdown:
		slog.Info("post-upgrade watchdog: daemon shutting down before health confirmed; leaving sentinel for next boot")
	case wdGiveUp:
		slog.Error("post-upgrade watchdog: new binary unhealthy but cannot safely roll back (already rolled back once, or no .old) — leaving to systemd/operator",
			"prev_version", sentinel.PrevVersion, "attempt", sentinel.Attempt)
		metrics.UpgradeWatchdogOutcome("giveup")
	case wdRollback:
		d.rollbackToOld(binaryPath, sentinel)
	}
}

// confirmUpgradeHealthy is the success action: flip the host upgrading→active,
// then clear the sentinel. Extracted so it's directly testable without standing
// up a gRPC server for the Ping loop.
//
// Order matters: the active-state write happens FIRST and the sentinel is
// cleared only if it succeeds. Clearing first would strand the host in
// 'upgrading' with no watchdog if that (transient) write failed; by keeping the
// sentinel, the next boot's watchdog re-confirms and retries the flip.
func (d *Daemon) confirmUpgradeHealthy(binaryPath string) {
	mctx, mcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer mcancel()
	if err := corrosion.UpdateHostState(mctx, d.db, d.cfg.HostName, "active"); err != nil {
		slog.Warn("post-upgrade watchdog: confirmed healthy but failed to mark host active — keeping sentinel for retry next boot", "error", err)
		metrics.UpgradeWatchdogOutcome("confirm_failed")
		return
	}
	upgrade.Clear(binaryPath)
	slog.Info("post-upgrade watchdog: new binary healthy (local gRPC ping ok)", "version", d.cfg.Version)
	metrics.UpgradeWatchdogOutcome("confirmed")
}

// rollbackToOld restores <binary>.old over the running binary path and exits
// non-zero so systemd restarts the restored binary. The attempt counter is
// bumped first so the restored binary's watchdog won't roll back again.
func (d *Daemon) rollbackToOld(binaryPath string, sentinel upgrade.Sentinel) {
	upgrade.BumpAttempt(binaryPath, sentinel)
	slog.Error("post-upgrade watchdog: NEW BINARY UNHEALTHY (local gRPC never pingable within deadline) — ROLLING BACK to previous binary",
		"prev_version", sentinel.PrevVersion)
	metrics.UpgradeWatchdogOutcome("rollback")
	// Linux permits renaming over the currently-executing file; the restored
	// binary content is what systemd execs on restart.
	if err := os.Rename(binaryPath+".old", binaryPath); err != nil {
		slog.Error("post-upgrade watchdog: rollback rename failed; exiting non-zero for systemd to retry", "error", err)
	}
	d.exit(1)
}

// localGRPCClient dials this node's own gRPC endpoint over real mTLS (the local
// host cert/CA — the host cert includes 127.0.0.1), the same TLS/auth shape a
// peer or CLI uses. No insecure bypass.
func (d *Daemon) localGRPCClient() (pb.LiteVirtClient, *grpc.ClientConn, error) {
	tlsCfg, err := pki.ClientTLSConfig(d.cfg.PKIDir)
	if err != nil {
		return nil, nil, err
	}
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", d.cfg.GRPCPort),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, nil, err
	}
	return pb.NewLiteVirtClient(conn), conn, nil
}

// pingUntil polls the local gRPC Ping until it succeeds or ctx (the deadline)
// expires. Returns true on the first successful Ping.
func pingUntil(ctx context.Context, client pb.LiteVirtClient) bool {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		pctx, pcancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := client.Ping(pctx, &pb.PingRequest{})
		pcancel()
		if err == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

// exit terminates the process (overridable in tests).
func (d *Daemon) exit(code int) {
	if d.exitFunc != nil {
		d.exitFunc(code)
		return
	}
	os.Exit(code)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
