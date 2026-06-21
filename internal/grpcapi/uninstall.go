package grpcapi

import (
	"context"
	"log/slog"
	"os/exec"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// UninstallHost removes litevirt from a host.
// After responding, it signals the daemon to shut down.
func (s *Server) UninstallHost(ctx context.Context, req *pb.UninstallHostRequest) (*pb.UninstallHostResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}

	// Forward to peer if target_host differs.
	if req.TargetHost != "" && req.TargetHost != s.hostName {
		return s.forwardUninstall(ctx, req)
	}

	slog.Info("uninstalling litevirt from this host", "keep_data", req.KeepData)

	steps := []struct {
		desc string
		cmd  string
	}{
		{"disable litevirt", "systemctl disable litevirt.service 2>/dev/null || true"},
		{"remove systemd units", "rm -f /etc/systemd/system/litevirt.service /etc/systemd/system/litevirt-rollback.service && systemctl daemon-reload"},
		{"remove daemon binary", "rm -f /usr/local/bin/litevirt /usr/local/bin/litevirt.old /usr/local/bin/litevirt.new /usr/local/bin/lv"},
		{"remove config and PKI", "rm -rf /etc/litevirt"},
		{"remove udev rule", "rm -f /etc/udev/rules.d/99-litevirt-pci.rules && udevadm control --reload-rules 2>/dev/null || true"},
		{"remove haproxy/keepalived drop-ins", "rm -rf /etc/systemd/system/haproxy@*.service.d /etc/systemd/system/keepalived@*.service.d"},
	}

	if !req.KeepData {
		steps = append(steps, struct {
			desc string
			cmd  string
		}{"remove data directory", "rm -rf /var/lib/litevirt"})
	}

	for _, step := range steps {
		slog.Info("uninstall step", "desc", step.desc)
		if out, err := exec.CommandContext(ctx, "bash", "-c", step.cmd).CombinedOutput(); err != nil {
			slog.Warn("uninstall step failed", "desc", step.desc, "error", err, "output", string(out))
		}
	}

	resp := &pb.UninstallHostResponse{
		HostName: s.hostName,
		Status:   "ok",
	}

	// Signal daemon shutdown after response is sent.
	// The binary itself gets removed by systemd stop + the step above.
	go func() {
		select {
		case s.ShutdownCh <- struct{}{}:
		default:
		}
	}()

	return resp, nil
}

// forwardUninstall relays the request to a remote peer.
func (s *Server) forwardUninstall(ctx context.Context, req *pb.UninstallHostRequest) (*pb.UninstallHostResponse, error) {
	client, conn, err := s.peerClient(ctx, req.TargetHost)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", req.TargetHost, err)
	}
	defer conn.Close()

	// Build a fresh request with the target cleared so the remote processes
	// locally. (Copying *req by value would drag the proto message's embedded
	// mutex/MessageState along — go vet flags it.)
	return client.UninstallHost(ctx, &pb.UninstallHostRequest{
		KeepData:   req.KeepData,
		TargetHost: "",
	})
}
