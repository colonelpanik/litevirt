package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GetSpiceInfo returns the SPICE host:port for a running VM that has SPICE
// graphics enabled. Operators connect with `remote-viewer spice://<uri>`
// or any SPICE client (virt-manager, looking-glass, etc.).
//
// Unlike VNC, we do not currently proxy SPICE through the daemon — clients
// must reach the host's SPICE port directly. SPICE has a TCP-tunnel mode
// (`-T` in remote-viewer) that pairs well with `lv host ssh`. Bundling a
// browser-based SPICE client (spice-html5) is a future enhancement; this
// RPC is the minimum viable surface to make SPICE usable today.
func (s *Server) GetSpiceInfo(ctx context.Context, req *pb.GetSpiceInfoRequest) (*pb.GetSpiceInfoResponse, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	// SPICE is interactive console/graphics access to the guest; require
	// vm.console on the VM's tenancy project, checked on the entry host where
	// the caller identity is present (before any forward to the owning host).
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.console", "operator"); err != nil {
		return nil, err
	}
	if vm.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q is not running (state: %s)", req.VmName, vm.State)
	}

	// If the VM lives on another host, forward to that host's daemon. We
	// already authenticated; the inter-daemon mTLS handles the hop.
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.GetSpiceInfo(ctx, req)
	}

	port, err := s.virt.GetVMSpicePort(req.VmName)
	if err != nil || port < 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"SPICE not available for %q: %v", req.VmName, err)
	}

	host, err := corrosion.GetHost(ctx, s.db, vm.HostName)
	if err != nil || host == nil {
		return nil, status.Errorf(codes.Internal, "lookup host %q: %v", vm.HostName, err)
	}

	uri := fmt.Sprintf("spice://%s:%d", host.Address, port)
	return &pb.GetSpiceInfoResponse{
		Host: host.Address,
		Port: int32(port),
		Uri:  uri,
	}, nil
}
