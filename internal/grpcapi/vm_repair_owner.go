package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// RepairVMOwner re-stamps a VM's host_name ownership with a fresh timestamp on the
// host that actually runs it — the narrow, audited admin repair for an
// equal-timestamp LWW ownership split that a stationary VM can't self-heal (a
// bystander node holds a stale host_name at the same updated_at, and ordinary
// replication keeps-local on the tie forever). The fresh updated_at wins by normal
// newer-LWW everywhere, so the stale row converges to the running host.
//
// Safety (invariant 8 — positive proof, never destructive):
//   - admin only;
//   - it is FORWARDED to the named host and applied ONLY when that host positively
//     confirms via its own libvirt that the VM is running locally — so ownership
//     can never be pointed at a host that doesn't run the VM;
//   - it only writes the DB owner row (UpdateVMHost); it never touches the domain,
//     so even a misdirected call can't destroy or move a workload, and is
//     recoverable by re-running against the correct host.
//
// This is the manual precursor to the Phase-3 runtime owner-assert, which
// automates the same write under full all-hosts-absent gating.
func (s *Server) RepairVMOwner(ctx context.Context, req *pb.RepairVMOwnerRequest) (*pb.RepairVMOwnerResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.GetName() == "" || req.GetHost() == "" {
		return nil, status.Error(codes.InvalidArgument, "name and host required")
	}

	// Forward to the target host — it must corroborate against its OWN libvirt.
	if req.GetHost() != s.hostName {
		client, conn, err := s.peerClient(ctx, req.GetHost())
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", req.GetHost(), err)
		}
		defer conn.Close()
		return client.RepairVMOwner(ctx, req)
	}

	// We are the target host. Require positive proof the VM runs HERE before
	// claiming ownership for this host.
	vm, err := corrosion.GetVM(ctx, s.db, req.GetName())
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "vm %q not found", req.GetName())
	}
	if s.virt == nil {
		return nil, status.Error(codes.Unavailable, "libvirt not wired on this host")
	}
	state, serr := s.virt.DomainState(req.GetName())
	if serr != nil || state != "running" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"vm %q is not running on %q (state=%q, err=%v); run repair-owner against the host that actually runs it",
			req.GetName(), s.hostName, state, serr)
	}

	prev := vm.HostName
	if err := corrosion.UpdateVMHost(ctx, s.db, req.GetName(), s.hostName, "running"); err != nil {
		return nil, status.Errorf(codes.Internal, "update owner: %v", err)
	}
	s.audit(ctx, "vm.repair-owner", req.GetName(),
		fmt.Sprintf("owner %s -> %s (running, fresh ts)", prev, s.hostName), "ok")
	return &pb.RepairVMOwnerResponse{Host: s.hostName, PreviousHost: prev}, nil
}
