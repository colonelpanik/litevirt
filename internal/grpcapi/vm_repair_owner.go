package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// repairActorMDKey carries the initiating operator's identity across a peer
// forward so the write-site audit names the real principal, not the peer
// daemon's bearerless "admin" mTLS identity. Trusted because the forward
// travels over peer mTLS (a compromised peer can already write the DB directly).
const repairActorMDKey = "x-litevirt-repair-actor"

// repairActor resolves who to attribute a repair to: the operator identity
// forwarded in peer-mTLS metadata if present (a forwarded call), otherwise the
// authenticated caller (the entry node / a direct call).
func repairActor(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(repairActorMDKey); len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	return callerUsername(ctx)
}

// RepairVMOwner re-stamps a VM's ownership (host_name) and running state with a
// fresh timestamp on the host that actually runs it — the narrow, audited admin
// repair for an equal-timestamp LWW ownership split that a stationary VM can't
// self-heal (a bystander node holds a stale host_name at the same updated_at,
// and ordinary replication keeps-local on the tie forever). The fresh updated_at
// wins by normal newer-LWW everywhere, so the stale row converges to the running
// host.
//
// Safety (invariant 8 — positive proof, never destructive):
//   - path-scoped RBAC: requires the "vm.repair-owner" verb on the VM's own
//     tenancy path, enforced on the ENTRY node BEFORE forwarding, so a
//     scope-limited token cannot repair a VM outside its scope;
//   - it is FORWARDED to the named host and applied ONLY when that host
//     positively confirms via its own libvirt that the VM is running locally —
//     so ownership can never be pointed at a host that doesn't run the VM;
//   - it writes only the VM's DB row (UpdateVMHost): host_name + state="running"
//     + cleared state_detail + fresh updated_at. It never touches the running
//     domain, so even a misdirected call can't destroy or move a workload, and
//     is recoverable by re-running against the correct host. Clearing
//     state_detail is intentional: the host has just proven the VM is running,
//     so any stale fence/migration marker is no longer true.
//
// This is the manual precursor to the Phase-3 runtime owner-assert, which
// automates the same write under full all-hosts-absent gating.
func (s *Server) RepairVMOwner(ctx context.Context, req *pb.RepairVMOwnerRequest) (*pb.RepairVMOwnerResponse, error) {
	if req.GetName() == "" || req.GetHost() == "" {
		return nil, status.Error(codes.InvalidArgument, "name and host required")
	}
	// Deny callers who could never be authorized for any path, without first
	// leaking whether the VM exists.
	if err := s.requirePermPrecheck(ctx, "admin"); err != nil {
		return nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.GetName())
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "vm %q not found", req.GetName())
	}
	// Authoritative, scope-enforced per-VM check on the entry node before we
	// forward — this is what stops a scoped token repairing out-of-scope VMs.
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.repair-owner", "admin"); err != nil {
		s.audit(ctx, "vm.repair-owner", req.GetName(), "permission denied", "denied")
		return nil, err
	}

	actor := repairActor(ctx)

	// Forward to the named host — only it can corroborate against its OWN
	// libvirt that the VM runs there. Carry the real operator identity so the
	// target's audit attributes the write correctly.
	if req.GetHost() != s.hostName {
		client, conn, err := s.peerClient(ctx, req.GetHost())
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", req.GetHost(), err)
		}
		defer conn.Close()
		fwdCtx := metadata.AppendToOutgoingContext(ctx, repairActorMDKey, actor)
		return client.RepairVMOwner(fwdCtx, req)
	}

	// We are the target host. Require positive proof the VM runs HERE before
	// claiming ownership for this host.
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
	s.auditAs(ctx, actor, "vm.repair-owner", req.GetName(),
		fmt.Sprintf("owner %s -> %s (running; state_detail cleared, fresh ts)", prev, s.hostName), "ok")
	return &pb.RepairVMOwnerResponse{Host: s.hostName, PreviousHost: prev}, nil
}
