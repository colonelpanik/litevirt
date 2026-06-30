package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// auditActor returns the username recorded on the single matching audit row.
func auditActor(t *testing.T, s *Server, action, result string) string {
	t.Helper()
	rows, err := s.db.Query(adminCtx(),
		`SELECT username FROM audit_log WHERE action = ? AND result = ?`, action, result)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 %s/%s audit row, got %d", action, result, len(rows))
	}
	return rows[0].String("username")
}

func TestRepairVMOwner(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake
	ctx := context.Background()

	// A VM whose DB row wrongly says host-b, with a stale fence/migration detail,
	// but which actually runs on host-a.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-b", State: "running", StateDetail: "migrating", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Not running locally yet → refused, owner untouched (can't claim a VM we
	// don't actually run).
	if _, err := s.RepairVMOwner(adminCtx(), &pb.RepairVMOwnerRequest{Name: "vm1", Host: "host-a"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("not-running: want FailedPrecondition, got %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm == nil || vm.HostName != "host-b" {
		t.Fatalf("owner must be unchanged when not running locally, got %+v", vm)
	}

	// Now it's confirmed running locally → re-assert ownership to host-a, set
	// state=running, and clear the now-false state_detail.
	fake.SetState("vm1", libvirtfake.StateRunning)
	resp, err := s.RepairVMOwner(adminCtx(), &pb.RepairVMOwnerRequest{Name: "vm1", Host: "host-a"})
	if err != nil {
		t.Fatalf("RepairVMOwner: %v", err)
	}
	if resp.GetHost() != "host-a" || resp.GetPreviousHost() != "host-b" {
		t.Fatalf("resp = %+v, want host-a (was host-b)", resp)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
	if vm == nil || vm.HostName != "host-a" || vm.State != "running" || vm.StateDetail != "" {
		t.Fatalf("owner must be re-stamped to host-a/running with cleared detail, got %+v", vm)
	}
	// Audited as the caller.
	if got := auditActor(t, s, "vm.repair-owner", "ok"); got != "admin" {
		t.Fatalf("audit actor = %q, want admin", got)
	}

	// Admin only.
	if _, err := s.RepairVMOwner(viewerCtx(), &pb.RepairVMOwnerRequest{Name: "vm1", Host: "host-a"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer: want PermissionDenied, got %v", err)
	}
	// Unknown VM.
	if _, err := s.RepairVMOwner(adminCtx(), &pb.RepairVMOwnerRequest{Name: "ghost", Host: "host-a"}); status.Code(err) != codes.NotFound {
		t.Fatalf("ghost: want NotFound, got %v", err)
	}
}

// A forwarded call (peer mTLS authenticates as the bearerless "admin") must
// attribute the audit to the operator who initiated it, carried in trusted
// peer-mTLS metadata.
func TestRepairVMOwner_ForwardedActorAttribution(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake
	ctx := context.Background()

	// The actor override is honored only for a genuine cluster peer (a host-cert
	// CN registered in `hosts`).
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "docker-peer", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-b", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake.SetState("vm1", libvirtfake.StateRunning)

	// Simulate the target receiving a forward from peer "docker-peer": the
	// initiating operator ("alice") rides in trusted metadata.
	fwd := metadata.NewIncomingContext(mtlsAdminCtx("docker-peer"), metadata.Pairs(repairActorMDKey, "alice"))
	if _, err := s.RepairVMOwner(fwd, &pb.RepairVMOwnerRequest{Name: "vm1", Host: "host-a"}); err != nil {
		t.Fatalf("RepairVMOwner (forwarded): %v", err)
	}
	if got := auditActor(t, s, "vm.repair-owner", "ok"); got != "alice" {
		t.Fatalf("forwarded audit actor = %q, want alice (the initiator), not the peer admin", got)
	}
}

// A non-peer caller (no host-cert mTLS) cannot spoof the audit actor by injecting
// the metadata — the override is honored only for a genuine peer, so the audit
// records the real caller.
func TestRepairVMOwner_NonPeerCannotSpoofActor(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-b", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake.SetState("vm1", libvirtfake.StateRunning)

	// A direct admin caller injects the actor header — it must be ignored.
	spoof := metadata.NewIncomingContext(adminCtx(), metadata.Pairs(repairActorMDKey, "alice"))
	if _, err := s.RepairVMOwner(spoof, &pb.RepairVMOwnerRequest{Name: "vm1", Host: "host-a"}); err != nil {
		t.Fatalf("RepairVMOwner: %v", err)
	}
	if got := auditActor(t, s, "vm.repair-owner", "ok"); got != "admin" {
		t.Fatalf("audit actor = %q, want admin (spoofed header must be ignored)", got)
	}
}

// A scoped token (admin role, but scope_paths limited to one project) must NOT
// be able to repair a VM outside its scope — the scope check runs on the entry
// node before any forward, so it can't be bypassed.
func TestRepairVMOwner_ScopedTokenDenied(t *testing.T) {
	s := scopedRequirePermSetup(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake
	ctx := context.Background()

	// VM lives in project "other"; alice is scoped to "/projects/acme".
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "db", HostName: "host-b", Project: "other", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	scoped := aliceCtxWithScopes([]string{"/projects/acme"})
	if _, err := s.RepairVMOwner(scoped, &pb.RepairVMOwnerRequest{Name: "db", Host: "host-a"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("out-of-scope repair: want PermissionDenied, got %v", err)
	}
	// Owner untouched.
	if vm, _ := corrosion.GetVM(ctx, s.db, "db"); vm == nil || vm.HostName != "host-b" {
		t.Fatalf("owner must be unchanged on a denied repair, got %+v", vm)
	}

	// A VM inside the scope is repairable (proves the per-VM scoping allows the
	// in-scope case, not a blanket deny).
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", HostName: "host-b", Project: "acme", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake.SetState("web", libvirtfake.StateRunning)
	if _, err := s.RepairVMOwner(scoped, &pb.RepairVMOwnerRequest{Name: "web", Host: "host-a"}); err != nil {
		t.Fatalf("in-scope repair: want allow, got %v", err)
	}
}
