package network

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// newTestDB returns an in-memory corrosion.Client with schema applied — the
// existing pattern used throughout this package (see ipam_test.go), wrapped
// here so allocator tests don't repeat the three-line setup.
func newTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

func TestBuiltinClaimIsAPassthrough(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	a := NewBuiltinAllocator(db)
	got, err := a.Claim(ctx, ClaimRequest{
		Network: "net-a", Subnet: "10.0.5.0/24", MAC: "52:54:00:aa:bb:cc",
		OwnerKind: "ct", OwnerHost: "host-1", Name: "ct-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Byte-identical to calling AllocateIPFor directly: the builtin allocator
	// must add NO behaviour, or the refactor changes what every existing
	// container deployment gets.
	if got.IP != "10.0.5.2" {
		t.Fatalf("IP = %q, want 10.0.5.2 (the first host address)", got.IP)
	}
	if got.NetBoxIPID != 0 {
		t.Fatalf("builtin must not report a NetBox id, got %d", got.NetBoxIPID)
	}
}

func TestBuiltinReleaseIsPerIPNotPerVM(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	a := NewBuiltinAllocator(db)

	// Two NICs for the SAME owner on the SAME network.
	first, err := a.Claim(ctx, ClaimRequest{
		Network: "net-a", Subnet: "10.0.5.0/24", MAC: "52:54:00:aa:bb:01",
		OwnerKind: "ct", OwnerHost: "host-1", Name: "ct-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Claim(ctx, ClaimRequest{
		Network: "net-a", Subnet: "10.0.5.0/24", MAC: "52:54:00:aa:bb:02",
		OwnerKind: "ct", OwnerHost: "host-1", Name: "ct-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Releasing ONE must not tombstone the other. The old bulk
	// UPDATE ... WHERE network = ? AND vm_name = ? released both.
	if err := a.Release(ctx, ReleaseRequest{
		Network: "net-a", IP: first.IP, MAC: "52:54:00:aa:bb:01",
		OwnerKind: "ct", OwnerHost: "host-1", Name: "ct-1",
	}); err != nil {
		t.Fatal(err)
	}

	alloc, err := GetAllocationFor(ctx, db, "net-a", "ct", "host-1", "ct-1")
	if err != nil {
		t.Fatal(err)
	}
	if alloc == nil {
		t.Fatal("releasing one NIC tombstoned the other lease")
	}
	if alloc.IP != second.IP {
		t.Fatalf("surviving lease = %q, want %q", alloc.IP, second.IP)
	}
}

// TestReleaseLeaseRefusesWrongOwner pins the owner-scoping in ReleaseLease's
// WHERE clause: a release for the wrong owner tuple on a live (network, ip)
// must be refused, not silently applied. Without the mac/owner predicates a
// stale detach — e.g. one arriving after the address was reassigned to a new
// holder — would tombstone the CURRENT holder's lease instead of erroring.
func TestReleaseLeaseRefusesWrongOwner(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	// Seed a live lease for owner A.
	ip, err := AllocateIPFor(ctx, db, "net-a", "10.0.5.0/24", "52:54:00:aa:bb:01", "ct", "host-a", "ct-a")
	if err != nil {
		t.Fatal(err)
	}
	before, err := GetAllocationFor(ctx, db, "net-a", "ct", "host-a", "ct-a")
	if err != nil {
		t.Fatal(err)
	}
	if before == nil {
		t.Fatal("seed lease is missing")
	}

	// Release with owner B's tuple (same network+ip, different host/name).
	err = ReleaseLease(ctx, db, "net-a", ip, "52:54:00:aa:bb:01", "ct", "host-b", "ct-b")
	if err == nil {
		t.Fatal("ReleaseLease with the wrong owner tuple must return an error")
	}

	after, err := GetAllocationFor(ctx, db, "net-a", "ct", "host-a", "ct-a")
	if err != nil {
		t.Fatal(err)
	}
	if after == nil {
		t.Fatal("owner A's lease was released despite the wrong owner tuple in the request")
	}
	if after.IP != ip {
		t.Fatalf("owner A's lease changed IP: got %q, want %q", after.IP, ip)
	}
}
