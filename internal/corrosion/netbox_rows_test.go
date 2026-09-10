package corrosion

import (
	"context"
	"testing"
)

func TestBindingPrefixIsUniqueAcrossNetworks(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t) // existing helper in this package's test files

	// Rows are created via ClaimBinding (the only path that may create a
	// binding) — this test's intent is to exercise the uniqueness path, not
	// UpsertBinding, which now refuses to create.
	claimed, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Fatal("first claim of an unbound prefix should succeed")
	}
	// A SECOND network claiming the SAME prefix must collide on the PK, which is
	// how overlap rejection is structural rather than a validation someone can
	// forget to call.
	claimed, err = ClaimBinding(ctx, c, BindingRecord{
		Network: "net-b", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("second network's claim of an already-bound prefix should fail")
	}
	got, err := GetBindingByPrefix(ctx, c, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("binding not found")
	}
	// Exactly one row exists for the prefix; the caller (bind validation) is what
	// refuses the second bind, and it reads this row to do so.
	all, err := ListBindings(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("want exactly 1 binding row for one prefix, got %d", len(all))
	}
}

func TestSuspendBinding(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if _, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	}); err != nil {
		t.Fatal(err)
	}
	if err := SuspendBinding(ctx, c, 7, "prefix CIDR changed"); err != nil {
		t.Fatal(err)
	}
	got, err := GetBindingByNetwork(ctx, c, "net-a")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Suspended || got.SuspendReason != "prefix CIDR changed" {
		t.Fatalf("binding = %+v, want suspended with a reason", got)
	}
}

// TestClaimBindingFirstWriterWins exercises ClaimBinding's safety-critical
// "first writer wins" contract: two concurrent binds of the same NetBox
// prefix by different networks must resolve to exactly one winner, and the
// loser must not overwrite the winner's row.
func TestClaimBindingFirstWriterWins(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	claimed, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Fatal("net-a should win the first claim of an unbound prefix")
	}

	claimed, err = ClaimBinding(ctx, c, BindingRecord{
		Network: "net-b", PrefixID: 7, ObservedCIDR: "10.0.6.0/24",
		VRFID: 3, ClusterFingerprint: "def456",
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("net-b should lose the claim: net-a already holds the prefix")
	}

	got, err := GetBindingByPrefix(ctx, c, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("binding not found")
	}
	if got.Network != "net-a" {
		t.Fatalf("loser must not overwrite the winner: got network %q, want net-a", got.Network)
	}

	// Idempotent re-claim by the current holder must still return true.
	claimed, err = ClaimBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Fatal("re-claim by the existing holder should succeed")
	}
}

// TestUpsertBindingRefusesToCreate pins UpsertBinding's contract: it updates
// an EXISTING binding only. When no row exists for the prefix it must return
// an error rather than silently creating one — a silent create would bypass
// ClaimBinding's uniqueness read-back.
func TestUpsertBindingRefusesToCreate(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	err := UpsertBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	})
	if err == nil {
		t.Fatal("UpsertBinding on a nonexistent prefix should error, not create a row")
	}

	got, err := GetBindingByPrefix(ctx, c, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("UpsertBinding must not have created a row, got %+v", got)
	}
}

// TestClaimBindingReclaimsTombstone pins the release→rebind cycle. The conflict
// target is the prefix_id PRIMARY KEY, which a TOMBSTONED row still occupies:
// a plain DO NOTHING would leave a released prefix permanently unclaimable —
// the insert would collide with the tombstone, the read-back (which filters
// deleted_at IS NULL) would see nothing, and the claim would fail with
// "vanished after insert". Releasing a prefix has to make it bindable again,
// or DeleteBinding just converts one leak into another.
func TestClaimBindingReclaimsTombstone(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if claimed, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	}); err != nil || !claimed {
		t.Fatalf("first claim: claimed=%v err=%v", claimed, err)
	}
	if err := DeleteBinding(ctx, c, 7); err != nil {
		t.Fatal(err)
	}
	got, err := GetBindingByPrefix(ctx, c, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("released prefix must read back as unbound, got %+v", got)
	}

	claimed, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "net-b", PrefixID: 7, ObservedCIDR: "10.0.6.0/24",
		VRFID: 4, ClusterFingerprint: "def456",
	})
	if err != nil {
		t.Fatalf("re-claim of a released prefix: %v", err)
	}
	if !claimed {
		t.Fatal("a released prefix must be claimable again")
	}

	got, err = GetBindingByPrefix(ctx, c, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("re-claimed binding not found")
	}
	// The resurrected row must carry the NEW holder's values throughout, not a
	// mix of the tombstone's and the claimant's.
	if got.Network != "net-b" || got.ObservedCIDR != "10.0.6.0/24" || got.VRFID != 4 ||
		got.ClusterFingerprint != "def456" {
		t.Fatalf("re-claim must fully rewrite the row, got %+v", got)
	}
	if got.Suspended {
		t.Fatal("a re-claimed binding must not inherit a suspension")
	}
	if b, err := GetBindingByNetwork(ctx, c, "net-a"); err != nil || b != nil {
		t.Fatalf("the released network must hold nothing, got %+v err=%v", b, err)
	}
}

// TestDeleteBindingIsIdempotent: a compensating caller retries a release, and a
// release of a prefix that was never bound must not error either.
func TestDeleteBindingIsIdempotent(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if err := DeleteBinding(ctx, c, 99); err != nil {
		t.Fatalf("releasing an unbound prefix must be a no-op, got %v", err)
	}
	if _, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteBinding(ctx, c, 7); err != nil {
		t.Fatal(err)
	}
	if err := DeleteBinding(ctx, c, 7); err != nil {
		t.Fatalf("second release must be a no-op, got %v", err)
	}
	all, err := ListBindings(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Fatalf("want no live bindings after release, got %d", len(all))
	}
}

// TestGetLeaseByIPForOwnerIgnoresAForeignLease pins the owner predicate on the
// READ, not just on the release.
//
// (network, ip) is the primary key, so a lease held by someone else is still a
// single row this read could hand back. A caller that then released it would be
// refused by the owner-scoped ReleaseLease — turning another owner's address
// into a workload that can never be deleted. Reading nil is what lets the caller
// treat it as "not ours, nothing to do".
func TestGetLeaseByIPForOwnerIgnoresAForeignLease(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if err := c.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES ('net-a', '10.0.5.100', 'aa:bb:cc:dd:ee:ff', 'other-vm', 'vm', '', 42, 7, ?, ?)`,
		c.NowWall(), c.NowWall()); err != nil {
		t.Fatalf("seed lease: %v", err)
	}

	// The row exists and is readable for the owner that holds it — without this
	// the miss below could be a typo in the seed rather than the predicate.
	got, err := GetLeaseByIPForOwner(ctx, c, "net-a", "10.0.5.100", "vm", "", "other-vm")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("the holder's own read must find the lease")
	}
	if got.NetBoxIPID != 42 || got.NetBoxPrefix != 7 {
		t.Fatalf("NetBox join keys = (%d, %d), want (42, 7)", got.NetBoxIPID, got.NetBoxPrefix)
	}

	// Every component of the triple is load-bearing, so each is missed alone.
	for _, tc := range []struct {
		what                       string
		ownerKind, ownerHost, name string
	}{
		{"a different name", "vm", "", "my-vm"},
		{"a different owner kind", "ct", "", "other-vm"},
		{"a different owner host", "vm", "node-2", "other-vm"},
	} {
		got, err := GetLeaseByIPForOwner(ctx, c, "net-a", "10.0.5.100", tc.ownerKind, tc.ownerHost, tc.name)
		if err != nil {
			t.Fatalf("%s: %v", tc.what, err)
		}
		if got != nil {
			t.Fatalf("%s must not read back a foreign lease, got %+v", tc.what, got)
		}
	}
}
