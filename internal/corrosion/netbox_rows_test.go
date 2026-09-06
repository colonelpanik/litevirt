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
