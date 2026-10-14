package corrosion

import (
	"context"
	"testing"
)

// TestUpsertBindingDoesNotResurrectATombstone is the #217 regression.
//
// UpsertBinding's UPDATE set `deleted_at = NULL` with `WHERE prefix_id = ?` and
// nothing else, so a revalidation or re-key pass that ran against a RELEASED
// binding silently brought it back — bound to a network that no longer exists.
//
// The damage does not stop there. ClaimBinding's conflict clause is guarded by
// `WHERE netbox_bindings.deleted_at IS NOT NULL`, so once the tombstone has
// been cleared that guard no longer fires: the prefix can never be reclaimed,
// and the read-back reports the resurrected row's network instead of the
// claimant's. ClaimBinding forty lines above has exactly the guard UpsertBinding
// lacked.
func TestUpsertBindingDoesNotResurrectATombstone(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if claimed, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	}); err != nil || !claimed {
		t.Fatalf("first claim: claimed=%v err=%v", claimed, err)
	}
	if err := DeleteBinding(ctx, c, 7); err != nil {
		t.Fatalf("DeleteBinding: %v", err)
	}

	// Revalidation of a binding that was released underneath it. UpsertBinding
	// documents itself as rewriting an EXISTING binding, and a tombstone is not
	// one — it must refuse, the same way it refuses a prefix with no row at all.
	err := UpsertBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	})
	if err == nil {
		t.Fatal("UpsertBinding on a RELEASED prefix should error, not resurrect it")
	}

	got, gErr := GetBindingByPrefix(ctx, c, 7)
	if gErr != nil {
		t.Fatalf("GetBindingByPrefix: %v", gErr)
	}
	if got != nil {
		t.Fatalf("the released prefix is bound again: %+v", got)
	}
}

// The consequence the resurrection causes: with the tombstone cleared,
// ClaimBinding's `deleted_at IS NOT NULL` conflict guard stops firing and the
// prefix becomes permanently unclaimable. Pinned separately so a regression
// that re-opens the write path is reported as the reclaim failure operators
// would actually see.
func TestReleasedPrefixStaysClaimableAfterARevalidation(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if claimed, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	}); err != nil || !claimed {
		t.Fatalf("first claim: claimed=%v err=%v", claimed, err)
	}
	if err := DeleteBinding(ctx, c, 7); err != nil {
		t.Fatalf("DeleteBinding: %v", err)
	}
	// A revalidation pass races in against the released prefix.
	_ = UpsertBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	})

	claimed, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "net-b", PrefixID: 7, ObservedCIDR: "10.0.6.0/24",
		VRFID: 4, ClusterFingerprint: "def456",
	})
	if err != nil {
		t.Fatalf("re-claim after a revalidation: %v", err)
	}
	if !claimed {
		t.Fatal("a released prefix must still be claimable after a revalidation pass")
	}
	got, gErr := GetBindingByPrefix(ctx, c, 7)
	if gErr != nil || got == nil {
		t.Fatalf("re-claimed binding not found: %+v err=%v", got, gErr)
	}
	if got.Network != "net-b" {
		t.Errorf("prefix bound to %q, want net-b", got.Network)
	}
}

// A LIVE binding must still be rewritable — that is what UpsertBinding is for.
func TestUpsertBindingStillRewritesALiveRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if claimed, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	}); err != nil || !claimed {
		t.Fatalf("first claim: claimed=%v err=%v", claimed, err)
	}
	if err := UpsertBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.9.0/24",
		VRFID: 5, ClusterFingerprint: "rekeyed",
	}); err != nil {
		t.Fatalf("rewriting a live binding: %v", err)
	}
	got, err := GetBindingByPrefix(ctx, c, 7)
	if err != nil || got == nil {
		t.Fatalf("binding not found: %+v err=%v", got, err)
	}
	if got.ObservedCIDR != "10.0.9.0/24" || got.VRFID != 5 || got.ClusterFingerprint != "rekeyed" {
		t.Errorf("rewrite did not land: %+v", got)
	}
}
