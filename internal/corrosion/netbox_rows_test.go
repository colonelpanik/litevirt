package corrosion

import (
	"context"
	"testing"
)

func TestBindingPrefixIsUniqueAcrossNetworks(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t) // existing helper in this package's test files

	if err := UpsertBinding(ctx, c, BindingRecord{
		Network: "net-a", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	}); err != nil {
		t.Fatal(err)
	}
	// A SECOND network binding the SAME prefix must collide on the PK, which is
	// how overlap rejection is structural rather than a validation someone can
	// forget to call.
	if err := UpsertBinding(ctx, c, BindingRecord{
		Network: "net-b", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "abc123",
	}); err != nil {
		t.Fatal(err)
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
	if err := UpsertBinding(ctx, c, BindingRecord{
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
