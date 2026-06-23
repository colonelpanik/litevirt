package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A stack network is matched for teardown by its stack_name column OR the
// scoped-name convention "<stack>_<net>" — the latter survives a migration that
// re-provisions the row with an empty stack_name (the live-test network orphan).
func TestNetworkBelongsToStack(t *testing.T) {
	cases := []struct {
		name  string
		nr    corrosion.NetworkRecord
		stack string
		want  bool
	}{
		{"stack_name match", corrosion.NetworkRecord{Name: "lbmix_lbnet", StackName: "lbmix"}, "lbmix", true},
		{"scoped-name match, empty stack_name (post-migration)", corrosion.NetworkRecord{Name: "lbmix_lbnet", StackName: ""}, "lbmix", true},
		{"unrelated network", corrosion.NetworkRecord{Name: "br0", StackName: ""}, "lbmix", false},
		{"other stack's network", corrosion.NetworkRecord{Name: "other_net", StackName: "other"}, "lbmix", false},
		{"empty stack name never matches", corrosion.NetworkRecord{Name: "_x", StackName: ""}, "", false},
	}
	for _, c := range cases {
		if got := networkBelongsToStack(c.nr, c.stack); got != c.want {
			t.Errorf("%s: networkBelongsToStack(%+v, %q) = %v, want %v", c.name, c.nr, c.stack, got, c.want)
		}
	}
}

// removeLBForStack must recognize a stack's LB even after DeleteStack has
// soft-deleted the lb_config row — otherwise haproxy/keepalived are orphaned.
func TestStackHasLBConfig_IncludesSoftDeleted(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	if s.stackHasLBConfig(ctx, "app-lb") {
		t.Fatal("no row yet, want false")
	}
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "app-lb", StackName: "app", VIP: "10.0.0.9/24", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if !s.stackHasLBConfig(ctx, "app-lb") {
		t.Fatal("active row, want true")
	}
	// Soft-delete the way DeleteStack does, then it must STILL be found.
	if err := corrosion.SoftDeleteLBConfig(ctx, s.db, "app-lb"); err != nil {
		t.Fatal(err)
	}
	if !s.stackHasLBConfig(ctx, "app-lb") {
		t.Fatal("soft-deleted row not found — teardown would orphan haproxy/keepalived")
	}
}
