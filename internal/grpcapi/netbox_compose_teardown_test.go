package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestComposeRefusesNetBoxPrefixBinding pins that a compose file cannot create a
// NetBox binding.
//
// Compose's pre-deploy calls provisionAndPersistNetwork directly, bypassing the
// bind validation CreateNetwork runs — so a `netbox-prefix-id:` key in a stack
// file would otherwise persist a network whose config names a prefix that was
// never validated and that nothing has claimed. Stack networks are also scoped,
// torn down and recreated with the stack, and the binding lifecycle does not
// follow that. Fail closed and point the operator at the command that binds.
func TestComposeRefusesNetBoxPrefixBinding(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	errs := s.provisionComposeNetworks(ctx, &compose.File{
		Name: "stack1",
		Networks: map[string]compose.NetworkDef{
			// sriov, so that with the refusal REMOVED this network provisions
			// cleanly and the assertions below fail on what actually went wrong
			// (a persisted network, an unclaimed prefix) rather than on an
			// unrelated rootless `ip link add` failure.
			"lan": {Type: "sriov", PF: "ens1f0", NetBoxPrefixID: 7},
		},
	})

	if len(errs) != 1 {
		t.Fatalf("want exactly one refusal, got %v", errs)
	}
	if !strings.Contains(errs[0], "lv network create") {
		t.Fatalf("refusal must point at the binding command, got %q", errs[0])
	}
	// Nothing may be persisted or claimed by a refused network.
	nr, err := corrosion.GetNetwork(ctx, s.db, compose.ScopedNetworkName("stack1", "lan"))
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if nr != nil {
		t.Fatalf("a refused compose network must not be persisted, got %+v", nr)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil {
		t.Fatalf("GetBindingByPrefix: %v", err)
	}
	if b != nil {
		t.Fatalf("a refused compose network must claim no prefix, got %+v", b)
	}
}

// TestComposeStillProvisionsUnboundNetworks is the negative control: the refusal
// must be scoped to defs that name a prefix. Without it, a refusal that rejected
// every compose network would pass the test above for the wrong reason.
func TestComposeStillProvisionsUnboundNetworks(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	// sriov provisions without touching the host, so this runs unprivileged.
	errs := s.provisionComposeNetworks(ctx, &compose.File{
		Name: "stack1",
		Networks: map[string]compose.NetworkDef{
			"lan": {Type: "sriov", PF: "ens1f0"},
		},
	})
	if len(errs) != 0 {
		t.Fatalf("an unbound compose network must still provision, got %v", errs)
	}
	nr, err := corrosion.GetNetwork(ctx, s.db, compose.ScopedNetworkName("stack1", "lan"))
	if err != nil || nr == nil {
		t.Fatalf("unbound compose network must be persisted: rec=%v err=%v", nr, err)
	}
}

// TestStackTeardownReleasesBinding pins that tearing a stack network down
// releases its NetBox prefix.
//
// deprovisionNetworkByName is the stack-teardown twin of DeleteNetwork, and it
// soft-deletes the network row. A binding left behind by it names a network that
// no longer exists, is invisible to every operator command, and permanently
// refuses every future bind of that prefix — recoverable only by editing the DB.
func TestStackTeardownReleasesBinding(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	seedNetworkDef(t, s, "stack1_lan", compose.NetworkDef{Type: "sriov", PF: "ens1f0", NetBoxPrefixID: 7})
	seedBinding(t, s, "stack1_lan", 7, false)

	if err := s.deprovisionNetworkByName(ctx, "stack1_lan"); err != nil {
		t.Fatalf("deprovisionNetworkByName: %v", err)
	}

	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil {
		t.Fatalf("GetBindingByPrefix: %v", err)
	}
	if b != nil {
		t.Fatalf("stack teardown must release the prefix, still bound: %+v", b)
	}
	// The prefix must be genuinely reusable afterwards, not merely absent from
	// this one query — a tombstone that still owns the primary key would refuse
	// every future bind just as loudly.
	ok, err := corrosion.ClaimBinding(ctx, s.db, corrosion.BindingRecord{
		Network: "other", PrefixID: 7, ObservedCIDR: "10.0.5.0/24", VRFID: 3,
		ClusterFingerprint: "fp",
	})
	if err != nil {
		t.Fatalf("ClaimBinding after release: %v", err)
	}
	if !ok {
		t.Fatal("a released prefix must be bindable again")
	}
}
