package network

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The PROVISION-TIME half of the DHCP refusal, and its operator surface.
//
// That refusal is what actually closes the host-local gap: BridgePreExisted is
// runtime state no row records, so a bind validated on one node says nothing
// about a node that lacks the bridge — and that node is exactly where litevirt
// would create one and stand up a second allocator over the bound prefix.
//
// WHAT IT DOES NOT DO IS STOP THE PLACEMENT. Every caller logs the refusal and
// then creates the bridge itself (see BoundNetworkDHCPRefusal), so the VM lands
// on the host the refusal named, on a bridge litevirt just made: no second DHCP
// server — that part holds, and it is the whole of the win here — but no uplink
// and no gateway either. Keeping that state visible is the health finding's job
// (netbox_dhcp_would_race), not this refusal's.
//
// Which makes two things load-bearing that were not:
//
//  1. THE MESSAGE HAS TO SAY WHICH HOST. It is read in a log line on whichever
//     node the scheduler picked — not as a placement failure, which is why
//     nothing else in front of the operator names that node — and "define the
//     network differently" is not actionable without knowing where the bridge
//     is missing.
//  2. THE REFUSAL HAS TO BE IDEMPOTENT. Provision created the bridge and THEN
//     refused, so a retry saw a pre-existing bridge, decided litevirt was not
//     the DHCP authority, and provisioned successfully — leaving a
//     litevirt-created bridge with a subnet and no DHCP server, which is guests
//     with no addresses and no explanation. That is the outcome the refusal's own
//     comment says it exists to prevent.

// recordingExec captures every command Provision would run, so a test can assert
// that a refused provision changed NOTHING on the host.
func recordingExec(t *testing.T) *[]string {
	t.Helper()
	var ran []string
	execCommand = func(name string, args ...string) ([]byte, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { execCommand = defaultExec })
	return &ran
}

func boundBridgeTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

// boundBridgeDef is the one shape that reaches the provision-time refusal: a
// managed bridge with a subnet, no VLAN, bound to a NetBox prefix, on a host
// where the bridge does not exist. Every other shape is refused at BIND time,
// cluster-wide, because its DHCP answer does not depend on the bridge.
var boundBridgeDef = compose.NetworkDef{
	Type: "bridge", Interface: "lv-no-such-br2", Subnet: "10.0.5.0/24",
	NetBoxPrefixID: 7,
}

// TestProvisionRefusalNamesTheHost.
func TestProvisionRefusalNamesTheHost(t *testing.T) {
	recordingExec(t)
	startDHCPFunc = func(_, _, _, _, _, _ string) error { return nil }
	t.Cleanup(func() { startDHCPFunc = StartDHCP })

	_, err := Provision(context.Background(), boundBridgeTestDB(t),
		"bound-net", boundBridgeDef, "10.0.0.1", "node-7")
	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "node-7") {
		t.Fatalf("the refusal must name the host it is about, got: %v", err)
	}
	// …and still the network, the prefix and what to change, which is the rest
	// of what makes it actionable.
	for _, want := range []string{"bound-net", "7", boundBridgeDef.Interface} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must name %q, got: %v", want, err)
		}
	}
}

// TestARefusedProvisionCreatesNoBridgeSoARetryRefusesToo.
//
// The refusal used to come AFTER EnsureBridge, so the first attempt created the
// bridge and the second read it as pre-existing infrastructure — which is the
// one input that turns DHCPWouldServe off for this shape. The provision then
// succeeded with no DHCP server on a subnet-ful network: guests with no
// addresses, silently, which is exactly what the refusal exists to avoid.
func TestARefusedProvisionCreatesNoBridgeSoARetryRefusesToo(t *testing.T) {
	ran := recordingExec(t)
	startDHCPFunc = func(_, _, _, _, _, _ string) error { return nil }
	t.Cleanup(func() { startDHCPFunc = StartDHCP })

	db := boundBridgeTestDB(t)
	ctx := context.Background()

	for attempt := 1; attempt <= 2; attempt++ {
		_, err := Provision(ctx, db, "bound-net", boundBridgeDef, "10.0.0.1", "node-7")
		if err == nil {
			t.Fatalf("attempt %d succeeded — a retry must refuse identically, or the refusal "+
				"is a one-shot failure a retry papers over", attempt)
		}
		if !errors.Is(err, ErrDHCPWouldRaceNetBox) {
			t.Fatalf("attempt %d: refusal must wrap ErrDHCPWouldRaceNetBox, got %v", attempt, err)
		}
	}
	// The state the retry would have read differently: nothing was created.
	for _, cmd := range *ran {
		if strings.Contains(cmd, "link add") {
			t.Fatalf("a refused provision created an interface (%q); the retry then sees a "+
				"pre-existing bridge and provisions with no DHCP server at all", cmd)
		}
	}
}

// TestBoundNetworkDHCPRefusalIsSharedWithTheEvaluator.
//
// The refusal and the health condition that makes it discoverable BEFORE a
// placement hits it must be the same predicate, not two copies of it — this
// branch has already shipped a comment that disagreed with the code it
// described, twice. So the exported form is what Provision itself calls.
func TestBoundNetworkDHCPRefusalIsSharedWithTheEvaluator(t *testing.T) {
	// The shape Provision refuses.
	err := BoundNetworkDHCPRefusal(boundBridgeDef,
		DHCPHostFacts{BridgePreExisted: false}, "bound-net", boundBridgeDef.Interface, "node-7")
	if err == nil {
		t.Fatal("the exported refusal must refuse the shape Provision refuses")
	}
	if !errors.Is(err, ErrDHCPWouldRaceNetBox) {
		t.Fatalf("want ErrDHCPWouldRaceNetBox, got %v", err)
	}
	if !strings.Contains(err.Error(), "node-7") {
		t.Fatalf("the refusal must name the host, got %v", err)
	}

	// A pre-existing bridge is the same definition on a host that does not need
	// litevirt to create one: no DHCP server, so nothing to refuse.
	if err := BoundNetworkDHCPRefusal(boundBridgeDef,
		DHCPHostFacts{BridgePreExisted: true}, "bound-net", boundBridgeDef.Interface,
		"node-7"); err != nil {
		t.Fatalf("an existing infrastructure bridge must not be refused: %v", err)
	}
	// An UNBOUND network is untouched, which is every network in every existing
	// deployment.
	unbound := boundBridgeDef
	unbound.NetBoxPrefixID = 0
	if err := BoundNetworkDHCPRefusal(unbound,
		DHCPHostFacts{BridgePreExisted: false}, "plain-net", unbound.Interface,
		"node-7"); err != nil {
		t.Fatalf("an unbound network must never be refused: %v", err)
	}
}
