package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// seedNetworkDef persists a network whose config blob is the given def — the
// same shape provisionAndPersistNetwork writes (json.Marshal of the def).
func seedNetworkDef(t *testing.T, s *Server, name string, def compose.NetworkDef) {
	t.Helper()
	cfg, err := json.Marshal(def)
	if err != nil {
		t.Fatalf("marshal def: %v", err)
	}
	ntype := def.Type
	if ntype == "" {
		ntype = "bridge"
	}
	if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{
		Name: name, Type: ntype, Config: string(cfg),
	}); err != nil {
		t.Fatalf("seed network %q: %v", name, err)
	}
}

// seedBinding claims a prefix for a network, the row CreateNetwork writes after
// validation succeeds.
func seedBinding(t *testing.T, s *Server, network string, prefixID int, suspended bool) {
	t.Helper()
	ctx := context.Background()
	ok, err := corrosion.ClaimBinding(ctx, s.db, corrosion.BindingRecord{
		Network: network, PrefixID: prefixID, ObservedCIDR: "10.0.5.0/24", VRFID: 3,
		ClusterFingerprint: "fp",
	})
	if err != nil {
		t.Fatalf("ClaimBinding: %v", err)
	}
	if !ok {
		t.Fatalf("ClaimBinding did not take prefix %d", prefixID)
	}
	// A bind always lands unsuspended (ClaimBinding pins suspended = 0);
	// suspension is a later revalidation outcome, so drive it the same way.
	if suspended {
		if err := corrosion.SuspendBinding(ctx, s.db, prefixID, "prefix re-CIDRed in NetBox"); err != nil {
			t.Fatalf("SuspendBinding: %v", err)
		}
	}
}

// writeTokenFile writes a NetBox API token where netbox.New can read it.
func writeTokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "netbox-token")
	if err := os.WriteFile(p, []byte("test-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return p
}

// TestAllocatorForVMOnUnboundNetworkAllocatesNothing pins today's behaviour: a
// VM on an unbound network gets NO allocator at all. Returning the builtin one
// would newly address every VM on every existing network.
func TestAllocatorForVMOnUnboundNetworkAllocatesNothing(t *testing.T) {
	s := testServer(t)
	seedNetworkDef(t, s, "plain", compose.NetworkDef{Type: "bridge", Subnet: "10.0.5.0/24"})

	alloc, binding, err := s.allocatorFor(context.Background(), "vm", "plain")
	if err != nil {
		t.Fatalf("unbound VM must not be refused: %v", err)
	}
	if alloc != nil {
		t.Fatalf("VM on an unbound network must get no allocator, got %T", alloc)
	}
	if binding != nil {
		t.Fatalf("unbound network reported a binding: %+v", binding)
	}
}

// TestAllocatorForContainerOnUnboundNetworkGetsBuiltin pins the other half of
// the matrix: containers keep allocating exactly as they do today.
func TestAllocatorForContainerOnUnboundNetworkGetsBuiltin(t *testing.T) {
	s := testServer(t)
	seedNetworkDef(t, s, "plain", compose.NetworkDef{Type: "bridge", Subnet: "10.0.5.0/24"})

	alloc, binding, err := s.allocatorFor(context.Background(), "ct", "plain")
	if err != nil {
		t.Fatalf("unbound container must not be refused: %v", err)
	}
	if alloc == nil {
		t.Fatal("container on an unbound network must get the builtin allocator")
	}
	if binding != nil {
		t.Fatalf("unbound network reported a binding: %+v", binding)
	}
	if got := fmt.Sprintf("%T", alloc); !strings.Contains(got, "builtin") {
		t.Fatalf("container allocator = %s, want the builtin one", got)
	}
}

// TestAllocatorForRefusesContainerOnBoundNetwork: a container on a bound network
// is refused, not silently allocated around the external IPAM.
func TestAllocatorForRefusesContainerOnBoundNetwork(t *testing.T) {
	s := testServer(t)
	seedNetworkDef(t, s, "bound", compose.NetworkDef{Type: "bridge", Subnet: "10.0.5.0/24", NetBoxPrefixID: 7})
	seedBinding(t, s, "bound", 7, false)

	alloc, _, err := s.allocatorFor(context.Background(), "ct", "bound")
	if err == nil {
		t.Fatal("a container on a bound network must be refused")
	}
	if alloc != nil {
		t.Fatalf("a refusal must hand back no allocator, got %T", alloc)
	}
	if !strings.Contains(err.Error(), "bound networks") {
		t.Fatalf("refusal must name the binding as the reason, got: %v", err)
	}
}

// TestAllocatorForRefusesUnboundDefNamingPrefix is the config/binding
// disagreement case.
//
// A network whose config names a NetBox prefix but has NO binding row was never
// validated against NetBox and holds no claim on that prefix. Treating it as
// unbound would silently allocate from the builtin allocator across an address
// space someone believes is externally managed, so it must be LOUD.
func TestAllocatorForRefusesUnboundDefNamingPrefix(t *testing.T) {
	s := testServer(t)
	seedNetworkDef(t, s, "half-bound", compose.NetworkDef{Type: "bridge", Subnet: "10.0.5.0/24", NetBoxPrefixID: 7})

	for _, kind := range []string{"vm", "ct"} {
		alloc, _, err := s.allocatorFor(context.Background(), kind, "half-bound")
		if err == nil {
			t.Fatalf("%s: a def naming prefix 7 with no binding row must be refused", kind)
		}
		if alloc != nil {
			t.Fatalf("%s: a refusal must hand back no allocator, got %T", kind, alloc)
		}
		if !strings.Contains(err.Error(), "no binding exists") {
			t.Fatalf("%s: refusal must say the binding is missing, got: %v", kind, err)
		}
	}
}

// TestAllocatorForRefusesSuspendedBinding: a suspended binding refuses rather
// than claiming from a prefix whose validation has gone stale.
func TestAllocatorForRefusesSuspendedBinding(t *testing.T) {
	s := testServer(t)
	seedNetworkDef(t, s, "bound", compose.NetworkDef{Type: "bridge", Subnet: "10.0.5.0/24", NetBoxPrefixID: 7})
	seedBinding(t, s, "bound", 7, true)

	if _, _, err := s.allocatorFor(context.Background(), "vm", "bound"); err == nil {
		t.Fatal("a suspended binding must refuse")
	} else if !strings.Contains(err.Error(), "suspended") {
		t.Fatalf("refusal must name the suspension, got: %v", err)
	}
}

// TestAllocatorForRefusesBoundVMWithoutNetBoxClient: no client, no fallback.
func TestAllocatorForRefusesBoundVMWithoutNetBoxClient(t *testing.T) {
	s := testServer(t)
	seedNetworkDef(t, s, "bound", compose.NetworkDef{Type: "bridge", Subnet: "10.0.5.0/24", NetBoxPrefixID: 7})
	seedBinding(t, s, "bound", 7, false)

	alloc, _, err := s.allocatorFor(context.Background(), "vm", "bound")
	if err == nil {
		t.Fatal("a bound network with no NetBox client on this node must refuse")
	}
	if alloc != nil {
		t.Fatalf("a refusal must hand back no allocator, got %T", alloc)
	}
}

// TestAllocatorForBoundVMGetsNetBoxAllocator is the positive selection case.
func TestAllocatorForBoundVMGetsNetBoxAllocator(t *testing.T) {
	s := testServer(t)
	client, err := netbox.New(netbox.Config{BaseURL: "http://127.0.0.1:1", TokenPath: writeTokenFile(t)})
	if err != nil {
		t.Fatalf("netbox.New: %v", err)
	}
	s.SetNetBoxClient(client)
	seedNetworkDef(t, s, "bound", compose.NetworkDef{Type: "bridge", Subnet: "10.0.5.0/24", NetBoxPrefixID: 7})
	seedBinding(t, s, "bound", 7, false)

	alloc, binding, err := s.allocatorFor(context.Background(), "vm", "bound")
	if err != nil {
		t.Fatalf("bound VM must be allowed: %v", err)
	}
	if alloc == nil {
		t.Fatal("bound VM must get an allocator")
	}
	if got := fmt.Sprintf("%T", alloc); !strings.Contains(got, "netbox") {
		t.Fatalf("bound VM allocator = %s, want the NetBox one", got)
	}
	if binding == nil || binding.PrefixID != 7 || binding.ObservedCIDR != "10.0.5.0/24" || binding.VRFID != 3 {
		t.Fatalf("binding must be handed back for the claim request, got %+v", binding)
	}
}

// TestAllocatorForFailsClosedOnAnUnreadableNetworkRecord pins the one accidental
// fail-OPEN in the selector.
//
// The "config names a prefix but no binding exists" guard is a READ of the
// networks row. lookupNetworkDef used to swallow its DB error and answer nil, so
// a read failure was indistinguishable from "this network names no prefix" — and
// the builtin allocator then handed out addresses across a prefix somebody
// believes is externally managed. A read that did not happen must refuse.
func TestAllocatorForFailsClosedOnAnUnreadableNetworkRecord(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	seedNetworkDef(t, s, "plain", compose.NetworkDef{Type: "bridge", Subnet: "10.0.5.0/24"})

	// A container on an unbound network is the case that PREVIOUSLY sailed
	// through: it gets the builtin allocator, so nothing else would have failed.
	if _, _, err := s.allocatorFor(ctx, "ct", "plain"); err != nil {
		t.Fatalf("control: an unbound network must resolve cleanly, got %v", err)
	}

	// Make every read of `networks` fail. Renaming is the only way to produce a
	// read error — SQLite has no BEFORE SELECT trigger — and is the same seam
	// hideLeaseTable uses for ip_allocations.
	if err := s.db.Execute(ctx, `ALTER TABLE networks RENAME TO networks_hidden`); err != nil {
		t.Fatalf("hide the networks table: %v", err)
	}

	_, _, err := s.allocatorFor(ctx, "ct", "plain")
	if err == nil {
		t.Fatal("an unreadable networks table must refuse — a read that did not happen " +
			"cannot prove the network names no NetBox prefix")
	}
	if !strings.Contains(err.Error(), "NetBox prefix") {
		t.Fatalf("the refusal must say what could not be determined, got: %v", err)
	}
}
