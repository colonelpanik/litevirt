package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// Bind-time adoption's LOCAL-ROW refusals.
//
// These four are decided entirely from the replicated database — no NetBox call
// is involved in any of them — so they belong here rather than in the fleet:
// they are cheaper, they are deterministic, and (the reason that actually
// matters) they assert the property the fleet cannot conveniently reach, which
// is that the refusal happens BEFORE the prefix is claimed. A bind refused for
// one of these reasons must leave no binding row at all, exactly as the six
// pre-existing checks do.
//
// The fleet scenarios (tests/fleet/netbox_adopt_test.go) cover everything that
// needs a real claim: the adoption itself, the collision it prevents,
// idempotence, a foreign identity, and a partial pass finished by a resume.

// adoptTestPrefix is the prefix every case here binds, with a CIDR that
// contains the addresses they seed.
const adoptTestPrefix = 7

// newAdoptTestServer is a server whose fake NetBox serves a bindable prefix.
func newAdoptTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: adoptTestPrefix, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
}

// seedVMHoldingIP gives the server a VM whose NIC already holds an address on a
// network — the state a guest is in before anybody binds that subnet to NetBox.
func seedVMHoldingIP(t *testing.T, s *Server, vmName, netName, mac, ip, uuid string) {
	t.Helper()
	spec := fmt.Sprintf(`{"name":%q,"uuid":%q}`, vmName, uuid)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: vmName, HostName: "test-host", State: "running", Spec: spec,
	}, []corrosion.InterfaceRecord{{
		VMName: vmName, NetworkName: netName, MAC: mac, IP: ip,
	}}, nil); err != nil {
		t.Fatalf("seed VM %s: %v", vmName, err)
	}
}

// assertNothingBound is the pre-claim property: a refusal made from local rows
// alone must not have taken the prefix.
func assertNothingBound(t *testing.T, s *Server) {
	t.Helper()
	b, err := corrosion.GetBindingByPrefix(context.Background(), s.db, adoptTestPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil {
		t.Fatalf("a refusal decided from local rows must claim nothing, got %+v", b)
	}
}

// TestBindRefusesWhenTheNetworkHoldsContainerLeases: containers are unsupported
// on a bound network, so adopting one's address would leave it holding a lease
// it could never renegotiate — it could not be migrated, re-addressed or
// recreated on that network again. The bind refuses instead, and names them.
func TestBindRefusesWhenTheNetworkHoldsContainerLeases(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	// The production writer, not a hand-rolled INSERT: this is exactly the row
	// the container path leaves behind.
	ok, err := network.ReserveContainerIP(ctx, s.db, "shared", "10.0.5.9", "aa:bb:cc:00:00:09",
		"test-host", "ct-1")
	if err != nil || !ok {
		t.Fatalf("seed container lease: ok=%v err=%v", ok, err)
	}

	err = s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix)
	if err == nil {
		t.Fatal("a network holding container leases must refuse the bind")
	}
	if !strings.Contains(err.Error(), "ct-1") {
		t.Fatalf("the refusal must NAME the containers so the operator can move them, got: %v", err)
	}
	if !strings.Contains(err.Error(), "container") {
		t.Fatalf("the refusal must say containers are the reason, got: %v", err)
	}
	assertNothingBound(t, s)
}

// TestBindRefusesWhenATemplateHoldsAnAddressInThePrefix.
//
// A template is invisible to the inventory mirror (desiredState skips it), so an
// address adopted for one would be an object no inventory names: the mirror
// cannot see it and the orphan sweeper's live-lease veto refuses to reclaim it,
// leaving it held by nothing until a human finds it. refuseTemplateIfBound
// already declines to create that state from the other direction — converting a
// bound-network VM into a template — and this is the same rule reached from the
// bind.
func TestBindRefusesWhenATemplateHoldsAnAddressInThePrefix(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	seedVMHoldingIP(t, s, "golden", "shared", "aa:bb:cc:00:00:01", "10.0.5.20",
		"11111111-1111-1111-1111-111111111111")
	if err := s.db.Execute(ctx,
		`UPDATE vms SET is_template = 1, updated_at = ? WHERE name = 'golden'`,
		s.db.NowTS()); err != nil {
		t.Fatalf("mark template: %v", err)
	}

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix)
	if err == nil {
		t.Fatal("a template holding an address inside the prefix must refuse the bind")
	}
	if !strings.Contains(err.Error(), "golden") || !strings.Contains(err.Error(), "template") {
		t.Fatalf("the refusal must name the template, got: %v", err)
	}
	assertNothingBound(t, s)
}

// TestBindRefusesALeaseNamingAnotherPrefix pins the OTHER half of the
// already-adopted skip.
//
// A lease carrying a netbox_ip_id names an object in whatever prefix that
// lease's network was bound to at the time. Skipping on the id ALONE would
// therefore treat an address recorded against a DIFFERENT prefix as already
// adopted — and the prefix being bound now would never learn about it, which is
// the collision the whole operation removes. Both halves of the skip predicate
// have to match.
func TestBindRefusesALeaseNamingAnotherPrefix(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	seedVMHoldingIP(t, s, "vm-1", "shared", "aa:bb:cc:00:00:02", "10.0.5.30",
		"22222222-2222-2222-2222-222222222222")
	// A live lease naming an object in prefix 99 — the shape a network that was
	// bound elsewhere, released, and is now being bound here leaves behind.
	if err := s.db.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES ('shared', '10.0.5.30', 'aa:bb:cc:00:00:02', 'vm-1', 'vm', '', 4242, 99, ?, ?)`,
		s.db.NowWall(), s.db.NowTS()); err != nil {
		t.Fatalf("seed stale lease: %v", err)
	}

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix)
	if err == nil {
		t.Fatal("a lease naming another prefix must refuse the bind, not read as already adopted")
	}
	if !strings.Contains(err.Error(), "10.0.5.30") {
		t.Fatalf("the refusal must name the address, got: %v", err)
	}
	if !strings.Contains(err.Error(), "99") {
		t.Fatalf("the refusal must name the prefix the stale lease points at, got: %v", err)
	}
	assertNothingBound(t, s)
}

// TestBindRefusesOverTheAdoptionCap: one bind adopts each address with its own
// NetBox request, so a prefix holding thousands of guests must refuse with the
// numbers in the message rather than run for minutes.
//
// Seeded one over the cap, so it also pins that the cap is the boundary and not
// an approximation, and refused before any NetBox address request is made.
func TestBindRefusesOverTheAdoptionCap(t *testing.T) {
	// A /22, so the prefix genuinely CONTAINS every seeded address: on a /24 the
	// containment skip would drop most of them and the cap would never be
	// reached, and this would pass for the wrong reason.
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: adoptTestPrefix, Prefix: "10.0.4.0/22", VRFID: 3},
		enforceUnique: true,
	})
	ctx := context.Background()

	for i := 0; i <= adoptionCap; i++ {
		host := i + 2 // skip the network address
		seedVMHoldingIP(t, s,
			fmt.Sprintf("vm-%d", i), "shared",
			fmt.Sprintf("aa:bb:cc:%02x:%02x:01", i/256, i%256),
			fmt.Sprintf("10.0.%d.%d", 4+host/256, host%256),
			fmt.Sprintf("33333333-3333-3333-3333-%012d", i))
	}

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix)
	if err == nil {
		t.Fatalf("a network with %d existing addresses must refuse a bind over the cap of %d",
			adoptionCap+1, adoptionCap)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(adoptionCap+1)) {
		t.Fatalf("the refusal must name how many there are (%d), got: %v", adoptionCap+1, err)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(adoptionCap)) {
		t.Fatalf("the refusal must name the cap (%d), got: %v", adoptionCap, err)
	}
	assertNothingBound(t, s)
}

// TestBindIgnoresAnAddressOutsideTheBoundPrefix: a litevirt network's subnet and
// the NetBox prefix it binds need not be identical, so a guest addressed outside
// the prefix is ordinary configuration — and not a collision risk either, because
// NetBox will never offer that address. It must neither be adopted nor refuse
// the bind.
func TestBindIgnoresAnAddressOutsideTheBoundPrefix(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	seedVMHoldingIP(t, s, "elsewhere", "shared", "aa:bb:cc:00:00:03", "10.9.9.9",
		"44444444-4444-4444-4444-444444444444")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix); err != nil {
		t.Fatalf("an address outside the bound prefix must not refuse the bind: %v", err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("no binding row")
	}
	if b.Suspended {
		t.Fatalf("nothing was owed, so the binding must be live, reason: %q", b.SuspendReason)
	}
}
