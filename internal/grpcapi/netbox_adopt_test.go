package grpcapi

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
	seedVMInState(t, s, vmName, netName, mac, ip, uuid, "running")
}

// seedVMInState is seedVMHoldingIP with the RUN STATE spelled out, for the cases
// whose whole subject is whether a guest is holding an address right now.
func seedVMInState(t *testing.T, s *Server, vmName, netName, mac, ip, uuid, state string) {
	t.Helper()
	spec := fmt.Sprintf(`{"name":%q,"uuid":%q}`, vmName, uuid)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: vmName, HostName: "test-host", State: state, Spec: spec,
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

	err = s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
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
	// The production writer, not a hand-rolled UPDATE: a fixture that set the
	// column itself would keep passing if the column ever moved.
	if err := corrosion.SetVMTemplate(ctx, s.db, "golden", true); err != nil {
		t.Fatalf("mark template: %v", err)
	}

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
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
	//
	// Raw SQL because no production writer produces it in one step: the NetBox
	// allocator writes these join keys, but only as the tail of a claim against
	// the prefix currently bound, so reaching "a lease naming ANOTHER prefix"
	// through it would mean binding, claiming, releasing and rebinding. The row
	// is the subject here, not the path that made it.
	if err := s.db.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES ('shared', '10.0.5.30', 'aa:bb:cc:00:00:02', 'vm-1', 'vm', '', 4242, 99, ?, ?)`,
		s.db.NowWall(), s.db.NowTS()); err != nil {
		t.Fatalf("seed stale lease: %v", err)
	}

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
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

// capTestServer seeds `count` VMs each holding a distinct address inside a /22,
// and returns the server plus the request counter its fake NetBox records on.
//
// A /22 rather than a /24, so the prefix genuinely CONTAINS every seeded
// address: on a /24 the containment skip would drop most of them, the cap would
// never be reached, and the refusal test would pass for the wrong reason.
func capTestServer(t *testing.T, count int) (*Server, *requestCounter) {
	t.Helper()
	rc := &requestCounter{}
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: adoptTestPrefix, Prefix: "10.0.4.0/22", VRFID: 3},
		enforceUnique: true,
		counter:       rc,
	})
	for i := 0; i < count; i++ {
		host := i + 2 // skip the network address
		seedVMHoldingIP(t, s,
			fmt.Sprintf("vm-%d", i), "shared",
			fmt.Sprintf("aa:bb:cc:%02x:%02x:01", i/256, i%256),
			fmt.Sprintf("10.0.%d.%d", 4+host/256, host%256),
			fmt.Sprintf("33333333-3333-3333-3333-%012d", i))
	}
	return s, rc
}

// TestBindRefusesOverTheAdoptionCap: one bind adopts each address with its own
// NetBox request, so a prefix holding thousands of guests must refuse with the
// numbers in the message rather than run for minutes.
//
// Seeded ONE over the cap. That alone does not pin the boundary — a `>=`
// off-by-one would refuse here too — so the acceptance side is
// TestBindAcceptsExactlyTheAdoptionCap below, and the two together are what make
// 256 the boundary rather than an approximation.
func TestBindRefusesOverTheAdoptionCap(t *testing.T) {
	s, rc := capTestServer(t, adoptionCap+1)
	ctx := context.Background()

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
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
	// ASSERTED, not asserted in a comment. The point of a cap is that the
	// refusal is cheap; a bind that walked the prefix in NetBox and then refused
	// would satisfy every check above.
	if got := rc.AddressRequests(); got != 0 {
		t.Fatalf("the cap must refuse before any NetBox address request, got %d", got)
	}
}

// TestBindAcceptsExactlyTheAdoptionCap is the acceptance side of the same
// boundary.
//
// Without it the cap could be `>=` and every existing test would still pass: a
// bind of exactly 256 addresses would be refused, and nothing would say so. It
// asserts the PLAN rather than driving the whole adoption, because this file's
// fake NetBox serves no address surface — what is under test is the count, not
// 256 claims.
func TestBindAcceptsExactlyTheAdoptionCap(t *testing.T) {
	s, _ := capTestServer(t, adoptionCap)
	ctx := context.Background()

	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	plan, perr := s.planAdoption(ctx, corrosion.BindingRecord{
		Network: "shared", PrefixID: adoptTestPrefix, ObservedCIDR: "10.0.4.0/22",
		VRFID: 3, ClusterFingerprint: fp,
	})
	if perr != nil {
		t.Fatalf("exactly %d addresses is AT the cap and must be accepted: %v", adoptionCap, perr)
	}
	if len(plan.candidates) != adoptionCap {
		t.Fatalf("planned %d candidates, want exactly %d", len(plan.candidates), adoptionCap)
	}
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

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
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

// liveLeaseCount is how many LIVE ip_allocations rows a network has, asked with
// its own query rather than through corrosion.ListLeasesByNetwork.
//
// The reader is what the refusal under test uses, so a precondition built on it
// would move a failure onto the helper instead of onto the behaviour — and here
// the precondition is the whole point: it is what proves the container route
// below is NOT the lease route wearing a different hat.
func liveLeaseCount(t *testing.T, s *Server, netName string) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT COUNT(*) AS n FROM ip_allocations WHERE network = ? AND deleted_at IS NULL`, netName)
	if err != nil {
		t.Fatalf("count leases on %q: %v", netName, err)
	}
	if len(rows) == 0 {
		t.Fatal("count query returned no rows")
	}
	return rows[0].Int("n")
}

// TestBindRefusesAContainerNICOnASubnetLessNetwork is the DHCP-container route.
//
// A container on a SUBNET-LESS network takes no lease — the create path says so
// itself ("a subnet-less network is DHCP (blank IP, no lease)") — so the
// lease-based refusal never fires for one. Its address lands in
// `container_interfaces.ip`, written by the IP scanner, and that is the third of
// the three tables nicClaimTables enumerates as recording a NIC's MAC and IP.
//
// Seeded through corrosion.UpsertContainerInterface, the production writer the
// migrate/restore/relocate paths use, and with the ZERO-LEASE precondition
// asserted: without it this case would pass on the lease branch and prove
// nothing about the table adoption never read.
func TestBindRefusesAContainerNICOnASubnetLessNetwork(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "test-host", CtName: "ct-dhcp", NetworkName: "shared", Ordinal: 0,
		MAC: "52:aa:bb:cc:dd:01", IP: "10.0.5.100",
		VethDevice: corrosion.ContainerVethName("ct-dhcp", 0),
	}); err != nil {
		t.Fatalf("seed container NIC: %v", err)
	}
	if got := liveLeaseCount(t, s, "shared"); got != 0 {
		t.Fatalf("precondition: a DHCP container holds NO lease, got %d rows — this case "+
			"has to reach the refusal through container_interfaces, not through the lease table", got)
	}

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
	if err == nil {
		t.Fatal("a network holding a container NIC must refuse the bind; binding it hands " +
			"the container's address to the next VM created on the network")
	}
	if !strings.Contains(err.Error(), "ct-dhcp") {
		t.Fatalf("the refusal must NAME the container so the operator can move it, got: %v", err)
	}
	if !strings.Contains(err.Error(), "10.0.5.100") {
		t.Fatalf("the refusal must name the address the container holds, got: %v", err)
	}
	if !strings.Contains(err.Error(), "container") {
		t.Fatalf("the refusal must say containers are the reason, got: %v", err)
	}
	assertNothingBound(t, s)
}

// TestBindRefusesAContainerNICWithNoRecordedAddress: the same NIC one scanner
// tick EARLIER, while DHCP is still pending.
//
// The row exists and its `ip` is empty, and the guest may already hold an
// address the scanner has not written yet. Refusing on the ROW rather than on
// its address is what makes the container refusal complete instead of racing a
// 30-second tick — and it is the right rule anyway, because a container is
// unsupported on a bound network at any address.
func TestBindRefusesAContainerNICWithNoRecordedAddress(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "test-host", CtName: "ct-pending", NetworkName: "shared", Ordinal: 0,
		MAC: "52:aa:bb:cc:dd:02", IP: "",
		VethDevice: corrosion.ContainerVethName("ct-pending", 0),
	}); err != nil {
		t.Fatalf("seed container NIC: %v", err)
	}

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
	if err == nil {
		t.Fatal("a container NIC whose address is not recorded yet must still refuse the bind")
	}
	if !strings.Contains(err.Error(), "ct-pending") {
		t.Fatalf("the refusal must name the container, got: %v", err)
	}
	assertNothingBound(t, s)
}

// TestBindIgnoresATombstonedContainerNIC is the negative control for the two
// above: the refusal must read LIVE rows only.
//
// A container's delete cascade tombstones its NIC rows, and a refusal that
// ignored `deleted_at` would make every network that ever hosted a container
// permanently unbindable — with no command to clear it.
func TestBindIgnoresATombstonedContainerNIC(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "test-host", CtName: "ct-gone", NetworkName: "shared", Ordinal: 0,
		MAC: "52:aa:bb:cc:dd:03", IP: "10.0.5.100",
		VethDevice: corrosion.ContainerVethName("ct-gone", 0),
	}); err != nil {
		t.Fatalf("seed container NIC: %v", err)
	}
	// The production cascade, not a hand-rolled UPDATE.
	if err := corrosion.DeleteContainerInterfaces(ctx, s.db, "test-host", "ct-gone"); err != nil {
		t.Fatalf("tombstone container NICs: %v", err)
	}

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatalf("a tombstoned container NIC must not refuse the bind: %v", err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil || b.Suspended {
		t.Fatalf("nothing was owed, so the binding must be live, got %+v", b)
	}
}

// TestBindRefusesARunningVMWithNoRecordedAddress closes the fail-OPEN branch.
//
// An empty NIC IP was the one state planAdoption stepped over, and it is the
// state that matters most: on an unbound network every VM created without an
// explicit address has one, because VMs get no allocator there. There is
// genuinely nothing to adopt for such a NIC — but the guest may be holding an
// address inside the prefix that litevirt has never recorded, and NetBox is
// about to offer that same address to the next VM.
func TestBindRefusesARunningVMWithNoRecordedAddress(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	seedVMInState(t, s, "live-guest", "shared", "aa:bb:cc:00:01:01", "",
		"55555555-5555-5555-5555-555555555555", "running")

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
	if err == nil {
		t.Fatal("a RUNNING VM whose NIC address litevirt has not recorded must refuse the bind")
	}
	if !strings.Contains(err.Error(), "live-guest") {
		t.Fatalf("the refusal must name the VM, got: %v", err)
	}
	assertNothingBound(t, s)
}

// TestBindProceedsForAStoppedVMWithNoRecordedAddress is the other half of that
// judgement, and the one that keeps the feature usable.
//
// A stopped guest holds no address right now, so there is nothing for NetBox to
// collide with. Refusing here would refuse the bind on every stopped VM with an
// unrecorded address — which on a real cluster is most of them — and the address
// such a guest picks up when it is next started is caught by the discovery gate,
// not by this check.
func TestBindProceedsForAStoppedVMWithNoRecordedAddress(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	seedVMInState(t, s, "cold-guest", "shared", "aa:bb:cc:00:01:02", "",
		"66666666-6666-6666-6666-666666666666", "stopped")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatalf("a STOPPED VM with no recorded address must not refuse the bind: %v", err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil || b.Suspended {
		t.Fatalf("nothing was owed, so the binding must be live, got %+v", b)
	}
}

// TestBindRefusesAVMWhoseRunStateIsNotProvablyStopped: the line is "provably
// stopped", not "not running".
//
// `error`, `migrating`, `unknown` and an empty state all describe a VM whose
// guest may well be up — a migrating one certainly is — so treating anything
// that is merely != "running" as safe would step over exactly the guests this
// check exists for. Only "stopped" is a positive statement that the guest holds
// nothing.
func TestBindRefusesAVMWhoseRunStateIsNotProvablyStopped(t *testing.T) {
	for _, state := range []string{"migrating", "error", "starting", "stopping", "", "unknown"} {
		t.Run("state="+state, func(t *testing.T) {
			s := newAdoptTestServer(t)
			seedVMInState(t, s, "odd-guest", "shared", "aa:bb:cc:00:01:03", "",
				"77777777-7777-7777-7777-777777777777", state)

			err := s.validateAndBindPrefix(context.Background(), "shared", adoptTestPrefix, noDHCPNetworkDef)
			if err == nil {
				t.Fatalf("state %q is not a proof that the guest holds no address; the bind must refuse", state)
			}
			if !strings.Contains(err.Error(), "odd-guest") {
				t.Fatalf("the refusal must name the VM, got: %v", err)
			}
			assertNothingBound(t, s)
		})
	}
}

// TestBindIgnoresAnUnrecordedNICOnAnotherNetwork is the scope control for the
// unrecorded-address refusal: it must look only at NICs on the network being
// bound. A VM elsewhere with an empty NIC address says nothing about this
// prefix, and refusing on it would make the bind unusable for a reason that has
// nothing to do with the prefix.
func TestBindIgnoresAnUnrecordedNICOnAnotherNetwork(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	seedVMInState(t, s, "elsewhere-guest", "other-net", "aa:bb:cc:00:01:04", "",
		"88888888-8888-8888-8888-888888888888", "running")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatalf("an unrecorded NIC on ANOTHER network must not refuse this bind: %v", err)
	}
	if b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix); err != nil || b == nil || b.Suspended {
		t.Fatalf("the binding must be live, got %+v (err %v)", b, err)
	}
}

// ── the resume doors as NetBox WRITE passes ─────────────────────────────────
//
// Adoption made both of them POST to NetBox, and `nbPassMu` is the rule that
// admits ONE NetBox write pass at a time on a node (server.go). RekeyBinding
// has taken it since it was written; these two were reading and clearing a flag
// when the rule was made, and they are not any more.

// suspendedBindingServer is a server holding ONE bound, SUSPENDED binding whose
// prefix still validates — so a resume of it is refused by nothing except the
// gates under test.
func suspendedBindingServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: adoptTestPrefix, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	ctx := context.Background()
	if err := s.validateAndBindPrefix(ctx, "bound", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := corrosion.SuspendBinding(ctx, s.db, adoptTestPrefix, "suspended by a test"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	return s
}

func bindingIsSuspended(t *testing.T, s *Server) bool {
	t.Helper()
	b, err := corrosion.GetBindingByPrefix(context.Background(), s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("read binding: %v (%+v)", err, b)
	}
	return b.Suspended
}

// TestResumeBindingRefusesWhileAnotherNetBoxPassRuns.
//
// ResumeBinding now finishes an owed adoption, which POSTs to NetBox — so it is
// a NetBox write pass, and an unexcluded one is the single thing `nbPassMu`
// exists to prevent. Its two siblings (the revalidate/sweep maintenance pass and
// RekeyBinding) both take it; a resume that did not could run its claims
// straight through a re-key that is rewriting the identities those claims are
// stamped with.
func TestResumeBindingRefusesWhileAnotherNetBoxPassRuns(t *testing.T) {
	s := suspendedBindingServer(t)

	// A pass in flight on this node.
	if !s.nbPassMu.TryLock() {
		t.Fatal("a fresh server's pass gate must be free")
	}
	_, err := s.ResumeBinding(adminCtx(), &pb.ResumeBindingRequest{Network: "bound"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("resume during another NetBox pass = %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "already running on this node") {
		t.Fatalf("the refusal must say a NetBox pass is already in flight on this node, got: %v", err)
	}
	if !bindingIsSuspended(t, s) {
		t.Fatal("a refused resume must leave the binding suspended")
	}

	// The other side, so this cannot pass against a resume that refuses
	// unconditionally: with the gate free the same call goes through.
	s.nbPassMu.Unlock()
	if _, err := s.ResumeBinding(adminCtx(), &pb.ResumeBindingRequest{Network: "bound"}); err != nil {
		t.Fatalf("resume with the gate free: %v", err)
	}
	if bindingIsSuspended(t, s) {
		t.Fatal("the resume did not lift the suspension — the exclusion is refusing more than the overlap")
	}
}

// TestBindTimeAdoptionRefusesWhileAnotherNetBoxPassRuns is the same rule at the
// THIRD resume door: the adoption CreateNetwork runs after the network row
// lands.
//
// It gets the pass gate and deliberately NOT the leader lease. A bind must not
// require cluster leadership — the mirror and the sweeper are periodic passes
// that can wait for their next tick, an operator creating a network cannot — and
// binding a prefix from a non-leader node is an ordinary thing to do.
func TestBindTimeAdoptionRefusesWhileAnotherNetBoxPassRuns(t *testing.T) {
	s := suspendedBindingServer(t)

	if !s.nbPassMu.TryLock() {
		t.Fatal("a fresh server's pass gate must be free")
	}
	err := s.finishAdoptionAndResume(context.Background(), "bound", adoptTestPrefix)
	if err == nil {
		t.Fatal("a bind-time adoption must not run inside another NetBox pass on this node")
	}
	if !strings.Contains(err.Error(), "already running on this node") {
		t.Fatalf("the refusal must say a NetBox pass is already in flight on this node, got: %v", err)
	}
	if !bindingIsSuspended(t, s) {
		t.Fatal("a refused adoption must leave the binding suspended, so `lv netbox resume` can finish it")
	}

	s.nbPassMu.Unlock()
	if err := s.finishAdoptionAndResume(context.Background(), "bound", adoptTestPrefix); err != nil {
		t.Fatalf("adoption with the gate free: %v", err)
	}
	if bindingIsSuspended(t, s) {
		t.Fatal("the adoption did not lift the suspension once the gate was free")
	}
}

// TestBindWithNothingOwedDoesNotContendForThePassGate is the control that keeps
// the gate off the ordinary path.
//
// A bind of a network with nothing to adopt leaves the binding LIVE, and
// finishAdoptionAndResume is then a no-op that makes no NetBox request at all.
// Taking the gate before establishing that would make every `lv network create`
// on a bound prefix fail whenever a 15-minute mirror sweep happened to be
// running — a refusal over an operation that was never going to write anything.
func TestBindWithNothingOwedDoesNotContendForThePassGate(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: adoptTestPrefix, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	ctx := context.Background()
	if err := s.validateAndBindPrefix(ctx, "bound", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// Live, because nothing was owed.
	if bindingIsSuspended(t, s) {
		t.Fatal("precondition: a bind with nothing to adopt must leave the binding live")
	}

	if !s.nbPassMu.TryLock() {
		t.Fatal("a fresh server's pass gate must be free")
	}
	defer s.nbPassMu.Unlock()
	if err := s.finishAdoptionAndResume(ctx, "bound", adoptTestPrefix); err != nil {
		t.Fatalf("a no-op adoption must not contend for the pass gate: %v", err)
	}
}

// ── the empty VM read ───────────────────────────────────────────────────────

// bindAndCaptureLogs binds the adoption prefix and returns everything logged
// while it ran.
func bindAndCaptureLogs(t *testing.T, s *Server) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if err := s.validateAndBindPrefix(context.Background(), "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return buf.String()
}

// TestBindReportsAnUncorroboratedEmptyVMRead.
//
// corrosion.ListVMs answers ([], nil) for a node that is hydrating after a
// database loss or a fresh join exactly as it does for a cluster that genuinely
// holds no VMs — and on the first of those, every address the cluster's guests
// hold inside the prefix is invisible to this bind.
//
// It is neither refused nor allowed to go live: the binding is created SUSPENDED
// and a revalidation pass resumes it (netbox_unhydrated_test.go covers the
// decision and the convergence). What it must not be is SILENT, so the log line
// stays pinned here.
func TestBindReportsAnUncorroboratedEmptyVMRead(t *testing.T) {
	s := newAdoptTestServer(t)
	// A peer is what makes the empty read uncorroborated: with no peer, this
	// node's database IS the cluster's and the read is its own answer.
	seedPeerHost(t, s, "peer-b")

	logs := bindAndCaptureLogs(t, s)

	if !strings.Contains(logs, "uncorroborated empty VM inventory") {
		t.Fatalf("a bind over an uncorroborated empty VM read logged nothing about it: %q", logs)
	}
	if !strings.Contains(logs, "level=WARN") {
		t.Fatalf("the report must be a WARN, not a debug aside: %q", logs)
	}
	// …and it must say WHICH host left the read unproven and what it did. "could
	// not be proven" with nothing attached is the line nobody can act on, and
	// the two negative answers have different remedies: a host that cannot be
	// reached needs reaching, a host that holds rows needs replicating from.
	if !strings.Contains(logs, "peer-b") || !strings.Contains(logs, "could not be asked") {
		t.Fatalf("the report must name the host that could not answer and say so: %q", logs)
	}
	// The bind still went THROUGH — it is not a refusal, which would refuse the
	// first bind on a young cluster with no override — but the binding serves no
	// claims until adoption can be re-run.
	b, err := corrosion.GetBindingByPrefix(context.Background(), s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("the bind must still record a binding row, got %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a binding made over an uncorroborated empty read must not go live")
	}
}

// TestBindDoesNotReportAnEmptyVMReadItCanCorroborate is the control that keeps
// the report meaningful.
//
// A cluster that deleted its last VM has TOMBSTONES, and a tombstone is exactly
// the positive evidence corrosion.HasVMRecords exists to find: this database has
// been told about VMs, so its empty live read is its own answer and not a
// replication gap. Reporting that case would put the warning on the ordinary
// lifecycle of every cluster and make it worth ignoring.
func TestBindDoesNotReportAnEmptyVMReadItCanCorroborate(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	// A VM, then the production delete — which tombstones rather than removing.
	seedVMInState(t, s, "was-here", "other-net", "aa:bb:cc:00:02:01", "",
		"99999999-9999-9999-9999-999999999999", "stopped")
	if err := corrosion.DeleteVM(ctx, s.db, "was-here"); err != nil {
		t.Fatalf("delete VM: %v", err)
	}
	// Precondition: the live read is empty, so the branch under test is reached.
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil || len(vms) != 0 {
		t.Fatalf("precondition: the live VM list must be empty, got %d (err %v)", len(vms), err)
	}

	logs := bindAndCaptureLogs(t, s)

	if strings.Contains(logs, "uncorroborated empty VM inventory") {
		t.Fatalf("an empty read backed by a tombstone must not be reported as uncorroborated: %q", logs)
	}
}
