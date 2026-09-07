package network

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// ── stubs ───────────────────────────────────────────────────────────────────

// stubIP is one canned NetBox object. Identity is NOT a field: the stub stamps
// whatever identity the call carried onto what it returns, exactly as a real
// NetBox does for an object we created or queried by that custom field. A stub
// that let a test hand-pick a mismatching identity would be modelling a server
// that answers a `cf_litevirt_identity=X` query with an object carrying Y.
type stubIP struct {
	ID      int
	Address string
	VRFID   int
}

// stubNetBox implements netboxAPI without an HTTP server.
type stubNetBox struct {
	// claimErr, when non-nil, is what BOTH claim entry points return.
	claimErr error
	// claimed is the object a successful claim returns.
	claimed stubIP

	byIdentity []stubIP
	byAddress  []stubIP

	// identityErr / addressErr fail the corresponding lookup.
	identityErr error
	addressErr  error

	// releaseErr fails ReleaseIP.
	releaseErr error

	released        []int
	byIdentityCalls int
	byAddressCalls  int
	claimCalls      int

	// addressIdentity overrides the identity stamped on byAddress results. Empty
	// means "the identity this claim used", i.e. the object is ours.
	//
	// THAT DEFAULT IS A VALUE FOR THE HAZARD INPUT, which is why the flag below
	// exists rather than a second sentinel string. An object with NO litevirt
	// identity is a distinct, refused case (ErrAddressNotOurs), and it is not
	// reachable by leaving this empty — so a test that wants it has to say so.
	// Had the default been "" instead, the identity-less branch would have
	// silently captured TestExplicitClaimCrossChecksAndRefusesDisagreement and
	// changed its outcome.
	addressIdentity string
	// addressNoIdentity makes byAddress results carry NO identity at all: an
	// operator-created object or a reservation, which litevirt refuses to stamp
	// itself onto.
	addressNoIdentity bool

	// lastIdentityVRF / lastIdentityPrefix record the scope the recovery lookup
	// was given, so a test can prove the scope is actually forwarded.
	lastIdentityVRF    int
	lastIdentityPrefix string
	// lastIdentity is the identity most recently passed to a claim or identity
	// lookup; LookupByAddress has no identity argument of its own.
	lastIdentity string
}

func (s *stubNetBox) toIP(in stubIP, identity string) netbox.IPAddress {
	return netbox.IPAddress{ID: in.ID, Address: in.Address, VRFID: in.VRFID, Identity: identity}
}

func (s *stubNetBox) toIPs(in []stubIP, identity string) []netbox.IPAddress {
	if in == nil {
		return nil
	}
	out := make([]netbox.IPAddress, 0, len(in))
	for _, ip := range in {
		out = append(out, s.toIP(ip, identity))
	}
	return out
}

func (s *stubNetBox) ClaimAvailableIP(_ context.Context, _ int, identity string) (netbox.IPAddress, error) {
	s.claimCalls++
	s.lastIdentity = identity
	if s.claimErr != nil {
		return netbox.IPAddress{}, s.claimErr
	}
	return s.toIP(s.claimed, identity), nil
}

func (s *stubNetBox) ClaimSpecificIP(_ context.Context, _ string, _ int, identity string) (netbox.IPAddress, error) {
	s.claimCalls++
	s.lastIdentity = identity
	if s.claimErr != nil {
		return netbox.IPAddress{}, s.claimErr
	}
	return s.toIP(s.claimed, identity), nil
}

func (s *stubNetBox) LookupByAddress(_ context.Context, _ string, _ int) ([]netbox.IPAddress, error) {
	s.byAddressCalls++
	if s.addressErr != nil {
		return nil, s.addressErr
	}
	// An address lookup has no identity parameter. By default the object is
	// ours (stamped with the identity this call used); addressIdentity models
	// an address that belongs to another system, and addressNoIdentity models
	// one that belongs to no litevirt at all.
	if s.addressNoIdentity {
		return s.toIPs(s.byAddress, ""), nil
	}
	identity := s.addressIdentity
	if identity == "" {
		identity = s.lastIdentity
	}
	return s.toIPs(s.byAddress, identity), nil
}

func (s *stubNetBox) LookupByIdentity(_ context.Context, identity string, vrfID int, prefixCIDR string) ([]netbox.IPAddress, error) {
	s.byIdentityCalls++
	s.lastIdentity = identity
	s.lastIdentityVRF = vrfID
	s.lastIdentityPrefix = prefixCIDR
	if s.identityErr != nil {
		return nil, s.identityErr
	}
	return s.toIPs(s.byIdentity, identity), nil
}

func (s *stubNetBox) ReleaseIP(_ context.Context, id int) error {
	if s.releaseErr != nil {
		return s.releaseErr
	}
	s.released = append(s.released, id)
	return nil
}

// errTimeout is a TRANSPORT failure: not an *netbox.APIError, so Classify puts
// it in ClassTransport and Ambiguous reports true.
var errTimeout = errors.New("dial tcp 10.0.0.1:443: i/o timeout")

// errDuplicate is NetBox's 400 "duplicate address". Ambiguous() calls it
// definite — which is exactly why the allocator must NOT branch on it: our own
// earlier POST can be what created the duplicate.
var errDuplicate = &netbox.APIError{Status: 400, Body: `{"address":["Duplicate IP address"]}`}

// errForbidden is a 403. Like errDuplicate it classifies as definite, and like
// errDuplicate it must still drive a recovery lookup.
var errForbidden = &netbox.APIError{Status: 403, Body: `{"detail":"permission denied"}`}

// noopMetrics satisfies apiErrorCounter without recording anything.
type noopMetrics struct{}

func (noopMetrics) IncAPIError(netbox.ErrClass) {}
func (noopMetrics) IncAmbiguousClaim()          {}

// countingMetrics records what the allocator emitted, so a test can assert on
// the ONE signal an ambiguous claim produces that nothing else does.
type countingMetrics struct {
	apiErrors []netbox.ErrClass
	ambiguous int
}

func (m *countingMetrics) IncAPIError(c netbox.ErrClass) { m.apiErrors = append(m.apiErrors, c) }
func (m *countingMetrics) IncAmbiguousClaim()            { m.ambiguous++ }

// ── db helpers ──────────────────────────────────────────────────────────────

// failDBWrites makes every ip_allocations INSERT abort, which is how these
// tests reach the window between a committed NetBox object and a persisted
// lease. Mirrors failNetworkInserts in internal/grpcapi/netbox_bind_test.go:
// reads still resolve, so the read-back confirm runs normally and only the
// write fails.
func failDBWrites(t *testing.T, db *corrosion.Client) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`CREATE TRIGGER test_fail_ip_alloc_insert BEFORE INSERT ON ip_allocations
		 BEGIN SELECT RAISE(ABORT, 'induced persist failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
}

// seedLiveLease writes a LIVE lease held by name on (network, ip).
func seedLiveLease(t *testing.T, db *corrosion.Client, network, ip, name string) {
	t.Helper()
	seedLiveLeaseFull(t, db, leaseIdentity{
		Network: network, IP: ip, MAC: "52:54:00:ff:ff:ff",
		OwnerKind: "vm", Name: name,
	})
}

// seedLiveLeaseFull writes a LIVE lease with every join key spelled out.
func seedLiveLeaseFull(t *testing.T, db *corrosion.Client, l leaseIdentity) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.Network, l.IP, l.MAC, l.Name, l.OwnerKind, l.OwnerHost,
		l.NetBoxIPID, l.PrefixID, db.NowWall(), db.NowTS()); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
}

// leaseOwner returns the vm_name of the LIVE lease on (network, ip), or "".
func leaseOwner(t *testing.T, db *corrosion.Client, network, ip string) string {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT vm_name FROM ip_allocations
		 WHERE network = ? AND ip = ? AND deleted_at IS NULL`, network, ip)
	if err != nil {
		t.Fatalf("read lease owner: %v", err)
	}
	if len(rows) == 0 {
		return ""
	}
	return rows[0].String("vm_name")
}

// boundReq is the shape every claim in this file starts from: a NetBox-bound
// network always carries a VRF and the prefix CIDR recorded at bind time, and
// validateClaim refuses a claim missing either. Tests vary only what they are
// about.
func boundReq() ClaimRequest {
	return ClaimRequest{
		Network: "net-a", Subnet: "10.0.5.0/24", PrefixCIDR: "10.0.5.0/24",
		PrefixID: 7, VRFID: 3, MAC: "52:54:00:aa:bb:cc",
		OwnerKind: "vm", Name: "vm-1",
		Identity: "lv:fp:uuid:52:54:00:aa:bb:cc",
	}
}

// ── recovery ────────────────────────────────────────────────────────────────

func TestDynamicClaimRecoversByIdentityOnly(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{
		claimErr:   errTimeout,                                             // POST times out
		byIdentity: []stubIP{{ID: 41, Address: "10.0.5.100/24", VRFID: 3}}, // but it committed
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})

	got, err := a.Claim(ctx, boundReq())
	if err != nil {
		t.Fatal(err)
	}
	if got.NetBoxIPID != 41 {
		t.Fatalf("want the committed object adopted, got %+v", got)
	}
	// A dynamic claim has NO address to look up, so an address lookup here would
	// be impossible. Assert we never attempted one.
	if nb.byAddressCalls != 0 {
		t.Fatalf("dynamic recovery must not call LookupByAddress, called %d times", nb.byAddressCalls)
	}
	// The recovery lookup must carry the binding's scope, or it would adopt an
	// object that has since moved to another VRF or prefix.
	if nb.lastIdentityVRF != 3 || nb.lastIdentityPrefix != "10.0.5.0/24" {
		t.Fatalf("recovery lookup scope = (vrf %d, prefix %q), want (3, 10.0.5.0/24)",
			nb.lastIdentityVRF, nb.lastIdentityPrefix)
	}
}

func TestZeroLookupResultIsUnknownNotAbsent(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{claimErr: errTimeout, byIdentity: nil} // lookup finds nothing
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})

	_, err := a.Claim(ctx, boundReq())
	if err == nil {
		t.Fatal("want refusal")
	}
	// The in-flight POST may STILL commit after this lookup, so the outcome is
	// unknown — not "did not commit". The sentinel is what tells the caller to
	// leave an orphan follow-up behind.
	if !errors.Is(err, ErrClaimUnknown) {
		t.Fatalf("want ErrClaimUnknown so an orphan follow-up is enqueued, got %v", err)
	}
}

func TestMultipleIdentityMatchesRefuse(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{
		claimErr: errTimeout,
		byIdentity: []stubIP{
			{ID: 41, Address: "10.0.5.100/24", VRFID: 3},
			{ID: 42, Address: "10.0.5.101/24", VRFID: 3},
		},
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})
	if _, err := a.Claim(ctx, boundReq()); !errors.Is(err, ErrClaimUnknown) {
		t.Fatalf("two identity matches must refuse as unknown, got %v", err)
	}
}

func TestExplicitClaimCrossChecksAndRefusesDisagreement(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{
		claimErr:   errTimeout,
		byAddress:  []stubIP{{ID: 41, Address: "10.0.5.50/24", VRFID: 3}},
		byIdentity: []stubIP{{ID: 99, Address: "10.0.5.50/24", VRFID: 3}}, // different object
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})
	req := boundReq()
	req.ExplicitIP = "10.0.5.50/24"
	if _, err := a.Claim(ctx, req); !errors.Is(err, ErrClaimUnknown) {
		t.Fatalf("disagreeing lookups must refuse, got %v", err)
	}
	// Pin that the refusal came from the CROSS-CHECK, not from an earlier scope
	// rejection: both lookups must actually have run.
	if nb.byIdentityCalls == 0 || nb.byAddressCalls == 0 {
		t.Fatalf("an explicit claim must consult BOTH lookups, got identity=%d address=%d",
			nb.byIdentityCalls, nb.byAddressCalls)
	}
}

// TestExplicitClaimAdoptsAgreeingLookups is the positive half of the
// cross-check: when both lookups name the SAME object it is adopted. Without
// it, a recover() that refused unconditionally would still pass the
// disagreement test above.
func TestExplicitClaimAdoptsAgreeingLookups(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{
		claimErr:   errTimeout,
		byAddress:  []stubIP{{ID: 41, Address: "10.0.5.50/24", VRFID: 3}},
		byIdentity: []stubIP{{ID: 41, Address: "10.0.5.50/24", VRFID: 3}},
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})
	req := boundReq()
	req.ExplicitIP = "10.0.5.50/24"
	got, err := a.Claim(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.NetBoxIPID != 41 || got.IP != "10.0.5.50" {
		t.Fatalf("got %+v, want the agreed object 41 at 10.0.5.50", got)
	}
}

// TestExplicitClaimRefusesAnotherSystemsAddress covers the branch where the
// address exists but carries somebody else's identity: that is a definite
// answer ("held by another system"), NOT an unknown outcome, so no orphan
// follow-up should be implied.
func TestExplicitClaimRefusesAnotherSystemsAddress(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{
		claimErr:        errDuplicate,
		byIdentity:      nil, // nothing carries OUR identity
		byAddress:       []stubIP{{ID: 41, Address: "10.0.5.50/24", VRFID: 3}},
		addressIdentity: "lv:someone:else:aa:bb",
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})
	req := boundReq()
	req.ExplicitIP = "10.0.5.50/24"
	_, err := a.Claim(ctx, req)
	if err == nil {
		t.Fatal("want refusal")
	}
	if errors.Is(err, ErrClaimUnknown) {
		t.Fatalf("an address definitively held by another system is not an unknown outcome: %v", err)
	}
	if !errors.Is(err, ErrAddressNotOurs) {
		t.Fatalf("want ErrAddressNotOurs, got %v", err)
	}
	// The FOREIGN IDENTITY has to be in the message. Without it the operator is
	// told an address is taken and given nothing to look up: which installation
	// holds it — a co-tenant cluster, or this one before a fingerprint move — is
	// the whole of what decides what to do next.
	if !strings.Contains(err.Error(), "lv:someone:else:aa:bb") {
		t.Fatalf("the refusal must name the identity holding the address, got %v", err)
	}
	if len(nb.released) != 0 {
		t.Fatalf("another system's object must not be released, got %v", nb.released)
	}
}

// TestExplicitClaimRefusesAnIdentityLessAddress is the other half of the same
// switch, and until now nothing produced it: an object at the requested address
// carrying NO litevirt identity.
//
// It is refused rather than ADOPTED, and that is the judgement worth pinning.
// Adopting it would mean stamping litevirt's identity onto a record litevirt did
// not create — and that identity is exactly what later authorizes the orphan
// sweep to DELETE the object. An operator's reservation would become something
// litevirt reclaims on its own.
//
// Named separately from the foreign-identity case above because the remedy is
// different and specific: remove the object in NetBox and let litevirt create
// the address itself.
func TestExplicitClaimRefusesAnIdentityLessAddress(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{
		claimErr:   errDuplicate,
		byIdentity: nil, // nothing carries OUR identity
		byAddress:  []stubIP{{ID: 41, Address: "10.0.5.50/24", VRFID: 3}},
		// The hazard input, spelled out. Leaving addressIdentity empty would
		// make the object OURS, which is a different case entirely.
		addressNoIdentity: true,
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})
	req := boundReq()
	req.ExplicitIP = "10.0.5.50/24"
	_, err := a.Claim(ctx, req)
	if err == nil {
		t.Fatal("an object with no litevirt identity must be refused, not adopted")
	}
	if !errors.Is(err, ErrAddressNotOurs) {
		t.Fatalf("want ErrAddressNotOurs — this is a definite answer, not an unknown one; got %v", err)
	}
	if errors.Is(err, ErrClaimUnknown) {
		t.Fatalf("an identity-less object is not an unknown outcome: %v", err)
	}
	// The remedy has to be in the message, and it is not the same remedy as the
	// foreign-identity case: there is nobody to go and ask.
	if !strings.Contains(err.Error(), "no litevirt identity") {
		t.Fatalf("the refusal must say the object carries no litevirt identity, got %v", err)
	}
	if !strings.Contains(err.Error(), "41") {
		t.Fatalf("the refusal must name the NetBox object so it can be found, got %v", err)
	}
	// And nothing was deleted. This object is somebody else's row; a claim that
	// tidied it away would be the exact failure the refusal exists to prevent.
	if len(nb.released) != 0 {
		t.Fatalf("an identity-less object must not be released, got %v", nb.released)
	}
}

// TestTheAddressLookupDefaultIsNotTheIdentityLessCase is the control the
// previous test needs.
//
// TestExplicitClaimCrossChecksAndRefusesDisagreement passes only because the
// stub stamps byAddress results with the identity the call used. Had it defaulted
// to "", the identity-less branch would have captured that test and changed its
// outcome from ErrClaimUnknown to ErrAddressNotOurs — a real refusal replaced by
// a differently-shaped one, with nothing failing. This asserts the default is
// still "ours", so that test keeps testing the cross-check.
func TestTheAddressLookupDefaultIsNotTheIdentityLessCase(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{
		claimErr:   errTimeout,
		byAddress:  []stubIP{{ID: 41, Address: "10.0.5.50/24", VRFID: 3}},
		byIdentity: []stubIP{{ID: 99, Address: "10.0.5.50/24", VRFID: 3}},
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})
	req := boundReq()
	req.ExplicitIP = "10.0.5.50/24"
	if _, err := a.Claim(ctx, req); errors.Is(err, ErrAddressNotOurs) {
		t.Fatalf("the stub's default byAddress identity must be OURS, or the cross-check test "+
			"is really testing the identity-less branch: %v", err)
	}
}

func TestRecoveryRunsAfterA4xxToo(t *testing.T) {
	ctx := context.Background()
	// A 400 "duplicate address" whose object turns out to be OURS: an earlier
	// POST committed and lost its response. Skipping recovery on a 4xx would
	// refuse this create AND strand the object.
	nb := &stubNetBox{
		claimErr:   errDuplicate, // HTTP 400
		byIdentity: []stubIP{{ID: 41, Address: "10.0.5.100/24", VRFID: 3}},
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})

	got, err := a.Claim(ctx, boundReq())
	if err != nil {
		t.Fatalf("our own committed object must be adopted, got %v", err)
	}
	if got.NetBoxIPID != 41 {
		t.Fatalf("got %+v", got)
	}
	if nb.byIdentityCalls == 0 {
		t.Fatal("recovery lookup must run after a 4xx")
	}
}

// TestRecoveryRunsAfterEveryDefiniteStatus generalises the case above: a 403
// classifies as ClassClient — a DEFINITE answer, exactly like a 400 — and is
// just as unusable as a decision about whether a write landed.
func TestRecoveryRunsAfterEveryDefiniteStatus(t *testing.T) {
	ctx := context.Background()
	if netbox.Classify(errForbidden) != netbox.ClassClient {
		t.Fatal("fixture is wrong: a 403 must classify as definite for this test to mean anything")
	}
	nb := &stubNetBox{
		claimErr:   errForbidden,
		byIdentity: []stubIP{{ID: 41, Address: "10.0.5.100/24", VRFID: 3}},
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})
	got, err := a.Claim(ctx, boundReq())
	if err != nil {
		t.Fatalf("recovery must run after a 403 too, got %v", err)
	}
	if got.NetBoxIPID != 41 {
		t.Fatalf("got %+v", got)
	}
}

// ── compensation and provenance ─────────────────────────────────────────────

func TestPersistFailureCompensatesTheRemoteClaim(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{claimed: stubIP{ID: 41, Address: "10.0.5.100/24", VRFID: 3}}
	db := newTestDB(t)
	failDBWrites(t, db) // lease insert will fail

	a := NewNetBoxAllocator(db, nb, noopMetrics{})
	_, err := a.Claim(ctx, boundReq())
	if err == nil {
		t.Fatal("want failure")
	}
	// The caller has not appended to its claim set yet, so nothing upstream can
	// compensate. The allocator must release what it just claimed.
	if len(nb.released) != 1 || nb.released[0] != 41 {
		t.Fatalf("the remote claim must be released, got %v", nb.released)
	}
}

func TestRecoveredObjectIsNeverDeletedOnPersistFailure(t *testing.T) {
	ctx := context.Background()
	// 400 -> recovery finds OUR object -> local persistence then fails.
	// That object may predate this call and already serve a live guest, so
	// deleting it here would free a live address.
	nb := &stubNetBox{
		claimErr:   errDuplicate,
		byIdentity: []stubIP{{ID: 41, Address: "10.0.5.100/24", VRFID: 3}},
	}
	db := newTestDB(t)
	failDBWrites(t, db)

	a := NewNetBoxAllocator(db, nb, noopMetrics{})
	_, err := a.Claim(ctx, boundReq())
	if !errors.Is(err, ErrClaimUnknown) {
		t.Fatalf("want ErrClaimUnknown so the sweep decides, got %v", err)
	}
	if len(nb.released) != 0 {
		t.Fatalf("a RECOVERED object must never be deleted here, released %v", nb.released)
	}
}

// TestOutOfScopeClaimIsCompensated pins the other compensation site: a POST
// that SUCCEEDS but hands back an address outside the bound prefix (a re-CIDR
// between revalidation and claim) must be released, not persisted.
func TestOutOfScopeClaimIsCompensated(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{claimed: stubIP{ID: 41, Address: "10.9.9.9/24", VRFID: 3}}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})
	if _, err := a.Claim(ctx, boundReq()); err == nil {
		t.Fatal("an address outside the bound prefix must not be accepted")
	}
	if len(nb.released) != 1 || nb.released[0] != 41 {
		t.Fatalf("an out-of-scope claim from OUR OWN post must be released, got %v", nb.released)
	}
}

// ── validation ──────────────────────────────────────────────────────────────

func TestValidateClaimEnforcesItsFullContract(t *testing.T) {
	base := ClaimRequest{
		VRFID: 3, PrefixCIDR: "10.0.5.0/24",
		Identity: "lv:fp:uuid:52:54:00:aa:bb:cc",
	}
	ok := netbox.IPAddress{ID: 41, Address: "10.0.5.100/24", VRFID: 3, Identity: base.Identity}

	if err := validateClaim(base, ok); err != nil {
		t.Fatalf("a valid claim must pass, got %v", err)
	}

	cases := []struct {
		name string
		req  ClaimRequest
		ip   netbox.IPAddress
	}{
		{"empty identity", base, netbox.IPAddress{ID: 41, Address: "10.0.5.100/24", VRFID: 3}},
		{"wrong identity", base, netbox.IPAddress{ID: 41, Address: "10.0.5.100/24", VRFID: 3, Identity: "lv:other:x:y"}},
		{"malformed CIDR", base, netbox.IPAddress{ID: 41, Address: "10.0.5.100/bad", VRFID: 3, Identity: base.Identity}},
		{"wrong VRF", base, netbox.IPAddress{ID: 41, Address: "10.0.5.100/24", VRFID: 9, Identity: base.Identity}},
		{"outside prefix", base, netbox.IPAddress{ID: 41, Address: "10.9.9.9/24", VRFID: 3, Identity: base.Identity}},
		{"no id", base, netbox.IPAddress{Address: "10.0.5.100/24", VRFID: 3, Identity: base.Identity}},
		{"no bound prefix", ClaimRequest{VRFID: 3, Identity: base.Identity}, ok},
		{"explicit mismatch",
			ClaimRequest{VRFID: 3, PrefixCIDR: "10.0.5.0/24", Identity: base.Identity, ExplicitIP: "10.0.5.50"},
			ok},
		// NetBox returns CIDR notation; a bare address means something
		// unexpected produced it, and tolerating it is a fail-open edge.
		{"returned bare address", base,
			netbox.IPAddress{ID: 41, Address: "10.0.5.100", VRFID: 3, Identity: base.Identity}},
		// Stripping before parsing would let this compare equal on the host.
		{"malformed explicit request",
			ClaimRequest{VRFID: 3, PrefixCIDR: "10.0.5.0/24", Identity: base.Identity, ExplicitIP: "10.0.5.100/bad"},
			ok},
		// Plain equality would accept 0 == 0, i.e. the global table.
		{"no bound VRF",
			ClaimRequest{PrefixCIDR: "10.0.5.0/24", Identity: base.Identity},
			netbox.IPAddress{ID: 41, Address: "10.0.5.100/24", VRFID: 0, Identity: base.Identity}},
	}
	for _, tc := range cases {
		if err := validateClaim(tc.req, tc.ip); err == nil {
			t.Errorf("%s: must be rejected", tc.name)
		}
	}
}

func TestRecoveryRejectsAMatchInAnotherVRF(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{
		claimErr:   errTimeout,
		byIdentity: []stubIP{{ID: 41, Address: "10.0.5.100/24", VRFID: 99}}, // wrong VRF
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})
	if _, err := a.Claim(ctx, boundReq()); !errors.Is(err, ErrClaimUnknown) {
		t.Fatalf("an identity match outside the bound VRF must not be adopted, got %v", err)
	}
}

func TestRecoveryRejectsAMatchOutsideThePrefix(t *testing.T) {
	ctx := context.Background()
	nb := &stubNetBox{
		claimErr:   errTimeout,
		byIdentity: []stubIP{{ID: 41, Address: "10.9.9.9/24", VRFID: 3}}, // outside subnet
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, noopMetrics{})
	if _, err := a.Claim(ctx, boundReq()); !errors.Is(err, ErrClaimUnknown) {
		t.Fatalf("an identity match outside the bound prefix must not be adopted, got %v", err)
	}
}

// ── persistence ─────────────────────────────────────────────────────────────

func TestReadBackDistinguishesTwoNICsOfOneVM(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	// A LIVE lease for the SAME VM and network but a DIFFERENT MAC. An
	// owner-only read-back would accept this as proof we hold the new address.
	seedLiveLeaseFull(t, db, leaseIdentity{
		Network: "net-a", IP: "10.0.5.100", MAC: "52:54:00:aa:bb:01",
		OwnerKind: "vm", Name: "vm-1", NetBoxIPID: 40, PrefixID: 7,
	})
	held, err := leaseHeldByExact(ctx, db, leaseIdentity{
		Network: "net-a", IP: "10.0.5.100", MAC: "52:54:00:aa:bb:02",
		OwnerKind: "vm", Name: "vm-1", NetBoxIPID: 41, PrefixID: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatal("another NIC's lease must not satisfy this NIC's read-back")
	}
}

// TestReadBackAcceptsTheExactLease is the positive control for the test above:
// a leaseHeldByExact that returned false unconditionally would pass it.
func TestReadBackAcceptsTheExactLease(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	l := leaseIdentity{
		Network: "net-a", IP: "10.0.5.100", MAC: "52:54:00:aa:bb:01",
		OwnerKind: "vm", Name: "vm-1", NetBoxIPID: 40, PrefixID: 7,
	}
	seedLiveLeaseFull(t, db, l)
	held, err := leaseHeldByExact(ctx, db, l)
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("the exact lease must satisfy its own read-back")
	}
}

// TestReadBackRequiresEveryField varies ONE field at a time off an otherwise
// identical live lease. TestReadBackDistinguishesTwoNICsOfOneVM differs in both
// MAC and NetBox id, so it stays green with the mac predicate deleted — each
// column needs its own probe to be pinned.
func TestReadBackRequiresEveryField(t *testing.T) {
	ctx := context.Background()
	seeded := leaseIdentity{
		Network: "net-a", IP: "10.0.5.100", MAC: "52:54:00:aa:bb:01",
		OwnerKind: "vm", OwnerHost: "host-a", Name: "vm-1",
		NetBoxIPID: 40, PrefixID: 7,
	}
	vary := map[string]func(l *leaseIdentity){
		"network":     func(l *leaseIdentity) { l.Network = "net-b" },
		"ip":          func(l *leaseIdentity) { l.IP = "10.0.5.101" },
		"mac":         func(l *leaseIdentity) { l.MAC = "52:54:00:aa:bb:02" },
		"owner kind":  func(l *leaseIdentity) { l.OwnerKind = "ct" },
		"owner host":  func(l *leaseIdentity) { l.OwnerHost = "host-b" },
		"name":        func(l *leaseIdentity) { l.Name = "vm-2" },
		"netbox ip":   func(l *leaseIdentity) { l.NetBoxIPID = 41 },
		"prefix id":   func(l *leaseIdentity) { l.PrefixID = 8 },
		"nothing (+)": func(l *leaseIdentity) {},
	}
	for name, mutate := range vary {
		t.Run(name, func(t *testing.T) {
			db := newTestDB(t)
			seedLiveLeaseFull(t, db, seeded)
			probe := seeded
			mutate(&probe)
			held, err := leaseHeldByExact(ctx, db, probe)
			if err != nil {
				t.Fatal(err)
			}
			want := probe == seeded // the "+" case is the positive control
			if held != want {
				t.Fatalf("leaseHeldByExact with a differing %s = %v, want %v", name, held, want)
			}
		})
	}
}

func TestPersistNeverStealsALiveLease(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	// A LIVE lease already holds this address for a different owner.
	seedLiveLease(t, db, "net-a", "10.0.5.100", "other-vm")

	nb := &stubNetBox{claimed: stubIP{ID: 41, Address: "10.0.5.100/24", VRFID: 3}}
	a := NewNetBoxAllocator(db, nb, noopMetrics{})
	_, err := a.Claim(ctx, boundReq())
	if err == nil {
		t.Fatal("an unconditional upsert would silently steal the live lease")
	}
	if owner := leaseOwner(t, db, "net-a", "10.0.5.100"); owner != "other-vm" {
		t.Fatalf("live lease was clobbered: owner is now %q", owner)
	}
}

// TestClaimPersistsEveryJoinKey is the happy path: a successful POST lands a
// lease carrying both NetBox join keys, so the orphan sweeper and the release
// path can find it.
func TestClaimPersistsEveryJoinKey(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	nb := &stubNetBox{claimed: stubIP{ID: 41, Address: "10.0.5.100/24", VRFID: 3}}
	a := NewNetBoxAllocator(db, nb, noopMetrics{})

	got, err := a.Claim(ctx, boundReq())
	if err != nil {
		t.Fatal(err)
	}
	if got.IP != "10.0.5.100" || got.NetBoxIPID != 41 {
		t.Fatalf("got %+v, want 10.0.5.100 / 41", got)
	}
	held, err := leaseHeldByExact(ctx, db, leaseIdentity{
		Network: "net-a", IP: "10.0.5.100", MAC: "52:54:00:aa:bb:cc",
		OwnerKind: "vm", Name: "vm-1", NetBoxIPID: 41, PrefixID: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("the persisted lease must carry the NetBox ip id and prefix id")
	}
}

// TestClaimResurrectsATombstonedLease pins the guarded upsert's other half: a
// RELEASED address must be re-claimable. The (network, ip) primary key blocks a
// plain re-INSERT, so without the ON CONFLICT clause an address could be used
// exactly once.
func TestClaimResurrectsATombstonedLease(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	nb := &stubNetBox{claimed: stubIP{ID: 41, Address: "10.0.5.100/24", VRFID: 3}}
	a := NewNetBoxAllocator(db, nb, noopMetrics{})

	if _, err := a.Claim(ctx, boundReq()); err != nil {
		t.Fatal(err)
	}
	if err := a.Release(ctx, ReleaseRequest{
		Network: "net-a", IP: "10.0.5.100", MAC: "52:54:00:aa:bb:cc",
		OwnerKind: "vm", Name: "vm-1", NetBoxIPID: 41,
	}); err != nil {
		t.Fatal(err)
	}
	if len(nb.released) != 1 || nb.released[0] != 41 {
		t.Fatalf("release must delete the NetBox object, got %v", nb.released)
	}

	nb.claimed = stubIP{ID: 42, Address: "10.0.5.100/24", VRFID: 3}
	req := boundReq()
	req.Name = "vm-2"
	req.MAC = "52:54:00:aa:bb:dd"
	req.Identity = "lv:fp:uuid2:52:54:00:aa:bb:dd"
	got, err := a.Claim(ctx, req)
	if err != nil {
		t.Fatalf("a released address must be re-claimable, got %v", err)
	}
	if got.NetBoxIPID != 42 {
		t.Fatalf("got %+v", got)
	}
	if owner := leaseOwner(t, db, "net-a", "10.0.5.100"); owner != "vm-2" {
		t.Fatalf("resurrected lease owner = %q, want vm-2", owner)
	}
}

// TestPersistKeysLeaseOnCanonicalAddress pins that the lease key is the PARSED
// address, not the text NetBox happened to send.
//
// ip_allocations is keyed on (network, ip), and IPv6 has many spellings of one
// address: "2001:0db8::0001" and "2001:db8::1" are the same address and
// different strings. Keyed on text, those are two rows — so the guarded upsert
// that exists to stop a live lease being stolen would not see the row it must
// lose to, and Release, which is given the address litevirt recorded, would
// tombstone one spelling while the other stayed live.
//
// The stub returns the LONG form deliberately: with a textual strip this test
// reads back "2001:0db8::0001" and fails.
func TestPersistKeysLeaseOnCanonicalAddress(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	nb := &stubNetBox{claimed: stubIP{ID: 41, Address: "2001:0db8::0001/64", VRFID: 3}}
	a := NewNetBoxAllocator(db, nb, noopMetrics{})

	req := boundReq()
	req.Subnet = "2001:db8::/64"
	req.PrefixCIDR = "2001:db8::/64"

	got, err := a.Claim(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	const want = "2001:db8::1"
	if got.IP != want {
		t.Fatalf("ClaimResult.IP = %q, want the canonical %q", got.IP, want)
	}
	rows, err := db.Query(ctx,
		`SELECT ip FROM ip_allocations WHERE network = ? AND deleted_at IS NULL`, "net-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly one lease row, got %d", len(rows))
	}
	if ip := rows[0].String("ip"); ip != want {
		t.Fatalf("lease row ip = %q, want the canonical %q — two spellings of one address would key two rows", ip, want)
	}
}

// ── release ordering ────────────────────────────────────────────────────────

// TestReleaseSkipsNetBoxWhenTheLocalTombstoneFails pins the order: the local
// tombstone is written FIRST and is mandatory. The reverse order would free an
// address in NetBox that litevirt still believes it holds, letting another
// system take an address a live guest is using.
func TestReleaseSkipsNetBoxWhenTheLocalTombstoneFails(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	nb := &stubNetBox{}
	a := NewNetBoxAllocator(db, nb, noopMetrics{})

	// No lease exists, so the owner-scoped ReleaseLease refuses.
	err := a.Release(ctx, ReleaseRequest{
		Network: "net-a", IP: "10.0.5.100", MAC: "52:54:00:aa:bb:cc",
		OwnerKind: "vm", Name: "vm-1", NetBoxIPID: 41,
	})
	if err == nil {
		t.Fatal("a release whose local tombstone fails must not succeed")
	}
	if len(nb.released) != 0 {
		t.Fatalf("NetBox must not be touched when the local tombstone failed, released %v", nb.released)
	}
}

// ── ambiguous-claim accounting ──────────────────────────────────────────────

// TestAmbiguousClaimIsCounted pins litevirt_netbox_ambiguous_claims_total's only
// increment site. A recovery lookup is the moment litevirt could not tell
// whether its own POST committed; that is invisible to a caller who gets an
// address back, and it is the signal that NetBox (or the path to it) is losing
// responses. Counted once per recovery, whatever the recovery decides.
func TestAmbiguousClaimIsCounted(t *testing.T) {
	ctx := context.Background()
	m := &countingMetrics{}
	nb := &stubNetBox{
		claimErr:   errDuplicate,
		byIdentity: []stubIP{{ID: 41, Address: "10.0.5.100/24", VRFID: 3}},
	}
	a := NewNetBoxAllocator(newTestDB(t), nb, m)
	if _, err := a.Claim(ctx, boundReq()); err != nil {
		t.Fatalf("recovery should have adopted our own object: %v", err)
	}
	if m.ambiguous != 1 {
		t.Fatalf("ambiguous claims counted %d times, want 1", m.ambiguous)
	}
	if len(m.apiErrors) != 1 {
		t.Fatalf("api errors counted %d times, want 1", len(m.apiErrors))
	}
}

// TestCleanClaimCountsNothing is the other half: a POST that answered 2xx never
// entered recovery, so neither counter moves. Without this the counter could be
// wired to every claim and still pass the test above.
func TestCleanClaimCountsNothing(t *testing.T) {
	ctx := context.Background()
	m := &countingMetrics{}
	nb := &stubNetBox{claimed: stubIP{ID: 41, Address: "10.0.5.100/24", VRFID: 3}}
	a := NewNetBoxAllocator(newTestDB(t), nb, m)
	if _, err := a.Claim(ctx, boundReq()); err != nil {
		t.Fatalf("clean claim: %v", err)
	}
	if m.ambiguous != 0 || len(m.apiErrors) != 0 {
		t.Fatalf("a clean claim counted ambiguous=%d apiErrors=%d, want 0/0", m.ambiguous, len(m.apiErrors))
	}
}
