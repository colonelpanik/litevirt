package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// driftBinding is the record a healthy bind leaves behind for the fake below.
func driftBinding(fp string) corrosion.BindingRecord {
	return corrosion.BindingRecord{
		Network: "bound", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: fp,
	}
}

// driftReason runs the predicate and fails the test if the answer was UNKNOWN.
//
// bindingDrift has three answers, and a helper that folded the error into "" for
// brevity would be re-committing the bug the third answer exists to prevent — in
// the tests, where it would then hide it everywhere else. Every scenario that
// wants the unknown answer asks for it explicitly.
func driftReason(t *testing.T, s *Server, b corrosion.BindingRecord, fp string) string {
	t.Helper()
	reason, err := s.bindingDrift(context.Background(), b, fp)
	if err != nil {
		t.Fatalf("the drift check could not read NetBox, which is not the answer this "+
			"scenario is about: %v", err)
	}
	return reason
}

func liveFingerprint(t *testing.T, s *Server) string {
	t.Helper()
	fp, err := corrosion.ClusterFingerprint(context.Background(), s.db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	return fp
}

// TestBindingDriftFingerprintMismatchNamesTheRekey pins all three halves of the
// pin: the comparison is against the RECORDED fingerprint, the reason tells the
// operator the one command that resolves it, and it states a cause production
// can actually produce.
//
// That last one is not cosmetic. This string is PERSISTED to
// netbox_bindings.suspend_reason and is what an operator reads mid-incident —
// through every allocation refusal, every ResumeBinding refusal, and the durable
// health-condition evidence `lv health` prints. The fingerprint is minted ONCE by
// corrosion.EnsureClusterRecord and deliberately never tracks `ca.crt`, and
// nothing in production rewrites `cluster.ca_cert` after that heal, so blaming a
// CA replacement sends the operator looking for a cause that cannot exist.
func TestBindingDriftFingerprintMismatchNamesTheRekey(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	reason := driftReason(t, s, driftBinding("an-older-ca"), liveFingerprint(t, s))
	if reason == "" {
		t.Fatal("a binding pinned to another fingerprint must be drift")
	}
	if !strings.Contains(reason, "netbox rekey") {
		t.Fatalf("reason = %q, want the re-key command", reason)
	}
	if !strings.Contains(reason, "fingerprint moved") {
		t.Fatalf("reason = %q, want the moved fingerprint named as the cause", reason)
	}
	if !strings.Contains(reason, "an-older-ca") {
		t.Fatalf("reason = %q, want the fingerprint the binding is pinned to", reason)
	}
	lower := strings.ToLower(reason)
	for _, blame := range []string{"ca changed", "ca replac", "ca rotat", "ca was"} {
		if strings.Contains(lower, blame) {
			t.Fatalf("reason = %q blames the cluster CA — replacing it cannot move the "+
				"fingerprint, so this sends an operator after a cause production cannot produce",
				reason)
		}
	}
}

func TestBindingDriftCIDRChange(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.6.0/24", VRFID: 3}, // re-CIDRed
		enforceUnique: true,
	})
	fp := liveFingerprint(t, s)
	reason := driftReason(t, s, driftBinding(fp), fp)
	if !strings.Contains(reason, "10.0.6.0/24") {
		t.Fatalf("reason = %q, want it to name the CIDR NetBox now reports", reason)
	}
}

func TestBindingDriftPrefixMovedToGlobalTable(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix: netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 0}, // no VRF
	})
	fp := liveFingerprint(t, s)
	reason := driftReason(t, s, driftBinding(fp), fp)
	if !strings.Contains(reason, "global table") {
		t.Fatalf("reason = %q, want it to name the global table", reason)
	}
}

func TestBindingDriftVRFStoppedEnforcingUniqueness(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: false,
	})
	fp := liveFingerprint(t, s)
	reason := driftReason(t, s, driftBinding(fp), fp)
	if !strings.Contains(reason, "unique") {
		t.Fatalf("reason = %q, want it to name the uniqueness setting", reason)
	}
}

// TestBindingDriftRejectsAMoveBetweenUniquenessEnforcingVRFs.
//
// The uniqueness read asks about the prefix's CURRENT VRF, which is a weaker
// fact than the one a binding needs: a prefix moved from one enforcing VRF into
// another satisfies it, while the binding's allocation scope is still pinned to
// the VRF the prefix has left. Both VRFs enforce uniqueness here, so nothing but
// an ID comparison can tell this apart from a healthy binding.
//
// AND THE REASON MUST NOT BE A REPIN. The row keeps the old vrf_id; re-pinning
// would move the scope without establishing that the addresses this network's
// guests already hold are unique inside the new one.
func TestBindingDriftRejectsAMoveBetweenUniquenessEnforcingVRFs(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		// The prefix now sits in VRF 4; the binding below is pinned to VRF 3.
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 4},
		enforceUnique: true,
	})
	fp := liveFingerprint(t, s)
	reason := driftReason(t, s, driftBinding(fp), fp)
	if reason == "" {
		t.Fatal("a prefix moved into a DIFFERENT uniqueness-enforcing VRF left the binding " +
			"live: the binding's allocation scope is still pinned to the VRF the prefix has " +
			"left, so dynamic claims fail the returned-VRF check and explicit ones address " +
			"the wrong VRF")
	}
	for _, want := range []string{"VRF 3", "VRF 4"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason = %q, want both VRFs named (%s)", reason, want)
		}
	}
}

// TestBindingDriftReportsAnUnreadableNetBoxAsUnknown pins the third answer, and
// pins it as DISTINCT from both of the other two.
//
// This is the shape the whole finding rests on: with the prefix and VRF reads
// failing, the predicate used to return the same empty string a clean
// re-validation returns. "I could not look" and "nothing is wrong" have to be
// different answers, or every caller that acts on the second acts on the first.
func TestBindingDriftReportsAnUnreadableNetBoxAsUnknown(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
		failReads:     true,
	})
	fp := liveFingerprint(t, s)
	reason, err := s.bindingDrift(context.Background(), driftBinding(fp), fp)
	if err == nil {
		t.Fatal("an unreadable NetBox was reported as a completed check; a read failure must " +
			"be its own answer, never the one a clean re-validation gives")
	}
	if reason != "" {
		t.Errorf("reason = %q, want it empty: nothing was established, so there is no drift "+
			"to state either", reason)
	}
}

// TestBindingDriftNoneWhenNothingChanged is the negative control: without it a
// bindingDrift that returned a reason unconditionally would pass every test
// above.
func TestBindingDriftNoneWhenNothingChanged(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	fp := liveFingerprint(t, s)
	if reason := driftReason(t, s, driftBinding(fp), fp); reason != "" {
		t.Fatalf("an unchanged binding must not drift, got %q", reason)
	}
}

// TestRevalidateSuspendsTheDriftedRow drives the whole pass, not just the
// predicate: a drifted binding must come back from the DB suspended, with the
// reason recorded for the operator.
func TestRevalidateSuspendsTheDriftedRow(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	if err := s.validateAndBindPrefix(ctx, "bound", 7, noDHCPNetworkDef); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// The replicated `cluster` row is rewritten out of band — the only thing that
	// moves the fingerprint — so the binding's pin no longer matches.
	if err := s.db.Execute(ctx, `UPDATE cluster SET ca_cert = ? WHERE id = 'default'`,
		"a-different-ca-cert"); err != nil {
		t.Fatalf("replace ca_cert: %v", err)
	}

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("RevalidateBindingsOnce: %v", err)
	}

	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil || b == nil {
		t.Fatalf("read binding: %v %v", b, err)
	}
	if !b.Suspended {
		t.Fatal("revalidation must suspend a binding whose fingerprint pin no longer matches")
	}
	if !strings.Contains(b.SuspendReason, "netbox rekey") {
		t.Fatalf("SuspendReason = %q, want the re-key command", b.SuspendReason)
	}
}

// TestRevalidateIsANoopWithoutANetBoxClient pins that a node with no netbox
// configuration does nothing at all. bindingDrift would dereference a nil
// client, so the guard is not cosmetic — and a node that cannot read NetBox has
// no standing to suspend a binding every other node can still validate.
func TestRevalidateIsANoopWithoutANetBoxClient(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	if err := s.validateAndBindPrefix(ctx, "bound", 7, noDHCPNetworkDef); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := s.db.Execute(ctx, `UPDATE cluster SET ca_cert = ? WHERE id = 'default'`,
		"a-different-ca-cert"); err != nil {
		t.Fatalf("replace ca_cert: %v", err)
	}
	s.netbox = nil

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("RevalidateBindingsOnce: %v", err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil || b == nil {
		t.Fatalf("read binding: %v %v", b, err)
	}
	if b.Suspended {
		t.Fatal("a node with no netbox configuration must suspend nothing")
	}
}

// TestRekeyBindingRequiresAdmin pins the role gate. A re-key rewrites the
// identity of every object litevirt owns in a prefix — it is an admin
// operation, and the check has to come before anything is read or written.
func TestRekeyBindingRequiresAdmin(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	if err := s.validateAndBindPrefix(context.Background(), "bound", 7, noDHCPNetworkDef); err != nil {
		t.Fatalf("bind: %v", err)
	}

	viewer := context.WithValue(context.WithValue(context.Background(),
		ctxKeyUsername, "vera"), ctxKeyRole, "viewer")
	_, err := s.RekeyBinding(viewer, &pb.RekeyBindingRequest{Network: "bound"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer got %v, want PermissionDenied", err)
	}

	// The same call as admin gets PAST the gate — without this the test would
	// also pass against a handler that refused everyone.
	if _, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{Network: "bound"}); err != nil {
		t.Fatalf("admin re-key: %v", err)
	}
}

// TestRekeyBindingRefusesAnUnboundNetwork keeps the refusal a NotFound naming
// the network, rather than a nil-binding panic or a silent success.
func TestRekeyBindingRefusesAnUnboundNetwork(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	_, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{Network: "unbound"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("got %v, want NotFound", err)
	}
	if !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("the refusal must name the network, got %v", err)
	}
}

// TestRekeyBindingWritesAnAuditRow: a re-key rewrites the identity of every
// NetBox object a network owns, fleet-wide, under an admin's hands. An
// operation of that reach that leaves no trace in the audit log is one `lv
// audit verify` can never account for afterwards.
func TestRekeyBindingWritesAnAuditRow(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	if err := s.validateAndBindPrefix(ctx, "bound", 7, noDHCPNetworkDef); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if _, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{Network: "bound"}); err != nil {
		t.Fatalf("re-key: %v", err)
	}

	rows, err := s.db.Query(ctx,
		`SELECT target, detail, result FROM audit_log WHERE action = 'netbox.rekey'`)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly one netbox.rekey audit row, got %d", len(rows))
	}
	if got := rows[0].String("target"); got != "bound" {
		t.Errorf("audit target = %q, want the network the re-key names", got)
	}
	if got := rows[0].String("result"); got != "ok" {
		t.Errorf("audit result = %q, want ok", got)
	}
	// The prefix is what the operation actually acted on, and the rewrite count
	// is the only record of how much of NetBox it touched.
	if got := rows[0].String("detail"); !strings.Contains(got, "prefix=7") ||
		!strings.Contains(got, "rewritten=") {
		t.Errorf("audit detail = %q, want the prefix and the rewrite count", got)
	}
}

// seedObjectRefs records n local index rows under one fingerprint — the state
// the inventory mirror leaves behind, which is where the cluster-scoped re-key
// derives its pin from.
func seedObjectRefs(t *testing.T, s *Server, fingerprint string) {
	t.Helper()
	ctx := context.Background()
	refs := []corrosion.ObjectRef{
		{
			LitevirtKind: "vm",
			LitevirtKey:  netbox.Identity(fingerprint, "3f6c2a10-0000-4000-8000-000000000001", ""),
			NetBoxKind:   "virtualization.virtualmachine",
			NetBoxID:     4001,
		},
		{
			LitevirtKind: "nic",
			LitevirtKey:  netbox.Identity(fingerprint, "3f6c2a10-0000-4000-8000-000000000001", "52:54:00:00:00:01"),
			NetBoxKind:   "virtualization.vminterface",
			NetBoxID:     6001,
		},
	}
	for _, r := range refs {
		if err := corrosion.PutObjectRef(ctx, s.db, r); err != nil {
			t.Fatalf("seed object ref %s: %v", r.LitevirtKey, err)
		}
	}
}

// TestRekeyInventoryOnlyRequiresAdmin pins the role gate on the NETWORK-LESS
// form.
//
// It is a separate scenario from TestRekeyBindingRequiresAdmin because the
// empty-network branch is a separate entry point: moving it above RequireRole —
// which reads naturally, since it needs no binding lookup — would leave a
// viewer able to rewrite every identity in the cluster with the bound form's
// gate still green.
func TestRekeyInventoryOnlyRequiresAdmin(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	seedObjectRefs(t, s, "0000000000000000")

	viewer := context.WithValue(context.WithValue(context.Background(),
		ctxKeyUsername, "vera"), ctxKeyRole, "viewer")
	if _, err := s.RekeyBinding(viewer, &pb.RekeyBindingRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer got %v, want PermissionDenied", err)
	}

	// The same call as admin gets PAST the gate — without this the test would
	// also pass against a handler that refused everyone.
	if _, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{}); err != nil {
		t.Fatalf("admin inventory re-key: %v", err)
	}
}

// TestRekeyInventoryOnlyWritesAnAuditRow: the cluster-scoped form rewrites
// identities fleet-wide with no binding row to record that it ran, so the audit
// row is the ONLY durable trace of it. The target has to distinguish it from a
// per-network re-key, and the detail has to say how much it touched.
func TestRekeyInventoryOnlyWritesAnAuditRow(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	seedObjectRefs(t, s, "0000000000000000")

	if _, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{}); err != nil {
		t.Fatalf("inventory re-key: %v", err)
	}

	rows, err := s.db.Query(ctx,
		`SELECT target, detail, result FROM audit_log WHERE action = 'netbox.rekey'`)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly one netbox.rekey audit row, got %d", len(rows))
	}
	if got := rows[0].String("target"); got != rekeyInventoryTarget {
		t.Errorf("audit target = %q, want %q — a network name here would read as a "+
			"per-network re-key", got, rekeyInventoryTarget)
	}
	if got := rows[0].String("result"); got != "ok" {
		t.Errorf("audit result = %q, want ok", got)
	}
	if got := rows[0].String("detail"); !strings.Contains(got, "pins=1") ||
		!strings.Contains(got, "refs=2") {
		t.Errorf("audit detail = %q, want the pin count and the rows rewritten", got)
	}

	// The rows themselves moved to the live fingerprint, which is what makes
	// the audited count mean something.
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	for _, kind := range []string{"vm", "nic"} {
		refs, err := corrosion.ListObjectRefs(ctx, s.db, kind)
		if err != nil {
			t.Fatalf("ListObjectRefs(%s): %v", kind, err)
		}
		if len(refs) != 1 {
			t.Fatalf("want exactly one live %s index row after the re-key, got %d", kind, len(refs))
		}
		if cf, _, _, ok := splitIdentity(refs[0].LitevirtKey); !ok || cf != fp {
			t.Errorf("%s index row key = %q, want one carrying the live fingerprint %q",
				kind, refs[0].LitevirtKey, fp)
		}
	}
}

// TestRekeyInventoryOnlyRefusesWithNoLocalIndex is the fail-closed half: with an
// EMPTY index nothing records the fingerprint this cluster's objects carry, and
// the only other rule available — "rewrite anything that is not current" —
// would seize a co-tenant installation's objects out of a shared NetBox. The
// refusal is audited, because an operator has to be able to see that the
// command ran and declined.
func TestRekeyInventoryOnlyRefusesWithNoLocalIndex(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})

	_, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "identity index") {
		t.Fatalf("the refusal must name the empty local identity index, got %v", err)
	}

	rows, err := s.db.Query(ctx,
		`SELECT result FROM audit_log WHERE action = 'netbox.rekey'`)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}
	if len(rows) != 1 || rows[0].String("result") != "error" {
		t.Fatalf("want one netbox.rekey audit row recording the refusal, got %d rows", len(rows))
	}
}

// TestResumeBindingRequiresAdmin pins the role gate on the resume, which lifts
// a safety flag on a cluster-wide binding.
func TestResumeBindingRequiresAdmin(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	if err := s.validateAndBindPrefix(context.Background(), "bound", 7, noDHCPNetworkDef); err != nil {
		t.Fatalf("bind: %v", err)
	}

	viewer := context.WithValue(context.WithValue(context.Background(),
		ctxKeyUsername, "vera"), ctxKeyRole, "viewer")
	_, err := s.ResumeBinding(viewer, &pb.ResumeBindingRequest{Network: "bound"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer got %v, want PermissionDenied", err)
	}

	// The same call as admin gets past the gate — without this the test would
	// also pass against a handler that refused everyone.
	if _, err := s.ResumeBinding(adminCtx(), &pb.ResumeBindingRequest{Network: "bound"}); err != nil {
		t.Fatalf("admin resume: %v", err)
	}
}

func TestResumeBindingRefusesAnUnboundNetwork(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	_, err := s.ResumeBinding(adminCtx(), &pb.ResumeBindingRequest{Network: "unbound"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("got %v, want NotFound", err)
	}
	if !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("the refusal must name the network, got %v", err)
	}
}

// TestResumeBindingRefusesADriftedCIDRAndKeepsThePin covers the two halves of
// the v1 re-CIDR limitation in one place: the refusal is a FailedPrecondition
// naming the drift, and the binding's observed_cidr is left exactly as pinned.
// A resume that adopted the new range would restart allocation into addresses
// the sweeper and lease repair — which enumerate by observed_cidr — cannot see.
func TestResumeBindingRefusesADriftedCIDRAndKeepsThePin(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	if err := s.validateAndBindPrefix(ctx, "bound", 7, noDHCPNetworkDef); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// The binding as a re-CIDR would leave it: suspended, still pinned to the
	// range it validated, while NetBox reports the prefix under another one.
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil || b == nil {
		t.Fatalf("read binding: %v %v", b, err)
	}
	pinned := *b
	pinned.ObservedCIDR = "10.0.9.0/24"
	pinned.Suspended = true
	pinned.SuspendReason = "prefix re-CIDRed from 10.0.9.0/24 to 10.0.5.0/24"
	if err := corrosion.UpsertBinding(ctx, s.db, pinned); err != nil {
		t.Fatalf("seed the suspended binding: %v", err)
	}

	_, err = s.ResumeBinding(adminCtx(), &pb.ResumeBindingRequest{Network: "bound"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "re-CIDRed") {
		t.Fatalf("the refusal must name the drift, got %v", err)
	}

	after, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil || after == nil {
		t.Fatalf("re-read binding: %v %v", after, err)
	}
	if !after.Suspended {
		t.Fatal("a refused resume must leave the binding suspended")
	}
	if after.ObservedCIDR != "10.0.9.0/24" {
		t.Fatalf("ObservedCIDR = %q, want the pinned 10.0.9.0/24 — resume must never "+
			"re-observe the prefix", after.ObservedCIDR)
	}
}

// TestResumeRefusesWhenTheBindingCouldNotBeRevalidated is the finding, at the
// door it was found at.
//
// The binding is suspended for a VRF that stopped enforcing uniqueness — the
// repair for which is made in NetBox — and NetBox is then unreadable. The resume
// re-proves rather than taking an operator's word for the repair, so a re-proof
// that could not run is a refusal: nothing has changed in NetBox, and lifting the
// suspension would make the binding serve claims across a prefix whose
// uniqueness enforcement may still be switched off.
func TestResumeRefusesWhenTheBindingCouldNotBeRevalidated(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
		failReads:     true,
	})
	fp := liveFingerprint(t, s)
	ours, err := corrosion.ClaimBinding(ctx, s.db, corrosion.BindingRecord{
		Network: "bound", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: fp,
	})
	if err != nil || !ours {
		t.Fatalf("seed the binding: ours=%v err=%v", ours, err)
	}
	if err := corrosion.SuspendBinding(ctx, s.db, 7,
		"VRF 3 no longer enforces uniqueness"); err != nil {
		t.Fatalf("suspend the binding: %v", err)
	}

	_, err = s.ResumeBinding(adminCtx(), &pb.ResumeBindingRequest{Network: "bound"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition — a resume may not rest on a re-validation "+
			"that never happened", err)
	}
	after, gerr := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if gerr != nil || after == nil {
		t.Fatalf("re-read the binding: %v %v", after, gerr)
	}
	if !after.Suspended {
		t.Fatal("the resume lifted a suspension while NetBox was unreadable, which is exactly " +
			"the condition the binding was suspended for going unchecked")
	}
	if after.SuspendReason != "VRF 3 no longer enforces uniqueness" {
		t.Errorf("SuspendReason = %q, want the original reason left standing", after.SuspendReason)
	}
}

// TestRevalidationKeepsItsToleranceForAnUnreadableNetBox is the other half, and
// the reason the fix is a signature change rather than a blanket refusal.
//
// The periodic pass may only ever make a binding LESS trusted, and a suspension
// is sticky. So an unreadable NetBox must leave a LIVE binding live: suspending
// on a maintenance window would turn a transient into a network that refuses
// every create until a human intervenes, with nothing having actually changed.
// The refusal belongs at the activation paths, not here.
func TestRevalidationKeepsItsToleranceForAnUnreadableNetBox(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
		failReads:     true,
	})
	fp := liveFingerprint(t, s)
	ours, err := corrosion.ClaimBinding(ctx, s.db, corrosion.BindingRecord{
		Network: "bound", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: fp,
	})
	if err != nil || !ours {
		t.Fatalf("seed the binding: ours=%v err=%v", ours, err)
	}

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("the pass must not fail over an unreadable NetBox: %v", err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil || b == nil {
		t.Fatalf("read the binding: %v %v", b, err)
	}
	if b.Suspended {
		t.Fatalf("an unreadable NetBox suspended a live binding (%q); suspension is sticky, "+
			"so a maintenance window would need an operator to undo", b.SuspendReason)
	}
}

// ── the re-key's leader lease ───────────────────────────────────────────────

// leaseFingerprint is the stale fingerprint seedObjectRefs stamps the local
// index with, so a cluster-scoped re-key has a pin to derive and real work to
// do. Sixteen hex characters, the shape corrosion.ClusterFingerprint produces.
const leaseFingerprint = "0000000000000000"

// indexFingerprints groups every live netbox_objects row by the cluster
// component of its key — the local half of "was anything rewritten".
func indexFingerprints(t *testing.T, s *Server) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, kind := range []string{rekeyRefKindVM, rekeyRefKindNIC} {
		refs, err := corrosion.ListObjectRefs(context.Background(), s.db, kind)
		if err != nil {
			t.Fatalf("ListObjectRefs(%s): %v", kind, err)
		}
		for _, r := range refs {
			cf, _, _, ok := splitIdentity(r.LitevirtKey)
			if !ok {
				t.Fatalf("index key %q is not an identity string", r.LitevirtKey)
			}
			out[cf]++
		}
	}
	return out
}

// TestRekeyRefusedWithoutTheLease is the fail-closed half of putting the re-key
// under the `netbox` leader lease.
//
// The re-key rewrites the very objects the inventory mirror reconciles, so the
// two may not run at once: BuildActual filters actual state on the LIVE
// fingerprint, a not-yet-rewritten VM is therefore invisible to it, Diff emits a
// create, and NetBox's cluster-scoped VM-name uniqueness refuses that create —
// failing the whole sweep. A re-key that cannot prove it leads the cluster must
// therefore rewrite NOTHING and say so.
//
// The binding assertion is the sharp one: the pin here is deliberately stale, so
// a re-key that took the lease anywhere AFTER its own suspend-first step would
// leave a network refusing allocations that this command is not going to repair.
func TestRekeyRefusedWithoutTheLease(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	if err := s.validateAndBindPrefix(ctx, "bound", 7, noDHCPNetworkDef); err != nil {
		t.Fatalf("bind: %v", err)
	}
	seedObjectRefs(t, s, leaseFingerprint)
	// The replicated `cluster` row is rewritten out of band, so the pin is stale and the
	// re-key has a reason to suspend before it rewrites.
	if err := s.db.Execute(ctx, `UPDATE cluster SET ca_cert = ? WHERE id = 'default'`,
		"a-different-ca-cert"); err != nil {
		t.Fatalf("replace ca_cert: %v", err)
	}
	// A peer holds the lease, and it has not expired.
	seedLease(t, s, "another-node", time.Now().Add(time.Hour))

	_, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{Network: "bound"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition — a lease this node does not hold is an "+
			"operator's retry, not an internal failure", err)
	}
	if !strings.Contains(err.Error(), "another-node") {
		t.Fatalf("the refusal must name the holder, got %v", err)
	}

	if got := indexFingerprints(t, s); got[leaseFingerprint] != 2 {
		t.Fatalf("local index rows by fingerprint = %v, want both still under %q — a refused "+
			"re-key must rewrite nothing", got, leaseFingerprint)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil || b == nil {
		t.Fatalf("read binding: %v %v", b, err)
	}
	if b.Suspended {
		t.Fatal("a re-key refused for want of the lease must leave the binding as it found it — " +
			"the lease has to be taken before the suspend, not after")
	}
	if s.holdsLeaderLease(ctx) {
		t.Fatal("a refused re-key must not have taken the lease")
	}

	// The other side: once the peer's lease has lapsed the SAME call goes
	// through. Without this the test would also pass against a re-key that
	// refused unconditionally.
	seedLease(t, s, "another-node", time.Now().Add(-time.Minute))
	if _, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{Network: "bound"}); err != nil {
		t.Fatalf("re-key with the lease free: %v", err)
	}
	if !s.holdsLeaderLease(ctx) {
		t.Fatal("a completed re-key must hold the lease it rewrote under")
	}
}

// TestRekeyInventoryOnlyTakesTheLeaseToo covers the CLUSTER-SCOPED form, which
// is a separate entry point with its own writes.
//
// It is the form a mirror-only cluster runs, and it rewrites exactly the objects
// the mirror reconciles — no addresses, no binding, nothing else. A lease taken
// in the per-network path alone would leave the only re-key such a cluster HAS
// racing the sweep it exists to keep working.
func TestRekeyInventoryOnlyTakesTheLeaseToo(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	seedObjectRefs(t, s, leaseFingerprint)
	seedLease(t, s, "another-node", time.Now().Add(time.Hour))

	_, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "another-node") {
		t.Fatalf("the refusal must name the holder, got %v", err)
	}
	if got := indexFingerprints(t, s); got[leaseFingerprint] != 2 {
		t.Fatalf("local index rows by fingerprint = %v, want both still under %q", got, leaseFingerprint)
	}
	if s.holdsLeaderLease(ctx) {
		t.Fatal("a refused inventory re-key must not have taken the lease")
	}
	// Audited, like every other outcome of this command: an operator has to be
	// able to see that it ran and declined.
	rows, err := s.db.Query(ctx,
		`SELECT result FROM audit_log WHERE action = 'netbox.rekey'`)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}
	if len(rows) != 1 || rows[0].String("result") != "error" {
		t.Fatalf("want one netbox.rekey audit row recording the refusal, got %d rows", len(rows))
	}

	// Once the peer's lease has lapsed the same call completes, and this node
	// ends up holding the lease it rewrote under.
	seedLease(t, s, "another-node", time.Now().Add(-time.Minute))
	if _, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{}); err != nil {
		t.Fatalf("inventory re-key with the lease free: %v", err)
	}
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	if got := indexFingerprints(t, s); got[fp] != 2 || got[leaseFingerprint] != 0 {
		t.Fatalf("local index rows by fingerprint = %v, want both under the live %q", got, fp)
	}
	if !s.holdsLeaderLease(ctx) {
		t.Fatal("a completed inventory re-key must hold the lease it rewrote under")
	}
}
