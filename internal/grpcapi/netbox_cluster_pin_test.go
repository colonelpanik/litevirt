package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// `netbox.cluster_name` must be uniform cluster-wide, and until now nothing
// enforced it.
//
// It names the NetBox `virtualization.cluster` this installation mirrors into,
// and the mirror sweep runs on whichever node holds the `netbox` leader lease.
// So a value set on some nodes only means whichever node leads decides that
// sweep: objects are created under one cluster and deleted under another as
// leadership moves, and the ones left behind are invisible to every sweep that
// resolves the other name, so nothing ever reaps them. Unlike every
// `enforcement.*` flag there is no latch to mediate it, because a capability
// token carries a name and not a value.
//
// The fix is a PIN on the binding row, next to the facts a binding already
// validates against. The row replicates, which is the only way a node learns
// what a peer's configuration says. A node whose own resolution disagrees with
// the pin refuses to mirror and raises a health condition naming both values —
// fail closed, and no new cross-host publication mechanism.

// bindOne runs a successful bind against a fake holding one usable prefix.
func bindOne(t *testing.T, s *Server, network string, prefixID int) {
	t.Helper()
	if err := s.validateAndBindPrefix(context.Background(), network, prefixID, noDHCPNetworkDef); err != nil {
		t.Fatalf("validateAndBindPrefix(%s, %d): %v", network, prefixID, err)
	}
}

func usableNetBox() fakeNetBox {
	return fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	}
}

// TestBindPinsTheResolvedNetBoxClusterName pins the RESOLVED name, which is the
// whole reason this comparison can be made at all.
//
// The resolution is `netbox.cluster_name` if set, else the local cluster name,
// else a placeholder — so what lands on the row is a concrete name and never an
// empty "use the default". That matters for the mismatch check: two nodes that
// both leave the key unset resolve the SAME local cluster name and agree, while
// a node that sets it and a node that does not resolve different names and
// disagree. Pinning the raw config value instead would make those two cases
// indistinguishable.
func TestBindPinsTheResolvedNetBoxClusterName(t *testing.T) {
	// No override: the local `cluster` row's name, which the fixture seeds.
	s := newTestServerWithNetBox(t, usableNetBox())
	bindOne(t, s, "net-a", 7)
	b, err := corrosion.GetBindingByPrefix(context.Background(), s.db, 7)
	if err != nil || b == nil {
		t.Fatalf("GetBindingByPrefix: %+v err=%v", b, err)
	}
	if b.NetBoxCluster != "test-cluster" {
		t.Fatalf("with no override, the pin must be the local cluster name; got %q", b.NetBoxCluster)
	}

	// With an override, the override — that is the value the mirror would use.
	s2 := newTestServerWithNetBox(t, usableNetBox())
	s2.SetNetBoxClusterName("site-a")
	bindOne(t, s2, "net-a", 7)
	b2, err := corrosion.GetBindingByPrefix(context.Background(), s2.db, 7)
	if err != nil || b2 == nil {
		t.Fatalf("GetBindingByPrefix: %+v err=%v", b2, err)
	}
	if b2.NetBoxCluster != "site-a" {
		t.Fatalf("with an override, the pin must be the override; got %q", b2.NetBoxCluster)
	}
}

// TestMirrorRefusesAClusterNameMismatch is the refusal.
//
// The lease is the observable, as everywhere else in the mirror's gates: a pass
// acquires the `netbox` leader lease before anything else and that acquire is
// itself a replicated write, so a check that ran after it would already have
// written — and worse, would have taken the leadership that decides which node
// mirrors.
func TestMirrorRefusesAClusterNameMismatch(t *testing.T) {
	s := newTestServerWithNetBox(t, usableNetBox())
	s.SetNetBoxClusterName("site-a")
	bindOne(t, s, "net-a", 7)

	// The same cluster, now read by a node configured for a DIFFERENT NetBox
	// cluster. Modelled by moving this node's override, which is exactly what
	// the disagreeing node's config does.
	s.SetNetBoxClusterName("site-b")
	ctx := context.Background()

	if err := s.RunNetBoxMirrorOnce(ctx); err != nil {
		t.Fatalf("a mismatching pass must decline quietly, not error: %v", err)
	}
	if got := mirrorLeaseHolder(t, s); got != "" {
		t.Fatalf("a node whose cluster_name disagrees with the pin took the lease (holder %q)", got)
	}

	// The positive control: back in agreement, the same fixture mirrors.
	s.SetNetBoxClusterName("site-a")
	_ = s.RunNetBoxMirrorOnce(ctx)
	if got := mirrorLeaseHolder(t, s); got != s.hostName {
		t.Fatalf("an agreeing node must mirror, lease holder = %q want %q", got, s.hostName)
	}
}

// TestUnsetClusterNameAgreesWithTheLocalName is the case the brief asks to be
// decided explicitly: one node leaves `netbox.cluster_name` unset.
//
// It is NOT a mismatch when the pin is the local cluster name, because that is
// precisely what an unset key resolves to — the two nodes would write into the
// same NetBox cluster, so refusing would break the DEFAULT deployment shape for
// no gain. It IS a mismatch when the pin came from an override, which is the
// dangerous half: one node writing into `site-a` and another into the local
// cluster name is the flapping inventory this closes.
func TestUnsetClusterNameAgreesWithTheLocalName(t *testing.T) {
	s := newTestServerWithNetBox(t, usableNetBox())
	bindOne(t, s, "net-a", 7) // pins "test-cluster", the local name
	ctx := context.Background()

	// Still unset here, as on every node of a default deployment.
	_ = s.RunNetBoxMirrorOnce(ctx)
	if got := mirrorLeaseHolder(t, s); got != s.hostName {
		t.Fatalf("an unset cluster_name must agree with a pin of the local name, lease holder %q", got)
	}

	// The other direction, on a fresh fixture: the pin came from an override, so
	// a node that leaves the key unset resolves something else and must refuse.
	s2 := newTestServerWithNetBox(t, usableNetBox())
	s2.SetNetBoxClusterName("site-a")
	bindOne(t, s2, "net-a", 7)
	s2.SetNetBoxClusterName("") // the node that never set the key
	if err := s2.RunNetBoxMirrorOnce(ctx); err != nil {
		t.Fatalf("a mismatching pass must decline quietly: %v", err)
	}
	if got := mirrorLeaseHolder(t, s2); got != "" {
		t.Fatalf("an unset cluster_name against an override pin must refuse (holder %q)", got)
	}
}

// TestUnpinnedBindingIsNotAMismatch covers the row an EARLIER build of this
// branch wrote, whose pin is empty.
//
// Empty means "not pinned", not "the empty name" — the resolution never yields
// an empty string. A row that recorded nothing cannot disagree with anything, so
// treating it as a mismatch would take every such cluster's mirror out of
// service on the strength of no evidence at all. It gets no enforcement instead,
// which is the state it was already in.
func TestUnpinnedBindingIsNotAMismatch(t *testing.T) {
	s := newTestServerWithNetBox(t, usableNetBox())
	s.SetNetBoxClusterName("site-a")
	bindOne(t, s, "net-a", 7)
	ctx := context.Background()

	// Blank the pin, exactly as a pre-column row reads back.
	if err := s.db.Execute(ctx,
		`UPDATE netbox_bindings SET netbox_cluster = '' WHERE prefix_id = ?`, 7); err != nil {
		t.Fatalf("blank the pin: %v", err)
	}
	s.SetNetBoxClusterName("site-b") // would be a mismatch against a real pin

	_ = s.RunNetBoxMirrorOnce(ctx)
	if got := mirrorLeaseHolder(t, s); got != s.hostName {
		t.Fatalf("an unpinned binding must not block the mirror, lease holder %q", got)
	}
}

// TestUnverifiableClusterNameDeclinesThePass is the fail-closed direction.
//
// A node that cannot RESOLVE its own NetBox cluster name has not established
// agreement — it has established nothing. Agreement is what authorizes rewriting
// shared inventory, so the absence of it must stop the pass, not be read as
// consent.
//
// The lease is again the observable, and here it is the ONLY one that separates
// the two behaviours: with the `cluster` row gone the sweep would fail at its
// fingerprint read a moment later either way, so a fail-open gate looks
// identical in NetBox. What it would have done first is take the leadership that
// decides which node mirrors.
func TestUnverifiableClusterNameDeclinesThePass(t *testing.T) {
	s := newTestServerWithNetBox(t, usableNetBox())
	bindOne(t, s, "net-a", 7)
	ctx := context.Background()

	// The `cluster` row is what the resolution reads. Gone, it cannot answer.
	if err := s.db.Execute(ctx, `DELETE FROM cluster`); err != nil {
		t.Fatalf("delete the cluster row: %v", err)
	}

	if err := s.RunNetBoxMirrorOnce(ctx); err != nil {
		t.Fatalf("an unverifiable pass must decline quietly, not error: %v", err)
	}
	if got := mirrorLeaseHolder(t, s); got != "" {
		t.Fatalf("a node that could not verify its cluster name took the lease (holder %q)", got)
	}
}

// TestClusterNameMismatchRaisesAHealthCondition is the operator-visible half.
//
// A refusal that only logged would be a mirror that silently stopped: nothing
// else litevirt reports changes, no workload is disturbed, and the first symptom
// is an inventory that quietly stops tracking reality. So the mismatch is a
// durable health_conditions row, like the two findings next to it.
//
// The subject is the HOST, not the network, and that is load-bearing rather than
// cosmetic. The finding is about one node's configuration, every node evaluates
// it for itself, and a finding keyed on the network would have the agreeing
// nodes and the disagreeing one writing the same row under LWW — the last writer
// deciding whether the cluster has a problem.
func TestClusterNameMismatchRaisesAHealthCondition(t *testing.T) {
	s := newTestServerWithNetBox(t, usableNetBox())
	s.SetNetBoxClusterName("site-a")
	bindOne(t, s, "net-a", 7)
	s.SetNetBoxClusterName("site-b")
	ctx := context.Background()

	if err := s.revalidateBindings(ctx); err != nil {
		t.Fatalf("revalidateBindings: %v", err)
	}
	got, ok := netboxCondition(t, s, condNetBoxClusterNameMismatch, s.hostName)
	if !ok {
		t.Fatal("a cluster_name mismatch raised no health condition")
	}
	if got.SubjectKind != "host" {
		t.Errorf("subject_kind = %q, want %q", got.SubjectKind, "host")
	}
	// BOTH values, because an operator cannot act on "these disagree": the fix is
	// to change one of them, and which one depends on knowing both.
	if !strings.Contains(got.Evidence, "site-a") {
		t.Errorf("evidence %q does not name the PINNED cluster", got.Evidence)
	}
	if !strings.Contains(got.Evidence, "site-b") {
		t.Errorf("evidence %q does not name this node's RESOLVED cluster", got.Evidence)
	}
	if !strings.Contains(got.Evidence, "net-a") {
		t.Errorf("evidence %q does not name the binding holding the pin", got.Evidence)
	}

	// It resolves once the configuration is fixed, or an operator who corrected
	// the config would be left with a standing finding about a problem that is
	// gone.
	s.SetNetBoxClusterName("site-a")
	for i := 0; i < netboxCleanPasses; i++ {
		if err := s.revalidateBindings(ctx); err != nil {
			t.Fatalf("revalidateBindings pass %d: %v", i, err)
		}
	}
	// netboxCondition includes resolved rows, so the assertion is on the
	// LIFECYCLE: the row stays for the history, it just stops being a finding.
	after, ok := netboxCondition(t, s, condNetBoxClusterNameMismatch, s.hostName)
	if !ok {
		t.Fatal("the condition row vanished rather than resolving")
	}
	if after.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("a corrected cluster_name left the finding at %q, want %q",
			after.Lifecycle, corrosion.ConditionResolved)
	}
}

// TestAgreeingNodeDoesNotClearAnotherHostsMismatch pins the ownership boundary
// the per-host subject exists for.
//
// Every configured node runs revalidation, and only one of them may be
// misconfigured. The two existing NetBox findings are written by the sweep,
// which runs under the leader lease, so the cluster has one writer at a time and
// a pass may clean-count every subject of its code. This one is not: an agreeing
// node's pass sees no mismatch of its own, and if it treated that as "clean" for
// the whole code it would resolve the disagreeing node's finding on the very
// next pass — the finding would vanish while the misconfiguration stayed.
func TestAgreeingNodeDoesNotClearAnotherHostsMismatch(t *testing.T) {
	s := newTestServerWithNetBox(t, usableNetBox())
	s.SetNetBoxClusterName("site-a")
	bindOne(t, s, "net-a", 7)
	ctx := context.Background()

	// The disagreeing node's finding, as it arrives by replication: a row this
	// node did not write, about a host that is not this one.
	other := "other-host"
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: netboxEvaluator, Code: condNetBoxClusterNameMismatch,
		SubjectKind: "host", SubjectID: other,
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
		ObserveCount: 3, Reporter: other,
		Evidence: encodeEvidence("pinned site-a, resolved site-b", nil),
	}); err != nil {
		t.Fatalf("seed the peer's finding: %v", err)
	}

	// This node AGREES, so its own passes are clean. Enough of them to resolve a
	// finding it owned.
	for i := 0; i < netboxCleanPasses+1; i++ {
		if err := s.revalidateBindings(ctx); err != nil {
			t.Fatalf("revalidateBindings pass %d: %v", i, err)
		}
	}

	// The LIFECYCLE, not mere presence: a resolved row is still a row, so
	// asserting it exists would pass with the ownership scope deleted.
	got, ok := netboxCondition(t, s, condNetBoxClusterNameMismatch, other)
	if !ok {
		t.Fatal("an agreeing node deleted another host's cluster_name mismatch")
	}
	if got.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("an agreeing node resolved another host's cluster_name mismatch " +
			"while that host was still misconfigured")
	}
}

// TestRekeyRefusesAClusterNameMismatch closes the other write path into the
// inventory.
//
// A re-key resolves the SAME cluster object the mirror does and then rewrites
// every identity under it. Run on a node whose configuration disagrees, it would
// re-stamp objects in the wrong cluster — or create that cluster and strand the
// real inventory — which is strictly worse than a sweep, because it is a
// deliberate operator action that reports success. Unlike the mirror it refuses
// LOUDLY: an operator is waiting on the answer.
func TestRekeyRefusesAClusterNameMismatch(t *testing.T) {
	s := newTestServerWithNetBox(t, usableNetBox())
	s.SetNetBoxClusterName("site-a")
	bindOne(t, s, "net-a", 7)
	s.SetNetBoxClusterName("site-b")

	_, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{Network: "net-a"})
	if err == nil {
		t.Fatal("a re-key on a node whose cluster_name disagrees must be refused")
	}
	if !strings.Contains(err.Error(), "site-a") || !strings.Contains(err.Error(), "site-b") {
		t.Fatalf("the refusal must name both values, got: %v", err)
	}
}
