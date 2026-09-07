package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The per-host half of the `netbox.cluster_name` uniformity enforcement.
//
// The binding pin (netbox_cluster_pin.go) catches a cluster-wide change away
// from what was pinned. It cannot catch live disagreement BETWEEN nodes on a
// cluster that mirrors inventory with no bound network at all: no binding row,
// no pin, no enforcement — and that shape is where the hazard is purest, because
// mirroring is the only thing such a cluster does with NetBox.
//
// So each node publishes the cluster name it resolves and the mirror compares
// across LIVE hosts. Both checks stay: neither subsumes the other.

// uniformityServer wires a node that resolves clusterName. It does NOT bind
// anything — the mirror-only shape is the point.
func uniformityServer(t *testing.T, clusterName string) *Server {
	t.Helper()
	s := newTestServerWithNetBox(t, usableNetBox())
	s.SetNetBoxClusterName(clusterName)
	return s
}

// publishAs writes what a PEER published, the way replication would deliver it,
// and gives that peer a host row in `state`.
//
// The host row is what makes the peer LIVE, and it is separate from the
// publication on purpose: the two interesting cases are a live peer with a
// disagreeing value and a DEAD peer with the same disagreeing value, and they
// differ only in this field.
func publishAs(t *testing.T, s *Server, host, state, clusterName string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: host, Address: "192.0.2.10", State: state, CertSerial: "serial-" + host,
	}); err != nil {
		t.Fatalf("insert host %s: %v", host, err)
	}
	if err := corrosion.PublishNetBoxHostConfig(ctx, s.db, host, clusterName); err != nil {
		t.Fatalf("publish %s=%s: %v", host, clusterName, err)
	}
}

// TestTheNodePublishesTheClusterNameItResolves is the publication half. Without
// it there is nothing to compare, and a node that never published would look to
// every peer like a node with no opinion.
func TestTheNodePublishesTheClusterNameItResolves(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()

	if !s.netboxClusterUniformityAgrees(ctx) {
		t.Fatal("a node with no peers cannot disagree with anybody")
	}
	got, err := corrosion.ListNetBoxHostConfig(ctx, s.db)
	if err != nil {
		t.Fatalf("ListNetBoxHostConfig: %v", err)
	}
	if got[s.hostName] != "site-a" {
		t.Fatalf("this node published %q, want %q", got[s.hostName], "site-a")
	}
}

// TestMirrorDeclinesWhenALiveHostPublishedADifferentName is the whole point of
// section F, in the shape the binding pin cannot reach: no bound network exists.
func TestMirrorDeclinesWhenALiveHostPublishedADifferentName(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()
	publishAs(t, s, "peer-1", "active", "site-b")

	// No binding row at all — the mirror-only cluster.
	bindings, err := corrosion.ListBindings(ctx, s.db)
	if err != nil {
		t.Fatalf("ListBindings: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("this scenario is only meaningful with no binding to pin: %+v", bindings)
	}

	if s.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("the mirror must decline a pass while a live peer resolves a different NetBox cluster")
	}
}

func TestMirrorProceedsWhenEveryLiveHostAgrees(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()
	publishAs(t, s, "peer-1", "active", "site-a")

	if !s.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("agreement must leave the mirror running exactly as before")
	}
}

// TestADownHostsStalePublishedValueDoesNotBlockMirroring is the counterpart the
// brief demands: a host that is down, fenced or decommissioned must not be able
// to stop mirroring forever by holding a stale value. The row is still there —
// nothing deletes a departed node's publication — so "only live hosts count"
// has to be the comparison's rule, not the row's lifecycle.
func TestADownHostsStalePublishedValueDoesNotBlockMirroring(t *testing.T) {
	ctx := context.Background()
	for _, state := range []string{"offline", "maintenance", "fenced"} {
		t.Run(state, func(t *testing.T) {
			s := uniformityServer(t, "site-a")
			publishAs(t, s, "peer-1", state, "site-b")
			if !s.netboxMirrorPassAuthorized(ctx) {
				t.Fatalf("a %s host must not block mirroring with a stale published value", state)
			}
		})
	}
	// A DECOMMISSIONED host is excluded the same way — its row is tombstoned,
	// which ListHosts filters, while its publication survives.
	t.Run("decommissioned", func(t *testing.T) {
		s := uniformityServer(t, "site-a")
		publishAs(t, s, "peer-1", "active", "site-b")
		if s.netboxMirrorPassAuthorized(ctx) {
			t.Fatal("precondition: a live peer holding another value must block mirroring")
		}
		if err := corrosion.DeleteHost(ctx, s.db, "peer-1"); err != nil {
			t.Fatalf("DeleteHost: %v", err)
		}
		if !s.netboxMirrorPassAuthorized(ctx) {
			t.Fatal("a decommissioned host must not block mirroring with a stale published value")
		}
	})
}

// TestClusterNameDisagreementRaisesAHealthCondition — a refusal an operator
// cannot see is a mirror that silently stopped.
func TestClusterNameDisagreementRaisesAHealthCondition(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()
	publishAs(t, s, "peer-1", "active", "site-b")

	if err := s.revalidateBindings(ctx); err != nil {
		t.Fatalf("revalidateBindings: %v", err)
	}
	got, ok := netboxCondition(t, s, condNetBoxClusterNameDisagreement, s.hostName)
	if !ok {
		t.Fatal("a live cluster_name disagreement raised no health condition")
	}
	if got.SubjectKind != "host" {
		t.Errorf("subject_kind = %q, want %q", got.SubjectKind, "host")
	}
	// BOTH values AND the host holding the other one: the fix is to change one
	// node's config, and the operator cannot pick without knowing which node.
	for _, want := range []string{"site-a", "site-b", "peer-1"} {
		if !strings.Contains(got.Evidence, want) {
			t.Errorf("evidence %q does not name %q", got.Evidence, want)
		}
	}

	// It resolves once the disagreement is gone.
	if err := corrosion.PublishNetBoxHostConfig(ctx, s.db, "peer-1", "site-a"); err != nil {
		t.Fatalf("re-publish peer-1: %v", err)
	}
	for i := 0; i < netboxCleanPasses; i++ {
		if err := s.revalidateBindings(ctx); err != nil {
			t.Fatalf("revalidateBindings pass %d: %v", i, err)
		}
	}
	after, ok := netboxCondition(t, s, condNetBoxClusterNameDisagreement, s.hostName)
	if !ok {
		t.Fatal("the condition row vanished rather than resolving")
	}
	if after.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("a corrected disagreement left the finding at %q, want %q",
			after.Lifecycle, corrosion.ConditionResolved)
	}
}

// TestBothUniformityChecksStayIndependent pins that neither check subsumes the
// other, which is why both exist.
//
// The binding pin fires where every live node agrees with each other but not
// with what the binding recorded — a cluster-wide re-home. The live comparison
// fires where two nodes disagree with each other, which is what makes inventory
// flap as leadership moves. A single mechanism catching only one of them was
// section B, and it was a partial fix.
func TestBothUniformityChecksStayIndependent(t *testing.T) {
	ctx := context.Background()

	// Live disagreement, nothing bound: the pin has nothing to say.
	live := uniformityServer(t, "site-a")
	publishAs(t, live, "peer-1", "active", "site-b")
	if _, bad, err := live.netboxClusterPinDisagrees(ctx); bad || err != nil {
		t.Fatalf("the binding pin should find nothing with no binding: bad=%v err=%v", bad, err)
	}
	if live.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("the live comparison must catch what the pin cannot")
	}

	// Cluster-wide re-home: every live node agrees, the binding does not.
	homed := uniformityServer(t, "site-a")
	bindOne(t, homed, "net-a", 7)
	homed.SetNetBoxClusterName("site-b")
	if !homed.netboxClusterUniformityAgrees(ctx) {
		t.Fatal("the live comparison should find nothing when every live host agrees")
	}
	if homed.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("the binding pin must catch what the live comparison cannot")
	}
}

// TestClusterPinCheckFailsClosedOnAnUnreadableBindingList closes the one error
// branch section B left untested: netboxClusterPinDisagrees returns an error
// rather than "agrees" when it cannot read the bindings, and the mirror gate
// collapses that into a declined pass.
func TestClusterPinCheckFailsClosedOnAnUnreadableBindingList(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()

	// Drop the table the check reads. A read that ERRORS is not agreement.
	if err := s.db.Execute(ctx, `DROP TABLE netbox_bindings`); err != nil {
		t.Fatalf("drop netbox_bindings: %v", err)
	}
	_, bad, err := s.netboxClusterPinDisagrees(ctx)
	if err == nil {
		t.Fatal("an unreadable binding list must be reported as an error, not as agreement")
	}
	if bad {
		t.Fatal("a read that failed is not a mismatch — the caller must be able to tell them apart")
	}
	if s.netboxClusterPinAgrees(ctx) {
		t.Fatal("the mirror gate must decline a pass it could not verify")
	}
}

// TestUniformityFailsClosedOnAnUnreadableHostTable pins the difference between
// "no live host disagrees" and "we could not tell who is live".
//
// The live set decides whose published value counts, so a read failure that
// produced an empty set would silently narrow the comparison to this node alone
// and let the mirror run — the fail-OPEN direction, on exactly the evidence that
// went missing.
func TestUniformityFailsClosedOnAnUnreadableHostTable(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()
	publishAs(t, s, "peer-1", "active", "site-b")

	if err := s.db.Execute(ctx, `DROP TABLE hosts`); err != nil {
		t.Fatalf("drop hosts: %v", err)
	}
	d, err := s.compareNetBoxClusterName(ctx)
	if err == nil {
		t.Fatal("an unreadable host table must be reported as an error, not as an empty live set")
	}
	if d.bad() {
		t.Fatal("a read that failed is not a finding — the caller must tell them apart")
	}
	if s.netboxClusterUniformityAgrees(ctx) {
		t.Fatal("the mirror gate must decline a pass whose live set it could not establish")
	}
}

// ── the publish/compare split, and the pass before every peer has spoken ────
//
// The gate used to PUBLISH inside the same function that COMPARED, and read the
// absence of a peer's row as "that node has not run this gate, so it cannot be
// mirroring". That reasoning holds for the peer and not for THIS node: on its
// own first pass a node publishes, compares against a set that does not yet
// include a peer with no pass of its own, and mirrors — one bounded pass under
// a disagreement it could not see. Fail closed for that pass instead.

// TestTheCompareDoesNotPublish is the split itself.
//
// A predicate with a write inside it cannot be reasoned about at its call sites,
// and this one is called from two (the mirror's gate and the health evaluator).
// The publication is now its own step, so the comparison is a pure read.
func TestTheCompareDoesNotPublish(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()

	if _, err := s.compareNetBoxClusterName(ctx); err != nil {
		t.Fatalf("compare: %v", err)
	}
	got, err := corrosion.ListNetBoxHostConfig(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, published := got[s.hostName]; published {
		t.Fatal("the comparison must not write; publication is its own step")
	}
}

// TestALiveHostThatHasNotPublishedBlocksThePass.
//
// The window: a live peer exists, this node has published, that peer has not.
// Mirroring there would be mirroring against an incomplete set while believing
// it was complete — and the value that peer is about to publish may disagree.
// One pass is bounded, but it is one pass in which the inventory can be written
// under the wrong cluster, and the whole enforcement exists to stop exactly
// that.
func TestALiveHostThatHasNotPublishedBlocksThePass(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()

	// A live peer with a host row and NO publication.
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer-1", Address: "192.0.2.10", State: "active", CertSerial: "serial-peer-1",
	}); err != nil {
		t.Fatalf("insert host: %v", err)
	}

	if s.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("the mirror must decline a pass in which a live host has published nothing")
	}
}

// TestTheUnpublishedPeerIsNamedInTheCondition: fail-closed silence is the worst
// of both. A mirror that has stopped and says only "declining" leaves an
// operator with nothing; the row has to name the hosts whose value is missing,
// because the remedy is about them.
func TestTheUnpublishedPeerIsNamedInTheCondition(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer-1", Address: "192.0.2.10", State: "active", CertSerial: "serial-peer-1",
	}); err != nil {
		t.Fatalf("insert host: %v", err)
	}

	s.evaluateNetBoxClusterUniformity(ctx)

	h, ok := netboxCondition(t, s, condNetBoxClusterNameUnpublished, s.hostName)
	if !ok {
		t.Fatal("a pass blocked on an unpublished peer must say so in lv health")
	}
	if !strings.Contains(h.Evidence, "peer-1") {
		t.Fatalf("the evidence must name the host that has published nothing, got %q", h.Evidence)
	}
	if !strings.Contains(h.Evidence, "DECLINES every pass") {
		t.Fatalf("the evidence must state that mirroring is stopped, got %q", h.Evidence)
	}
}

// TestOnceThePeerPublishesThePassProceeds is what keeps the block bounded rather
// than permanent: every configured node publishes on its own first pass, so the
// window closes on its own.
func TestOnceThePeerPublishesThePassProceeds(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()
	publishAs(t, s, "peer-1", "active", "site-a")

	if !s.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("a peer that has published an agreeing value must not block the pass")
	}
	// …and the condition resolves.
	for i := 0; i < netboxCleanPasses; i++ {
		s.evaluateNetBoxClusterUniformity(ctx)
	}
	if h, ok := netboxCondition(t, s, condNetBoxClusterNameUnpublished, s.hostName); ok &&
		h.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("the finding must not stand once every live host has published, got %+v", h)
	}
}

// TestADownHostThatHasNotPublishedDoesNotBlockThePass keeps the same rule the
// disagreement check already follows. A host that is offline, fenced or
// decommissioned will never publish, and a fail-closed gate that waited for it
// would stop mirroring permanently over a node that has left.
func TestADownHostThatHasNotPublishedDoesNotBlockThePass(t *testing.T) {
	ctx := context.Background()
	for _, state := range []string{"offline", "maintenance", "fenced"} {
		t.Run(state, func(t *testing.T) {
			s := uniformityServer(t, "site-a")
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
				Name: "peer-1", Address: "192.0.2.10", State: state, CertSerial: "serial-peer-1",
			}); err != nil {
				t.Fatalf("insert host: %v", err)
			}
			if !s.netboxMirrorPassAuthorized(ctx) {
				t.Fatalf("a %s host that never publishes must not block mirroring forever", state)
			}
		})
	}
}

// TestAWitnessThatHasNotPublishedDoesNotBlockThePass.
//
// A witness votes and never hosts a workload, so it has no reason to be
// configured for NetBox — but `health.VotingEligible` counts witnesses (the
// quorum denominator does, so the live-host predicate must), and the gate blocks
// until every live host has published. A witness therefore blocks mirroring
// FOREVER, on a cluster whose configuration is entirely correct, and the only
// remedies would be to configure NetBox on a node that does not need it or to
// remove the witness.
//
// It is NOT safe because a witness cannot mirror: a NetBox-configured witness
// takes the lease and mirrors like anything else. It is safe because excusing a
// node from THIS node's set does not excuse it from its own — see
// TestTwoWitnessesStillGateEachOther for the one case where that argument runs
// out and the exclusion has to stop.
func TestAWitnessThatHasNotPublishedDoesNotBlockThePass(t *testing.T) {
	ctx := context.Background()
	s := uniformityServer(t, "site-a")
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer-1", Address: "192.0.2.10", State: "active",
		CertSerial: "serial-peer-1", Role: "witness",
	}); err != nil {
		t.Fatalf("insert witness host: %v", err)
	}
	if !s.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("a live witness that never publishes must not block mirroring forever: it hosts " +
			"no workload, so it has nothing to be uniform about — and it still gates itself")
	}
}

// TestAWitnessExclusionDoesNotExcuseAWorker is the control: the exclusion must
// be about the ROLE and nothing else, or it would hand every unpublished host a
// way through.
func TestAWitnessExclusionDoesNotExcuseAWorker(t *testing.T) {
	ctx := context.Background()
	s := uniformityServer(t, "site-a")
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer-1", Address: "192.0.2.10", State: "active",
		CertSerial: "serial-peer-1", Role: "worker",
	}); err != nil {
		t.Fatalf("insert worker host: %v", err)
	}
	if s.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("a live WORKER that has not published must still stop the pass")
	}
}

// TestAPublicationFailureStillStopsTheGate. Publishing is what makes this node's
// opinion visible to its peers, and a node whose opinion nobody can see is
// exactly the node that must not go on to mirror on the strength of a comparison
// that therefore excludes it. Splitting publish from compare must not lose that.
func TestAPublicationFailureStillStopsTheGate(t *testing.T) {
	s := uniformityServer(t, "site-a")
	ctx := context.Background()
	if err := s.db.Execute(ctx,
		`CREATE TRIGGER test_fail_nb_host_config BEFORE INSERT ON netbox_host_config
		 BEGIN SELECT RAISE(ABORT, 'induced publish failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}

	if s.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("a node that could not publish its own value must not mirror")
	}
}

// asWitness gives host a live `hosts` row with role=witness, so the exclusion
// below has something to act on. Separate from publishAs because the witnesses
// these cases need differ in whether they published at all.
func asWitness(t *testing.T, s *Server, host string) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: host, Address: "192.0.2.11", State: "active",
		CertSerial: "serial-" + host, Role: "witness",
	}); err != nil {
		t.Fatalf("insert witness host %s: %v", host, err)
	}
}

// TestTwoWitnessesStillGateEachOther is the hole the exclusion would otherwise
// open, and the reason it is ONE-WAY.
//
// Excluding a witness is safe because the excluded node still runs this
// comparison itself and declines the moment it disagrees with a live host it did
// not exclude. That argument needs the excluded node to have somebody left to be
// gated by. Two witnesses resolving different names, with no live non-witness
// host, would each compute a live set of {self}, agree with themselves, and both
// mirror — the inventory flap the whole gate exists to prevent, arriving through
// the exemption meant to keep a witness from wedging it.
func TestTwoWitnessesStillGateEachOther(t *testing.T) {
	ctx := context.Background()
	s := uniformityServer(t, "site-a")
	asWitness(t, s, s.hostName)
	asWitness(t, s, "peer-1")
	if err := corrosion.PublishNetBoxHostConfig(ctx, s.db, "peer-1", "site-b"); err != nil {
		t.Fatalf("publish peer-1: %v", err)
	}

	if s.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("two witnesses resolving different names, with no live worker between them: each " +
			"would mirror under its own name and delete the other's objects, which is exactly " +
			"the flap this comparison exists to stop. A witness must not excuse another witness")
	}
}

// TestAWitnessDoesNotExcuseAPeerWitnessSilence is the same rule for the other
// finding: a peer witness that has published NOTHING must still stop a witness
// that is about to mirror, because that witness is the one node its peers have
// stopped watching.
func TestAWitnessDoesNotExcuseAPeerWitnessSilence(t *testing.T) {
	ctx := context.Background()
	s := uniformityServer(t, "site-a")
	asWitness(t, s, s.hostName)
	asWitness(t, s, "peer-1")

	if s.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("a witness with an unpublished witness peer and no live worker must decline: " +
			"nothing else is comparing the two")
	}
}

// TestAWorkerStillExcusesAWitness is the control that keeps the fix scoped. The
// wedge the exclusion removes — one witness blocking an otherwise correct
// cluster forever — is the ordinary topology, and it must stay removed.
func TestAWorkerStillExcusesAWitness(t *testing.T) {
	ctx := context.Background()
	s := uniformityServer(t, "site-a")
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: s.hostName, Address: "192.0.2.9", State: "active",
		CertSerial: "serial-self", Role: "worker",
	}); err != nil {
		t.Fatalf("insert self as worker: %v", err)
	}
	asWitness(t, s, "peer-1")

	if !s.netboxMirrorPassAuthorized(ctx) {
		t.Fatal("a MIRRORING node must still excuse a witness that has published nothing: it is " +
			"the only node comparing, and a witness has nothing to be uniform about")
	}
}
