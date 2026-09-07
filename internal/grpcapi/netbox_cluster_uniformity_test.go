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
	_, bad, err := s.declareAndCompareNetBoxCluster(ctx)
	if err == nil {
		t.Fatal("an unreadable host table must be reported as an error, not as an empty live set")
	}
	if bad {
		t.Fatal("a read that failed is not a disagreement — the caller must tell them apart")
	}
	if s.netboxClusterUniformityAgrees(ctx) {
		t.Fatal("the mirror gate must decline a pass whose live set it could not establish")
	}
}
