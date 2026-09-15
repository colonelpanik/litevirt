package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// completeEvaluator is a single evaluator with fresh, complete coverage — the
// baseline against which the legs added below are the only variable.
func completeEvaluator(now time.Time) []corrosion.HealthEvaluatorStatus {
	return []corrosion.HealthEvaluatorStatus{{
		Evaluator: "dual_run", LastScan: now.Format(time.RFC3339),
		Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}}
}

// TestOverallHealth_FutureLastScanIsNotFresh pins the clock-skew lower bound.
//
// The freshness check was `now.Sub(at) <= evaluatorScanTTL`, which is trivially
// true for any NEGATIVE age — so a row dated in the future read as the most
// current scan in the table. A skewed or forged timestamp could therefore hold
// the cluster green while nothing was actually scanning.
func TestOverallHealth_FutureLastScanIsNotFresh(t *testing.T) {
	now := time.Now().UTC()
	evaluators := []corrosion.HealthEvaluatorStatus{{
		Evaluator: "dual_run", LastScan: now.Add(time.Hour).Format(time.RFC3339),
		Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}}
	if got := overallHealth(nil, evaluators, nil, nil, now); got != HealthUnknown {
		t.Fatalf("future-dated LastScan overall = %q, want UNKNOWN — clock skew must not read as fresh", got)
	}
}

// TestOverallHealth_InfoSeverityDoesNotDegrade pins that an info condition is a
// note, not a fault. Every non-resolved condition used to degrade regardless of
// severity, which makes the roll-up permanently yellow for evaluators that
// record observations nobody is expected to act on — and a light that is always
// on tells an operator nothing.
func TestOverallHealth_InfoSeverityDoesNotDegrade(t *testing.T) {
	now := time.Now().UTC()
	info := []corrosion.HealthCondition{{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityInfo,
	}}
	if got := overallHealth(info, completeEvaluator(now), nil, nil, now); got != HealthHealthy {
		t.Errorf("active info condition overall = %q, want HEALTHY", got)
	}

	// The tier above it must still register, or this would be a hole rather
	// than a distinction.
	warn := []corrosion.HealthCondition{{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
	}}
	if got := overallHealth(warn, completeEvaluator(now), nil, nil, now); got != HealthDegraded {
		t.Errorf("active warning condition overall = %q, want DEGRADED", got)
	}
}

// TestOverallHealth_ConnectivityTiers pins that a bad edge lands in the
// DEGRADED bucket and no higher: a broken probe is an observability gap, not
// evidence of corruption, so it must not escalate to CRITICAL. An unrecognised
// status stays silent rather than degrading — a future value the checker starts
// writing must not blanket-degrade every node that has not upgraded yet.
func TestOverallHealth_ConnectivityTiers(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		status string
		want   string
	}{
		{"healthy", HealthHealthy},
		{"suspect", HealthDegraded},
		{"failing", HealthDegraded},
		{"some-future-state", HealthHealthy},
	} {
		mesh := []connectivityEdge{{Observer: "a", Target: "b", Status: tc.status}}
		if got := overallHealth(nil, completeEvaluator(now), nil, mesh, now); got != tc.want {
			t.Errorf("edge status %q overall = %q, want %q", tc.status, got, tc.want)
		}
	}

	// A critical condition still wins over a merely-degrading mesh.
	conditions := []corrosion.HealthCondition{{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
	}}
	mesh := []connectivityEdge{{Observer: "a", Target: "b", Status: "failing"}}
	if got := overallHealth(conditions, completeEvaluator(now), nil, mesh, now); got != HealthCritical {
		t.Fatalf("critical condition + failing edge overall = %q, want CRITICAL", got)
	}
}

// TestGetClusterHealth_ConnectivityAffectsOverall pins the connectivity leg
// end-to-end. The handler already RETURNED the mesh while the overall state
// ignored it entirely, so a fully partitioned cluster read HEALTHY. This goes
// through GetClusterHealth rather than overallHealth precisely because the
// defect was the wiring, not the rule.
func TestGetClusterHealth_ConnectivityAffectsOverall(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertHealthEvaluatorStatus(context.Background(), s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}

	get := func() *pb.ClusterHealth {
		t.Helper()
		h, err := s.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
		if err != nil {
			t.Fatalf("GetClusterHealth: %v", err)
		}
		return h
	}

	// A healthy edge is returned and does not degrade.
	if err := s.db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('host-a', 'host-b', 'healthy', 0, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert healthy edge: %v", err)
	}
	resp := get()
	if len(resp.GetConnectivity()) != 1 {
		t.Fatalf("connectivity edges = %d, want 1", len(resp.GetConnectivity()))
	}
	if got := resp.GetOverall(); got != HealthHealthy {
		t.Fatalf("healthy mesh overall = %q, want HEALTHY — a good edge must not degrade", got)
	}

	// One failing edge, conditions and evaluator coverage otherwise clean.
	if err := s.db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('host-b', 'host-c', 'failing', 5, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert failing edge: %v", err)
	}
	if got := get().GetOverall(); got != HealthDegraded {
		t.Fatalf("failing-edge overall = %q, want DEGRADED — a dead peer link is a coverage gap, "+
			"and a partitioned mesh must not read HEALTHY", got)
	}
}

// TestGetClusterHealth_TombstonedEdgeIsNotReported guards the mesh query's
// tombstone filter now that the same rows feed the overall state: a resurrected
// edge would not merely appear in the body, it would degrade the cluster.
func TestGetClusterHealth_TombstonedEdgeIsNotReported(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertHealthEvaluatorStatus(context.Background(), s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := s.db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at, deleted_at)
		 VALUES ('host-a', 'gone', 'failing', 9, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', '2026-09-02T00:00:00Z')`); err != nil {
		t.Fatalf("insert tombstoned edge: %v", err)
	}

	h, err := s.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatalf("GetClusterHealth: %v", err)
	}
	if n := len(h.GetConnectivity()); n != 0 {
		t.Errorf("connectivity edges = %d, want 0 — a removed host's edge is not a live link", n)
	}
	if got := h.GetOverall(); got != HealthHealthy {
		t.Errorf("overall = %q, want HEALTHY — a tombstoned edge must not degrade the cluster", got)
	}
}
