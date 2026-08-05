package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// freshScan is a LastScan inside evaluatorScanTTL — the staleness bound means
// a fixed literal date would read as a stopped detector.
func freshScan() string { return time.Now().UTC().Format(time.RFC3339) }

// TestGetClusterHealth_OverallStates pins the roll-up contract the CLI exit
// codes (0/1/2) and admission policy hang off:
//
//	UNKNOWN  — nothing has ever scanned (not the same as nothing wrong);
//	HEALTHY  — complete coverage, no active conditions;
//	DEGRADED — warnings, incomplete coverage, or incomplete capacity;
//	CRITICAL — any ACTIVE critical condition, resolved ones excluded.
func TestGetClusterHealth_OverallStates(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	get := func() *pb.ClusterHealth {
		t.Helper()
		h, err := s.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
		if err != nil {
			t.Fatalf("GetClusterHealth: %v", err)
		}
		return h
	}

	// No evaluator has ever run.
	if got := get().GetOverall(); got != HealthUnknown {
		t.Fatalf("virgin cluster overall = %q, want UNKNOWN — nothing watching is not nothing wrong", got)
	}

	// A completed clean scan.
	if err := corrosion.UpsertHealthEvaluatorStatus(context.Background(), s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if got := get().GetOverall(); got != HealthHealthy {
		t.Fatalf("clean cluster overall = %q, want HEALTHY", got)
	}

	// Partial coverage degrades.
	if err := corrosion.UpsertHealthEvaluatorStatus(context.Background(), s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoveragePartial, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if got := get().GetOverall(); got != HealthDegraded {
		t.Fatalf("partial-coverage overall = %q, want DEGRADED — blind is not clean", got)
	}
	if err := corrosion.UpsertHealthEvaluatorStatus(context.Background(), s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}

	// A warning condition degrades; a critical one dominates.
	warn := corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "coverage_gap", SubjectKind: "host", SubjectID: "h3",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
		FirstSeen: "2026-08-04T10:00:00Z", LastSeen: "2026-08-04T10:00:00Z",
	}
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, warn); err != nil {
		t.Fatalf("warn condition: %v", err)
	}
	if got := get().GetOverall(); got != HealthDegraded {
		t.Fatalf("warning-condition overall = %q, want DEGRADED", got)
	}
	crit := corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "web-1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
		Hosts:     []string{"h1", "h2"},
		FirstSeen: "2026-08-04T10:00:00Z", LastSeen: "2026-08-04T10:00:00Z",
	}
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, crit); err != nil {
		t.Fatalf("crit condition: %v", err)
	}
	if got := get().GetOverall(); got != HealthCritical {
		t.Fatalf("critical-condition overall = %q, want CRITICAL", got)
	}

	// The response names both holders — the operator's first question.
	var found bool
	for _, c := range get().GetConditions() {
		if c.GetCode() == "vm_dual_run" && len(c.GetHosts()) == 2 {
			found = true
		}
	}
	if !found {
		t.Fatal("the critical condition must carry its involved hosts")
	}

	// RESOLVED critical must not dominate; excluded by default, present with
	// include_resolved.
	crit.Lifecycle = corrosion.ConditionResolved
	crit.ResolvedAt = "2026-08-04T11:00:00Z"
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, crit); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	warn.Lifecycle = corrosion.ConditionResolved
	warn.ResolvedAt = "2026-08-04T11:00:00Z"
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, warn); err != nil {
		t.Fatalf("resolve warn: %v", err)
	}
	h := get()
	if h.GetOverall() != HealthHealthy {
		t.Fatalf("after resolution overall = %q, want HEALTHY", h.GetOverall())
	}
	if len(h.GetConditions()) != 0 {
		t.Fatalf("default response contains %d resolved conditions, want 0", len(h.GetConditions()))
	}
	hr, err := s.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{IncludeResolved: true})
	if err != nil {
		t.Fatalf("include_resolved: %v", err)
	}
	if len(hr.GetConditions()) != 2 {
		t.Fatalf("resolved history has %d conditions, want 2", len(hr.GetConditions()))
	}
}

// TestGetClusterHealth_IncompleteCapacityDegrades: a host whose runtime
// inventory could not account for everything is a DEGRADED signal — placement
// treats it as unknown, and health must say so.
func TestGetClusterHealth_IncompleteCapacityDegrades(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.UpsertHealthEvaluatorStatus(ctx, s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := corrosion.UpsertHostCapacityObservation(ctx, s.db, corrosion.HostCapacityObservation{
		HostName: "h1", Complete: false, Detail: "uncapped container rogue-ct",
		SampledAt: "2026-08-04T10:00:00Z",
	}); err != nil {
		t.Fatalf("capacity: %v", err)
	}
	h, err := s.GetClusterHealth(adminCtx(), &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatalf("GetClusterHealth: %v", err)
	}
	if h.GetOverall() != HealthDegraded {
		t.Fatalf("incomplete capacity overall = %q, want DEGRADED", h.GetOverall())
	}
	if len(h.GetCapacity()) != 1 || h.GetCapacity()[0].GetComplete() {
		t.Fatalf("capacity assessment = %+v, want the incomplete sample surfaced", h.GetCapacity())
	}
}

// TestGetClusterHealth_StaleEvaluatorIsNotGreen: the evaluator status row is
// LWW state with no expiry, so a stopped or wedged detector leaves its last
// "coverage=complete" row standing forever. Health must bound the age of the
// evidence: a scan past evaluatorScanTTL means nothing is watching NOW, which
// is UNKNOWN when it is the only evaluator — never HEALTHY. A critical
// condition still dominates: stale watching does not un-know known facts.
func TestGetClusterHealth_StaleEvaluatorIsNotGreen(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	stale := time.Now().UTC().Add(-2 * evaluatorScanTTL).Format(time.RFC3339)
	if err := corrosion.UpsertHealthEvaluatorStatus(ctx, s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: stale, Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}
	h, err := s.GetClusterHealth(adminCtx(), &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatalf("GetClusterHealth: %v", err)
	}
	if h.GetOverall() != HealthUnknown {
		t.Fatalf("sole evaluator %s stale, overall = %q, want UNKNOWN — a green light older than the TTL is no light at all",
			evaluatorScanTTL, h.GetOverall())
	}

	// A known critical condition dominates staleness.
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "web-1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
		Hosts: []string{"h1", "h2"}, FirstSeen: stale, LastSeen: stale,
	}); err != nil {
		t.Fatalf("condition: %v", err)
	}
	if h, _ = s.GetClusterHealth(adminCtx(), &pb.GetClusterHealthRequest{}); h.GetOverall() != HealthCritical {
		t.Fatalf("stale evaluator + critical condition = %q, want CRITICAL", h.GetOverall())
	}

	// A fresh scan beside the stale one: watching again, but degraded — one
	// evaluator's evidence is out of date.
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "web-1",
		Lifecycle: corrosion.ConditionResolved, Severity: corrosion.SeverityCritical,
		Hosts: []string{"h1", "h2"}, FirstSeen: stale, LastSeen: stale, ResolvedAt: freshScan(),
	}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := corrosion.UpsertHealthEvaluatorStatus(ctx, s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "other_eval", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("second evaluator: %v", err)
	}
	if h, _ = s.GetClusterHealth(adminCtx(), &pb.GetClusterHealthRequest{}); h.GetOverall() != HealthDegraded {
		t.Fatalf("one stale + one fresh evaluator = %q, want DEGRADED", h.GetOverall())
	}
}
