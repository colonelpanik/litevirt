package corrosion

import (
	"context"
	"testing"
	"time"
)

func seedCondition(name string) HealthCondition {
	return HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: name,
		Lifecycle: ConditionObserved, Severity: SeverityWarning,
		Hosts: []string{"h1", "h2"}, Evidence: `{"holders":["h1","h2"]}`,
		ObserveCount: 1, FirstSeen: "2026-08-04T10:00:00Z", LastSeen: "2026-08-04T10:00:00Z",
		Reporter: "h1",
	}
}

func TestHealthCondition_UpsertRoundTrips(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	want := seedCondition("web-1")
	if err := UpsertHealthCondition(ctx, db, want); err != nil {
		t.Fatalf("UpsertHealthCondition: %v", err)
	}
	got, ok, err := GetHealthCondition(ctx, db, "dual_run", "vm_dual_run", "vm", "web-1")
	if err != nil || !ok {
		t.Fatalf("GetHealthCondition: ok=%v err=%v", ok, err)
	}
	if got.Lifecycle != ConditionObserved || got.Severity != SeverityWarning ||
		got.ObserveCount != 1 || got.Evidence != want.Evidence || got.Reporter != "h1" {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if len(got.Hosts) != 2 || got.Hosts[0] != "h1" || got.Hosts[1] != "h2" {
		t.Errorf("hosts = %v, want [h1 h2]", got.Hosts)
	}

	// A later scan's transition replaces the row's state wholesale.
	want.Lifecycle = ConditionConfirmed
	want.Severity = SeverityCritical
	want.ObserveCount = 2
	want.ConfirmedAt = "2026-08-04T10:01:00Z"
	if err := UpsertHealthCondition(ctx, db, want); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	got, _, err = GetHealthCondition(ctx, db, "dual_run", "vm_dual_run", "vm", "web-1")
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if got.Lifecycle != ConditionConfirmed || got.Severity != SeverityCritical ||
		got.ObserveCount != 2 || got.ConfirmedAt != "2026-08-04T10:01:00Z" {
		t.Errorf("after confirm: %+v", got)
	}
}

func TestHealthCondition_ListFiltersResolved(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	active := seedCondition("active-vm")
	if err := UpsertHealthCondition(ctx, db, active); err != nil {
		t.Fatalf("upsert active: %v", err)
	}
	resolved := seedCondition("fixed-vm")
	resolved.Lifecycle = ConditionResolved
	resolved.ResolvedAt = "2026-08-01T00:00:00Z"
	if err := UpsertHealthCondition(ctx, db, resolved); err != nil {
		t.Fatalf("upsert resolved: %v", err)
	}

	activeOnly, err := ListHealthConditions(ctx, db, false)
	if err != nil {
		t.Fatalf("ListHealthConditions(active): %v", err)
	}
	if len(activeOnly) != 1 || activeOnly[0].SubjectID != "active-vm" {
		t.Errorf("active list = %+v, want the one unresolved condition", activeOnly)
	}
	all, err := ListHealthConditions(ctx, db, true)
	if err != nil {
		t.Fatalf("ListHealthConditions(all): %v", err)
	}
	if len(all) != 2 {
		t.Errorf("full list has %d rows, want 2 (resolved history is readable)", len(all))
	}
}

// TestHealthCondition_GCKeepsRecentResolved: the 30-day retention is an operator
// affordance — "what happened last week" must still be answerable — and the GC
// must never touch an ACTIVE condition regardless of age.
func TestHealthCondition_GCKeepsRecentResolved(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

	old := seedCondition("ancient")
	old.Lifecycle = ConditionResolved
	old.ResolvedAt = now.Add(-31 * 24 * time.Hour).Format(time.RFC3339)
	recent := seedCondition("last-week")
	recent.Lifecycle = ConditionResolved
	recent.ResolvedAt = now.Add(-7 * 24 * time.Hour).Format(time.RFC3339)
	stillActive := seedCondition("ongoing")
	stillActive.FirstSeen = now.Add(-90 * 24 * time.Hour).Format(time.RFC3339)
	for _, h := range []HealthCondition{old, recent, stillActive} {
		if err := UpsertHealthCondition(ctx, db, h); err != nil {
			t.Fatalf("upsert %s: %v", h.SubjectID, err)
		}
	}

	n, err := TombstoneResolvedHealthConditions(ctx, db, now)
	if err != nil {
		t.Fatalf("TombstoneResolvedHealthConditions: %v", err)
	}
	if n != 1 {
		t.Errorf("GC removed %d rows, want exactly 1 (the 31-day-old resolved one)", n)
	}
	all, err := ListHealthConditions(ctx, db, true)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	names := map[string]bool{}
	for _, h := range all {
		names[h.SubjectID] = true
	}
	if names["ancient"] || !names["last-week"] || !names["ongoing"] {
		t.Errorf("post-GC rows = %v, want last-week + ongoing only", names)
	}
}

func TestHealthEvaluatorStatus_RoundTrips(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := UpsertHealthEvaluatorStatus(ctx, db, HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: "2026-08-04T10:00:00Z",
		Coverage: CoveragePartial, Reporter: "h1", Detail: "h3 unreachable",
	}); err != nil {
		t.Fatalf("UpsertHealthEvaluatorStatus: %v", err)
	}
	// The next scan overwrites — status is "latest scan", not history.
	if err := UpsertHealthEvaluatorStatus(ctx, db, HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: "2026-08-04T10:05:00Z",
		Coverage: CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	sts, err := ListHealthEvaluatorStatus(ctx, db)
	if err != nil {
		t.Fatalf("ListHealthEvaluatorStatus: %v", err)
	}
	if len(sts) != 1 || sts[0].Coverage != CoverageComplete || sts[0].LastScan != "2026-08-04T10:05:00Z" {
		t.Errorf("status = %+v, want the newest complete scan", sts)
	}
}

func TestHostCapacityObservation_RoundTrips(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := UpsertHostCapacityObservation(ctx, db, HostCapacityObservation{
		HostName: "h1", DBCPU: 8, DBMemMiB: 8192,
		ExtraCPU: 2, ExtraMemMiB: 2048,
		EffectiveCPU: 10, EffectiveMemMiB: 10240,
		Complete: false, Detail: "uncapped container rogue-ct",
		SampledAt: "2026-08-04T10:00:00Z",
	}); err != nil {
		t.Fatalf("UpsertHostCapacityObservation: %v", err)
	}
	got, ok, err := GetHostCapacityObservation(ctx, db, "h1")
	if err != nil || !ok {
		t.Fatalf("GetHostCapacityObservation: ok=%v err=%v", ok, err)
	}
	if got.EffectiveCPU != 10 || got.EffectiveMemMiB != 10240 || got.Complete ||
		got.ExtraCPU != 2 || got.Detail == "" {
		t.Errorf("observation = %+v", got)
	}

	// The next sample replaces the row; completeness can recover.
	if err := UpsertHostCapacityObservation(ctx, db, HostCapacityObservation{
		HostName: "h1", DBCPU: 8, DBMemMiB: 8192,
		EffectiveCPU: 8, EffectiveMemMiB: 8192, Complete: true,
		SampledAt: "2026-08-04T10:01:00Z",
	}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	got, _, _ = GetHostCapacityObservation(ctx, db, "h1")
	if !got.Complete || got.ExtraCPU != 0 || got.SampledAt != "2026-08-04T10:01:00Z" {
		t.Errorf("after recovery sample: %+v", got)
	}
}
