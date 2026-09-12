package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
)

func TestRunSupersededGC_TombstonesOldResolvedHealthConditions(t *testing.T) {
	c := newHostTestClient(t) // defined in host_address_test.go, same package
	d := &Daemon{db: c, cfg: &Config{}}
	gcCtx, gcCancel := context.WithTimeout(context.Background(), 3*time.Minute)

	// runSupersededGC is an infinite ticker loop: it keeps querying d.db after
	// the assertion below until its context is cancelled. newHostTestClient
	// registered a t.Cleanup that closes that db, and cleanups run as soon as
	// this function returns — so the goroutine must be JOINED here, not left to
	// race the close. gcDone is closed by the goroutine on exit and waited on at
	// the end of the test, after gcCancel has told the loop to stop.
	gcDone := make(chan struct{})
	defer func() {
		gcCancel()
		select {
		case <-gcDone:
		case <-time.After(30 * time.Second):
			t.Error("runSupersededGC did not exit within 30s of context cancellation; " +
				"the test db may be closed underneath it")
		}
	}()

	old := corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "old-vm",
		Lifecycle: corrosion.ConditionResolved, Severity: corrosion.SeverityWarning,
		FirstSeen: "2026-08-01T00:00:00Z", LastSeen: "2026-08-01T00:00:00Z",
		ResolvedAt: time.Now().Add(-40 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Reporter:   "host-a",
	}
	if err := corrosion.UpsertHealthCondition(context.Background(), c, old); err != nil {
		t.Fatalf("seed condition: %v", err)
	}

	recent := corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "recent-vm",
		Lifecycle: corrosion.ConditionResolved, Severity: corrosion.SeverityWarning,
		FirstSeen: "2026-08-01T00:00:00Z", LastSeen: "2026-08-01T00:00:00Z",
		ResolvedAt: time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339),
		Reporter:   "host-a",
	}
	if err := corrosion.UpsertHealthCondition(context.Background(), c, recent); err != nil {
		t.Fatalf("seed condition: %v", err)
	}

	go func() {
		defer close(gcDone)
		d.runSupersededGC(gcCtx, metrics.NewGCMetrics())
	}()
	time.Sleep(121 * time.Second) // Wait for initial 2-minute sleep to complete, then GC to run

	all, err := corrosion.ListHealthConditions(context.Background(), c, true)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var sawRecent bool
	for _, cond := range all {
		if cond.SubjectID == "old-vm" {
			t.Fatal("40-day-old resolved condition survived runSupersededGC")
		}
		if cond.SubjectID == "recent-vm" {
			sawRecent = true
		}
	}
	if !sawRecent {
		t.Fatal("recently-resolved condition was tombstoned by runSupersededGC; retention should only remove conditions past ResolvedConditionRetention")
	}
}
