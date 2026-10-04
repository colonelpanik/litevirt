package scheduler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hlc"
)

// A rebalance_proposals updated_at must stay an RFC3339 instant even once the
// cluster has latched hlc_lww. During a rolling upgrade an older release's
// reaper, retention prune and receiver-side bulk reap compare updated_at
// LEXICALLY against an RFC3339 cutoff, and an HLC "17…" stamp sorts below every
// one of them: in-flight rows reaped early, fresh terminal rows pruned. The
// same-second ordering the stamp exists for needs sub-second resolution, not
// HLC, so these writers use NowWallTS.

func latchHLCEmission(t *testing.T, db *corrosion.Client) {
	t.Helper()
	db.SetHLCEmit(func() bool { return true })
	if ts := db.NowTS(); !hlc.IsHLC(ts) {
		t.Fatalf("precondition: NowTS = %q with HLC emission on, want an HLC string", ts)
	}
}

func requireProposalWallStamps(t *testing.T, db *corrosion.Client, wantStatus string) {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id, status, updated_at FROM rebalance_proposals`)
	if err != nil {
		t.Fatalf("list proposals: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no proposals; the assertion would be vacuous")
	}
	for _, r := range rows {
		if r.String("status") != wantStatus {
			t.Errorf("proposal %s is %q, want %q", r.String("id"), r.String("status"), wantStatus)
		}
		ts := r.String("updated_at")
		if hlc.IsHLC(ts) {
			t.Errorf("proposal %s (%s): updated_at = %q is an HLC string", r.String("id"), r.String("status"), ts)
		} else if _, err := time.Parse(time.RFC3339, ts); err != nil {
			t.Errorf("proposal %s: updated_at = %q is not RFC3339: %v", r.String("id"), ts, err)
		}
	}
}

func imbalancedCluster(t *testing.T, spec string) *corrosion.Client {
	t.Helper()
	db := newRebalancerTestDB(t)
	insertHost(t, db, "loaded", 16, 65536)
	insertHost(t, db, "empty", 16, 65536)
	for i := 0; i < 4; i++ {
		insertVM(t, db, fmt.Sprintf("vm-%d", i), "loaded", 4, 8192, spec)
	}
	latchHLCEmission(t, db)
	return db
}

func TestRebalancer_RecordProposalStampsWallTimeUnderHLC(t *testing.T) {
	db := imbalancedCluster(t, balanceDryRunSpec)
	if err := NewRebalancer("loaded", db).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	requireProposalWallStamps(t, db, "pending")
}

func TestRebalancer_MarkApprovedStampsWallTimeUnderHLC(t *testing.T) {
	db := imbalancedCluster(t, balanceAutoSpec)
	if err := NewRebalancer("loaded", db).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	requireProposalWallStamps(t, db, "approved")
}

func TestRebalancer_ExpireStampsWallTimeUnderHLC(t *testing.T) {
	db := imbalancedCluster(t, balanceDryRunSpec)
	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// Past every proposal's TTL.
	r.Now = func() time.Time { return time.Now().Add(r.ProposalTTL + time.Hour) }
	if err := r.expireOldProposals(context.Background()); err != nil {
		t.Fatalf("expireOldProposals: %v", err)
	}
	requireProposalWallStamps(t, db, "expired")
}
