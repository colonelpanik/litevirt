package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCoordinator_QuorumExcludesStaleObservers guards the freshness predicate:
// host_health.updated_at is RFC3339, and comparing it against datetime('now')
// as a string is always true once the date matches ('T' > ' '), which would let
// a DEAD observer's stale "suspect" row still count toward fencing quorum —
// defeating the freshness gate and risking a false-positive fence. With the fix
// (RFC3339 cutoff) stale rows are excluded, so a host backed only by stale
// observations is NOT fenced.
func TestCoordinator_QuorumExcludesStaleObservers(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.10", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost bad: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "good", Address: "10.0.0.11", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost good: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// STALE suspect rows (5 minutes old, RFC3339) from a quorum of observers.
	// Past the 30s freshness window — must NOT count.
	stale := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	for _, obs := range []string{"coordinator", "good"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'bad', 'suspect', ?, NULL, ?)`,
			obs, offlineThreshold, stale); err != nil {
			t.Fatalf("insert stale health: %v", err)
		}
	}

	c := newTestCoordinator("coordinator", db)
	c.run(ctx)

	h, _ := corrosion.GetHost(ctx, db, "bad")
	if h == nil || h.State != "active" {
		t.Errorf("host backed only by STALE observations must not be fenced; state=%v", h)
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.HostName != "bad" {
		t.Errorf("VM must not be rescheduled off a non-fenced host; vm=%+v", vm)
	}
}
