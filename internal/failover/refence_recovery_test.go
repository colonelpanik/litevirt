package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCoordinator_RefenceAfterRecovery reproduces the silent-non-fence bug found
// in live f3 e2e: the in-memory `fenced` set is populated by the terminal-state
// skip (not only by an actual fence), and was never cleared when a host
// recovered. So a host that is offline (e.g. fenced earlier), recovers, then
// fails again was silently skipped forever — the coordinator quietly never
// re-fenced it. The fix clears recovered hosts from the set each cycle.
func TestCoordinator_RefenceAfterRecovery(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Two hosts. "bad" starts OFFLINE (as if fenced in a previous episode);
	// "good" is the healthy reschedule target.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.10", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "offline", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost bad: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "good", Address: "10.0.0.11", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost good: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	failing := func() {
		for _, obs := range []string{"coordinator", "good"} {
			if err := db.Execute(ctx,
				`INSERT OR REPLACE INTO host_health
				 (observer, target, status, consecutive_failures, last_seen, updated_at)
				 VALUES (?, 'bad', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
				obs, offlineThreshold); err != nil {
				t.Fatalf("insert health: %v", err)
			}
		}
	}

	c := newTestCoordinator("coordinator", db)

	// Cycle 1: "bad" is offline + failing → the terminal-state skip marks it in
	// the fenced set (no actual fence). VM is not rescheduled (host still
	// offline state, skipped).
	failing()
	c.run(ctx)

	// "bad" recovers and is healthy again, then fails again.
	if err := corrosion.UpdateHostState(ctx, db, "bad", "active"); err != nil {
		t.Fatalf("recover bad: %v", err)
	}
	failing()

	// Cycle 2: with the fix, "bad" is cleared from the fenced set (it recovered)
	// and is fenced + its VM rescheduled. Without the fix this silently no-ops.
	c.run(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v %v", err, vm)
	}
	if vm.HostName != "good" {
		t.Errorf("recovered-then-refailed host must be re-fenced and its VM rescheduled to 'good'; got host=%q (silent-skip bug)", vm.HostName)
	}
}
