package corrosion

import (
	"context"
	"testing"
	"time"
)

func TestMembershipChanged_Coalesces(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer c.Close()

	ch := c.MembershipChanged()
	// No kick yet → nothing buffered.
	select {
	case <-ch:
		t.Fatal("unexpected signal before any kick")
	default:
	}

	// Multiple kicks coalesce into a single pending signal (cap-1 channel) and
	// never block the caller (these run on memberlist's event goroutines).
	for i := 0; i < 5; i++ {
		c.kickMembership()
	}
	select {
	case <-ch:
	default:
		t.Fatal("expected a pending membership signal after kicks")
	}
	select {
	case <-ch:
		t.Fatal("expected kicks to coalesce into exactly one signal")
	default:
	}
}

func TestScheduleWatermarkCleanup_DedupAndDeletes(t *testing.T) {
	old := watermarkCleanupGrace
	watermarkCleanupGrace = 10 * time.Millisecond
	defer func() { watermarkCleanupGrace = old }()

	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	seedWatermark(t, c, "gone")

	// Two schedules for the same peer → only one timer in flight.
	r.scheduleWatermarkCleanup("gone")
	r.scheduleWatermarkCleanup("gone")

	deadline := time.After(2 * time.Second)
	for watermarkExists(t, c, "gone") {
		select {
		case <-deadline:
			t.Fatal("watermark was not reclaimed within deadline")
		case <-time.After(5 * time.Millisecond):
		}
	}
	// The in-flight tracker is cleared once the cleanup goroutine completes.
	r.wg.Wait()
	r.mu.Lock()
	pending := r.cleanupPending["gone"]
	r.mu.Unlock()
	if pending {
		t.Error("cleanupPending should be cleared after the cleanup runs")
	}
}

// With no visible members (e.g. a local gossip outage), reconcile must NOT reap
// watermarks — reaping would force needless re-syncs when peers reappear.
func TestReconcileDepartedWatermarks_NoMembersNoReap(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	seedWatermark(t, c, "someone")

	r.reconcileDepartedWatermarks(context.Background())
	r.wg.Wait()

	if !watermarkExists(t, c, "someone") {
		t.Error("reconcile must not reap watermarks when no members are visible")
	}
}
