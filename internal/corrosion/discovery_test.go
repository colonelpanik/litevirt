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

// Reconcile reclaims a watermark for a peer that is gone from membership even
// when it was never in r.peers (the relay-reshuffle-then-leave case), while a
// peer still in membership keeps its watermark.
func TestReconcileDepartedWatermarks_SchedulesNonMembers(t *testing.T) {
	old := watermarkCleanupGrace
	watermarkCleanupGrace = 10 * time.Millisecond
	defer func() { watermarkCleanupGrace = old }()

	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	seedWatermark(t, c, "departed") // absent from membership, never in r.peers
	seedWatermark(t, c, "alive")    // still a member

	r.reconcileDepartedWatermarksAgainst(context.Background(), map[string]bool{"alive": true})

	deadline := time.After(2 * time.Second)
	for watermarkExists(t, c, "departed") {
		select {
		case <-deadline:
			t.Fatal("departed peer's watermark was not reclaimed")
		case <-time.After(5 * time.Millisecond):
		}
	}
	r.wg.Wait()
	if !watermarkExists(t, c, "alive") {
		t.Error("a still-live member's watermark must be kept")
	}
}
