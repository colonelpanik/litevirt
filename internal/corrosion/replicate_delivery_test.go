package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// deliverySeam drives ReplicateNowTo's loop deterministically. The real path cannot: it
// does gRPC, so a peer's watermark cannot be stalled on purpose.
type deliverySeam struct {
	wm       int64   // current watermark
	advance  []int64 // watermark after each successful push, consumed in order
	sent     []int   // entries reported per push, consumed in order
	pushErr  error
	pushes   int
	pushedTo []string
}

func (d *deliverySeam) push(_ context.Context, peer string) (int, error) {
	d.pushes++
	d.pushedTo = append(d.pushedTo, peer)
	if d.pushErr != nil {
		return 0, d.pushErr
	}
	sent := 1
	if len(d.sent) > 0 {
		sent = d.sent[0]
		d.sent = d.sent[1:]
	}
	if len(d.advance) > 0 {
		d.wm = d.advance[0]
		d.advance = d.advance[1:]
	}
	return sent, nil
}

func (d *deliverySeam) watermark(context.Context, string) (int64, error) { return d.wm, nil }

func seamedReplicator(t *testing.T, d *deliverySeam) *Replicator {
	t.Helper()
	r := &Replicator{}
	r.SetDeliverySeamsForTests(d.push, d.watermark)
	return r
}

// TestReplicateNowTo_LoopsUntilTheWatermarkCoversTheEntry is the regression test for
// confirming delivery.
//
// replicateOnce ships at most replicateBatchSize entries, so a single push against a
// backlogged peer returns cleanly while the entry we care about sits in a LATER batch.
// Only the watermark answers the real question, so the call must keep pushing until it
// passes throughSeq. Here the entry is at seq 30 and the watermark advances 10 → 20 → 30,
// i.e. it takes three pushes.
func TestReplicateNowTo_LoopsUntilTheWatermarkCoversTheEntry(t *testing.T) {
	d := &deliverySeam{wm: 0, advance: []int64{10, 20, 30}}
	r := seamedReplicator(t, d)

	if err := r.ReplicateNowTo(context.Background(), "node-b", 30); err != nil {
		t.Fatalf("ReplicateNowTo: %v", err)
	}
	if d.pushes != 3 {
		t.Errorf("pushed %d time(s), want 3 — a single bounded batch is not proof the entry "+
			"arrived on a peer with a backlog", d.pushes)
	}
}

// TestReplicateNowTo_ReturnsImmediatelyWhenAlreadyCovered: no push when the peer is
// already ahead of the entry, so the barrier costs nothing on a caught-up cluster.
func TestReplicateNowTo_ReturnsImmediatelyWhenAlreadyCovered(t *testing.T) {
	d := &deliverySeam{wm: 99}
	if err := seamedReplicator(t, d).ReplicateNowTo(context.Background(), "node-b", 30); err != nil {
		t.Fatalf("ReplicateNowTo: %v", err)
	}
	if d.pushes != 0 {
		t.Errorf("pushed %d time(s) with the watermark already past the entry, want 0", d.pushes)
	}
}

// TestReplicateNowTo_StalledPeerIsAnError: the log stops moving and the watermark still
// does not cover the entry. Reporting success there is exactly the bug — the barrier would
// count the peer as holding a reservation it does not have.
func TestReplicateNowTo_StalledPeerIsAnError(t *testing.T) {
	d := &deliverySeam{wm: 5, sent: []int{0}} // nothing sent, watermark unchanged
	err := seamedReplicator(t, d).ReplicateNowTo(context.Background(), "node-b", 30)
	if err == nil {
		t.Fatal("a stalled peer reported success; the barrier would then count it as holding a " +
			"reservation it does not have")
	}
	if !strings.Contains(err.Error(), "stalled") {
		t.Errorf("error = %v, want it to name the stall", err)
	}
}

// TestReplicateNowTo_PushErrorPropagates: a transport failure must not read as delivered.
func TestReplicateNowTo_PushErrorPropagates(t *testing.T) {
	d := &deliverySeam{wm: 0, pushErr: errors.New("peer unreachable")}
	if err := seamedReplicator(t, d).ReplicateNowTo(context.Background(), "node-b", 30); err == nil {
		t.Error("a push error reported success")
	}
}

// TestReplicateNowTo_HonoursContextDeadline: the loop must not spin forever against a peer
// that keeps accepting entries but never catches up.
func TestReplicateNowTo_HonoursContextDeadline(t *testing.T) {
	// Watermark advances by 1 per push and never reaches the target.
	d := &deliverySeam{wm: 0}
	d.advance = make([]int64, 0, 4096)
	for i := int64(1); i <= 4096; i++ {
		d.advance = append(d.advance, i)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- seamedReplicator(t, d).ReplicateNowTo(ctx, "node-b", 1<<30) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("returned success without ever covering the entry")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReplicateNowTo did not honour the context deadline — it must not spin forever " +
			"against a peer that never catches up")
	}
}
