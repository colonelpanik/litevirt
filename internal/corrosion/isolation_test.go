package corrosion

import (
	"context"
	"errors"
	"testing"
)

func seedHost(t *testing.T, c *Client, name string) {
	t.Helper()
	if err := InsertHost(context.Background(), c, HostRecord{
		Name: name, Address: "10.0.0.1", SSHUser: "root", CertSerial: "x",
	}); err != nil {
		t.Fatalf("seed host %s: %v", name, err)
	}
}

// The epoch is CLUSTER state about a host, written by a healthy peer: a node
// that cannot be trusted to replicate cannot be trusted to record (or clear)
// its own quarantine.
func TestIsolationEpochIsPeerWrittenAndMonotone(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedHost(t, c, "n1")
	seedHost(t, c, "n2")

	// A host may not isolate itself.
	if err := IsolateHost(ctx, c, "n1", "n1", IsolationManual); !errors.Is(err, ErrSelfIsolation) {
		t.Fatalf("self-isolation: err=%v, want ErrSelfIsolation", err)
	}
	// A made-up reason is refused — the reason drives operator surfaces.
	if err := IsolateHost(ctx, c, "n2", "n1", "because"); err == nil {
		t.Fatal("an unknown isolation reason must be refused")
	}
	if epoch, _, _ := HostIsolation(ctx, c, "n1"); epoch != 0 {
		t.Fatalf("refused isolations must not have landed: epoch=%d", epoch)
	}

	// A healthy peer records it.
	if err := IsolateHost(ctx, c, "n2", "n1", IsolationRolledBackLatch); err != nil {
		t.Fatalf("peer isolation: %v", err)
	}
	epoch, reason, err := HostIsolation(ctx, c, "n1")
	if err != nil || epoch != 1 || reason != IsolationRolledBackLatch {
		t.Fatalf("after isolation: epoch=%d reason=%q err=%v", epoch, reason, err)
	}

	// Re-observation is idempotent: the epoch does NOT climb on every sweep
	// (the detector runs continuously, so a fresh epoch per pass would make the
	// number meaningless and rewrite the row forever).
	if err := IsolateHost(ctx, c, "n2", "n1", IsolationRolledBackLatch); !errors.Is(err, ErrIsolationNotMonotone) {
		t.Fatalf("re-isolation: err=%v, want ErrIsolationNotMonotone", err)
	}
	if e, _, _ := HostIsolation(ctx, c, "n1"); e != 1 {
		t.Fatalf("re-observation moved the epoch: %d", e)
	}

	// A second isolated host takes the NEXT cluster-wide epoch, so the values
	// order isolations across the cluster.
	seedHost(t, c, "n3")
	if err := IsolateHost(ctx, c, "n2", "n3", IsolationManual); err != nil {
		t.Fatalf("isolate n3: %v", err)
	}
	if e, _, _ := HostIsolation(ctx, c, "n3"); e != 2 {
		t.Fatalf("second isolation epoch = %d, want 2", e)
	}
}

// Only a VERIFIED reseed clears the epoch, and only the epoch it reconciled:
// an isolation recorded while the reseed ran must not be swallowed by it.
func TestClearHostIsolationPinsTheEpoch(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedHost(t, c, "n1")
	seedHost(t, c, "n2")
	if err := IsolateHost(ctx, c, "n2", "n1", IsolationManual); err != nil {
		t.Fatalf("isolate: %v", err)
	}

	// Clearing a DIFFERENT epoch than the one recorded matches nothing.
	if err := ClearHostIsolation(ctx, c, "n1", 99); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("stale-epoch clear: err=%v, want ErrNoRowsAffected", err)
	}
	if e, _, _ := HostIsolation(ctx, c, "n1"); e != 1 {
		t.Fatalf("a stale clear must leave the isolation: epoch=%d", e)
	}

	// Clearing the reconciled epoch works.
	if err := ClearHostIsolation(ctx, c, "n1", 1); err != nil {
		t.Fatalf("clear: %v", err)
	}
	e, reason, _ := HostIsolation(ctx, c, "n1")
	if e != 0 || reason != "" {
		t.Fatalf("after clear: epoch=%d reason=%q", e, reason)
	}

	// A host that was never isolated is not isolated, and an unknown host is
	// NOT reported isolated — inventing one would refuse legitimate first
	// contact from a peer we haven't recorded yet.
	if e, _, _ := HostIsolation(ctx, c, "never-seen"); e != 0 {
		t.Fatalf("unknown host reported isolated: %d", e)
	}
}

// A refused push does not advance the sender's watermark (by design — a
// transient refusal must not lose entries), so an isolated node QUEUES its
// out-of-regime writes. If a reseed does not retire that queue, the quarantine
// is only a DELAY: the backlog replays onto every peer the instant the epoch
// clears. The lab caught exactly that — a container the peers had refused for
// half an hour landed on all of them seconds after the reseed, carrying its
// original created_at.
func TestReseedRetiresTheOutboundBacklog(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedHost(t, c, "n1")

	// Writes made while isolated, with a peer watermark left behind them —
	// exactly the state a refused push leaves.
	for i := 0; i < 3; i++ {
		if err := UpsertContainer(ctx, c, ContainerRecord{
			HostName: "n1", Name: "queued", State: "stopped", Image: "alpine",
		}); err != nil {
			t.Fatalf("queued write: %v", err)
		}
	}
	var head int64
	if err := c.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0) FROM mutation_log`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if head == 0 {
		t.Fatal("precondition: the writes must have produced a mutation-log backlog")
	}
	if err := c.execLocal(ctx,
		`INSERT INTO replication_watermarks (peer_name, last_seq, updated_at) VALUES (?, ?, ?)`,
		"n2", 0, nowRFC3339()); err != nil {
		t.Fatal(err)
	}

	if _, err := c.DiscardReplicatedStateForReseed(ctx); err != nil {
		t.Fatalf("discard: %v", err)
	}

	// Every peer watermark now sits at the head, so nothing written before the
	// reseed is ever selected for push again.
	var wm int64
	if err := c.db.QueryRowContext(ctx,
		`SELECT last_seq FROM replication_watermarks WHERE peer_name = 'n2'`).Scan(&wm); err != nil {
		t.Fatal(err)
	}
	if wm < head {
		t.Fatalf("watermark %d is still behind the pre-reseed head %d — the out-of-regime "+
			"backlog would replay the moment the epoch cleared", wm, head)
	}

	// A peer that joins AFTER the reseed starts at watermark 0 — it was not
	// around to refuse anything — so the pre-reseed entries must be gone from
	// the log entirely, not merely watermarked past.
	var remaining int64
	if err := c.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mutation_log WHERE seq <= ?`, head).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("%d pre-reseed entries still in the log — a peer joining later would be "+
			"served the out-of-regime backlog from watermark 0", remaining)
	}

	// And the node is not muted forever: a write made AFTER the reseed is past
	// the retired watermark, so it still replicates.
	if err := UpsertContainer(ctx, c, ContainerRecord{
		HostName: "n1", Name: "after-reseed", State: "stopped", Image: "alpine",
	}); err != nil {
		t.Fatalf("post-reseed write: %v", err)
	}
	var newHead int64
	if err := c.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0) FROM mutation_log`).Scan(&newHead); err != nil {
		t.Fatal(err)
	}
	if newHead <= wm {
		t.Fatalf("a post-reseed write (seq %d) must be ahead of the retired watermark %d", newHead, wm)
	}
}
