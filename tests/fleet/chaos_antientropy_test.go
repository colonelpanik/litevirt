package fleet

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// recordingSyncMetrics implements corrosion.SyncMetrics to verify PR #54's
// anti-entropy timing/rows metrics fire during a real fleet sync.
type recordingSyncMetrics struct {
	mu                             sync.Mutex
	dumps, digests, merges, merged int
}

func (r *recordingSyncMetrics) ObserveDump(time.Duration, int) { r.mu.Lock(); r.dumps++; r.mu.Unlock() }
func (r *recordingSyncMetrics) ObserveDigest(time.Duration)    { r.mu.Lock(); r.digests++; r.mu.Unlock() }
func (r *recordingSyncMetrics) ObserveMerge(_ time.Duration, m, _ int) {
	r.mu.Lock()
	r.merges++
	r.merged += m
	r.mu.Unlock()
}
func (r *recordingSyncMetrics) snap() (d, dg, m, mr int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dumps, r.digests, r.merges, r.merged
}

// TestFleet_ChaosAntiEntropyReconvergence drives PR #54 end-to-end on the
// in-process cluster: partition two nodes, diverge BOTH sides, heal, and
// reconverge over the REAL anti-entropy RPC path (digest → StreamStateDump →
// chunked LWW merge) while a concurrent writer mutates the merging node (stressing
// the per-chunk lock release under -race). Asserts union convergence + that the
// dump/digest/merge metrics fired.
func TestFleet_ChaosAntiEntropyReconvergence(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	a, b := c.Node("node-0"), c.Node("node-1")
	ctx := context.Background()

	mA, mB := &recordingSyncMetrics{}, &recordingSyncMetrics{}
	a.DB.SetSyncMetrics(mA)
	b.DB.SetSyncMetrics(mB)

	c.Partition(a, b)

	// Diverge: distinct state on each side while partitioned.
	for i := 0; i < 25; i++ {
		_ = corrosion.InsertImage(ctx, a.DB, corrosion.ImageRecord{Name: fmt.Sprintf("a-img%02d", i), Format: "qcow2", SizeBytes: int64(i)})
		_ = corrosion.InsertImage(ctx, b.DB, corrosion.ImageRecord{Name: fmt.Sprintf("b-img%02d", i), Format: "qcow2", SizeBytes: int64(i)})
	}
	if _, err := peerPull(c, b, a); status.Code(err) != codes.Unavailable {
		t.Fatalf("partitioned pull must fail, got %v", err)
	}
	// Divergence: neither side sees the other's writes while partitioned.
	if n := rowCount(t, b, "SELECT count(*) AS n FROM images WHERE name = ?", "a-img00"); n != 0 {
		t.Fatalf("b should not see a's writes across the partition (n=%d)", n)
	}

	c.Heal(a, b)

	// b merges a's dump while a concurrent writer mutates b — exercises the
	// chunked merge's lock release (run under -race).
	blob, err := peerPull(c, b, a)
	if err != nil {
		t.Fatalf("post-heal pull a→b: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 25; i++ {
			_ = corrosion.InsertImage(ctx, b.DB, corrosion.ImageRecord{Name: fmt.Sprintf("b-live%02d", i), Format: "qcow2", SizeBytes: int64(i)})
		}
		close(done)
	}()
	b.DB.MergeStateBytesLWW(blob)
	<-done

	// Bidirectional: a merges b's dump too.
	blob2, err := peerPull(c, a, b)
	if err != nil {
		t.Fatalf("post-heal pull b→a: %v", err)
	}
	a.DB.MergeStateBytesLWW(blob2)

	// Reconverged: each side has the other's images; b's concurrent writes survived.
	if n := rowCount(t, b, "SELECT count(*) AS n FROM images WHERE name = ?", "a-img00"); n != 1 {
		t.Fatalf("b missing a's image after heal (n=%d)", n)
	}
	if n := rowCount(t, a, "SELECT count(*) AS n FROM images WHERE name = ?", "b-img00"); n != 1 {
		t.Fatalf("a missing b's image after heal (n=%d)", n)
	}
	if n := rowCount(t, b, "SELECT count(*) AS n FROM images WHERE name = ?", "b-live00"); n != 1 {
		t.Fatalf("concurrent write lost during merge (n=%d)", n)
	}

	// PR #54 metrics fired during the real anti-entropy.
	if d, _, _, _ := mA.snap(); d == 0 {
		t.Error("dump metric not recorded on the served node (a)")
	}
	if _, _, m, mr := mB.snap(); m == 0 || mr == 0 {
		t.Errorf("merge metric not recorded on the merging node (b): merges=%d merged=%d", m, mr)
	}
}
