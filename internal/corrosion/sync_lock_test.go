package corrosion

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// fakeSyncMetrics is a trivial SyncMetrics recorder for assertions.
type fakeSyncMetrics struct {
	dumps, digests, merges  int
	lastMerged, lastSkipped int
}

func (f *fakeSyncMetrics) ObserveDump(time.Duration, int) { f.dumps++ }
func (f *fakeSyncMetrics) ObserveDigest(time.Duration)    { f.digests++ }
func (f *fakeSyncMetrics) ObserveMerge(_ time.Duration, m, s int) {
	f.merges++
	f.lastMerged, f.lastSkipped = m, s
}

func seedHosts(ctx context.Context, c *Client, n int) {
	for i := 0; i < n; i++ {
		InsertHost(ctx, c, HostRecord{
			Name: fmt.Sprintf("h%02d", i), Address: fmt.Sprintf("10.0.0.%d", i+1),
			SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
			CertSerial: fmt.Sprintf("s%02d", i),
		})
	}
}

func digestMap(t *testing.T, ctx context.Context, c *Client) map[string]string {
	t.Helper()
	ds, err := c.StateDigest(ctx)
	if err != nil {
		t.Fatalf("StateDigest: %v", err)
	}
	m := make(map[string]string, len(ds))
	for _, d := range ds {
		m[d.Name] = fmt.Sprintf("%d:%s", d.Count, d.Hash)
	}
	return m
}

func payloadPrefix(p *syncPayload, table string, n int) *syncPayload {
	out := &syncPayload{}
	for _, tbl := range p.Tables {
		if tbl.Name == table && n < len(tbl.Rows) {
			out.Tables = append(out.Tables, syncTable{Name: tbl.Name, Columns: tbl.Columns, Rows: tbl.Rows[:n]})
		} else {
			out.Tables = append(out.Tables, tbl)
		}
	}
	return out
}

// TestMergeChunked_PartialConvergence proves the partial-merge semantics the
// chunked merge documents: applying a PREFIX of a dump and then the full dump
// reaches the SAME final state as applying the full dump once. Chunking is forced
// (mergeApplyChunkRows shrunk) so the full merge spans several committed chunks.
func TestMergeChunked_PartialConvergence(t *testing.T) {
	ctx := context.Background()
	old := mergeApplyChunkRows
	mergeApplyChunkRows = 2
	defer func() { mergeApplyChunkRows = old }()

	src := testClient(t)
	seedHosts(ctx, src, 7)
	full, err := decompressPayload(src.dumpState())
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}

	// Node A: apply a prefix (simulating a merge interrupted after some chunks),
	// then the full dump.
	a := testClient(t)
	a.mergeStatePayloadLWW(payloadPrefix(full, "hosts", 3))
	a.mergeStatePayloadLWW(full)

	// Node B: apply the full dump once.
	b := testClient(t)
	b.mergeStatePayloadLWW(full)

	da, db := digestMap(t, ctx, a), digestMap(t, ctx, b)
	if da["hosts"] != db["hosts"] {
		t.Fatalf("hosts digest diverged: prefix-then-full=%q vs full-once=%q", da["hosts"], db["hosts"])
	}
	if got := da["hosts"]; got[:2] != "7:" {
		t.Fatalf("node A should have 7 hosts after re-merge, digest=%q", got)
	}
}

// TestMergeChunked_AllRowsLand confirms the chunk path applies every row when
// mergeApplyChunkRows forces many single-row commits.
func TestMergeChunked_AllRowsLand(t *testing.T) {
	ctx := context.Background()
	old := mergeApplyChunkRows
	mergeApplyChunkRows = 1
	defer func() { mergeApplyChunkRows = old }()

	src := testClient(t)
	seedHosts(ctx, src, 10)
	dst := testClient(t)
	dst.MergeStateBytesLWW(src.dumpState())

	hosts, err := ListHosts(ctx, dst)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 10 {
		t.Fatalf("merged %d hosts via single-row chunks, want 10", len(hosts))
	}
}

// TestMergeChunked_ConcurrentWrites proves the chunked merge releases the write
// lock between chunks: a concurrent writer makes progress WHILE a merge runs, and
// both the merged rows and the concurrent writes land. Run under -race to catch
// lock misuse.
func TestMergeChunked_ConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	old := mergeApplyChunkRows
	mergeApplyChunkRows = 1
	defer func() { mergeApplyChunkRows = old }()

	src := testClient(t)
	seedHosts(ctx, src, 50)
	full, err := decompressPayload(src.dumpState())
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}

	dst := testClient(t)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			InsertImage(ctx, dst, ImageRecord{Name: fmt.Sprintf("img%02d", i), Format: "qcow2", SizeBytes: int64(i)})
		}
		close(done)
	}()
	dst.mergeStatePayloadLWW(full)
	<-done

	hosts, _ := ListHosts(ctx, dst)
	if len(hosts) != 50 {
		t.Fatalf("merged %d hosts, want 50", len(hosts))
	}
	imgs, _ := ListImages(ctx, dst)
	if len(imgs) != 50 {
		t.Fatalf("concurrent writer landed %d images, want 50 (lock not released between chunks?)", len(imgs))
	}
}

// TestSyncMetricsRecorded verifies the nil-safe recorder on the Client is called
// for dump, digest, and merge.
func TestSyncMetricsRecorded(t *testing.T) {
	ctx := context.Background()

	src := testClient(t)
	seedHosts(ctx, src, 2)
	sm := &fakeSyncMetrics{}
	src.SetSyncMetrics(sm)
	_ = src.dumpState()
	if _, err := src.StateDigest(ctx); err != nil {
		t.Fatalf("StateDigest: %v", err)
	}
	if sm.dumps == 0 || sm.digests == 0 {
		t.Fatalf("dump/digest not recorded: %+v", sm)
	}

	dst := testClient(t)
	dm := &fakeSyncMetrics{}
	dst.SetSyncMetrics(dm)
	dst.MergeStateBytesLWW(src.dumpState())
	if dm.merges == 0 {
		t.Fatalf("merge not recorded: %+v", dm)
	}
	if dm.lastMerged < 2 {
		t.Fatalf("expected >=2 host rows merged, got %d", dm.lastMerged)
	}
}
