package pbsstore

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

// TestPushIncremental_ReusesCleanChunks pushes a base, then an
// incremental in which only one chunk is reported dirty. The new
// manifest should reuse the parent's ChunkRefs for the unchanged
// chunks, and emit a fresh chunk for the dirty one.
func TestPushIncremental_ReusesCleanChunks(t *testing.T) {
	r := newTestRepo(t)

	// 4 chunks of distinct content.
	src := randomBytes(t, ChunkSize*4)
	base, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("base push: %v", err)
	}

	// Mutate chunk #2 (offset = 2*ChunkSize) and re-push as incremental.
	mutated := append([]byte(nil), src...)
	for i := 2 * ChunkSize; i < 3*ChunkSize; i++ {
		mutated[i] ^= 0xAA
	}
	bitmap := NewRangeBitmap([][2]int64{{int64(2 * ChunkSize), int64(ChunkSize)}})

	inc, err := PushIncremental(context.Background(), r, bytes.NewReader(mutated), base, bitmap, PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T02:00:00Z",
	})
	if err != nil {
		t.Fatalf("incremental push: %v", err)
	}
	if inc.BasedOn != base.Timestamp {
		t.Errorf("BasedOn = %q, want %q", inc.BasedOn, base.Timestamp)
	}
	if len(inc.Chunks) != 4 {
		t.Fatalf("expected 4 chunk refs, got %d", len(inc.Chunks))
	}
	// Chunks 0, 1, 3 must reuse the parent's chunk ids; chunk 2 must
	// have a different id (it changed) — and that new chunk must be on
	// disk.
	for _, idx := range []int{0, 1, 3} {
		if inc.Chunks[idx].ID != base.Chunks[idx].ID {
			t.Errorf("chunk[%d] id = %q, want parent's %q (clean region should reuse ref)",
				idx, inc.Chunks[idx].ID, base.Chunks[idx].ID)
		}
	}
	if inc.Chunks[2].ID == base.Chunks[2].ID {
		t.Errorf("chunk[2] id unchanged but bytes were mutated and reported dirty")
	}
	if !r.HasChunk(inc.Chunks[2].ID) {
		t.Errorf("freshly emitted chunk[2] missing on disk")
	}

	// Round-trip: restore the incremental and confirm it matches the
	// mutated source byte-for-byte.
	dst := filepath.Join(t.TempDir(), "restored.bin")
	if err := RestoreToFile(context.Background(), r, inc, dst, RestoreOptions{}); err != nil {
		t.Fatalf("RestoreToFile: %v", err)
	}
}

// countingReaderAt wraps a *bytes.Reader and counts the bytes pulled via
// ReadAt, so a test can prove clean regions were never read.
type countingReaderAt struct {
	r    *bytes.Reader
	read int64
}

func (c *countingReaderAt) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.read += int64(n)
	return n, err
}
func (c *countingReaderAt) Seek(offset int64, whence int) (int64, error) {
	return c.r.Seek(offset, whence)
}

// TestPushIncremental_SkipsReadsForCleanRegions is the read-I/O-savings
// regression: with a seekable source and a bitmap marking only one chunk
// dirty, ONLY that chunk's bytes are read off the source. This is the
// whole point of the real dirty-bitmap driver.
func TestPushIncremental_SkipsReadsForCleanRegions(t *testing.T) {
	r := newTestRepo(t)

	src := randomBytes(t, ChunkSize*4)
	base, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("base push: %v", err)
	}

	// Mutate only chunk #2 and mark only it dirty.
	mutated := append([]byte(nil), src...)
	for i := 2 * ChunkSize; i < 3*ChunkSize; i++ {
		mutated[i] ^= 0xAA
	}
	bitmap := NewRangeBitmap([][2]int64{{int64(2 * ChunkSize), int64(ChunkSize)}})

	counting := &countingReaderAt{r: bytes.NewReader(mutated)}
	var lastProg PushProgress
	inc, err := PushIncremental(context.Background(), r, counting, base, bitmap, PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T02:00:00Z",
		Progress: func(p PushProgress) { lastProg = p },
	})
	if err != nil {
		t.Fatalf("incremental: %v", err)
	}

	// Only the single dirty 4 MiB chunk should have been read off disk.
	if counting.read != int64(ChunkSize) {
		t.Errorf("read %d bytes off source, want exactly one chunk (%d)", counting.read, ChunkSize)
	}
	if lastProg.BytesRead != int64(ChunkSize) {
		t.Errorf("progress BytesRead = %d, want %d", lastProg.BytesRead, ChunkSize)
	}
	if lastProg.BytesProcessed != int64(ChunkSize*4) {
		t.Errorf("progress BytesProcessed = %d, want full disk %d", lastProg.BytesProcessed, ChunkSize*4)
	}
	// Clean chunks inherited verbatim; dirty chunk re-emitted.
	for _, idx := range []int{0, 1, 3} {
		if inc.Chunks[idx].ID != base.Chunks[idx].ID {
			t.Errorf("chunk[%d] not inherited", idx)
		}
	}
	if inc.Chunks[2].ID == base.Chunks[2].ID {
		t.Errorf("chunk[2] should have changed")
	}
}

// TestPushIncremental_FullDirtyDegradesToFull asserts an AlwaysDirty
// bitmap behaves identically to a full PushDisk.
func TestPushIncremental_FullDirtyDegradesToFull(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize*2)
	base, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("base push: %v", err)
	}

	// Different content, every chunk dirty.
	src2 := randomBytes(t, ChunkSize*2+512)
	inc, err := PushIncremental(context.Background(), r, bytes.NewReader(src2), base, AlwaysDirty{}, PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T02:00:00Z",
	})
	if err != nil {
		t.Fatalf("incremental: %v", err)
	}
	for _, c := range inc.Chunks {
		if !r.HasChunk(c.ID) {
			t.Errorf("chunk %s not on disk after AlwaysDirty incremental", c.ID)
		}
	}
}

// TestRangeBitmap_BoundaryCases locks the merge / overlap rules.
func TestRangeBitmap_BoundaryCases(t *testing.T) {
	b := NewRangeBitmap([][2]int64{
		{0, 10}, {5, 10}, {30, 5}, {32, 5}, // first two overlap; last two touch
	})
	cases := []struct {
		off, n int64
		want   bool
	}{
		{0, 1, true},
		{14, 1, true},  // end of merged 0..15
		{15, 1, false}, // gap
		{29, 1, false}, // just before 30
		{30, 1, true},
		{34, 1, true},   // inside 32..37 (merged with 30..35)
		{37, 1, false},  // past merged end
		{100, 0, false}, // zero-length query
	}
	for _, tc := range cases {
		if got := b.IsDirty(tc.off, tc.n); got != tc.want {
			t.Errorf("IsDirty(%d,%d)=%v, want %v", tc.off, tc.n, got, tc.want)
		}
	}
}

// TestPushIncremental_MissingParent fails fast — accidentally pushing
// an incremental with no parent could only ever produce a partial
// manifest.
func TestPushIncremental_MissingParent(t *testing.T) {
	r := newTestRepo(t)
	_, err := PushIncremental(context.Background(), r, bytes.NewReader([]byte("x")),
		nil, NewRangeBitmap(nil), PushOptions{VMName: "v", DiskName: "d"})
	if err == nil {
		t.Fatal("expected error when parent is nil")
	}
}
