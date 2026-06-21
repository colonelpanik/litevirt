package pbsstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// TestPushDisk_RoundTrip pushes a random byte stream and restores it,
// asserting the round-trip is bit-for-bit identical.
func TestPushDisk_RoundTrip(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize*3+1234)

	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-09T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	if m.TotalSize != int64(len(src)) {
		t.Errorf("TotalSize = %d, want %d", m.TotalSize, len(src))
	}
	wantChunks := (len(src) + ChunkSize - 1) / ChunkSize
	if len(m.Chunks) != wantChunks {
		t.Errorf("len(Chunks) = %d, want %d", len(m.Chunks), wantChunks)
	}

	dst := filepath.Join(t.TempDir(), "restored.bin")
	if err := RestoreToFile(context.Background(), r, m, dst, RestoreOptions{}); err != nil {
		t.Fatalf("RestoreToFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(src, got) {
		t.Errorf("round-trip mismatch (lengths %d vs %d)", len(src), len(got))
	}
}

// TestPushDisk_DedupAcrossSnapshots verifies a second push of the same
// bytes produces the same chunk ids and adds no new chunks on disk.
func TestPushDisk_DedupAcrossSnapshots(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize*2)

	if _, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	}); err != nil {
		t.Fatalf("first push: %v", err)
	}
	chunks1 := countChunks(t, r.Root())

	if _, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-09T02:00:00Z",
	}); err != nil {
		t.Fatalf("second push: %v", err)
	}
	chunks2 := countChunks(t, r.Root())
	if chunks2 != chunks1 {
		t.Errorf("chunk count grew (%d → %d) on identical second push", chunks1, chunks2)
	}

	manifests, err := r.ListManifests()
	if err != nil {
		t.Fatalf("ListManifests: %v", err)
	}
	if len(manifests) != 2 {
		t.Errorf("expected 2 manifests, got %d", len(manifests))
	}
}

// TestPushDisk_ProgressCallbackEmitsForEachChunk verifies the caller
// observes progress for every chunk in order.
func TestPushDisk_ProgressCallbackEmitsForEachChunk(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize*4)
	var calls []PushProgress
	if _, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "d",
		Progress: func(p PushProgress) { calls = append(calls, p) },
	}); err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	if len(calls) != 4 {
		t.Fatalf("expected 4 progress callbacks, got %d", len(calls))
	}
	if calls[3].BytesProcessed != int64(len(src)) {
		t.Errorf("final BytesProcessed = %d, want %d", calls[3].BytesProcessed, len(src))
	}
	for i := 1; i < len(calls); i++ {
		if calls[i].BytesProcessed <= calls[i-1].BytesProcessed {
			t.Errorf("BytesProcessed not monotonic: %v", calls)
		}
	}
}

// TestPushDisk_RespectsCancel cancels the context mid-stream and
// verifies PushDisk returns ctx.Err.
func TestPushDisk_RespectsCancel(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize*5)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before we start
	_, err := PushDisk(ctx, r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "d",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestRestoreToFile_DetectsCorruption flips a chunk on disk and
// confirms restore aborts with ErrChunkMismatch.
func TestRestoreToFile_DetectsCorruption(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize+1)

	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "d", Timestamp: "2026-05-09T03:00:00Z",
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	// Corrupt the first chunk.
	if err := os.WriteFile(r.chunkPath(m.Chunks[0].ID),
		bytes.Repeat([]byte{0xFF}, int(m.Chunks[0].Size)), 0640); err != nil {
		t.Fatalf("corrupt chunk: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "out.bin")
	err = RestoreToFile(context.Background(), r, m, dst, RestoreOptions{})
	if !errors.Is(err, ErrChunkMismatch) {
		t.Fatalf("expected ErrChunkMismatch, got %v", err)
	}
}

// TestRestoreToFile_PreservesExistingOnFailure is the bug-sweep #2 regression:
// a restore over an existing file that fails on a corrupt chunk must leave the
// original intact (restore goes via a temp + atomic rename, no truncate-in-place).
func TestRestoreToFile_PreservesExistingOnFailure(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize+1)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "d", Timestamp: "2026-05-09T03:00:00Z",
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	// Corrupt the first chunk so the restore aborts mid-stream.
	if err := os.WriteFile(r.chunkPath(m.Chunks[0].ID),
		bytes.Repeat([]byte{0xFF}, int(m.Chunks[0].Size)), 0640); err != nil {
		t.Fatalf("corrupt chunk: %v", err)
	}

	// Destination already holds important data (in-place DR over a live path).
	dst := filepath.Join(t.TempDir(), "existing.bin")
	original := []byte("PRECIOUS-ORIGINAL-DATA")
	if err := os.WriteFile(dst, original, 0640); err != nil {
		t.Fatalf("seed dst: %v", err)
	}

	if err := RestoreToFile(context.Background(), r, m, dst, RestoreOptions{}); !errors.Is(err, ErrChunkMismatch) {
		t.Fatalf("expected ErrChunkMismatch, got %v", err)
	}

	// Original must be untouched, and no temp left behind.
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("destination corrupted by failed restore: got %q err=%v (want %q preserved)", got, err, original)
	}
	if _, err := os.Stat(dst + ".restore-tmp"); !os.IsNotExist(err) {
		t.Errorf("restore temp leaked: %v", err)
	}
}

// TestRestoreToFile_HandlesEmptyManifest is a guard against zero-byte
// snapshots (unusual but possible — e.g. a freshly attached blank disk).
func TestRestoreToFile_HandlesEmptyManifest(t *testing.T) {
	r := newTestRepo(t)
	m := &Manifest{VMName: "v", DiskName: "d", Timestamp: "2026-05-09T04:00:00Z"}
	if err := r.PutManifest(m); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "empty.bin")
	if err := RestoreToFile(context.Background(), r, m, dst, RestoreOptions{}); err != nil {
		t.Fatalf("RestoreToFile: %v", err)
	}
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != 0 {
		t.Errorf("size = %d, want 0", st.Size())
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.New(rand.NewSource(int64(n))).Read(b); err != nil {
		t.Fatalf("rng: %v", err)
	}
	return b
}

func countChunks(t *testing.T, root string) int {
	t.Helper()
	count := 0
	err := filepath.WalkDir(filepath.Join(root, "chunks"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			count++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return count
}

// _ keeps io imported for tests that may add streaming pieces later.
var _ = io.EOF
