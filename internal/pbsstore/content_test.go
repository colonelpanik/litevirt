package pbsstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestPushFromSource_FullSparse backs up a 3-chunk disk where the middle
// chunk is a hole. The manifest must contain only the two allocated chunks,
// carry the full virtual size, and round-trip restore to the original
// (hole reads back as zeros).
func TestPushFromSource_FullSparse(t *testing.T) {
	r := newTestRepo(t)
	size := int64(ChunkSize * 3)
	data := make([]byte, size)
	for i := 0; i < ChunkSize; i++ {
		data[i] = 0xAA
	}
	for i := 2 * ChunkSize; i < 3*ChunkSize; i++ {
		data[i] = 0xCC
	}
	alloc := [][2]int64{{0, ChunkSize}, {2 * ChunkSize, ChunkSize}} // chunk 1 is a hole

	m, err := PushFromSource(context.Background(), r, bytes.NewReader(data), size, alloc, nil,
		PushOptions{VMName: "vm", DiskName: "root", Timestamp: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("PushFromSource: %v", err)
	}
	if len(m.Chunks) != 2 {
		t.Fatalf("expected 2 chunks (hole skipped), got %d", len(m.Chunks))
	}
	if m.TotalSize != size {
		t.Errorf("TotalSize = %d, want virtual size %d", m.TotalSize, size)
	}
	if m.Chunks[0].Offset != 0 || m.Chunks[1].Offset != 2*ChunkSize {
		t.Errorf("chunk offsets = %d,%d", m.Chunks[0].Offset, m.Chunks[1].Offset)
	}

	dst := filepath.Join(t.TempDir(), "restored.raw")
	if err := RestoreToFile(context.Background(), r, m, dst, RestoreOptions{}); err != nil {
		t.Fatalf("RestoreToFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("restored content != original (hole not preserved as zeros?)")
	}
}

// TestPushFromSource_Incremental backs up a full, then an incremental where
// only the last chunk changed. The unchanged allocated chunk is inherited
// from the parent (same id, not re-read); the changed chunk is fresh; and
// the incremental restores to the new content.
func TestPushFromSource_Incremental(t *testing.T) {
	r := newTestRepo(t)
	size := int64(ChunkSize * 3)
	data := make([]byte, size)
	copy(data[0:ChunkSize], bytes.Repeat([]byte{0xAA}, ChunkSize))
	copy(data[2*ChunkSize:3*ChunkSize], bytes.Repeat([]byte{0xCC}, ChunkSize))
	alloc := [][2]int64{{0, ChunkSize}, {2 * ChunkSize, ChunkSize}}

	parent, err := PushFromSource(context.Background(), r, bytes.NewReader(data), size, alloc, nil,
		PushOptions{VMName: "vm", DiskName: "root", Timestamp: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("full: %v", err)
	}

	// Change only the last chunk; mark only it dirty.
	data2 := append([]byte(nil), data...)
	for i := 2 * ChunkSize; i < 3*ChunkSize; i++ {
		data2[i] = 0xEE
	}
	dirty := [][2]int64{{2 * ChunkSize, ChunkSize}}

	inc, err := PushFromSource(context.Background(), r, bytes.NewReader(data2), size, dirty, parent,
		PushOptions{VMName: "vm", DiskName: "root", Timestamp: "2026-01-02T00:00:00Z"})
	if err != nil {
		t.Fatalf("incremental: %v", err)
	}
	if inc.BasedOn != "2026-01-01T00:00:00Z" {
		t.Errorf("BasedOn = %q, want 2026-01-01T00:00:00Z", inc.BasedOn)
	}
	if len(inc.Chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(inc.Chunks))
	}
	// chunk @0 inherited from parent (same id); chunk @2*ChunkSize changed.
	if inc.Chunks[0].ID != parent.Chunks[0].ID {
		t.Errorf("clean chunk@0 not inherited from parent")
	}
	if inc.Chunks[1].ID == parent.Chunks[1].ID {
		t.Errorf("dirty chunk@2 should have a new id")
	}

	dst := filepath.Join(t.TempDir(), "restored.raw")
	if err := RestoreToFile(context.Background(), r, inc, dst, RestoreOptions{}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data2) {
		t.Errorf("incremental restore != expected new content")
	}
}
