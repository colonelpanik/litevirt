package pbsstore

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// manifestPathFor is the on-disk location ListManifests walks.
func manifestPathFor(r *Repo, m *Manifest) string {
	return filepath.Join(r.root, "snapshots", m.VMName,
		filenameSafeTS(m.Timestamp)+"-"+m.DiskName+".manifest.json")
}

// corruptOneField rewrites a manifest on disk so it still PARSES as JSON but
// fails ValidateManifest — the "one damaged integer" case. The file stays
// hand-repairable, which is the whole point: an operator can put the value back
// and the backup is whole again, as long as its chunks are still there.
func corruptOneField(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	doc["total_size"] = -1 // ValidateManifest: "manifest total_size negative"
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	// Precondition: it must still parse, and must now be invalid.
	var m Manifest
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("the corrupted manifest must still parse: %v", err)
	}
	if err := ValidateManifest(&m); err == nil {
		t.Fatal("the corrupted manifest must fail validation")
	}
}

// TestGC_DoesNotSweepTheChunksOfAnInvalidManifest is the #205 regression.
//
// ListManifests skips a manifest that fails validation with a slog.Warn, so its
// chunks never enter GC's live set and the very next sweep deletes them. That
// turns a hand-repairable backup — one bad integer in a JSON file — into a
// permanently lost one: the operator can fix the field, but the data it points
// at is gone.
//
// The comment on the skip says an invalid manifest is "never offered for a
// restore/prune". GC is the third reader, and it does not merely decline to
// offer the backup — it destroys it.
func TestGC_DoesNotSweepTheChunksOfAnInvalidManifest(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize*2)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(m.Chunks) == 0 {
		t.Fatal("push produced no chunks")
	}
	corruptOneField(t, manifestPathFor(r, m))

	// grace=0 so the retention window cannot be what saves the chunks.
	stats, err := GCWithOptions(context.Background(), r, GCOptions{ChunkGracePeriod: 0})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	for _, c := range m.Chunks {
		if !r.HasChunk(c.ID) {
			t.Fatalf("GC swept chunk %s, which the (repairable) invalid manifest still "+
				"references — the backup is now unrecoverable. stats=%+v", c.ID, stats)
		}
	}
	if stats.ChunksDeleted != 0 {
		t.Errorf("ChunksDeleted = %d, want 0 — nothing in this repo is unreferenced", stats.ChunksDeleted)
	}
}

// The firmware bundle rides the same manifest and must be retained too —
// AllChunks() exists precisely so repo maintenance cannot miss it.
func TestGC_RetainsFirmwareChunksOfAnInvalidManifest(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T02:00:00Z",
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	// Attach a firmware bundle the way TestGC_KeepsFirmwareChunks does.
	fwRefs, err := r.PutBytes(randomBytes(t, 4096))
	if err != nil {
		t.Fatalf("PutBytes firmware: %v", err)
	}
	m.FirmwareChunks = fwRefs
	if err := r.PutManifest(m); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	corruptOneField(t, manifestPathFor(r, m))

	if _, err := GCWithOptions(context.Background(), r, GCOptions{ChunkGracePeriod: 0}); err != nil {
		t.Fatalf("GC: %v", err)
	}
	for _, c := range m.FirmwareChunks {
		if !r.HasChunk(c.ID) {
			t.Errorf("GC swept firmware chunk %s of an invalid manifest", c.ID)
		}
	}
}

// A genuinely orphaned chunk must still be swept: retaining an invalid
// manifest's chunks must not turn GC into a no-op.
func TestGC_StillSweepsRealOrphansAlongsideAnInvalidManifest(t *testing.T) {
	r := newTestRepo(t)

	// Different sizes on purpose: randomBytes is seeded by length, so two calls
	// with the same n yield identical bytes and the content-addressed store
	// deduplicates them into ONE chunk — which would make the "orphan" chunk
	// legitimately still referenced and the assertion below meaningless.
	keep, err := PushDisk(context.Background(), r, bytes.NewReader(randomBytes(t, ChunkSize)), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T03:00:00Z",
	})
	if err != nil {
		t.Fatalf("Push(keep): %v", err)
	}
	corruptOneField(t, manifestPathFor(r, keep))

	orphan, err := PushDisk(context.Background(), r, bytes.NewReader(randomBytes(t, ChunkSize*3)), PushOptions{
		VMName: "vm", DiskName: "data", Timestamp: "2026-05-09T04:00:00Z",
	})
	if err != nil {
		t.Fatalf("Push(orphan): %v", err)
	}
	if err := os.Remove(manifestPathFor(r, orphan)); err != nil {
		t.Fatalf("remove orphan manifest: %v", err)
	}

	stats, err := GCWithOptions(context.Background(), r, GCOptions{ChunkGracePeriod: 0})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	for _, c := range keep.Chunks {
		if !r.HasChunk(c.ID) {
			t.Errorf("chunk %s of the invalid-but-present manifest was swept", c.ID)
		}
	}
	for _, c := range orphan.Chunks {
		if r.HasChunk(c.ID) {
			t.Errorf("chunk %s has no manifest at all and should have been swept", c.ID)
		}
	}
	if stats.ChunksDeleted == 0 {
		t.Error("GC deleted nothing; the genuinely orphaned chunks should have gone")
	}
}
