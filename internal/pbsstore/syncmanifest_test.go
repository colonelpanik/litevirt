package pbsstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// SyncManifest copies exactly one manifest + its chunks into a fresh repo and
// the result restores bit-identically; a second run dedups every chunk.
func TestSyncManifest_CopiesOneManifest(t *testing.T) {
	src := newTestRepo(t)
	dst := newTestRepo(t)

	payload := randomBytes(t, ChunkSize*2+128)
	m, err := PushDisk(context.Background(), src, bytes.NewReader(payload), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}

	stats, err := SyncManifest(context.Background(), src, m, RepoSink(dst))
	if err != nil {
		t.Fatalf("SyncManifest: %v", err)
	}
	if stats.ManifestsCopied != 1 || stats.ChunksCopied != len(m.Chunks) {
		t.Fatalf("stats = %+v (want 1 manifest, %d chunks)", stats, len(m.Chunks))
	}

	got, err := dst.GetManifest(m.VMName, m.Timestamp, m.DiskName)
	if err != nil {
		t.Fatalf("dst.GetManifest: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := RestoreToFile(context.Background(), dst, got, out, RestoreOptions{}); err != nil {
		t.Fatalf("RestoreToFile: %v", err)
	}

	// Second run: all chunks already present → fully deduped.
	stats2, err := SyncManifest(context.Background(), src, m, RepoSink(dst))
	if err != nil {
		t.Fatalf("second SyncManifest: %v", err)
	}
	if stats2.ChunksCopied != 0 || stats2.ChunksSkipped != len(m.Chunks) {
		t.Fatalf("second run not deduped: %+v", stats2)
	}
}

// SyncManifest works on PLAINTEXT across differing encryption modes — the source
// decrypts on read, the destination re-encrypts at rest with its own key. This is
// exactly the property the remote wire path needs, and the one SyncRepo's
// sealed-byte copy refuses.
func TestSyncManifest_CrossEncryptionModes(t *testing.T) {
	src := newTestRepo(t) // plaintext
	encDir := t.TempDir()
	dst, err := InitEncrypted(encDir, EncryptionModeAESGCM)
	if err != nil {
		t.Fatalf("InitEncrypted: %v", err)
	}
	if err := dst.SetKey(bytes.Repeat([]byte{0x22}, 32)); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	payload := randomBytes(t, ChunkSize+4096)
	m, err := PushDisk(context.Background(), src, bytes.NewReader(payload), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T11:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}

	// SyncRepo would refuse this (mode mismatch); SyncManifest must succeed.
	if _, err := SyncManifest(context.Background(), src, m, RepoSink(dst)); err != nil {
		t.Fatalf("SyncManifest across modes: %v", err)
	}
	got, err := dst.GetManifest(m.VMName, m.Timestamp, m.DiskName)
	if err != nil {
		t.Fatalf("dst.GetManifest: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := RestoreToFile(context.Background(), dst, got, out, RestoreOptions{}); err != nil {
		t.Fatalf("RestoreToFile from encrypted dst: %v", err)
	}
	restored, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, payload) {
		t.Fatalf("restored bytes differ from source")
	}
}

// recordingSink is a ChunkSink that records call ordering and can inject a
// PutChunk failure, so a test can assert "manifest written last" and "no
// manifest on a mid-transfer error".
type recordingSink struct {
	present     map[string]bool
	puts        []string // chunk ids put, in order
	manifestPut bool
	order       []string // coarse op log: "chunk" / "manifest"
	failPutAt   int      // 1-based index of a PutChunk to fail; 0 = never
	putCount    int
}

func newRecordingSink() *recordingSink { return &recordingSink{present: map[string]bool{}} }

func (s *recordingSink) HasChunks(_ context.Context, ids []string) ([]bool, error) {
	out := make([]bool, len(ids))
	for i, id := range ids {
		out[i] = s.present[id]
	}
	return out, nil
}

func (s *recordingSink) PutChunk(_ context.Context, data []byte) error {
	s.putCount++
	if s.failPutAt != 0 && s.putCount == s.failPutAt {
		return errors.New("injected put failure")
	}
	id := ChunkID(data)
	s.puts = append(s.puts, id)
	s.present[id] = true
	s.order = append(s.order, "chunk")
	return nil
}

func (s *recordingSink) PutManifest(_ context.Context, _ *Manifest) error {
	s.manifestPut = true
	s.order = append(s.order, "manifest")
	return nil
}

// The manifest must be the LAST thing written — every chunk it references is put
// first, so a reader never sees a manifest whose chunks haven't landed.
func TestSyncManifest_ManifestWrittenLast(t *testing.T) {
	src := newTestRepo(t)
	m, err := PushDisk(context.Background(), src, bytes.NewReader(randomBytes(t, ChunkSize*3)), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	sink := newRecordingSink()
	if _, err := SyncManifest(context.Background(), src, m, sink); err != nil {
		t.Fatalf("SyncManifest: %v", err)
	}
	if len(sink.order) == 0 || sink.order[len(sink.order)-1] != "manifest" {
		t.Fatalf("manifest not last; order=%v", sink.order)
	}
	for i, op := range sink.order[:len(sink.order)-1] {
		if op != "chunk" {
			t.Fatalf("op %d before manifest was %q, want chunk; order=%v", i, op, sink.order)
		}
	}
}

// A mid-transfer PutChunk failure must abort WITHOUT writing the manifest — the
// already-transferred chunks are left as harmless GC'able orphans.
func TestSyncManifest_NoManifestOnChunkError(t *testing.T) {
	src := newTestRepo(t)
	m, err := PushDisk(context.Background(), src, bytes.NewReader(randomBytes(t, ChunkSize*3)), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T13:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	sink := newRecordingSink()
	sink.failPutAt = 2 // fail on the second chunk
	if _, err := SyncManifest(context.Background(), src, m, sink); err == nil {
		t.Fatal("expected an error from the injected PutChunk failure")
	}
	if sink.manifestPut {
		t.Fatal("manifest must NOT be written when a chunk transfer failed")
	}
}
