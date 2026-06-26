package pbsstore

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestInit_CreatesLayout verifies a fresh Init builds the canonical
// repo.json + chunks/ + snapshots/ tree.
func TestInit_CreatesLayout(t *testing.T) {
	dir := t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if r.Root() != dir {
		t.Errorf("Root() = %q, want %q", r.Root(), dir)
	}
	for _, sub := range []string{"repo.json", "chunks", "snapshots"} {
		if _, err := os.Stat(filepath.Join(dir, sub)); err != nil {
			t.Errorf("missing %s: %v", sub, err)
		}
	}
	if r.meta.SchemaVersion != SchemaVersion {
		t.Errorf("schema = %d, want %d", r.meta.SchemaVersion, SchemaVersion)
	}
}

// TestInit_RefusesOnExisting prevents accidental clobber of an in-use repo.
func TestInit_RefusesOnExisting(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	if _, err := Init(dir); err == nil {
		t.Fatal("second Init should fail")
	}
}

// TestOpen_RejectsFutureSchema simulates downgrading a binary against a
// repo written by a newer one.
func TestOpen_RejectsFutureSchema(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Hand-edit repo.json to bump schema version.
	if err := os.WriteFile(filepath.Join(dir, "repo.json"),
		[]byte(`{"schema_version":99,"created_at":"2026-01-01T00:00:00Z"}`), 0640); err != nil {
		t.Fatalf("rewrite repo.json: %v", err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("Open should refuse a newer schema version")
	}
}

// TestPutChunk_Dedup verifies a second write with identical bytes is a
// no-op (created=false) and stored bytes are read back unchanged.
func TestPutChunk_Dedup(t *testing.T) {
	r := newTestRepo(t)
	data := []byte("the quick brown fox jumps over the lazy dog")

	id1, created1, err := r.PutChunk(data)
	if err != nil {
		t.Fatalf("PutChunk first: %v", err)
	}
	if !created1 {
		t.Error("first PutChunk should report created=true")
	}

	id2, created2, err := r.PutChunk(data)
	if err != nil {
		t.Fatalf("PutChunk second: %v", err)
	}
	if id1 != id2 {
		t.Errorf("chunk id changed across calls: %s vs %s", id1, id2)
	}
	if created2 {
		t.Error("dedup hit should report created=false")
	}

	got, err := r.GetChunk(id1)
	if err != nil {
		t.Fatalf("GetChunk: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("round-trip mismatch")
	}
}

// TestPutChunk_ConcurrentWriters has many goroutines write the same and
// distinct chunks at once. The store must remain consistent.
func TestPutChunk_ConcurrentWriters(t *testing.T) {
	r := newTestRepo(t)
	rng := rand.New(rand.NewSource(42))

	// Pre-build a small set of chunk payloads. Workers pick from this
	// set so we exercise both dedup and new-chunk paths.
	chunks := make([][]byte, 8)
	for i := range chunks {
		chunks[i] = make([]byte, 1024+rng.Intn(4096))
		rng.Read(chunks[i])
	}

	const workers = 16
	const writes = 64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lr := rand.New(rand.NewSource(int64(w)))
			for i := 0; i < writes; i++ {
				idx := lr.Intn(len(chunks))
				if _, _, err := r.PutChunk(chunks[idx]); err != nil {
					t.Errorf("PutChunk worker=%d idx=%d: %v", w, idx, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	// Every chunk must be retrievable and its hash must match.
	for _, data := range chunks {
		id := ChunkID(data)
		got, err := r.GetChunk(id)
		if err != nil {
			t.Errorf("GetChunk %s: %v", id, err)
			continue
		}
		if !bytes.Equal(got, data) {
			t.Errorf("chunk %s round-trip mismatch", id)
		}
	}
}

// TestGetChunk_DetectsCorruption simulates bit-rot: edit the on-disk
// file so its hash no longer matches its filename.
func TestGetChunk_DetectsCorruption(t *testing.T) {
	r := newTestRepo(t)
	id, _, err := r.PutChunk([]byte("hello"))
	if err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	if err := os.WriteFile(r.chunkPath(id), []byte("hello\x00"), 0640); err != nil {
		t.Fatalf("rewrite chunk file: %v", err)
	}
	_, err = r.GetChunk(id)
	if !errors.Is(err, ErrChunkMismatch) {
		t.Fatalf("expected ErrChunkMismatch, got %v", err)
	}
}

// TestPutManifest_RoundTrip verifies the manifest file lands at the
// expected path and reloads identically.
func TestPutManifest_RoundTrip(t *testing.T) {
	r := newTestRepo(t)
	m := &Manifest{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-09T12:34:56Z",
		TotalSize: 8192,
		Chunks: []ChunkRef{
			{ID: strings.Repeat("a", 64), Size: 4096, Offset: 0},
			{ID: strings.Repeat("b", 64), Size: 4096, Offset: 4096},
		},
	}
	if err := r.PutManifest(m); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	got, err := r.GetManifest("vm1", "2026-05-09T12:34:56Z", "root")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if got.VMName != m.VMName || got.DiskName != m.DiskName || len(got.Chunks) != 2 {
		t.Errorf("manifest round-trip mismatch: %+v", got)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Errorf("manifest schema = %d, want %d", got.SchemaVersion, SchemaVersion)
	}
}

// TestListManifests_SortedByTimestamp drops three manifests with
// out-of-order ts and verifies List returns them in ascending order.
func TestListManifests_SortedByTimestamp(t *testing.T) {
	r := newTestRepo(t)
	for _, ts := range []string{"2026-05-09T03:00:00Z", "2026-05-09T01:00:00Z", "2026-05-09T02:00:00Z"} {
		if err := r.PutManifest(&Manifest{
			VMName: "vm", DiskName: "root", Timestamp: ts,
		}); err != nil {
			t.Fatalf("PutManifest: %v", err)
		}
	}
	got, err := r.ListManifests()
	if err != nil {
		t.Fatalf("ListManifests: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Timestamp >= got[i].Timestamp {
			t.Errorf("not sorted: %v", got)
		}
	}
}

// TestReadChunks_AlignsToChunkSize feeds an 11-byte stream through
// ReadChunks with a 4-byte buffer and asserts the offsets and final
// short chunk arrive correctly.
func TestReadChunks_AlignsToChunkSize(t *testing.T) {
	src := bytes.NewReader([]byte("hello world"))
	buf := make([]byte, 4)
	type rec struct {
		off  int64
		data string
	}
	var got []rec
	if err := ReadChunks(src, buf, func(off int64, data []byte) error {
		got = append(got, rec{off, string(append([]byte(nil), data...))})
		return nil
	}); err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}
	want := []rec{
		{0, "hell"}, {4, "o wo"}, {8, "rld"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rec %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestReadChunks_EmptyReader returns no records and no error.
func TestReadChunks_EmptyReader(t *testing.T) {
	var calls int
	err := ReadChunks(bytes.NewReader(nil), nil, func(off int64, data []byte) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}
	if calls != 0 {
		t.Errorf("expected 0 callbacks for empty reader, got %d", calls)
	}
}

// TestReadChunks_PropagatesError surfaces user callback errors.
func TestReadChunks_PropagatesError(t *testing.T) {
	want := errors.New("boom")
	err := ReadChunks(bytes.NewReader([]byte("data")), make([]byte, 2), func(int64, []byte) error {
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("expected %v, got %v", want, err)
	}
}

// TestPutChunk_EnsuresParentDirShard verifies the chunks/aa/aabbcc...
// shard is created.
func TestPutChunk_EnsuresParentDirShard(t *testing.T) {
	r := newTestRepo(t)
	id, _, err := r.PutChunk([]byte("shard me"))
	if err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	if len(id) < 2 {
		t.Fatalf("unexpectedly short id %q", id)
	}
	shardDir := filepath.Join(r.root, "chunks", id[:2])
	if _, err := os.Stat(shardDir); err != nil {
		t.Errorf("shard dir missing: %v", err)
	}
}

// newTestRepo returns a fresh Repo in a t.TempDir.
func newTestRepo(t *testing.T) *Repo {
	t.Helper()
	r, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return r
}

// hush unused-imports for io even when only used in some test methods.
var _ = io.EOF
