// Package pbsstore implements litevirt's PBS-equivalent backup repository:
// content-addressed deduped chunk storage with BLAKE3 hashing,
// dirty-bitmap incremental support, encryption, GC, and verify.
//
// is delivered in slices:
//
//	1.3.A (this file): on-disk chunk store + manifest format.
//	1.3.B: BackupSnapshot RPC streams a disk into a repo.
//	1.3.C: RestoreSnapshot RPC rebuilds a disk from a manifest.
//	1.3.D: Dirty-bitmap incremental.
//	1.3.E: GC (mark-and-sweep).
//	1.3.F: Retention + verify.
//	1.3.G: Encryption.
//	1.3.H: SyncRepo over mTLS gRPC.
//
// On-disk layout for a repository at /backup/repo-name:
//
//	/backup/repo-name/
//	├── repo.json              metadata: created_at, encryption-mode, schema-version
//	├── chunks/
//	│   ├── 0a/
//	│   │   ├── 0a1b2c…/       64-char-hex BLAKE3 of the chunk
//	│   │   └── …
//	│   └── …
//	└── snapshots/
//	    └── &lt;vm&gt;/
//	        └── &lt;ts&gt;-&lt;disk&gt;.manifest.json
//
// A chunk file is the chunk's bytes verbatim (encryption layered on top
// when enabled in 1.3.G — the on-disk filename is still the BLAKE3 of
// the *plaintext* so dedup survives key rotation).
package pbsstore

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/safename"
	"lukechampine.com/blake3"
)

// SchemaVersion is bumped on incompatible repository-format changes.
const SchemaVersion = 1

// ChunkSize is the rolling window we feed into BLAKE3. 4 MiB matches
// PBS's default and balances dedup ratio vs metadata overhead.
const ChunkSize = 4 * 1024 * 1024

// ErrChunkMismatch is returned when a chunk read back from disk does
// not hash to the expected ID. Indicates corruption.
var ErrChunkMismatch = errors.New("chunk hash mismatch")

// RepoMeta is the contents of repo.json.
type RepoMeta struct {
	SchemaVersion int    `json:"schema_version"`
	CreatedAt     string `json:"created_at"`
	Encryption    string `json:"encryption,omitempty"` // "" | "aes256gcm" (1.3.G)
}

// ChunkRef is a manifest entry pointing at one chunk in the store.
type ChunkRef struct {
	ID     string `json:"id"`     // hex BLAKE3 of plaintext bytes
	Size   int64  `json:"size"`   // plaintext bytes; <= ChunkSize
	Offset int64  `json:"offset"` // byte offset inside the source disk
}

// Manifest describes one snapshot — i.e. one VM disk frozen at a point
// in time, expressed as an ordered list of ChunkRefs whose concatenation
// reproduces the disk byte-for-byte.
type Manifest struct {
	VMName     string     `json:"vm_name"`
	DiskName   string     `json:"disk_name"`
	Timestamp  string     `json:"timestamp"`  // RFC3339
	TotalSize  int64      `json:"total_size"` // sum of chunk sizes
	Chunks     []ChunkRef `json:"chunks"`
	BasedOn    string     `json:"based_on,omitempty"`    // 1.3.D incremental parent ts
	BitmapName string     `json:"bitmap_name,omitempty"` // 1.3.D libvirt checkpoint/bitmap id
	// VMSpecJSON embeds the source VM's serialized pb.VMSpec so a live
	// restore can auto-define the domain without the source cluster.
	// Captured on the root-disk manifest only; empty on older manifests.
	VMSpecJSON string `json:"vm_spec_json,omitempty"`
	// DomainXML embeds the live domain XML at backup time (best-effort,
	// for fidelity/debugging). Restore prefers VMSpecJSON.
	DomainXML string `json:"domain_xml,omitempty"`
	// FirmwareChunks references the content-addressed firmware-state bundle
	// (UEFI NVRAM + swtpm state, tar) for a Secure-Boot/vTPM VM, so a restore
	// materializes BitLocker-binding firmware before defining the domain (G1).
	// Captured on the root-disk manifest only; empty for non-firmware VMs.
	FirmwareChunks []ChunkRef `json:"firmware_chunks,omitempty"`
	// ContainerSpecJSON embeds a serialized container spec (cpu/mem/labels/
	// restart/project/image) for a container backup, so a restore can recreate
	// the cluster row without the source cluster. The archived rootfs+config
	// carries everything else. Empty on VM-disk manifests.
	ContainerSpecJSON string `json:"container_spec_json,omitempty"`
	SchemaVersion     int    `json:"schema_version"`
}

// Repo is an open backup repository. Multiple goroutines may use one
// Repo concurrently — chunk writes are atomic (tmp+rename) and
// idempotent (same content → same id → same path).
type Repo struct {
	root string
	meta RepoMeta

	// writeMu guards the rare case where two writers race to create the
	// same chunk path. The fast path (chunk already present) doesn't
	// take the lock.
	writeMu sync.Mutex

	// aead, when non-nil, transparently seals chunk bytes before
	// writing and authenticates+decrypts on read. SetKey installs it.
	aead cipher.AEAD
}

// Init creates a new repository on disk. Refuses if the directory
// already contains a repo.json.
func Init(root string) (*Repo, error) {
	if err := os.MkdirAll(root, 0750); err != nil {
		return nil, fmt.Errorf("mkdir repo root: %w", err)
	}
	metaPath := filepath.Join(root, "repo.json")
	if _, err := os.Stat(metaPath); err == nil {
		return nil, fmt.Errorf("repository already initialised at %s", root)
	}
	for _, sub := range []string{"chunks", "snapshots"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0750); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", sub, err)
		}
	}
	meta := RepoMeta{
		SchemaVersion: SchemaVersion,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeJSONAtomic(metaPath, meta); err != nil {
		return nil, fmt.Errorf("write repo.json: %w", err)
	}
	return &Repo{root: root, meta: meta}, nil
}

// Open loads an existing repository. Errors if repo.json is missing or
// declares a schema-version newer than this binary supports.
func Open(root string) (*Repo, error) {
	metaPath := filepath.Join(root, "repo.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("read repo.json: %w", err)
	}
	var meta RepoMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse repo.json: %w", err)
	}
	if meta.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("repository schema-version %d newer than supported %d",
			meta.SchemaVersion, SchemaVersion)
	}
	return &Repo{root: root, meta: meta}, nil
}

// Root returns the on-disk root directory.
func (r *Repo) Root() string { return r.root }

// Meta returns a copy of the repository metadata.
func (r *Repo) Meta() RepoMeta { return r.meta }

// PutChunk writes the chunk to disk if not already present. Returns
// the BLAKE3 id and whether the chunk was newly created (false ⇒ dedup
// hit). The on-disk layout is chunks/aa/aabbcc… so directory listings
// stay reasonable.
func (r *Repo) PutChunk(data []byte) (id string, created bool, err error) {
	id = ChunkID(data)
	path := r.chunkPath(id)
	if _, err := os.Stat(path); err == nil {
		return id, false, nil
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	// Recheck after locking.
	if _, err := os.Stat(path); err == nil {
		return id, false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return "", false, fmt.Errorf("mkdir chunk dir: %w", err)
	}
	storage, err := r.encryptForStorage(data)
	if err != nil {
		return "", false, fmt.Errorf("seal chunk: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, storage, 0640); err != nil {
		return "", false, fmt.Errorf("write chunk tmp: %w", err)
	}
	// fsync the file before rename so a crash mid-write doesn't leave a
	// renamed-but-unflushed chunk that hashes to nothing on recovery.
	if err := fsyncFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return "", false, fmt.Errorf("fsync chunk tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", false, fmt.Errorf("rename chunk: %w", err)
	}
	return id, true, nil
}

// HasChunk reports whether a chunk with the given id exists in the repo.
func (r *Repo) HasChunk(id string) bool {
	if safename.ValidateChunkID(id) != nil {
		return false
	}
	_, err := os.Stat(r.chunkPath(id))
	return err == nil
}

// GetChunk reads a chunk, decrypts it (if the repo is encrypted), and
// verifies the BLAKE3 hash matches the chunk's filename. Returns
// ErrChunkMismatch on plaintext corruption and wraps ErrKeyMismatch
// when AES-GCM authentication fails.
func (r *Repo) GetChunk(id string) ([]byte, error) {
	if err := safename.ValidateChunkID(id); err != nil {
		return nil, err
	}
	storage, err := os.ReadFile(r.chunkPath(id))
	if err != nil {
		return nil, fmt.Errorf("read chunk %s: %w", id, err)
	}
	plaintext, err := r.decryptFromStorage(storage)
	if err != nil {
		return nil, err
	}
	if got := ChunkID(plaintext); got != id {
		return nil, fmt.Errorf("%w: stored=%s actual=%s", ErrChunkMismatch, id, got)
	}
	return plaintext, nil
}

// DeleteChunk removes a chunk. Used by GC; not exposed to callers
// directly because manifest-aware reference tracking is the only safe
// way to drop chunks.
func (r *Repo) DeleteChunk(id string) error {
	if err := safename.ValidateChunkID(id); err != nil {
		return err
	}
	if err := os.Remove(r.chunkPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// PutManifest writes a snapshot manifest at snapshots/<vm>/<ts>-<disk>.manifest.json.
// The timestamp portion is taken from m.Timestamp; if empty, "now" is used.
func (r *Repo) PutManifest(m *Manifest) error {
	if m.SchemaVersion == 0 {
		m.SchemaVersion = SchemaVersion
	}
	if m.Timestamp == "" {
		m.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if err := ValidateManifest(m); err != nil {
		return fmt.Errorf("refusing to write invalid manifest: %w", err)
	}
	dir := filepath.Join(r.root, "snapshots", m.VMName)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("mkdir snapshots dir: %w", err)
	}
	name := fmt.Sprintf("%s-%s.manifest.json", filenameSafeTS(m.Timestamp), m.DiskName)
	return writeJSONAtomic(filepath.Join(dir, name), m)
}

// GetManifest loads a single manifest by VM name + timestamp + disk name. The
// caller-supplied components are validated BEFORE they compose the on-disk path
// (filenameSafeTS only strips ':', so a '/'-bearing timestamp would otherwise
// escape), and the loaded manifest is validated before it's returned.
func (r *Repo) GetManifest(vm, ts, disk string) (*Manifest, error) {
	if err := safename.ValidateVMName(vm); err != nil {
		return nil, err
	}
	if err := safename.ValidateTimestamp(ts); err != nil {
		return nil, err
	}
	if err := safename.ValidateDiskName(disk); err != nil {
		return nil, err
	}
	path := filepath.Join(r.root, "snapshots", vm,
		fmt.Sprintf("%s-%s.manifest.json", filenameSafeTS(ts), disk))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if err := ValidateManifest(&m); err != nil {
		return nil, fmt.Errorf("invalid manifest %s@%s/%s: %w", vm, ts, disk, err)
	}
	return &m, nil
}

// LatestManifestFor returns the most-recent manifest for (vm, disk)
// in the repo. ok=false means there isn't one yet — caller should
// fall back to a full backup. Used by the incremental backup path to
// pick a parent without forcing the operator to track timestamps.
func (r *Repo) LatestManifestFor(vm, disk string) (*Manifest, bool, error) {
	all, err := r.ListManifests()
	if err != nil {
		return nil, false, err
	}
	var latest *Manifest
	for i := range all {
		m := &all[i]
		if m.VMName != vm || m.DiskName != disk {
			continue
		}
		if latest == nil || m.Timestamp > latest.Timestamp {
			latest = m
		}
	}
	if latest == nil {
		return nil, false, nil
	}
	return latest, true, nil
}

// ListManifests returns every manifest in the repo, sorted by timestamp
// ascending. Used by GC, retention, and the UI's snapshot list.
func (r *Repo) ListManifests() ([]Manifest, error) {
	var out []Manifest
	root := filepath.Join(r.root, "snapshots")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".manifest.json") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		// A structurally-invalid manifest is skipped (not fatal) so one bad file
		// can't deny listing every other backup, and it's never offered for a
		// restore/prune.
		if verr := ValidateManifest(&m); verr != nil {
			slog.Warn("pbsstore: skipping invalid manifest", "path", path, "error", verr)
			return nil
		}
		out = append(out, m)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp < out[j].Timestamp })
	return out, nil
}

// AllChunks returns every chunk a manifest references — the disk chunks plus
// the firmware-state bundle (nvram+swtpm). Repo maintenance (GC reachability,
// Verify, Sync) MUST iterate this, not just Chunks, or it would treat a valid
// backup's firmware bundle as garbage / miss it on verify / drop it on sync.
func (m *Manifest) AllChunks() []ChunkRef {
	if len(m.FirmwareChunks) == 0 {
		return m.Chunks
	}
	out := make([]ChunkRef, 0, len(m.Chunks)+len(m.FirmwareChunks))
	out = append(out, m.Chunks...)
	out = append(out, m.FirmwareChunks...)
	return out
}

// chunkPath returns the on-disk path for a chunk id. Splits into
// chunks/<first-2-chars>/<full-id> so directory size stays manageable.
func (r *Repo) chunkPath(id string) string {
	if len(id) < 2 {
		return filepath.Join(r.root, "chunks", id)
	}
	return filepath.Join(r.root, "chunks", id[:2], id)
}

// ChunkID returns the BLAKE3-256 hex digest of data — the canonical id
// used by every other API in this package.
func ChunkID(data []byte) string {
	h := blake3.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SplitIntoChunks reads from src and emits successive (offset, bytes)
// records of up to ChunkSize bytes. The final record is short. Used by
// BackupSnapshot in 1.3.B.
type ChunkBatch struct {
	Offset int64
	Data   []byte
}

// ReadChunks streams chunks from r in ChunkSize-aligned slices. It
// reuses the buffer passed via buf each iteration — callers must not
// retain the slice across calls.
func ReadChunks(r io.Reader, buf []byte, fn func(offset int64, data []byte) error) error {
	if len(buf) == 0 {
		buf = make([]byte, ChunkSize)
	}
	var off int64
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			if cb := fn(off, buf[:n]); cb != nil {
				return cb
			}
			off += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// writeJSONAtomic encodes v to JSON in a tmp file, fsyncs, then renames.
func writeJSONAtomic(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return err
	}
	if err := fsyncFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func fsyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	err = f.Sync()
	cerr := f.Close()
	if err != nil {
		return err
	}
	return cerr
}

// filenameSafeTS makes an RFC3339 timestamp safe to use as a filename
// (replaces ":" → "-" so Windows-imported repos don't break).
func filenameSafeTS(ts string) string {
	return strings.ReplaceAll(ts, ":", "-")
}

// randomChunkSuffix is reserved for tests that want predictable chunk
// ids. Production callers should never need this.
func randomChunkSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
