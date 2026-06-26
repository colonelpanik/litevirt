package pbsstore

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// ManifestReader exposes a Manifest as a random-access io.ReaderAt so a
// VM can boot off a backup chain via NBD without first staging the
// whole disk. Reads are decrypted on the fly and cached in-memory at
// chunk granularity so a tight read-loop over the same chunk doesn't
// re-decrypt every call.
//
// Lifecycle: NewManifestReader opens the manifest, Close releases the
// chunk cache. Goroutine-safe — multiple NBD client threads share one
// reader concurrently.
type ManifestReader struct {
	repo     *Repo
	manifest *Manifest

	// chunks is sorted by Offset for O(log N) lookup. The manifest's
	// Chunks slice is already in offset order in practice, but we
	// re-sort defensively so a hand-edited manifest can't break us.
	chunks []ChunkRef

	cacheMu sync.Mutex
	cache   map[string][]byte // chunk-id → plaintext bytes
}

// NewManifestReader constructs a random-access reader over the given
// manifest backed by the given repo. The manifest's parent chain is
// NOT walked here — incremental manifests with BasedOn set rely on
// their chunk refs pointing into a parent's chunks via the shared
// content-addressed store. Repo.GetChunk handles that transparently.
func NewManifestReader(repo *Repo, m *Manifest) (*ManifestReader, error) {
	if m == nil {
		return nil, fmt.Errorf("nil manifest")
	}
	// The manifest is untrusted; validate its structure at the boundary so a
	// hand-edited/tampered manifest can't drive ReadAt with bad offsets/sizes.
	if err := ValidateManifest(m); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}
	chunks := make([]ChunkRef, len(m.Chunks))
	copy(chunks, m.Chunks)
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].Offset < chunks[j].Offset })
	return &ManifestReader{
		repo: repo, manifest: m, chunks: chunks,
		cache: map[string][]byte{},
	}, nil
}

// Size returns the manifest's logical disk size.
func (r *ManifestReader) Size() int64 { return r.manifest.TotalSize }

// ReadAt fulfills io.ReaderAt. Reads that span chunk boundaries are
// broken into per-chunk reads; reads past TotalSize return io.EOF.
// Holes in the chunk layout (gaps between consecutive ChunkRef
// offsets) read as zero bytes — preserves the same shape PushDisk
// emits when the source is a sparse qcow2.
func (r *ManifestReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ReadAt: negative offset %d", off)
	}
	if off >= r.manifest.TotalSize {
		return 0, io.EOF
	}
	end := off + int64(len(p))
	if end > r.manifest.TotalSize {
		end = r.manifest.TotalSize
		p = p[:int(end-off)]
	}
	for i := range p {
		p[i] = 0
	}
	// Find the first chunk whose end is past `off`.
	idx := sort.Search(len(r.chunks), func(i int) bool {
		return r.chunks[i].Offset+r.chunks[i].Size > off
	})
	var written int
	for i := idx; i < len(r.chunks); i++ {
		ch := r.chunks[i]
		if ch.Offset >= end {
			break
		}
		chunkData, err := r.fetch(ch)
		if err != nil {
			return written, fmt.Errorf("fetch chunk %s: %w", ch.ID, err)
		}
		// Compute the overlap of [ch.Offset, ch.Offset+ch.Size)
		// with the requested window [off, end).
		readStart := off
		if ch.Offset > readStart {
			readStart = ch.Offset
		}
		readEnd := end
		if ch.Offset+ch.Size < readEnd {
			readEnd = ch.Offset + ch.Size
		}
		if readEnd <= readStart {
			continue
		}
		copy(p[readStart-off:readEnd-off], chunkData[readStart-ch.Offset:readEnd-ch.Offset])
		if int(readEnd-off) > written {
			written = int(readEnd - off)
		}
	}
	// Return len(p) even when there are zero-fill holes — the caller
	// wants the full requested range, and we just return zeros for
	// uncovered byte ranges (the source disk semantics).
	return len(p), nil
}

// Close drops the chunk cache so memory is reclaimed. Safe to call
// even with concurrent ReadAt in flight (cache is recreated lazily).
func (r *ManifestReader) Close() error {
	r.cacheMu.Lock()
	r.cache = map[string][]byte{}
	r.cacheMu.Unlock()
	return nil
}

// fetch returns the plaintext bytes for a chunk, populating the cache
// on miss. We keep an unbounded cache for simplicity; the typical VM
// boot reads ~100 MiB of sectors, which at 4 MiB/chunk is 25 entries.
// A bound is a polish.
func (r *ManifestReader) fetch(ch ChunkRef) ([]byte, error) {
	r.cacheMu.Lock()
	if data, ok := r.cache[ch.ID]; ok {
		r.cacheMu.Unlock()
		return data, nil
	}
	r.cacheMu.Unlock()

	data, err := r.repo.GetChunk(ch.ID)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != ch.Size {
		return nil, fmt.Errorf("chunk %s size %d, manifest expected %d", ch.ID, len(data), ch.Size)
	}

	r.cacheMu.Lock()
	r.cache[ch.ID] = data
	r.cacheMu.Unlock()
	return data, nil
}

var _ io.ReaderAt = (*ManifestReader)(nil)
