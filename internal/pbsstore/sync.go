package pbsstore

import (
	"context"
	"fmt"
)

// SyncStats summarises a SyncRepo / SyncManifest pass.
type SyncStats struct {
	ManifestsCopied int
	ChunksCopied    int
	ChunksSkipped   int // already present at destination
	BytesCopied     int64
}

func (s *SyncStats) add(o SyncStats) {
	s.ManifestsCopied += o.ManifestsCopied
	s.ChunksCopied += o.ChunksCopied
	s.ChunksSkipped += o.ChunksSkipped
	s.BytesCopied += o.BytesCopied
}

// ChunkSink is the write side of a content-addressed transfer: a destination
// that can be probed for chunk presence, fed plaintext chunks, and finally
// handed a manifest. A local *Repo satisfies it via RepoSink; a peer-streaming
// adapter (grpcapi.remoteRepoSink) satisfies it over mTLS, so the SAME diff
// logic (SyncManifest) drives both a local DR copy and a wire transfer.
//
// Plaintext crosses this boundary, never sealed bytes: the source's GetChunk
// decrypts+verifies on read and the sink's PutChunk re-encrypts at rest with the
// destination's OWN key. So no key ever crosses the wire and a transfer works
// across repos with differing encryption modes — which is why SyncManifest, unlike
// the sealed-byte SyncRepo, carries no encryption-mode guard.
type ChunkSink interface {
	// HasChunks reports presence of each id at the destination, in order. The
	// implementation may probe in bounded batches (a manifest can hold hundreds
	// of thousands of refs); callers pass the full id list.
	HasChunks(ctx context.Context, ids []string) ([]bool, error)
	// PutChunk writes one plaintext chunk. Idempotent (content-addressed): a
	// chunk already present is a no-op. The destination re-encrypts at rest.
	PutChunk(ctx context.Context, data []byte) error
	// PutManifest writes the manifest. MUST be called last — every chunk it
	// references has to be present first, so a reader never observes a manifest
	// whose chunks haven't landed.
	PutManifest(ctx context.Context, m *Manifest) error
}

// localSink adapts a *Repo to ChunkSink for the local-to-local SyncRepo path.
type localSink struct{ r *Repo }

// RepoSink returns a ChunkSink that writes into the given local repo.
func RepoSink(r *Repo) ChunkSink { return &localSink{r: r} }

func (s *localSink) HasChunks(_ context.Context, ids []string) ([]bool, error) {
	out := make([]bool, len(ids))
	for i, id := range ids {
		out[i] = s.r.HasChunk(id)
	}
	return out, nil
}

func (s *localSink) PutChunk(_ context.Context, data []byte) error {
	_, _, err := s.r.PutChunk(data)
	return err
}

func (s *localSink) PutManifest(_ context.Context, m *Manifest) error {
	return s.r.PutManifest(m)
}

// SyncManifest transfers exactly ONE manifest and only the chunks it references
// that the destination is missing, then writes the manifest last. It is the
// single-manifest building block behind every cross-host backup/restore/migrate
// transfer — unlike SyncRepo, which walks the whole repo (and would stream every
// historical backup). The destination is any ChunkSink (a local repo or a peer
// stream).
//
// Order: probe all referenced ids in one HasChunks call (the sink batches as
// needed), stream the missing chunks as plaintext, then PutManifest. On a chunk
// read/write error or context cancel, the manifest is NOT written, so the
// already-transferred content-addressed chunks remain only as harmless,
// GC-collectable orphans (nothing references them).
func SyncManifest(ctx context.Context, src *Repo, m *Manifest, dst ChunkSink) (SyncStats, error) {
	var stats SyncStats

	// De-duplicate ids: a manifest can reference the same chunk at multiple
	// offsets, and we only need to probe/transfer each once.
	refs := m.AllChunks()
	ids := make([]string, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, c := range refs {
		if _, ok := seen[c.ID]; ok {
			continue
		}
		seen[c.ID] = struct{}{}
		ids = append(ids, c.ID)
	}

	present, err := dst.HasChunks(ctx, ids)
	if err != nil {
		return stats, fmt.Errorf("probe destination chunks: %w", err)
	}
	if len(present) != len(ids) {
		return stats, fmt.Errorf("destination returned %d presence flags for %d ids", len(present), len(ids))
	}

	for i, id := range ids {
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		default:
		}
		if present[i] {
			stats.ChunksSkipped++
			continue
		}
		data, err := src.GetChunk(id)
		if err != nil {
			return stats, fmt.Errorf("read source chunk %s: %w", id, err)
		}
		if err := dst.PutChunk(ctx, data); err != nil {
			return stats, fmt.Errorf("put destination chunk %s: %w", id, err)
		}
		stats.ChunksCopied++
		stats.BytesCopied += int64(len(data))
	}

	// Manifest written last — chunks must be present before a reader could
	// observe the manifest.
	if err := dst.PutManifest(ctx, m); err != nil {
		return stats, fmt.Errorf("put destination manifest: %w", err)
	}
	stats.ManifestsCopied++
	return stats, nil
}

// SyncRepo copies any manifests in src missing from dst, plus the
// chunks they reference. Chunks already present at the destination
// are skipped (content-addressing makes this trivial — same id implies
// same bytes, so re-copying would waste IO).
//
// Encryption mode and per-chunk format must agree between src and dst
// (or the chunks are bit-identical regardless). We refuse a sync if
// the modes differ to prevent silently writing plaintext into an
// encrypted DR copy. (This guard is specific to the whole-repo local
// copy; the per-manifest wire path — SyncManifest — works on plaintext
// and intentionally tolerates differing encryption modes.)
//
// SyncRepo is idempotent: running it repeatedly is a no-op once both
// sides are in sync.
func SyncRepo(ctx context.Context, src, dst *Repo) (SyncStats, error) {
	var stats SyncStats
	if src.meta.Encryption != dst.meta.Encryption {
		return stats, fmt.Errorf(
			"encryption mode mismatch: src=%q dst=%q — refusing to sync",
			src.meta.Encryption, dst.meta.Encryption)
	}
	manifests, err := src.ListManifests()
	if err != nil {
		return stats, fmt.Errorf("list source manifests: %w", err)
	}
	sink := RepoSink(dst)
	for _, m := range manifests {
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		default:
		}
		// Manifest already at destination?
		if _, err := dst.GetManifest(m.VMName, m.Timestamp, m.DiskName); err == nil {
			continue
		}
		manifestCopy := m
		st, err := SyncManifest(ctx, src, &manifestCopy, sink)
		if err != nil {
			return stats, err
		}
		stats.add(st)
	}
	return stats, nil
}
