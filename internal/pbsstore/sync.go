package pbsstore

import (
	"context"
	"fmt"
)

// SyncStats summarises a SyncRepo pass.
type SyncStats struct {
	ManifestsCopied int
	ChunksCopied    int
	ChunksSkipped   int // already present at destination
	BytesCopied     int64
}

// SyncRepo copies any manifests in src missing from dst, plus the
// chunks they reference. Chunks already present at the destination
// are skipped (content-addressing makes this trivial — same id implies
// same bytes, so re-copying would waste IO).
//
// Encryption mode and per-chunk format must agree between src and dst
// (or the chunks are bit-identical regardless). We refuse a sync if
// the modes differ to prevent silently writing plaintext into an
// encrypted DR copy.
//
// SyncRepo is idempotent: running it repeatedly is a no-op once both
// sides are in sync.
//
// This local-to-local helper is the building block for the over-the-wire
// gRPC SyncRepo RPC, where dst is replaced
// with a streaming client. Both share the same diff logic; the wire
// version only adds a transport adapter.
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
		// Push every chunk this manifest references that's missing at dst —
		// including the firmware-state bundle, or a synced vTPM backup would
		// restore without its NVRAM/swtpm state.
		for _, c := range m.AllChunks() {
			if dst.HasChunk(c.ID) {
				stats.ChunksSkipped++
				continue
			}
			data, err := src.GetChunk(c.ID)
			if err != nil {
				return stats, fmt.Errorf("read source chunk %s: %w", c.ID, err)
			}
			if _, _, err := dst.PutChunk(data); err != nil {
				return stats, fmt.Errorf("put dest chunk %s: %w", c.ID, err)
			}
			stats.ChunksCopied++
			stats.BytesCopied += int64(len(data))
		}
		// Manifest written last — chunks must be present before a
		// reader could observe the manifest.
		manifestCopy := m
		if err := dst.PutManifest(&manifestCopy); err != nil {
			return stats, fmt.Errorf("put dest manifest: %w", err)
		}
		stats.ManifestsCopied++
	}
	return stats, nil
}
