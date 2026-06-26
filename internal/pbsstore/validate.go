package pbsstore

import (
	"fmt"
	"math"

	"github.com/litevirt/litevirt/internal/safename"
)

// ValidateManifest checks a manifest is structurally sound before it is written,
// read, or used to drive a restore/prune. A manifest is untrusted data (it lives
// in a backup repo that may be shared, synced, or tampered with), so this guards
// both the path-bearing fields — VM/disk names and timestamps that compose the
// on-disk manifest filename — and the chunk lists, so a malformed manifest can't
// drive a bad restore even when it can't escape a path.
func ValidateManifest(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("nil manifest")
	}
	if err := safename.ValidateVMName(m.VMName); err != nil {
		return fmt.Errorf("manifest vm name: %w", err)
	}
	if err := safename.ValidateDiskName(m.DiskName); err != nil {
		return fmt.Errorf("manifest disk name: %w", err)
	}
	if err := safename.ValidateTimestamp(m.Timestamp); err != nil {
		return fmt.Errorf("manifest timestamp: %w", err)
	}
	// BasedOn is optional: empty means this is a full backup, not an error.
	if m.BasedOn != "" {
		if err := safename.ValidateTimestamp(m.BasedOn); err != nil {
			return fmt.Errorf("manifest based_on: %w", err)
		}
	}
	if m.TotalSize < 0 {
		return fmt.Errorf("manifest total_size negative (%d)", m.TotalSize)
	}
	// Disk chunks reconstruct the disk: every chunk must lie within [0,TotalSize)
	// (backups are sparse, so chunk sizes need NOT sum to TotalSize — holes are
	// skipped and zero-filled on restore).
	if err := validateChunkList(m.Chunks, true, m.TotalSize); err != nil {
		return fmt.Errorf("manifest chunks: %w", err)
	}
	// Firmware chunks are a SEPARATE blob (the nvram+swtpm tar); validate them
	// the same way but with no TotalSize bound — they don't belong to the disk
	// extent.
	if err := validateChunkList(m.FirmwareChunks, false, 0); err != nil {
		return fmt.Errorf("manifest firmware chunks: %w", err)
	}
	return nil
}

// validateChunkList checks a chunk list: every id is 64-char hex, sizes/offsets
// are non-negative, each size is <= ChunkSize, and offsets are monotonically
// increasing and non-overlapping. When bounded is true, each chunk's extent
// (offset+size) must also be <= maxExtent (the disk's TotalSize).
func validateChunkList(chunks []ChunkRef, bounded bool, maxExtent int64) error {
	prevEnd := int64(0) // first byte not yet covered by an earlier chunk
	first := true
	for i, c := range chunks {
		if err := safename.ValidateChunkID(c.ID); err != nil {
			return fmt.Errorf("chunk %d: %w", i, err)
		}
		if c.Size < 0 || c.Offset < 0 {
			return fmt.Errorf("chunk %d: negative size/offset (size=%d offset=%d)", i, c.Size, c.Offset)
		}
		if c.Size > ChunkSize {
			return fmt.Errorf("chunk %d: size %d exceeds ChunkSize %d", i, c.Size, ChunkSize)
		}
		if !first && c.Offset < prevEnd {
			return fmt.Errorf("chunk %d: offset %d overlaps/regresses previous extent ending at %d", i, c.Offset, prevEnd)
		}
		// Guard against int64 overflow before computing the extent.
		if c.Offset > math.MaxInt64-c.Size {
			return fmt.Errorf("chunk %d: offset %d + size %d overflows", i, c.Offset, c.Size)
		}
		end := c.Offset + c.Size
		if bounded && end > maxExtent {
			return fmt.Errorf("chunk %d: extent %d exceeds total_size %d", i, end, maxExtent)
		}
		prevEnd = end
		first = false
	}
	return nil
}
