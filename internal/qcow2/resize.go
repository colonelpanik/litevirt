package qcow2

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Resize grows the virtual size of a qcow2 image.
// newSizeBytes must be >= the current virtual size. Only grow is supported.
func Resize(path string, newSizeBytes uint64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	h, err := readHeader(f)
	if err != nil {
		return err
	}

	if newSizeBytes < h.Size {
		return fmt.Errorf("cannot shrink: current %d > requested %d", h.Size, newSizeBytes)
	}
	if newSizeBytes == h.Size {
		return nil // nothing to do
	}

	clusterSize := h.ClusterSize()
	newL1Size := l1Entries(newSizeBytes, clusterSize)

	if newL1Size > h.L1Size {
		// Need to expand the L1 table.
		if err := expandL1(f, h, newL1Size); err != nil {
			return fmt.Errorf("expand L1: %w", err)
		}
	}

	// Update virtual size and L1 size in the header.
	h.Size = newSizeBytes
	h.L1Size = newL1Size

	// Write the two fields directly to avoid rewriting the entire header.
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], newSizeBytes)
	if _, err := f.WriteAt(buf[:], 24); err != nil { // offset 24 = Size field
		return fmt.Errorf("write virtual size: %w", err)
	}
	var l1Buf [4]byte
	binary.BigEndian.PutUint32(l1Buf[:], newL1Size)
	if _, err := f.WriteAt(l1Buf[:], 36); err != nil { // offset 36 = L1Size field
		return fmt.Errorf("write L1 size: %w", err)
	}

	return f.Sync()
}

// expandL1 allocates a new, larger L1 table, copies old entries, and updates
// the header and refcounts accordingly.
func expandL1(f *os.File, h *Header, newL1Size uint32) error {
	clusterSize := h.ClusterSize()
	refcountBits := uint32(1) << h.RefcountOrder

	// Read existing L1 entries.
	oldL1Bytes := uint64(h.L1Size) * 8
	oldL1 := make([]byte, oldL1Bytes)
	if _, err := f.ReadAt(oldL1, int64(h.L1TableOffset)); err != nil {
		return fmt.Errorf("read old L1: %w", err)
	}

	// Determine how many clusters the new L1 table needs.
	newL1Bytes := uint64(newL1Size) * 8
	newL1Clusters := (newL1Bytes + clusterSize - 1) / clusterSize

	// Allocate new clusters at the end of the file.
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	fileSize := uint64(fi.Size())
	// Align to cluster boundary.
	newL1Offset := (fileSize + clusterSize - 1) / clusterSize * clusterSize

	// Write new L1 table (old entries + zeros for new entries).
	newL1 := make([]byte, newL1Clusters*clusterSize)
	copy(newL1, oldL1)
	if _, err := f.WriteAt(newL1, int64(newL1Offset)); err != nil {
		return fmt.Errorf("write new L1: %w", err)
	}

	// Update refcounts: +1 for new L1 clusters, -1 for old L1 clusters.
	// For simplicity, we set refcounts for new clusters and clear old ones.
	for i := uint64(0); i < newL1Clusters; i++ {
		clusterIdx := (newL1Offset / clusterSize) + i
		if err := setRefcount(f, h, clusterIdx, 1, refcountBits); err != nil {
			return fmt.Errorf("set refcount for new L1 cluster %d: %w", i, err)
		}
	}

	oldL1Clusters := (oldL1Bytes + clusterSize - 1) / clusterSize
	for i := uint64(0); i < oldL1Clusters; i++ {
		clusterIdx := (h.L1TableOffset / clusterSize) + i
		if err := setRefcount(f, h, clusterIdx, 0, refcountBits); err != nil {
			return fmt.Errorf("clear refcount for old L1 cluster %d: %w", i, err)
		}
	}

	// Update header with new L1 offset.
	h.L1TableOffset = newL1Offset
	h.L1Size = newL1Size
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], newL1Offset)
	if _, err := f.WriteAt(buf[:], 40); err != nil { // offset 40 = L1TableOffset
		return fmt.Errorf("write L1 offset: %w", err)
	}

	return nil
}

// setRefcount sets the refcount for a given cluster index by locating the
// correct refcount block (allocating a new one if needed).
func setRefcount(f *os.File, h *Header, clusterIdx uint64, value uint16, refcountBits uint32) error {
	clusterSize := h.ClusterSize()
	entriesPerBlock := clusterSize * 8 / uint64(refcountBits)

	blockIdx := clusterIdx / entriesPerBlock
	entryIdx := clusterIdx % entriesPerBlock

	// The refcount table entry for this block must lie within the table's own
	// cluster(s); if not, the image needs a larger refcount table (not grown here).
	// Fail loud rather than writing past the table into the following cluster.
	rcTableBytes := uint64(h.RefcountTableClusters) * clusterSize
	if blockIdx*8+8 > rcTableBytes {
		return fmt.Errorf("refcount table too small for cluster %d (block %d exceeds %d-byte table)",
			clusterIdx, blockIdx, rcTableBytes)
	}

	// Read refcount table entry.
	rcTableEntryOffset := int64(h.RefcountTableOffset) + int64(blockIdx*8)
	var rcEntry [8]byte
	if _, err := f.ReadAt(rcEntry[:], rcTableEntryOffset); err != nil {
		return fmt.Errorf("read rctable entry: %w", err)
	}
	blockOffset := binary.BigEndian.Uint64(rcEntry[:])

	if blockOffset == 0 {
		// Allocate a new refcount block at end of file.
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		blockOffset = (uint64(fi.Size()) + clusterSize - 1) / clusterSize * clusterSize
		newBlockCluster := blockOffset / clusterSize
		block := make([]byte, clusterSize)
		writeRefcount(block, entryIdx, value, refcountBits)
		// The new refcount block occupies a cluster that itself must be counted.
		// If that cluster falls within THIS block's own coverage, set it in-place
		// (the common case: the block sits right after the clusters it covers);
		// otherwise it belongs to a different block, handled by the recursive call
		// after this block is linked. Without this the new block's own cluster is
		// left refcount 0 → qemu treats it as free and hands it out on the next
		// allocation while it holds live refcount data → silent corruption.
		selfBlockIdx := newBlockCluster / entriesPerBlock
		if selfBlockIdx == blockIdx {
			writeRefcount(block, newBlockCluster%entriesPerBlock, 1, refcountBits)
		}
		if _, err := f.WriteAt(block, int64(blockOffset)); err != nil {
			return err
		}
		// Update refcount table.
		binary.BigEndian.PutUint64(rcEntry[:], blockOffset)
		if _, err := f.WriteAt(rcEntry[:], rcTableEntryOffset); err != nil {
			return err
		}
		if selfBlockIdx != blockIdx {
			// The new block's own cluster is covered by a different refcount block.
			// Count it there (bounded recursion — a block covers entriesPerBlock
			// clusters, so this terminates once a block's cluster lands in itself).
			return setRefcount(f, h, newBlockCluster, 1, refcountBits)
		}
		return nil
	}

	// Read existing block, update entry, write back.
	block := make([]byte, clusterSize)
	if _, rErr := f.ReadAt(block, int64(blockOffset)); rErr != nil {
		return rErr
	}
	writeRefcount(block, entryIdx, value, refcountBits)
	_, wErr := f.WriteAt(block, int64(blockOffset))
	return wErr
}
