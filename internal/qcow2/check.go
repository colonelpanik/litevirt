package qcow2

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Check validates the internal consistency of a qcow2 file.
// It verifies: magic/version, refcount integrity, L1/L2 table bounds,
// and backing file metadata.
func Check(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	h, err := readHeader(f)
	if err != nil {
		return err
	}

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	fileSize := uint64(fi.Size())
	clusterSize := h.ClusterSize()

	// Validate basic header fields.
	if h.ClusterBits < 9 || h.ClusterBits > 21 {
		return fmt.Errorf("invalid cluster_bits %d", h.ClusterBits)
	}
	if h.Size == 0 {
		return fmt.Errorf("virtual size is 0")
	}
	if h.RefcountOrder > 6 {
		return fmt.Errorf("invalid refcount_order %d", h.RefcountOrder)
	}

	// Validate L1 table is within file bounds.
	l1Bytes := uint64(h.L1Size) * 8
	if h.L1TableOffset+l1Bytes > fileSize {
		return fmt.Errorf("L1 table extends beyond file (offset %d + %d > %d)",
			h.L1TableOffset, l1Bytes, fileSize)
	}

	// Validate refcount table is within file bounds.
	rcTableBytes := uint64(h.RefcountTableClusters) * clusterSize
	if h.RefcountTableOffset+rcTableBytes > fileSize {
		return fmt.Errorf("refcount table extends beyond file")
	}

	// Validate backing file metadata.
	if h.BackingFileOffset > 0 {
		if h.BackingFileOffset+uint64(h.BackingFileSize) > clusterSize {
			return fmt.Errorf("backing file path extends beyond cluster 0")
		}
	}

	// Validate L1 → L2 references are within file bounds.
	l1 := make([]byte, l1Bytes)
	if _, err := f.ReadAt(l1, int64(h.L1TableOffset)); err != nil {
		return fmt.Errorf("read L1 table: %w", err)
	}

	for i := uint64(0); i < uint64(h.L1Size); i++ {
		l1Entry := binary.BigEndian.Uint64(l1[i*8 : i*8+8])
		l2Offset := l1Entry & 0x00fffffffffffe00
		if l2Offset == 0 {
			continue
		}
		if l2Offset+clusterSize > fileSize {
			return fmt.Errorf("L1[%d] points to L2 at %d, beyond file end %d",
				i, l2Offset, fileSize)
		}

		// Validate L2 entries.
		l2 := make([]byte, clusterSize)
		if _, err := f.ReadAt(l2, int64(l2Offset)); err != nil {
			return fmt.Errorf("read L2 at %d: %w", l2Offset, err)
		}

		l2Entries := clusterSize / 8
		for j := uint64(0); j < l2Entries; j++ {
			l2Entry := binary.BigEndian.Uint64(l2[j*8 : j*8+8])
			if l2Entry == 0 {
				continue
			}
			if l2Entry&(1<<62) != 0 {
				// Compressed — validate host offset is within file.
				csizeShift := 62 - (h.ClusterBits - 8)
				csizeMask := (uint64(1) << (h.ClusterBits - 8)) - 1
				offsetMask := (uint64(1) << csizeShift) - 1
				sectors := ((l2Entry >> csizeShift) & csizeMask) + 1
				hostOffset := l2Entry & offsetMask
				endByte := hostOffset + sectors*512
				if endByte > fileSize {
					return fmt.Errorf("L2[%d][%d] compressed data at %d+%d exceeds file",
						i, j, hostOffset, sectors*512)
				}
			} else {
				hostOffset := l2Entry & 0x00fffffffffffe00
				if hostOffset > 0 && hostOffset+clusterSize > fileSize {
					return fmt.Errorf("L2[%d][%d] data cluster at %d exceeds file",
						i, j, hostOffset)
				}
			}
		}
	}

	// Validate refcount table entries.
	rcTable := make([]byte, rcTableBytes)
	if _, err := f.ReadAt(rcTable, int64(h.RefcountTableOffset)); err != nil {
		return fmt.Errorf("read refcount table: %w", err)
	}

	rcEntries := rcTableBytes / 8
	for i := uint64(0); i < rcEntries; i++ {
		blockOffset := binary.BigEndian.Uint64(rcTable[i*8 : i*8+8])
		if blockOffset == 0 {
			continue
		}
		if blockOffset+clusterSize > fileSize {
			return fmt.Errorf("refcount table[%d] points to block at %d, beyond file",
				i, blockOffset)
		}
	}

	return nil
}
