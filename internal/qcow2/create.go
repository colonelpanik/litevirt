package qcow2

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// closeAndCleanup closes c and folds any Close error into err (when err is
// otherwise nil), then removes path if the overall result is an error. A failed
// Close/fsync on a freshly written qcow2 means the header may not be durable, so
// the file is removed rather than left in a suspect state. Used from a deferred
// `err = closeAndCleanup(f, path, err)` so it can amend the named return.
func closeAndCleanup(c io.Closer, path string, err error) error {
	if cerr := c.Close(); cerr != nil && err == nil {
		err = fmt.Errorf("close %s: %w", path, cerr)
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// Create creates a new empty qcow2 v3 image at path with the given virtual size.
// opts may be nil for defaults (64 KB clusters, 16-bit refcounts).
func Create(path string, sizeBytes uint64, opts *Options) error {
	if sizeBytes == 0 {
		return fmt.Errorf("virtual size must be > 0")
	}
	return createImage(path, "", "", sizeBytes, opts)
}

// CreateWithBacking creates a qcow2 overlay image backed by backingPath.
// If sizeBytes is 0, the virtual size is inherited from the backing file.
// opts may be nil for defaults.
func CreateWithBacking(path, backingPath string, sizeBytes uint64, opts *Options) error {
	if backingPath == "" {
		return fmt.Errorf("backing file path is required")
	}

	// Inherit virtual size from backing file when not specified.
	if sizeBytes == 0 {
		info, err := Info(backingPath)
		if err != nil {
			return fmt.Errorf("read backing file %s: %w", backingPath, err)
		}
		sizeBytes = info.VirtualSize
	}
	if sizeBytes == 0 {
		return fmt.Errorf("could not determine virtual size from backing file")
	}

	// A local backing file produced by litevirt is itself a qcow2 image.
	return createImage(path, backingPath, "qcow2", sizeBytes, opts)
}

// CreateWithBackingFormat creates a qcow2 overlay backed by a local file with
// an explicit backing format ("qcow2" or "raw"). Failover promotion uses it: a
// replica may be a full qcow2 copy or a raw incremental replica, and declaring
// the wrong backing format makes qemu reject the image at open time. When
// sizeBytes is 0 it is inferred — from the qcow2 header for a qcow2 backing, or
// the file size for a raw one.
func CreateWithBackingFormat(path, backingPath, backingFormat string, sizeBytes uint64, opts *Options) error {
	if backingPath == "" {
		return fmt.Errorf("backing file path is required")
	}
	if backingFormat != "qcow2" && backingFormat != "raw" {
		return fmt.Errorf("backing format must be qcow2 or raw, got %q", backingFormat)
	}
	if sizeBytes == 0 {
		if backingFormat == "qcow2" {
			info, err := Info(backingPath)
			if err != nil {
				return fmt.Errorf("read backing file %s: %w", backingPath, err)
			}
			sizeBytes = info.VirtualSize
		} else {
			st, err := os.Stat(backingPath)
			if err != nil {
				return fmt.Errorf("stat backing file %s: %w", backingPath, err)
			}
			sizeBytes = uint64(st.Size())
		}
	}
	if sizeBytes == 0 {
		return fmt.Errorf("could not determine virtual size from backing file")
	}
	return createImage(path, backingPath, backingFormat, sizeBytes, opts)
}

// CreateWithBackingURI creates a qcow2 overlay whose backing reference
// is an arbitrary URI rather than a local file path. Used by the
// live-restore path where the backing is `nbd://host:port/export` —
// the qcow2 itself can't introspect a virtual size out of that, so
// sizeBytes is required.
//
// qemu accepts the URI through the backing_file header verbatim and
// resolves it via its own NBD client when the qcow2 is opened.
//
// The backing format is declared as "raw": the live-restore NBD export
// (internal/nbd backed by a pbsstore.ManifestReader) serves GUEST-VISIBLE
// raw content, not a nested qcow2 container. Declaring it "qcow2" makes qemu
// reject the backing with "Image is not in qcow2 format" at open/start time.
func CreateWithBackingURI(path, backingURI string, sizeBytes uint64, opts *Options) error {
	if backingURI == "" {
		return fmt.Errorf("backing URI is required")
	}
	if sizeBytes == 0 {
		return fmt.Errorf("sizeBytes is required (cannot introspect a URI backing)")
	}
	return createImage(path, backingURI, "raw", sizeBytes, opts)
}

// createImage is the shared implementation for Create and CreateWithBacking.
//
// On-disk layout (cluster indices):
//
//	Cluster 0: Header + header extensions + optional backing file path
//	Cluster 1: Refcount table
//	Cluster 2: Refcount block 0
//	Cluster 3: L1 table
func createImage(path, backingPath, backingFormat string, sizeBytes uint64, opts *Options) (err error) {
	clusterBits := opts.clusterBits()
	clusterSize := opts.clusterSize()
	refcountOrder := opts.refcountOrder()

	l1Size := l1Entries(sizeBytes, clusterSize)

	// How many clusters the L1 table needs.
	l1Bytes := uint64(l1Size) * 8
	l1Clusters := (l1Bytes + clusterSize - 1) / clusterSize
	if l1Clusters == 0 {
		l1Clusters = 1
	}

	// Total metadata clusters: header(1) + rctable(1) + rcblock(1) + L1(l1Clusters).
	totalMeta := 3 + l1Clusters

	h := &Header{
		Magic:                 Magic,
		Version:               Version,
		ClusterBits:           clusterBits,
		Size:                  sizeBytes,
		L1Size:                l1Size,
		L1TableOffset:         3 * clusterSize, // cluster 3
		RefcountTableOffset:   1 * clusterSize, // cluster 1
		RefcountTableClusters: 1,
		RefcountOrder:         refcountOrder,
		HeaderLength:          104,
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer func() { err = closeAndCleanup(f, path, err) }()

	// Write header.
	if err = writeHeader(f, h); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Write header extensions + backing file path (all within cluster 0).
	extOffset := int64(104)
	if backingPath != "" {
		// Backing format extension. Defaults to "qcow2" for a plain backing
		// file; callers that back onto raw content (e.g. an NBD URI) pass
		// "raw" so qemu opens the backing with the correct driver.
		bf := backingFormat
		if bf == "" {
			bf = "qcow2"
		}
		n, wErr := writeHeaderExtension(f, extOffset, ExtBackingFormat, []byte(bf))
		if wErr != nil {
			err = fmt.Errorf("write backing format ext: %w", wErr)
			return err
		}
		extOffset += n
	}

	// End-of-extensions marker.
	if err = writeEndOfExtensions(f, extOffset); err != nil {
		return fmt.Errorf("write end-of-extensions: %w", err)
	}
	extOffset += 8

	// Write backing file path (after extensions, still in cluster 0).
	if backingPath != "" {
		backingBytes := []byte(backingPath)
		h.BackingFileOffset = uint64(extOffset)
		h.BackingFileSize = uint32(len(backingBytes))
		if _, wErr := f.WriteAt(backingBytes, extOffset); wErr != nil {
			err = fmt.Errorf("write backing file path: %w", wErr)
			return err
		}

		// Re-write header with updated backing file offset/size.
		if err = writeHeader(f, h); err != nil {
			return fmt.Errorf("rewrite header: %w", err)
		}
	}

	// Cluster 1: Refcount table — one entry pointing to refcount block 0 at cluster 2.
	rcTable := make([]byte, clusterSize)
	binary.BigEndian.PutUint64(rcTable[0:8], 2*clusterSize) // rcblock 0 at cluster 2
	if _, err = f.WriteAt(rcTable, int64(1*clusterSize)); err != nil {
		return fmt.Errorf("write refcount table: %w", err)
	}

	// Cluster 2: Refcount block 0 — set refcount=1 for each metadata cluster.
	rcBlock := make([]byte, clusterSize)
	refcountBits := uint32(1) << refcountOrder
	for i := uint64(0); i < totalMeta; i++ {
		writeRefcount(rcBlock, i, 1, refcountBits)
	}
	if _, err = f.WriteAt(rcBlock, int64(2*clusterSize)); err != nil {
		return fmt.Errorf("write refcount block: %w", err)
	}

	// Cluster 3+: L1 table — all zeros (no data allocated yet).
	l1Table := make([]byte, l1Clusters*clusterSize)
	if _, err = f.WriteAt(l1Table, int64(3*clusterSize)); err != nil {
		return fmt.Errorf("write L1 table: %w", err)
	}

	if err = f.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	// Self-check. The contents are Sync'd above, so Check can read them back
	// while f is still open; the deferred closeAndCleanup performs the single
	// close (and surfaces any close error). Closing here too would double-close
	// and the spurious "file already closed" error would wrongly remove the file.
	if checkErr := Check(path); checkErr != nil {
		err = fmt.Errorf("post-create check failed: %w", checkErr)
		return err
	}
	return nil
}

// writeRefcount sets the refcount for cluster index idx in a refcount block.
func writeRefcount(block []byte, idx uint64, value uint16, refcountBits uint32) {
	switch refcountBits {
	case 16:
		off := idx * 2
		if off+2 <= uint64(len(block)) {
			binary.BigEndian.PutUint16(block[off:off+2], value)
		}
	case 32:
		off := idx * 4
		if off+4 <= uint64(len(block)) {
			binary.BigEndian.PutUint32(block[off:off+4], uint32(value))
		}
	case 8:
		if idx < uint64(len(block)) {
			block[idx] = byte(value)
		}
	case 1:
		byteIdx := idx / 8
		bitIdx := 7 - (idx % 8)
		if byteIdx < uint64(len(block)) {
			if value != 0 {
				block[byteIdx] |= 1 << bitIdx
			} else {
				block[byteIdx] &^= 1 << bitIdx
			}
		}
	case 2:
		byteIdx := idx / 4
		shift := (3 - (idx % 4)) * 2
		if byteIdx < uint64(len(block)) {
			block[byteIdx] = (block[byteIdx] &^ (3 << shift)) | (byte(value&3) << shift)
		}
	case 4:
		byteIdx := idx / 2
		shift := (1 - (idx % 2)) * 4
		if byteIdx < uint64(len(block)) {
			block[byteIdx] = (block[byteIdx] &^ (0xf << shift)) | (byte(value&0xf) << shift)
		}
	case 64:
		off := idx * 8
		if off+8 <= uint64(len(block)) {
			binary.BigEndian.PutUint64(block[off:off+8], uint64(value))
		}
	}
}

// readRefcount reads the refcount for cluster index idx from a refcount block.
func readRefcount(block []byte, idx uint64, refcountBits uint32) uint64 {
	switch refcountBits {
	case 16:
		off := idx * 2
		if off+2 <= uint64(len(block)) {
			return uint64(binary.BigEndian.Uint16(block[off : off+2]))
		}
	case 32:
		off := idx * 4
		if off+4 <= uint64(len(block)) {
			return uint64(binary.BigEndian.Uint32(block[off : off+4]))
		}
	case 8:
		if idx < uint64(len(block)) {
			return uint64(block[idx])
		}
	case 1:
		byteIdx := idx / 8
		bitIdx := 7 - (idx % 8)
		if byteIdx < uint64(len(block)) {
			return uint64((block[byteIdx] >> bitIdx) & 1)
		}
	case 2:
		byteIdx := idx / 4
		shift := (3 - (idx % 4)) * 2
		if byteIdx < uint64(len(block)) {
			return uint64((block[byteIdx] >> shift) & 3)
		}
	case 4:
		byteIdx := idx / 2
		shift := (1 - (idx % 2)) * 4
		if byteIdx < uint64(len(block)) {
			return uint64((block[byteIdx] >> shift) & 0xf)
		}
	case 64:
		off := idx * 8
		if off+8 <= uint64(len(block)) {
			return binary.BigEndian.Uint64(block[off : off+8])
		}
	}
	return 0
}
