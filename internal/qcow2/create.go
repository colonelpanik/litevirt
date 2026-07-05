package qcow2

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// fsyncDir best-effort fsyncs a directory so a rename into it survives power
// loss. Errors are ignored: the file is already renamed and valid on the live
// filesystem; the dir fsync only upgrades crash-durability of the directory entry.
func fsyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

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
//	Cluster 0:                     Header + header extensions + optional backing path
//	Clusters [1, 1+T):             Refcount table (T clusters)
//	Clusters [1+T, 1+T+B):         Refcount blocks (B clusters)
//	Clusters [1+T+B, 1+T+B+L1):    L1 table
//
// The refcount blocks (B) and table (T) must count EVERY metadata cluster,
// including themselves — both are self-referential, so their sizes are solved
// by a fixed-point iteration. At the 64K default this settles at T=1, B=1 (the
// classic single-block layout: rctable@1, rcblock@2, L1@3); only a small cluster
// size with a large virtual size needs B>1. Writing a single fixed block there
// (the old behavior) silently dropped the refcounts of every metadata cluster
// past the block's capacity — qemu would later hand those in-use clusters to a
// new allocation, corrupting the guest.
func createImage(path, backingPath, backingFormat string, sizeBytes uint64, opts *Options) (err error) {
	clusterBits := opts.clusterBits()
	clusterSize := opts.clusterSize()
	refcountOrder := opts.refcountOrder()
	refcountBits := uint32(1) << refcountOrder
	entriesPerBlock := clusterSize * 8 / uint64(refcountBits)

	l1Size := l1Entries(sizeBytes, clusterSize)
	l1Bytes := uint64(l1Size) * 8
	l1Clusters := (l1Bytes + clusterSize - 1) / clusterSize
	if l1Clusters == 0 {
		l1Clusters = 1
	}

	// Solve refcount-table-cluster (T) and refcount-block (B) counts to a fixed
	// point: B must cover header+T+B+L1 metadata clusters, and T must be able to
	// point at B blocks. Both grow monotonically, so this converges in a few steps.
	rcTableClusters := uint64(1)
	rcBlocks := uint64(1)
	for {
		totalMeta := 1 + rcTableClusters + rcBlocks + l1Clusters
		neededBlocks := (totalMeta + entriesPerBlock - 1) / entriesPerBlock
		neededTable := (neededBlocks*8 + clusterSize - 1) / clusterSize
		if neededBlocks <= rcBlocks && neededTable <= rcTableClusters {
			break
		}
		if neededBlocks > rcBlocks {
			rcBlocks = neededBlocks
		}
		if neededTable > rcTableClusters {
			rcTableClusters = neededTable
		}
	}
	totalMeta := 1 + rcTableClusters + rcBlocks + l1Clusters

	rcTableOffset := 1 * clusterSize
	rcBlockBase := (1 + rcTableClusters) * clusterSize
	l1Offset := (1 + rcTableClusters + rcBlocks) * clusterSize

	h := &Header{
		Magic:                 Magic,
		Version:               Version,
		ClusterBits:           clusterBits,
		Size:                  sizeBytes,
		L1Size:                l1Size,
		L1TableOffset:         l1Offset,
		RefcountTableOffset:   rcTableOffset,
		RefcountTableClusters: uint32(rcTableClusters),
		RefcountOrder:         refcountOrder,
		HeaderLength:          104,
	}

	// Write to a temp file and atomically rename into place, then fsync the parent
	// dir: a crash mid-write can't leave a partial/torn qcow2 at the real path.
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			f.Close() // may double-close after the explicit Close below — harmless
			os.Remove(tmpPath)
		}
	}()

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
			return fmt.Errorf("write backing format ext: %w", wErr)
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
		// The header + extensions + backing path all live in cluster 0; refuse a
		// path that would spill into the refcount table rather than silently
		// corrupt it (previously only caught reactively by the post-create Check).
		if uint64(extOffset)+uint64(len(backingBytes)) > clusterSize {
			return fmt.Errorf("backing path (%d bytes at offset %d) does not fit in cluster 0 (%d bytes)",
				len(backingBytes), extOffset, clusterSize)
		}
		h.BackingFileOffset = uint64(extOffset)
		h.BackingFileSize = uint32(len(backingBytes))
		if _, wErr := f.WriteAt(backingBytes, extOffset); wErr != nil {
			return fmt.Errorf("write backing file path: %w", wErr)
		}

		// Re-write header with updated backing file offset/size.
		if err = writeHeader(f, h); err != nil {
			return fmt.Errorf("rewrite header: %w", err)
		}
	}

	// Refcount table: one entry per refcount block.
	rcTable := make([]byte, rcTableClusters*clusterSize)
	for b := uint64(0); b < rcBlocks; b++ {
		binary.BigEndian.PutUint64(rcTable[b*8:b*8+8], rcBlockBase+b*clusterSize)
	}
	if _, err = f.WriteAt(rcTable, int64(rcTableOffset)); err != nil {
		return fmt.Errorf("write refcount table: %w", err)
	}

	// Refcount blocks: refcount=1 for every metadata cluster in [0, totalMeta),
	// spread across as many blocks as the layout requires.
	rcBlockBytes := make([]byte, rcBlocks*clusterSize)
	for i := uint64(0); i < totalMeta; i++ {
		b := i / entriesPerBlock
		e := i % entriesPerBlock
		writeRefcount(rcBlockBytes[b*clusterSize:(b+1)*clusterSize], e, 1, refcountBits)
	}
	if _, err = f.WriteAt(rcBlockBytes, int64(rcBlockBase)); err != nil {
		return fmt.Errorf("write refcount blocks: %w", err)
	}

	// L1 table — all zeros (no data allocated yet).
	l1Table := make([]byte, l1Clusters*clusterSize)
	if _, err = f.WriteAt(l1Table, int64(l1Offset)); err != nil {
		return fmt.Errorf("write L1 table: %w", err)
	}

	if err = f.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	// Self-check the finished temp image before publishing it.
	if err = Check(tmpPath); err != nil {
		return fmt.Errorf("post-create check failed: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	committed = true
	fsyncDir(filepath.Dir(path))
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
