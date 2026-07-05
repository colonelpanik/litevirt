package qcow2

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Convert reads through the backing chain of src, flattens all layers, applies
// zlib compression, and writes a standalone qcow2 image to dst.
// The destination has no backing file. opts may be nil for defaults.
func Convert(ctx context.Context, src, dst string, opts *Options) error {
	tmpPath := dst + ".tmp"

	err := doConvert(ctx, src, tmpPath, opts)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Atomic rename.
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp to dest: %w", err)
	}
	return nil
}

func doConvert(ctx context.Context, src, dst string, opts *Options) error {
	// Open the source chain.
	chain, err := openChain(src)
	if err != nil {
		return fmt.Errorf("open backing chain: %w", err)
	}
	defer func() {
		for _, img := range chain {
			img.f.Close()
		}
	}()

	top := chain[0]
	virtualSize := top.h.Size
	clusterBits := opts.clusterBits()
	clusterSize := opts.clusterSize()

	// Create the destination image.
	if err := Create(dst, virtualSize, opts); err != nil {
		return fmt.Errorf("create dest: %w", err)
	}

	// Open dest for writing.
	df, err := os.OpenFile(dst, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer df.Close()

	dstH, err := readHeader(df)
	if err != nil {
		return err
	}

	refcountBits := uint32(1) << dstH.RefcountOrder
	zeroCluster := make([]byte, clusterSize)
	totalClusters := (virtualSize + clusterSize - 1) / clusterSize
	noCompress := opts != nil && opts.Uncompressed

	// Track allocated clusters for refcount updates at the end.
	// Start with metadata clusters already counted by Create().
	nextOffset := findNextFreeOffset(df, clusterSize)

	// Allocate L2 tables and data clusters.
	l2Entries := clusterSize / 8
	l1Size := uint64(dstH.L1Size)

	// Read L1 table.
	l1 := make([]byte, l1Size*8)
	if _, err := df.ReadAt(l1, int64(dstH.L1TableOffset)); err != nil {
		return fmt.Errorf("read dst L1: %w", err)
	}

	for clusterNum := uint64(0); clusterNum < totalClusters; clusterNum++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		virtualOffset := clusterNum * clusterSize

		// Read cluster data from chain. A hole everywhere (allocated=false) is
		// skipped without touching disk or a zero-compare — the dominant win on
		// a sparse multi-GB image.
		data, allocated, err := readChainCluster(chain, virtualOffset, clusterSize)
		if err != nil {
			return fmt.Errorf("read cluster %d: %w", clusterNum, err)
		}
		if !allocated {
			continue
		}
		// Allocated but all-zero → keep the destination sparse.
		if bytes.Equal(data, zeroCluster) {
			continue
		}

		l1Idx := clusterNum / l2Entries
		l2Idx := clusterNum % l2Entries

		// Ensure L2 table exists.
		l2Offset := binary.BigEndian.Uint64(l1[l1Idx*8 : l1Idx*8+8])
		if l2Offset == 0 {
			// Allocate L2 table.
			l2Offset = nextOffset
			nextOffset += clusterSize
			l2Table := make([]byte, clusterSize)
			if _, err := df.WriteAt(l2Table, int64(l2Offset)); err != nil {
				return fmt.Errorf("write L2 table: %w", err)
			}
			// Mark in L1 (set copied bit 63).
			binary.BigEndian.PutUint64(l1[l1Idx*8:l1Idx*8+8], l2Offset|1<<63)
		}
		l2Offset &^= 1 << 63 // strip copied flag for reading

		// Compress each cluster with raw deflate (matching QEMU's
		// deflateInit2(..., -12,...)) UNLESS the caller asked for uncompressed
		// output. Compression is the dominant cost of a convert and yields a
		// disk that must be inflated on every guest read — so clones skip it.
		var compressed []byte
		useCompressed := false
		if !noCompress {
			var zbuf bytes.Buffer
			zw, _ := flate.NewWriter(&zbuf, flate.BestCompression)
			zw.Write(data)
			zw.Close()
			compressed = zbuf.Bytes()
			useCompressed = uint64(len(compressed)) < clusterSize-1
		}

		if useCompressed {
			// Write compressed data.
			dataOffset := nextOffset
			// Calculate nb_csectors the way QEMU does: number of 512-byte
			// sector boundaries crossed by the compressed data.
			nbCsectors := (dataOffset+uint64(len(compressed))-1)/512 - dataOffset/512
			nextFull := (nextOffset + uint64(len(compressed)) + 511) / 512 * 512
			if _, err := df.WriteAt(compressed, int64(dataOffset)); err != nil {
				return fmt.Errorf("write compressed cluster: %w", err)
			}
			nextOffset = nextFull

			// Encode compressed L2 entry.
			l2Entry := encodeCompressedL2(dataOffset, nbCsectors, clusterBits)

			// Write L2 entry.
			var l2Buf [8]byte
			binary.BigEndian.PutUint64(l2Buf[:], l2Entry)
			if _, err := df.WriteAt(l2Buf[:], int64(l2Offset)+int64(l2Idx*8)); err != nil {
				return fmt.Errorf("write L2 entry: %w", err)
			}
		} else {
			// Write uncompressed — cluster-aligned.
			dataOffset := (nextOffset + clusterSize - 1) / clusterSize * clusterSize
			if _, err := df.WriteAt(data, int64(dataOffset)); err != nil {
				return fmt.Errorf("write uncompressed cluster: %w", err)
			}
			nextOffset = dataOffset + clusterSize

			// Standard L2 entry with copied bit.
			var l2Buf [8]byte
			binary.BigEndian.PutUint64(l2Buf[:], dataOffset|1<<63)
			if _, err := df.WriteAt(l2Buf[:], int64(l2Offset)+int64(l2Idx*8)); err != nil {
				return fmt.Errorf("write L2 entry: %w", err)
			}
		}
	}

	// Write updated L1 table back.
	if _, err := df.WriteAt(l1, int64(dstH.L1TableOffset)); err != nil {
		return fmt.Errorf("write L1: %w", err)
	}

	// Rebuild refcounts for all allocated clusters.
	if err := rebuildRefcounts(df, dstH, nextOffset, refcountBits); err != nil {
		return fmt.Errorf("rebuild refcounts: %w", err)
	}

	if err := df.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	df.Close()
	return Check(dst)
}

// encodeCompressedL2 builds a compressed L2 table entry.
// Bit 62 = 1 (compressed). Bit 63 must be 0 (no copied flag for compressed).
// Layout (QEMU format): bits [61..csizeShift] = nb_csectors,
// bits [csizeShift-1..0] = host byte offset.
// Where csizeShift = 62 - (cluster_bits - 8).
// nb_csectors is the number of 512-byte sector boundaries crossed by the
// compressed data — QEMU adds 1 when decoding to get total sectors.
func encodeCompressedL2(hostOffset, nbCsectors uint64, clusterBits uint32) uint64 {
	csizeShift := 62 - (clusterBits - 8)

	entry := uint64(1) << 62 // compressed flag (bit 63 stays 0)
	entry |= nbCsectors << csizeShift
	entry |= hostOffset & ((uint64(1) << csizeShift) - 1)

	return entry
}

// chainImage represents one layer in a qcow2 backing chain. l1 (the whole L1
// table) and l2cache (L2 tables by host offset) are read once and kept in
// memory so cluster lookups during a convert don't issue two tiny ReadAt
// syscalls per virtual cluster — the dominant cost on a sparse multi-GB image.
type chainImage struct {
	f       *os.File
	h       *Header
	l1      []byte
	l2cache map[uint64][]byte
}

// l2Table returns the (cached) L2 table at the given host offset.
func (img *chainImage) l2Table(offset, clusterSize uint64) ([]byte, error) {
	if t, ok := img.l2cache[offset]; ok {
		return t, nil
	}
	t := make([]byte, clusterSize)
	if _, err := img.f.ReadAt(t, int64(offset)); err != nil {
		return nil, fmt.Errorf("read L2 table @%d: %w", offset, err)
	}
	img.l2cache[offset] = t
	return t, nil
}

// openChain opens src and all its backing files, returning them from topmost to base.
func openChain(src string) ([]*chainImage, error) {
	var chain []*chainImage
	path := src

	for {
		f, err := os.Open(path)
		if err != nil {
			// Close already opened files.
			for _, img := range chain {
				img.f.Close()
			}
			return nil, fmt.Errorf("open %s: %w", path, err)
		}

		h, err := readHeader(f)
		if err != nil {
			f.Close()
			for _, img := range chain {
				img.f.Close()
			}
			return nil, fmt.Errorf("read header %s: %w", path, err)
		}

		img := &chainImage{f: f, h: h, l2cache: make(map[uint64][]byte)}
		// Read the whole L1 table up front (small) so per-cluster lookups don't
		// each do an 8-byte ReadAt.
		if h.L1Size > 0 && h.L1TableOffset > 0 {
			img.l1 = make([]byte, uint64(h.L1Size)*8)
			if _, err := f.ReadAt(img.l1, int64(h.L1TableOffset)); err != nil {
				f.Close()
				for _, c := range chain {
					c.f.Close()
				}
				return nil, fmt.Errorf("read L1 table %s: %w", path, err)
			}
		}
		chain = append(chain, img)

		if h.BackingFileOffset == 0 || h.BackingFileSize == 0 {
			break
		}

		// Read backing file path.
		buf := make([]byte, h.BackingFileSize)
		if _, err := f.ReadAt(buf, int64(h.BackingFileOffset)); err != nil {
			for _, img := range chain {
				img.f.Close()
			}
			return nil, fmt.Errorf("read backing path from %s: %w", path, err)
		}
		backingPath := string(buf)

		// Resolve relative paths against the directory of the current image.
		if !filepath.IsAbs(backingPath) {
			backingPath = filepath.Join(filepath.Dir(path), backingPath)
		}
		path = backingPath
	}

	return chain, nil
}

// readChainCluster reads a cluster from the backing chain, checking each layer
// from top to bottom. The bool reports whether the cluster is allocated in ANY
// layer; when false the caller can skip it entirely (it's a hole → zero) without
// reading data or doing a zero-compare.
func readChainCluster(chain []*chainImage, virtualOffset, clusterSize uint64) ([]byte, bool, error) {
	for _, img := range chain {
		data, allocated, err := readImageCluster(img, virtualOffset, clusterSize)
		if err != nil {
			return nil, false, err
		}
		if allocated {
			return data, true, nil
		}
	}
	return nil, false, nil
}

// readImageCluster reads a single cluster from one image layer, using the
// image's cached L1 table and L2-table cache (no per-cluster metadata syscalls).
func readImageCluster(img *chainImage, virtualOffset, clusterSize uint64) ([]byte, bool, error) {
	h := img.h
	imgClusterSize := h.ClusterSize()
	l2Entries := imgClusterSize / 8

	l1Idx := virtualOffset / (imgClusterSize * l2Entries)
	l2Idx := (virtualOffset / imgClusterSize) % l2Entries

	if l1Idx >= uint64(h.L1Size) || uint64(len(img.l1)) < (l1Idx+1)*8 {
		return nil, false, nil
	}

	l1Entry := binary.BigEndian.Uint64(img.l1[l1Idx*8 : l1Idx*8+8])
	l2TableOffset := l1Entry & 0x00fffffffffffe00 // mask off flags
	if l2TableOffset == 0 {
		return nil, false, nil
	}

	l2, err := img.l2Table(l2TableOffset, imgClusterSize)
	if err != nil {
		return nil, false, err
	}
	l2Entry := binary.BigEndian.Uint64(l2[l2Idx*8 : l2Idx*8+8])

	if l2Entry == 0 {
		return nil, false, nil
	}

	// Check if compressed (bit 62).
	if l2Entry&(1<<62) != 0 {
		return readCompressedCluster(img.f, l2Entry, h.ClusterBits, imgClusterSize)
	}

	// Standard cluster.
	hostOffset := l2Entry & 0x00fffffffffffe00
	if hostOffset == 0 {
		return nil, false, nil
	}

	data := make([]byte, imgClusterSize)
	if _, err := img.f.ReadAt(data, int64(hostOffset)); err != nil {
		return nil, false, fmt.Errorf("read data cluster: %w", err)
	}
	return data, true, nil
}

// readCompressedCluster decompresses a raw-deflate compressed cluster.
// QEMU uses raw deflate (no zlib header/trailer) with windowBits=-12.
func readCompressedCluster(f *os.File, l2Entry uint64, clusterBits uint32, clusterSize uint64) ([]byte, bool, error) {
	csizeShift := 62 - (clusterBits - 8)
	csizeMask := (uint64(1) << (clusterBits - 8)) - 1
	offsetMask := (uint64(1) << csizeShift) - 1

	nbCsectors := ((l2Entry >> csizeShift) & csizeMask) + 1
	hostOffset := l2Entry & offsetMask

	// Compressed size = nb_csectors * 512 - sub-sector offset at start.
	// This matches QEMU's qcow2_parse_compressed_l2_entry.
	compressedSize := nbCsectors*512 - (hostOffset & 511)

	compressed := make([]byte, compressedSize)
	if _, err := f.ReadAt(compressed, int64(hostOffset)); err != nil {
		return nil, false, fmt.Errorf("read compressed data: %w", err)
	}

	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()

	data := make([]byte, clusterSize)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, false, fmt.Errorf("deflate decompress: %w", err)
	}

	return data, true, nil
}

// findNextFreeOffset returns the next cluster-aligned offset at or after the
// end of the file.
func findNextFreeOffset(f *os.File, clusterSize uint64) uint64 {
	fi, _ := f.Stat()
	size := uint64(fi.Size())
	return (size + clusterSize - 1) / clusterSize * clusterSize
}

// rebuildRefcounts walks the entire image and sets refcounts for all allocated clusters.
func rebuildRefcounts(f *os.File, h *Header, fileEnd uint64, refcountBits uint32) error {
	clusterSize := h.ClusterSize()
	totalClusters := (fileEnd + clusterSize - 1) / clusterSize

	// Build a refcount map.
	refcounts := make([]uint16, totalClusters)

	// Mark metadata clusters.
	// Cluster 0: header. The refcount table and blocks are (re)allocated at EOF
	// below and marked there — the table's original reserved area from Create is
	// abandoned (left as free space), so it is deliberately NOT marked here.
	markRef(refcounts, 0)

	// Scan L1 table and mark L1 clusters.
	l1Bytes := uint64(h.L1Size) * 8
	l1Clusters := (l1Bytes + clusterSize - 1) / clusterSize
	for i := uint64(0); i < l1Clusters; i++ {
		markRef(refcounts, h.L1TableOffset/clusterSize+i)
	}

	// Read L1, scan L2 tables and data clusters.
	l1 := make([]byte, l1Bytes)
	if _, err := f.ReadAt(l1, int64(h.L1TableOffset)); err != nil {
		return fmt.Errorf("read L1: %w", err)
	}

	for i := uint64(0); i < uint64(h.L1Size); i++ {
		l1Entry := binary.BigEndian.Uint64(l1[i*8 : i*8+8])
		l2Offset := l1Entry & 0x00fffffffffffe00
		if l2Offset == 0 {
			continue
		}

		markRef(refcounts, l2Offset/clusterSize)

		// Read L2 table.
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
				// Compressed — mark the sectors used.
				csizeShift := 62 - (h.ClusterBits - 8)
				csizeMask := (uint64(1) << (h.ClusterBits - 8)) - 1
				offsetMask := (uint64(1) << csizeShift) - 1
				sectors := ((l2Entry >> csizeShift) & csizeMask) + 1
				hostOffset := l2Entry & offsetMask
				// Mark all clusters that the compressed data spans.
				startCluster := hostOffset / clusterSize
				endByte := hostOffset + sectors*512
				endCluster := (endByte + clusterSize - 1) / clusterSize
				for c := startCluster; c < endCluster && c < totalClusters; c++ {
					markRef(refcounts, c)
				}
			} else {
				hostOffset := l2Entry & 0x00fffffffffffe00
				if hostOffset > 0 {
					markRef(refcounts, hostOffset/clusterSize)
				}
			}
		}
	}

	// Lay out the refcount blocks AND the refcount table at the end of the file so
	// they don't collide with L1/L2/data. The table and blocks must count every
	// cluster including themselves, and the table's size depends on the block count
	// (which depends on how many clusters the table+blocks add) — a self-referential
	// layout solved by the same fixed-point iteration create uses. Relocating the
	// table to EOF (rather than rewriting it in place at its Create-reserved cluster)
	// is what lets it GROW past one cluster for a small-cluster/large image without
	// spilling over the L1/data region.
	entriesPerBlock := clusterSize * 8 / uint64(refcountBits)
	rcBlockBase := (fileEnd + clusterSize - 1) / clusterSize * clusterSize
	baseCluster := rcBlockBase / clusterSize // first EOF cluster; == current totalClusters

	numBlocks := uint64(1)
	rcTableClusters := uint64(1)
	for {
		total := baseCluster + numBlocks + rcTableClusters
		nb := (total + entriesPerBlock - 1) / entriesPerBlock
		nt := (nb*8 + clusterSize - 1) / clusterSize
		if nb <= numBlocks && nt <= rcTableClusters {
			break
		}
		if nb > numBlocks {
			numBlocks = nb
		}
		if nt > rcTableClusters {
			rcTableClusters = nt
		}
	}

	// Grow the refcount map to cover the block + table clusters, then mark them.
	totalClusters = baseCluster + numBlocks + rcTableClusters
	for uint64(len(refcounts)) < totalClusters {
		refcounts = append(refcounts, 0)
	}
	for b := uint64(0); b < numBlocks; b++ {
		markRef(refcounts, baseCluster+b)
	}
	for i := uint64(0); i < rcTableClusters; i++ {
		markRef(refcounts, baseCluster+numBlocks+i)
	}

	// Write the refcount blocks and build the table that points at them.
	rcTable := make([]byte, rcTableClusters*clusterSize)
	for b := uint64(0); b < numBlocks; b++ {
		blockOffset := rcBlockBase + b*clusterSize
		binary.BigEndian.PutUint64(rcTable[b*8:b*8+8], blockOffset)

		block := make([]byte, clusterSize)
		for e := uint64(0); e < entriesPerBlock; e++ {
			globalIdx := b*entriesPerBlock + e
			if globalIdx >= totalClusters {
				break
			}
			writeRefcount(block, e, refcounts[globalIdx], refcountBits)
		}
		if _, err := f.WriteAt(block, int64(blockOffset)); err != nil {
			return fmt.Errorf("write rcblock %d: %w", b, err)
		}
	}

	// Write the refcount table at EOF (right after the blocks).
	tableOffset := (baseCluster + numBlocks) * clusterSize
	if _, err := f.WriteAt(rcTable, int64(tableOffset)); err != nil {
		return fmt.Errorf("write rctable: %w", err)
	}

	// Point the header at the relocated table and its (possibly grown) size.
	if tableOffset != h.RefcountTableOffset {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], tableOffset)
		if _, err := f.WriteAt(buf[:], 48); err != nil { // offset 48 = RefcountTableOffset
			return err
		}
		h.RefcountTableOffset = tableOffset
	}
	if uint32(rcTableClusters) != h.RefcountTableClusters {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(rcTableClusters))
		if _, err := f.WriteAt(buf[:], 56); err != nil { // offset 56 = RefcountTableClusters
			return err
		}
		h.RefcountTableClusters = uint32(rcTableClusters)
	}

	return nil
}

func markRef(refcounts []uint16, clusterIdx uint64) {
	if clusterIdx < uint64(len(refcounts)) {
		refcounts[clusterIdx]++
	}
}
