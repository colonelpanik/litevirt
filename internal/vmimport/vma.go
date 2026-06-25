package vmimport

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// VMA (Proxmox vzdump qemu) on-disk format constants, transcribed from the
// pve-qemu vma.h / vma_spec.txt reference. All multi-byte integers in the VMA
// container are big-endian.
const (
	vmaBlockSize        = 1 << 12                       // 4096 — smallest stored unit
	vmaClusterBits      = 12 + 4                        // block bits + 4
	vmaClusterSize      = 1 << vmaClusterBits           // 65536 — 16 blocks
	vmaBlocksPerCluster = vmaClusterSize / vmaBlockSize // 16
	vmaExtentHeaderSize = 512
	vmaBlocksPerExtent  = 59
	vmaMaxConfigs       = 256
	vmaMaxDevices       = 256
	vmaHeaderStructSize = 12288 // sizeof(VmaHeader)

	// vmaMaxExtentSize = header + 59 full clusters. Bounds a single extent read.
	vmaMaxExtentSize = vmaExtentHeaderSize + vmaClusterSize*vmaBlocksPerExtent

	// Sanity ceilings (DoS guards): a malicious header could claim an absurd
	// header_size / device count; these bound the in-memory header read.
	vmaMaxHeaderSize = 1 << 24 // 16 MiB — header + blob table (real ones are KiB)
	// vmaMaxDeviceSize caps a declared device size to avoid a runaway Truncate.
	vmaMaxDeviceSize = uint64(64) << 40 // 64 TiB
)

var (
	vmaMagic     = []byte{'V', 'M', 'A', 0x00}
	vmaeMagic    = []byte{'V', 'M', 'A', 'E'}
	zstdMagic    = []byte{0x28, 0xB5, 0x2F, 0xFD}
	gzipMagic    = []byte{0x1F, 0x8B}
	lzoMagicByte = byte(0x89) // .lzo files begin with 0x89 'L' 'Z' 'O'
)

// vmaDevice is one device-info-table entry (index 1..255; 0 is unused).
type vmaDevice struct {
	id   int
	name string // e.g. "drive-scsi0"
	size uint64 // device size in bytes
}

// ParseVMA reads a Proxmox VMA archive from r (raw .vma, or transparently
// .vma.zst / .vma.gz), reconstructs each device image as a sparse <devname>.raw
// file under destDir, parses the embedded qemu-server.conf, and returns the
// assembled ForeignVM with each disk's LocalPath pointing at its raw file.
func ParseVMA(r io.Reader, destDir string) (*ForeignVM, error) {
	dec, err := vmaDecompress(r)
	if err != nil {
		return nil, err
	}
	if c, ok := dec.(io.Closer); ok {
		defer c.Close()
	}

	br := bufio.NewReaderSize(dec, vmaMaxExtentSize)

	// --- Read + parse the fixed header struct. ---
	hdr := make([]byte, vmaHeaderStructSize)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("vma: read header: %w", err)
	}
	if !bytes.HasPrefix(hdr, vmaMagic) {
		return nil, fmt.Errorf("vma: bad magic %#x (not a VMA archive)", hdr[:4])
	}
	version := binary.BigEndian.Uint32(hdr[4:8])
	if version != 1 {
		return nil, fmt.Errorf("vma: unsupported version %d (only 1 is known)", version)
	}
	uuid := append([]byte(nil), hdr[8:24]...)
	blobOffset := binary.BigEndian.Uint32(hdr[48:52])
	blobSize := binary.BigEndian.Uint32(hdr[52:56])
	headerSize := binary.BigEndian.Uint32(hdr[56:60])

	if headerSize < vmaHeaderStructSize || headerSize > vmaMaxHeaderSize {
		return nil, fmt.Errorf("vma: implausible header_size %d", headerSize)
	}
	if uint64(blobOffset)+uint64(blobSize) > uint64(headerSize) || blobOffset < vmaHeaderStructSize {
		return nil, fmt.Errorf("vma: blob buffer (off=%d size=%d) outside header (size=%d)", blobOffset, blobSize, headerSize)
	}

	// The header region is header_size bytes; we already read the fixed struct,
	// so pull the remainder (blob table lives here) into a single buffer.
	headData := make([]byte, headerSize)
	copy(headData, hdr)
	if _, err := io.ReadFull(br, headData[vmaHeaderStructSize:]); err != nil {
		return nil, fmt.Errorf("vma: read header tail (blob table): %w", err)
	}

	// --- Index the blob buffer (pos → bytes). ---
	blobs := parseVMABlobs(headData, blobOffset, blobSize)

	// --- Config files (config_names[i] → config_data[i]). ---
	confNamesBase := 2044 // offset of config_names[0]
	confDataBase := confNamesBase + vmaMaxConfigs*4
	configs := map[string][]byte{} // filename → content
	for i := 0; i < vmaMaxConfigs; i++ {
		namePtr := binary.BigEndian.Uint32(headData[confNamesBase+i*4 : confNamesBase+i*4+4])
		dataPtr := binary.BigEndian.Uint32(headData[confDataBase+i*4 : confDataBase+i*4+4])
		if namePtr == 0 || dataPtr == 0 {
			continue
		}
		nameBlob, ok1 := blobs[namePtr]
		dataBlob, ok2 := blobs[dataPtr]
		if !ok1 || !ok2 {
			continue
		}
		configs[blobString(nameBlob)] = dataBlob
	}

	// --- Device info table (dev_info[1..255]). ---
	devInfoBase := 4096
	devices := map[int]*vmaDevice{} // dev_id → device
	for i := 1; i < vmaMaxDevices; i++ {
		base := devInfoBase + i*32
		devnamePtr := binary.BigEndian.Uint32(headData[base : base+4])
		size := binary.BigEndian.Uint64(headData[base+8 : base+16])
		if size == 0 || devnamePtr == 0 {
			continue
		}
		nameBlob, ok := blobs[devnamePtr]
		if !ok {
			continue
		}
		name := blobString(nameBlob)
		if name == "vmstate" {
			// VM RAM state — restored separately by Proxmox; not a disk.
			continue
		}
		if size > vmaMaxDeviceSize {
			return nil, fmt.Errorf("vma: device %q size %d exceeds cap", name, size)
		}
		devices[i] = &vmaDevice{id: i, name: name, size: size}
	}

	// --- Parse the embedded qemu-server.conf into the base ForeignVM. ---
	confBytes, ok := configs["qemu-server.conf"]
	if !ok {
		return nil, fmt.Errorf("vma: no embedded qemu-server.conf blob")
	}
	fv, err := parseProxmoxConfBytes(confBytes)
	if err != nil {
		return nil, fmt.Errorf("vma: parse embedded conf: %w", err)
	}

	// --- Create the sparse raw target files, indexed by dev_id. ---
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return nil, fmt.Errorf("vma: mkdir dest: %w", err)
	}
	targets := map[int]*os.File{}
	rawPaths := map[int]string{}
	defer func() {
		for _, f := range targets {
			f.Close()
		}
	}()
	for id, dev := range devices {
		raw := filepath.Join(destDir, dev.name+".raw")
		f, err := os.OpenFile(raw, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("vma: create %s: %w", raw, err)
		}
		// Pre-size sparsely so unwritten clusters read back as zero.
		if err := f.Truncate(int64(dev.size)); err != nil {
			return nil, fmt.Errorf("vma: truncate %s: %w", raw, err)
		}
		targets[id] = f
		rawPaths[id] = raw
	}

	// --- Stream the extents and scatter cluster data into the targets. ---
	if err := vmaRestoreExtents(br, uuid, devices, targets); err != nil {
		return nil, err
	}

	// --- Wire reconstructed raw paths onto the matching conf disks. ---
	matched := map[int]bool{}
	for i := range fv.Disks {
		fd := &fv.Disks[i]
		if fd.IsCDROM {
			continue
		}
		dev := findDeviceForDisk(devices, fd.SourceID)
		if dev == nil {
			fv.Warnf("conf disk %q (%s) has no matching device stream in the VMA; left unresolved", fd.Name, fd.SourceID)
			continue
		}
		fd.LocalPath = rawPaths[dev.id]
		fd.Format = "raw"
		matched[dev.id] = true
	}
	for id, dev := range devices {
		if !matched[id] {
			fv.Warnf("VMA device %q (dev_id=%d) has no matching conf disk; its reconstructed image %s is left orphaned", dev.name, id, rawPaths[id])
		}
	}

	fv.Normalize()
	return fv, nil
}

// vmaDecompress peeks the first bytes of r and wraps it in the appropriate
// decompressor (none for raw .vma, zstd, or gzip). .lzo and anything else is a
// clear error.
func vmaDecompress(r io.Reader) (io.Reader, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	peek, err := br.Peek(4)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("vma: peek magic: %w", err)
	}
	if len(peek) < 4 {
		return nil, fmt.Errorf("vma: input too short to identify (%d bytes)", len(peek))
	}
	switch {
	case bytes.HasPrefix(peek, vmaMagic):
		return br, nil
	case bytes.HasPrefix(peek, zstdMagic):
		zr, err := zstd.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("vma: zstd init: %w", err)
		}
		return zr.IOReadCloser(), nil
	case bytes.HasPrefix(peek, gzipMagic):
		gr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("vma: gzip init: %w", err)
		}
		return gr, nil
	case peek[0] == lzoMagicByte && peek[1] == 'L' && peek[2] == 'Z' && peek[3] == 'O':
		return nil, fmt.Errorf("vma: .vma.lzo (lzop) compression is unsupported; decompress first (lzop -d) and re-import the raw .vma")
	default:
		return nil, fmt.Errorf("vma: unrecognised container magic %#x; supported: raw .vma, .vma.zst, .vma.gz", peek)
	}
}

// parseVMABlobs walks the blob buffer and returns pos → blob-bytes, where pos is
// the offset of the blob's length prefix relative to blobOffset (matching the
// values stored in config_names/config_data/devname_ptr). Each blob is a 2-byte
// little-endian length followed by that many bytes. Scanning starts at offset 1
// within the blob buffer (offset 0 is reserved).
func parseVMABlobs(headData []byte, blobOffset, blobSize uint32) map[uint32][]byte {
	blobs := map[uint32][]byte{}
	bstart := blobOffset + 1
	bend := blobOffset + blobSize
	if uint64(bend) > uint64(len(headData)) {
		bend = uint32(len(headData))
	}
	for bstart+2 <= bend {
		// 2-byte LITTLE-endian size (per the pve-qemu reader).
		size := uint32(headData[bstart]) | uint32(headData[bstart+1])<<8
		if bstart+size+2 <= bend {
			pos := bstart - blobOffset
			data := append([]byte(nil), headData[bstart+2:bstart+2+size]...)
			blobs[pos] = data
		}
		bstart += size + 2
		if size == 0 {
			// Defensive: a zero-length blob would otherwise loop on the same
			// position only if +2 didn't advance — it does, but guard anyway.
			continue
		}
	}
	return blobs
}

// blobString returns a blob as a string with a single trailing NUL trimmed
// (config names/data and device names are NUL-terminated in the VMA).
func blobString(b []byte) string {
	s := string(b)
	return strings.TrimRight(s, "\x00")
}

// vmaRestoreExtents reads VMAE extents until EOF and writes each present block
// into the matching device file at its computed offset.
func vmaRestoreExtents(br *bufio.Reader, uuid []byte, devices map[int]*vmaDevice, targets map[int]*os.File) error {
	ehdr := make([]byte, vmaExtentHeaderSize)
	for {
		// Read the extent header (or clean EOF between extents).
		_, err := io.ReadFull(br, ehdr)
		if err == io.EOF {
			return nil // end of archive
		}
		if err == io.ErrUnexpectedEOF {
			return fmt.Errorf("vma: truncated extent header")
		}
		if err != nil {
			return fmt.Errorf("vma: read extent header: %w", err)
		}
		if !bytes.HasPrefix(ehdr, vmaeMagic) {
			return fmt.Errorf("vma: bad extent magic %#x", ehdr[:4])
		}
		if binary.BigEndian.Uint16(ehdr[4:6]) != 0 {
			return fmt.Errorf("vma: extent reserved field nonzero")
		}
		blockCount := int(binary.BigEndian.Uint16(ehdr[6:8]))
		if !bytes.Equal(ehdr[8:24], uuid) {
			return fmt.Errorf("vma: extent uuid mismatch")
		}
		if blockCount > vmaClusterSize/vmaBlockSize*vmaBlocksPerExtent {
			return fmt.Errorf("vma: extent block_count %d exceeds max", blockCount)
		}

		// Read the extent's data region (block_count × 4 KiB).
		dataLen := blockCount * vmaBlockSize
		data := make([]byte, dataLen)
		if _, err := io.ReadFull(br, data); err != nil {
			return fmt.Errorf("vma: read extent data (%d bytes): %w", dataLen, err)
		}

		if err := vmaScatterExtent(ehdr, data, devices, targets); err != nil {
			return err
		}
	}
}

// vmaScatterExtent decodes the 59 blockinfo entries of one extent and writes
// each present 4 KiB block (or whole 64 KiB cluster when mask==0xffff) into the
// owning device file. data is the extent's block region (after the 512B header);
// pos tracks the consumption cursor through it.
func vmaScatterExtent(ehdr, data []byte, devices map[int]*vmaDevice, targets map[int]*os.File) error {
	pos := 0
	for i := 0; i < vmaBlocksPerExtent; i++ {
		off := 40 + i*8 // blockinfo[i] starts at byte 40
		bi := binary.BigEndian.Uint64(ehdr[off : off+8])
		clusterNum := bi & 0xffffffff
		devID := int((bi >> 32) & 0xff)
		mask := uint16(bi >> 48)
		if devID == 0 {
			continue // empty slot
		}
		dev := devices[devID]
		f := targets[devID]
		// dev/f may be nil if this stream is the vmstate (skipped) or an
		// unknown device; we must still consume its bytes to stay aligned.
		clusterBase := clusterNum * vmaClusterSize

		if mask == 0xffff {
			// Whole cluster present (one contiguous 64 KiB run).
			if pos+vmaClusterSize > len(data) {
				return fmt.Errorf("vma: short extent: full cluster overruns data region")
			}
			if f != nil && dev != nil {
				if err := writeClamped(f, data[pos:pos+vmaClusterSize], int64(clusterBase), dev.size); err != nil {
					return err
				}
			}
			pos += vmaClusterSize
			continue
		}

		// Sparse: one 4 KiB block per set bit, in bit order j = 0..15.
		for j := 0; j < vmaBlocksPerCluster; j++ {
			if mask&(1<<uint(j)) == 0 {
				continue // absent block reads back as the zero we pre-truncated
			}
			if pos+vmaBlockSize > len(data) {
				return fmt.Errorf("vma: short extent: block overruns data region")
			}
			if f != nil && dev != nil {
				blockOff := int64(clusterBase) + int64(j*vmaBlockSize)
				if err := writeClamped(f, data[pos:pos+vmaBlockSize], blockOff, dev.size); err != nil {
					return err
				}
			}
			pos += vmaBlockSize
		}
	}
	return nil
}

// writeClamped writes buf at off into f, truncating the tail that would extend
// past devSize (the final block of a device can be a partial block).
func writeClamped(f *os.File, buf []byte, off int64, devSize uint64) error {
	if off >= int64(devSize) {
		return nil // entirely beyond declared end — drop (defensive)
	}
	end := off + int64(len(buf))
	if end > int64(devSize) {
		buf = buf[:int64(devSize)-off]
	}
	if _, err := f.WriteAt(buf, off); err != nil {
		return fmt.Errorf("vma: write device data at %d: %w", off, err)
	}
	return nil
}

// findDeviceForDisk matches a conf disk's SourceID (e.g. "scsi0") to a VMA
// device whose name is "drive-scsi0" (Proxmox prefixes block-device streams
// with "drive-").
func findDeviceForDisk(devices map[int]*vmaDevice, sourceID string) *vmaDevice {
	want := "drive-" + sourceID
	for _, dev := range devices {
		if dev.name == want || dev.name == sourceID {
			return dev
		}
	}
	return nil
}
