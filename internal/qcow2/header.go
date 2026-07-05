// Package qcow2 implements native qcow2 v3 image creation, inspection,
// resize, and conversion without requiring the qemu-img binary.
package qcow2

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

// On-disk constants.
const (
	Magic   uint32 = 0x514649fb // "QFI\xfb"
	Version uint32 = 3

	DefaultClusterBits   uint32 = 16 // 64 KB
	DefaultRefcountOrder uint32 = 4  // 16-bit refcounts
	HeaderLength         uint32 = 104

	// Header extension types.
	ExtBackingFormat uint32 = 0xE2792ACA
	ExtEndOfArea     uint32 = 0x00000000
)

// Options allows callers to override format defaults.
// Zero values use defaults (64 KB clusters, 16-bit refcounts).
type Options struct {
	ClusterBits   uint32 // 9–21 (512 B – 2 MB), default 16 (64 KB)
	RefcountOrder uint32 // 0–6 (1–64 bit), default 4 (16-bit)
	// Uncompressed, when true, makes Convert write data clusters uncompressed.
	// Default (false) zlib-compresses each cluster (smaller output, good for
	// stored/archival images) but is CPU-heavy to write AND forces a per-read
	// inflate on the running guest. Uncompressed is far faster both ways — the
	// right choice for VM clones. Zero value preserves the legacy behavior.
	Uncompressed bool
}

func (o *Options) clusterBits() uint32 {
	if o != nil && o.ClusterBits >= 9 && o.ClusterBits <= 21 {
		return o.ClusterBits
	}
	return DefaultClusterBits
}

func (o *Options) refcountOrder() uint32 {
	if o != nil && o.RefcountOrder >= 1 && o.RefcountOrder <= 6 {
		return o.RefcountOrder
	}
	return DefaultRefcountOrder
}

func (o *Options) clusterSize() uint64 {
	return 1 << o.clusterBits()
}

// Header is the qcow2 v3 on-disk header (104 bytes, big-endian).
type Header struct {
	Magic                 uint32
	Version               uint32
	BackingFileOffset     uint64
	BackingFileSize       uint32
	ClusterBits           uint32
	Size                  uint64 // virtual size in bytes
	CryptMethod           uint32
	L1Size                uint32
	L1TableOffset         uint64
	RefcountTableOffset   uint64
	RefcountTableClusters uint32
	NbSnapshots           uint32
	SnapshotsOffset       uint64
	// v3 fields
	IncompatibleFeatures uint64
	CompatibleFeatures   uint64
	AutoclearFeatures    uint64
	RefcountOrder        uint32
	HeaderLength         uint32
}

// ClusterSize returns the cluster size derived from ClusterBits.
func (h *Header) ClusterSize() uint64 {
	return 1 << h.ClusterBits
}

// L2Entries returns the number of L2 entries per cluster.
func (h *Header) L2Entries() uint64 {
	return h.ClusterSize() / 8
}

// readHeader parses a qcow2 header from r.
func readHeader(r io.ReaderAt) (*Header, error) {
	var h Header
	buf := make([]byte, 104)
	if _, err := r.ReadAt(buf, 0); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	h.Magic = binary.BigEndian.Uint32(buf[0:4])
	h.Version = binary.BigEndian.Uint32(buf[4:8])
	h.BackingFileOffset = binary.BigEndian.Uint64(buf[8:16])
	h.BackingFileSize = binary.BigEndian.Uint32(buf[16:20])
	h.ClusterBits = binary.BigEndian.Uint32(buf[20:24])
	h.Size = binary.BigEndian.Uint64(buf[24:32])
	h.CryptMethod = binary.BigEndian.Uint32(buf[32:36])
	h.L1Size = binary.BigEndian.Uint32(buf[36:40])
	h.L1TableOffset = binary.BigEndian.Uint64(buf[40:48])
	h.RefcountTableOffset = binary.BigEndian.Uint64(buf[48:56])
	h.RefcountTableClusters = binary.BigEndian.Uint32(buf[56:60])
	h.NbSnapshots = binary.BigEndian.Uint32(buf[60:64])
	h.SnapshotsOffset = binary.BigEndian.Uint64(buf[64:72])
	h.IncompatibleFeatures = binary.BigEndian.Uint64(buf[72:80])
	h.CompatibleFeatures = binary.BigEndian.Uint64(buf[80:88])
	h.AutoclearFeatures = binary.BigEndian.Uint64(buf[88:96])
	h.RefcountOrder = binary.BigEndian.Uint32(buf[96:100])
	h.HeaderLength = binary.BigEndian.Uint32(buf[100:104])

	if h.Magic != Magic {
		return nil, fmt.Errorf("not a qcow2 file (magic %#x)", h.Magic)
	}
	if h.Version < 2 || h.Version > 3 {
		return nil, fmt.Errorf("unsupported qcow2 version %d", h.Version)
	}

	return &h, nil
}

// writeHeader serialises the header to w at offset 0.
func writeHeader(w io.WriterAt, h *Header) error {
	buf := make([]byte, 104)
	binary.BigEndian.PutUint32(buf[0:4], h.Magic)
	binary.BigEndian.PutUint32(buf[4:8], h.Version)
	binary.BigEndian.PutUint64(buf[8:16], h.BackingFileOffset)
	binary.BigEndian.PutUint32(buf[16:20], h.BackingFileSize)
	binary.BigEndian.PutUint32(buf[20:24], h.ClusterBits)
	binary.BigEndian.PutUint64(buf[24:32], h.Size)
	binary.BigEndian.PutUint32(buf[32:36], h.CryptMethod)
	binary.BigEndian.PutUint32(buf[36:40], h.L1Size)
	binary.BigEndian.PutUint64(buf[40:48], h.L1TableOffset)
	binary.BigEndian.PutUint64(buf[48:56], h.RefcountTableOffset)
	binary.BigEndian.PutUint32(buf[56:60], h.RefcountTableClusters)
	binary.BigEndian.PutUint32(buf[60:64], h.NbSnapshots)
	binary.BigEndian.PutUint64(buf[64:72], h.SnapshotsOffset)
	binary.BigEndian.PutUint64(buf[72:80], h.IncompatibleFeatures)
	binary.BigEndian.PutUint64(buf[80:88], h.CompatibleFeatures)
	binary.BigEndian.PutUint64(buf[88:96], h.AutoclearFeatures)
	binary.BigEndian.PutUint32(buf[96:100], h.RefcountOrder)
	binary.BigEndian.PutUint32(buf[100:104], h.HeaderLength)

	_, err := w.WriteAt(buf, 0)
	return err
}

// writeHeaderExtension writes a single header extension entry at offset.
// Returns the number of bytes written (padded to 8-byte alignment).
func writeHeaderExtension(w io.WriterAt, offset int64, extType uint32, data []byte) (int64, error) {
	padded := (len(data) + 7) &^ 7 // round up to 8-byte boundary
	buf := make([]byte, 8+padded)
	binary.BigEndian.PutUint32(buf[0:4], extType)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(data)))
	copy(buf[8:], data)

	if _, err := w.WriteAt(buf, offset); err != nil {
		return 0, err
	}
	return int64(len(buf)), nil
}

// writeEndOfExtensions writes the end-of-header-extensions marker.
func writeEndOfExtensions(w io.WriterAt, offset int64) error {
	buf := make([]byte, 8)
	// type=0, length=0 — already zero
	_, err := w.WriteAt(buf, offset)
	return err
}

// l1Entries calculates the required L1 table size for a given virtual size.
func l1Entries(virtualSize, clusterSize uint64) uint32 {
	l2Coverage := clusterSize * (clusterSize / 8) // bytes covered by one L2 table
	n := (virtualSize + l2Coverage - 1) / l2Coverage
	if n == 0 {
		n = 1
	}
	return uint32(n)
}

// ParseSize converts a human-readable size string to bytes.
// Accepted forms: "20G", "512M", "1T", "64K", "1073741824".
func ParseSize(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	// Pure numeric.
	if unicode.IsDigit(rune(s[len(s)-1])) {
		return strconv.ParseUint(s, 10, 64)
	}

	suffix := strings.ToUpper(s[len(s)-1:])
	numStr := strings.TrimSpace(s[:len(s)-1])
	num, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse size %q: %w", s, err)
	}

	var mult uint64
	switch suffix {
	case "K":
		mult = 1024
	case "M":
		mult = 1024 * 1024
	case "G":
		mult = 1024 * 1024 * 1024
	case "T":
		mult = 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown size suffix %q in %q", suffix, s)
	}
	// Reject overflow rather than silently wrapping to a tiny size.
	if num > 0 && num > (1<<64-1)/mult {
		return 0, fmt.Errorf("size %q overflows uint64", s)
	}
	return num * mult, nil
}
