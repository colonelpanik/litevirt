package vmimport

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// --- Synthetic VMA builder -------------------------------------------------
//
// vmaBuilder constructs a minimal, spec-valid VMA byte stream so the reader can
// be exercised end-to-end without a real Proxmox host. It mirrors the writer in
// pve-qemu: a 12288-byte VmaHeader, a blob buffer holding NUL-terminated config
// names + data and device names, the dev_info table, then VMAE extents.

type vmaBuilder struct {
	uuid    [16]byte
	blobBuf []byte      // starts with one reserved byte at offset 0
	configs [][2]string // {name, data}
	devices []struct {
		id   int
		name string
		size uint64
	}
	allNonzero bool // force every content byte nonzero (exercises mask==0xffff)
}

// content generates the deterministic synthetic payload for a device.
func (b *vmaBuilder) content(id int, size uint64) []byte {
	out := make([]byte, size)
	for i := range out {
		v := byte((id*37 + i) % 251)
		if b.allNonzero && v == 0 {
			v = 1
		}
		out[i] = v
	}
	return out
}

func newVMABuilder() *vmaBuilder {
	b := &vmaBuilder{blobBuf: []byte{0x00}} // offset 0 reserved
	for i := range b.uuid {
		b.uuid[i] = byte(i + 1)
	}
	return b
}

// addBlob appends a NUL-terminated payload to the blob buffer and returns its
// pos (offset of the 2-byte length prefix, relative to the blob buffer start).
func (b *vmaBuilder) addBlob(data []byte) uint32 {
	payload := append(append([]byte(nil), data...), 0x00) // NUL-terminate
	pos := uint32(len(b.blobBuf))
	var lp [2]byte
	binary.LittleEndian.PutUint16(lp[:], uint16(len(payload)))
	b.blobBuf = append(b.blobBuf, lp[0], lp[1])
	b.blobBuf = append(b.blobBuf, payload...)
	return pos
}

func (b *vmaBuilder) addConfig(name, data string) {
	b.configs = append(b.configs, [2]string{name, data})
}
func (b *vmaBuilder) addDevice(id int, name string, size uint64) {
	b.devices = append(b.devices, struct {
		id   int
		name string
		size uint64
	}{id, name, size})
}

// build returns the full VMA byte stream, plus the device payloads it embedded
// (so a test can assert the reconstructed bytes).
func (b *vmaBuilder) build() (vma []byte, devData map[int][]byte) {
	const headerStruct = 12288
	const blobBufferOffset = headerStruct // place blob buffer right after the struct

	// Allocate blobs for config names/data and device names; record pointers.
	type cfgPtr struct{ namePtr, dataPtr uint32 }
	var cfgPtrs []cfgPtr
	for _, c := range b.configs {
		np := b.addBlob([]byte(c[0]))
		dp := b.addBlob([]byte(c[1]))
		cfgPtrs = append(cfgPtrs, cfgPtr{np, dp})
	}
	devNamePtr := map[int]uint32{}
	for _, d := range b.devices {
		devNamePtr[d.id] = b.addBlob([]byte(d.name))
	}

	blobSize := uint32(len(b.blobBuf))
	headerSize := uint32(blobBufferOffset) + blobSize
	// Round header up to a multiple of 512 (the real writer does; reader allows any).
	if rem := headerSize % 512; rem != 0 {
		headerSize += 512 - rem
	}

	head := make([]byte, headerSize)
	copy(head[0:4], vmaMagic)
	binary.BigEndian.PutUint32(head[4:8], 1) // version
	copy(head[8:24], b.uuid[:])
	binary.BigEndian.PutUint64(head[24:32], 0) // ctime
	// md5sum (32:48) left zero — the reader does not verify it.
	binary.BigEndian.PutUint32(head[48:52], uint32(blobBufferOffset))
	binary.BigEndian.PutUint32(head[52:56], blobSize)
	binary.BigEndian.PutUint32(head[56:60], headerSize)

	// config_names[256] @2044, config_data[256] @2044+1024.
	const confNamesBase = 2044
	const confDataBase = confNamesBase + 256*4
	for i, p := range cfgPtrs {
		binary.BigEndian.PutUint32(head[confNamesBase+i*4:], p.namePtr)
		binary.BigEndian.PutUint32(head[confDataBase+i*4:], p.dataPtr)
	}

	// dev_info[256] @4096, 32 bytes each.
	const devInfoBase = 4096
	for _, d := range b.devices {
		base := devInfoBase + d.id*32
		binary.BigEndian.PutUint32(head[base:], devNamePtr[d.id])
		binary.BigEndian.PutUint64(head[base+8:], d.size)
	}

	// Copy the blob buffer into the header at blobBufferOffset.
	copy(head[blobBufferOffset:], b.blobBuf)

	// --- Build one extent carrying each device's content. ---
	// We emit each device's data cluster-by-cluster. For simplicity each device
	// here is <= one cluster; we use a full-cluster (mask 0xffff) entry per
	// device when the data fills a cluster, else per-block masks.
	devData = map[int][]byte{}

	type blockInfo struct {
		clusterNum uint64
		devID      int
		mask       uint16
	}
	var infos []blockInfo
	var dataRegion []byte

	for _, d := range b.devices {
		// Deterministic synthetic content.
		content := b.content(d.id, d.size)
		devData[d.id] = content

		clusters := (int(d.size) + vmaClusterSize - 1) / vmaClusterSize
		for c := 0; c < clusters; c++ {
			start := c * vmaClusterSize
			end := start + vmaClusterSize
			if end > len(content) {
				end = len(content)
			}
			cluster := make([]byte, vmaClusterSize)
			copy(cluster, content[start:end]) // tail zero-padded

			// Decide mask: include only non-zero 4 KiB blocks (mirrors the
			// writer's buffer_is_zero optimisation), but to keep the test
			// meaningful we include every block that has any data.
			var mask uint16
			blocksData := make([]byte, 0, vmaClusterSize)
			for j := 0; j < vmaBlocksPerCluster; j++ {
				blk := cluster[j*vmaBlockSize : (j+1)*vmaBlockSize]
				if !allZero(blk) {
					mask |= 1 << uint(j)
					blocksData = append(blocksData, blk...)
				}
			}
			if mask == 0 {
				continue // fully sparse cluster — emit nothing
			}
			if mask == 0xffff {
				// Whole cluster present (one contiguous 64 KiB run).
				dataRegion = append(dataRegion, cluster...)
			} else {
				dataRegion = append(dataRegion, blocksData...)
			}
			infos = append(infos, blockInfo{clusterNum: uint64(c), devID: d.id, mask: mask})
		}
	}

	// One extent (the synthetic content fits well under 59 clusters).
	ehead := make([]byte, vmaExtentHeaderSize)
	copy(ehead[0:4], vmaeMagic)
	binary.BigEndian.PutUint16(ehead[4:6], 0) // reserved
	blockCount := len(dataRegion) / vmaBlockSize
	binary.BigEndian.PutUint16(ehead[6:8], uint16(blockCount))
	copy(ehead[8:24], b.uuid[:])
	// md5sum (24:40) left zero — reader does not verify.
	for i, bi := range infos {
		val := (bi.clusterNum & 0xffffffff) |
			(uint64(bi.devID) << 32) |
			(uint64(bi.mask) << 48)
		binary.BigEndian.PutUint64(ehead[40+i*8:], val)
	}

	vma = append(vma, head...)
	vma = append(vma, ehead...)
	vma = append(vma, dataRegion...)
	return vma, devData
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// --- Tests -----------------------------------------------------------------

const vmaEmbeddedConf = `name: vm-100
ostype: l26
cores: 2
sockets: 1
memory: 2048
bios: seabios
machine: pc-i440fx-8.1
scsihw: virtio-scsi-single
scsi0: local-lvm:vm-100-disk-0,size=128K
net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=5
`

func buildSyntheticVMA(t *testing.T) ([]byte, map[int][]byte) {
	t.Helper()
	b := newVMABuilder()
	b.addConfig("qemu-server.conf", vmaEmbeddedConf)
	// One device matching scsi0: name "drive-scsi0", 128 KiB = 2 clusters.
	b.addDevice(1, "drive-scsi0", 128*1024)
	return b.build()
}

func TestParseVMA_RawEndToEnd(t *testing.T) {
	vma, devData := buildSyntheticVMA(t)
	dest := t.TempDir()

	fv, err := ParseVMA(bytes.NewReader(vma), dest)
	if err != nil {
		t.Fatalf("ParseVMA: %v", err)
	}

	// Embedded conf parsed.
	if fv.Name != "vm-100" {
		t.Errorf("Name = %q, want vm-100", fv.Name)
	}
	if fv.CPUs != 2 {
		t.Errorf("CPUs = %d, want 2", fv.CPUs)
	}
	if fv.MemoryMiB != 2048 {
		t.Errorf("MemoryMiB = %d, want 2048", fv.MemoryMiB)
	}
	if fv.Machine != "pc" || fv.Firmware != "bios" {
		t.Errorf("Machine/Firmware = %q/%q, want pc/bios", fv.Machine, fv.Firmware)
	}
	if len(fv.NICs) != 1 || fv.NICs[0].VLAN != 5 {
		t.Errorf("NIC = %+v, want one NIC VLAN 5", fv.NICs)
	}

	// Disk reconstructed and wired to the raw file.
	if len(fv.Disks) != 1 {
		t.Fatalf("Disks = %d, want 1", len(fv.Disks))
	}
	d := fv.Disks[0]
	if d.SourceID != "scsi0" {
		t.Errorf("Disk SourceID = %q, want scsi0", d.SourceID)
	}
	if d.Format != "raw" {
		t.Errorf("Disk Format = %q, want raw", d.Format)
	}
	wantPath := filepath.Join(dest, "drive-scsi0.raw")
	if d.LocalPath != wantPath {
		t.Errorf("Disk LocalPath = %q, want %q", d.LocalPath, wantPath)
	}

	// Reconstructed bytes must match the embedded device content exactly.
	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read reconstructed raw: %v", err)
	}
	want := devData[1]
	if len(got) != len(want) {
		t.Fatalf("raw size = %d, want %d", len(got), len(want))
	}
	if !bytes.Equal(got, want) {
		// Report the first divergence for debuggability.
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("raw byte %d = %d, want %d", i, got[i], want[i])
			}
		}
	}
}

func TestParseVMA_ZstdRoundTrip(t *testing.T) {
	vma, devData := buildSyntheticVMA(t)

	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := zw.Write(vma); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}

	// Sanity: the compressed stream carries the zstd magic.
	if !bytes.HasPrefix(buf.Bytes(), zstdMagic) {
		t.Fatalf("compressed stream missing zstd magic")
	}

	dest := t.TempDir()
	fv, err := ParseVMA(bytes.NewReader(buf.Bytes()), dest)
	if err != nil {
		t.Fatalf("ParseVMA(.vma.zst): %v", err)
	}
	if fv.Name != "vm-100" {
		t.Errorf("Name = %q, want vm-100", fv.Name)
	}
	got, err := os.ReadFile(filepath.Join(dest, "drive-scsi0.raw"))
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if !bytes.Equal(got, devData[1]) {
		t.Errorf("zstd round-trip device bytes differ from original")
	}
}

func TestParseVMA_RejectsBadMagic(t *testing.T) {
	// gzip wrapper is detected, but a bogus magic inside should error cleanly.
	if _, err := ParseVMA(bytes.NewReader([]byte("not a vma stream at all")), t.TempDir()); err == nil {
		t.Error("expected an error for a non-VMA stream")
	}
}

func TestParseVMA_RejectsLZO(t *testing.T) {
	lzo := append([]byte{0x89, 'L', 'Z', 'O'}, make([]byte, 16)...)
	_, err := ParseVMA(bytes.NewReader(lzo), t.TempDir())
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("lzo")) {
		t.Errorf("want an lzo-unsupported error, got %v", err)
	}
}

func TestParseVMA_MissingConf(t *testing.T) {
	b := newVMABuilder()
	b.addDevice(1, "drive-scsi0", vmaClusterSize)
	vma, _ := b.build()
	if _, err := ParseVMA(bytes.NewReader(vma), t.TempDir()); err == nil {
		t.Error("expected an error when qemu-server.conf is absent")
	}
}

// A full-cluster (mask 0xffff) device exercises the contiguous-cluster path.
func TestParseVMA_FullClusterPath(t *testing.T) {
	b := newVMABuilder()
	b.allNonzero = true // every byte nonzero → all 16 blocks present → mask 0xffff
	b.addConfig("qemu-server.conf", vmaEmbeddedConf)
	b.addDevice(1, "drive-scsi0", vmaClusterSize) // exactly one cluster
	vma, devData := b.build()

	dest := t.TempDir()
	fv, err := ParseVMA(bytes.NewReader(vma), dest)
	if err != nil {
		t.Fatalf("ParseVMA: %v", err)
	}
	got, err := os.ReadFile(fv.Disks[0].LocalPath)
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if !bytes.Equal(got, devData[1]) {
		t.Error("full-cluster reconstruction mismatch")
	}
}
