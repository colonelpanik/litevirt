package qcow2

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// qemuCheckIfAvailable runs `qemu-img check` as an INDEPENDENT oracle and fails
// the test on any reported error or leak (exit 2/3). Unlike qemuImgCheck it does
// NOT skip the whole test when qemu-img is absent — the pure-Go Check still ran;
// this only adds the second opinion when the binary is present. A bug shared
// between the writer and our own Check would still be caught here.
func qemuCheckIfAvailable(t *testing.T, path string) {
	t.Helper()
	if _, err := exec.LookPath("qemu-img"); err != nil {
		return
	}
	if out, err := exec.Command("qemu-img", "check", path).CombinedOutput(); err != nil {
		t.Errorf("qemu-img check reported a problem (exit %v):\n%s", err, out)
	}
}

// clusterRefcount reads the on-disk refcount recorded for a cluster index,
// independently of Check (so a test can assert a specific metadata cluster is
// counted). Returns 0 if the covering refcount block is unallocated.
func clusterRefcount(t *testing.T, path string, cluster uint64) uint64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	h, err := readHeader(f)
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	clusterSize := h.ClusterSize()
	refcountBits := uint32(1) << h.RefcountOrder
	entriesPerBlock := clusterSize * 8 / uint64(refcountBits)
	blockIdx := cluster / entriesPerBlock
	var entry [8]byte
	if _, err := f.ReadAt(entry[:], int64(h.RefcountTableOffset)+int64(blockIdx*8)); err != nil {
		t.Fatalf("read rctable entry: %v", err)
	}
	blockOffset := binary.BigEndian.Uint64(entry[:])
	if blockOffset == 0 {
		return 0
	}
	block := make([]byte, clusterSize)
	if _, err := f.ReadAt(block, int64(blockOffset)); err != nil {
		t.Fatalf("read rcblock: %v", err)
	}
	return readRefcount(block, cluster%entriesPerBlock, refcountBits)
}

// lastMetadataCluster returns the index of the final L1-table cluster — the
// cluster that Bug 2 left uncounted (it fell past the single refcount block).
func lastMetadataCluster(t *testing.T, path string) uint64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	h, err := readHeader(f)
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	clusterSize := h.ClusterSize()
	l1Bytes := uint64(h.L1Size) * 8
	l1Clusters := (l1Bytes + clusterSize - 1) / clusterSize
	return h.L1TableOffset/clusterSize + l1Clusters - 1
}

// TestCheck_DetectsUndercountedMetadata proves the refcount-verification guard
// directly and WITHOUT qemu-img: corrupt a referenced metadata cluster's refcount
// to 0 — exactly what the create/resize bugs produced — and assert Check now
// fails. This is what makes "Check passed" meaningful in the tests below.
func TestCheck_DetectsUndercountedMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "img.qcow2")
	if err := Create(path, 1<<20, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// A correct image must pass first.
	if err := Check(path); err != nil {
		t.Fatalf("freshly created image should pass Check: %v", err)
	}

	// Zero cluster 0's (the header's) refcount inside refcount block 0.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	h, err := readHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	var entry [8]byte
	if _, err := f.ReadAt(entry[:], int64(h.RefcountTableOffset)); err != nil {
		t.Fatal(err)
	}
	block0 := binary.BigEndian.Uint64(entry[:])
	if _, err := f.WriteAt([]byte{0, 0}, int64(block0)); err != nil { // entry 0, 16-bit refcount
		t.Fatal(err)
	}
	f.Close()

	if err := Check(path); err == nil {
		t.Fatal("Check must detect an undercounted (refcount=0) referenced metadata cluster")
	} else if !strings.Contains(err.Error(), "refcount mismatch") {
		t.Errorf("expected a refcount-mismatch error, got: %v", err)
	}
}

// TestCreate_RefcountsCoverAllMetadata_Bug2 reproduces and fixes Bug 2: createImage
// used to write exactly ONE refcount block, so when metadata spanned more than one
// block (small clusters + a large virtual size) the L1-tail clusters were left
// refcount 0. Pre-fix, every case here fails `qemu-img check` with
// "cluster N refcount=0 reference=1"; post-fix all pass both oracles. The default
// 64K case is a single-block regression guard (its layout is unchanged).
func TestCreate_RefcountsCoverAllMetadata_Bug2(t *testing.T) {
	cases := []struct {
		name        string
		clusterBits uint32
		sizeBytes   uint64
		multiBlock  bool // metadata must span >1 refcount block (the bug trigger)
	}{
		{"512B-clusters/1GB", 9, 1 << 30, true},
		{"512B-clusters/4GB", 9, 4 << 30, true},
		{"1KB-clusters/8GB", 10, 8 << 30, true},
		{"4KB-clusters/4TB", 12, 4 << 40, true},
		{"default-64K/20GB-single-block-regression", 16, 20 << 30, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "img.qcow2")
			// Create runs the post-create Check internally; a failure here already
			// means the writer produced an inconsistent image.
			if err := Create(path, tc.sizeBytes, &Options{ClusterBits: tc.clusterBits}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if err := Check(path); err != nil {
				t.Fatalf("internal Check: %v", err)
			}
			qemuCheckIfAvailable(t, path)

			// Directly assert the specific cluster Bug 2 left at 0 is now counted.
			last := lastMetadataCluster(t, path)
			if rc := clusterRefcount(t, path, last); rc != 1 {
				t.Errorf("last metadata (L1-tail) cluster %d has refcount %d, want 1 (Bug 2)", last, rc)
			}
			// Prove the case exercises the intended layout: entriesPerBlock is
			// clusterSize*8/16 (16-bit refcounts) = clusterSize/2, so a metadata
			// cluster at index >= that lives beyond refcount block 0 — exactly the
			// region Bug 2 dropped. The regression case must stay within block 0.
			entriesPerBlock := (uint64(1) << tc.clusterBits) / 2
			if tc.multiBlock && last < entriesPerBlock {
				t.Errorf("case %q did not span >1 refcount block (last=%d, entriesPerBlock=%d)",
					tc.name, last, entriesPerBlock)
			}
			if !tc.multiBlock && last >= entriesPerBlock {
				t.Errorf("regression case %q unexpectedly spans >1 block (last=%d, entriesPerBlock=%d)",
					tc.name, last, entriesPerBlock)
			}
		})
	}
}

// TestResize_RefcountsAfterNewBlock_Bug1 reproduces and fixes Bug 1: when a resize
// grew the L1 table past the current refcount block's coverage, setRefcount
// allocated a NEW refcount block but never counted the new block's own cluster.
// Growing L1 alone (no data) crosses a block boundary at small cluster sizes; the
// 16GB case allocates ~8192 new L1 clusters spanning ~32 refcount blocks, also
// exercising the cross-block self-accounting recursion. The identical setRefcount
// path runs at the 64K default once a disk's file exceeds ~2GiB allocated — the
// real production trigger (a routine `lv` disk resize) — validated here fast at
// small clusters. Pre-fix each case fails `qemu-img check`.
func TestResize_RefcountsAfterNewBlock_Bug1(t *testing.T) {
	cases := []struct {
		name        string
		clusterBits uint32
		initialSize uint64
		resizeSize  uint64
	}{
		{"512B/8MB->4GB", 9, 8 << 20, 4 << 30},
		{"512B/8MB->16GB-32blocks-recursion", 9, 8 << 20, 16 << 30},
		{"1KB/16MB->64GB", 10, 16 << 20, 64 << 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "img.qcow2")
			if err := Create(path, tc.initialSize, &Options{ClusterBits: tc.clusterBits}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if err := Resize(path, tc.resizeSize); err != nil {
				t.Fatalf("Resize: %v", err)
			}
			if err := Check(path); err != nil {
				t.Fatalf("internal Check after resize: %v", err)
			}
			qemuCheckIfAvailable(t, path)

			// The relocated L1 tail must be counted (the class Bug 1 corrupted).
			last := lastMetadataCluster(t, path)
			if rc := clusterRefcount(t, path, last); rc != 1 {
				t.Errorf("post-resize L1-tail cluster %d has refcount %d, want 1 (Bug 1)", last, rc)
			}
		})
	}
}

// TestResize_EmptyImageStillWorks guards the common no-boundary-crossing path
// (an empty image resize that stays within one refcount block).
func TestResize_EmptyImageStillWorks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "img.qcow2")
	if err := Create(path, 1<<30, nil); err != nil { // default 64K clusters
		t.Fatalf("Create: %v", err)
	}
	if err := Resize(path, 8<<30); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if err := Check(path); err != nil {
		t.Fatalf("Check: %v", err)
	}
	qemuCheckIfAvailable(t, path)
}

// TestCreate_Atomic_NoPartialFileOnFailure proves the temp+rename discipline: a
// create that fails partway leaves NO file at the real path and no leftover .tmp.
func TestCreate_Atomic_NoPartialFileOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "img.qcow2")
	// An over-long backing URI can't fit in cluster 0 → createImage fails after the
	// temp file is opened, exercising the cleanup path.
	longURI := "nbd://" + strings.Repeat("h", 70000)
	if err := CreateWithBackingURI(path, longURI, 1<<20, nil); err == nil {
		t.Fatal("expected failure for an over-long backing URI")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("no image must exist at the real path after a failed create")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("the temp file must be removed after a failed create")
	}
}

// TestCreate_Atomic_SuccessLeavesNoTemp confirms the happy path renames cleanly.
func TestCreate_Atomic_SuccessLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "img.qcow2")
	if err := Create(path, 1<<20, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("final image missing after successful create: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file must not remain after a successful create")
	}
}

// TestParseSize_RejectsOverflow ensures a size that overflows uint64 errors rather
// than silently wrapping to a tiny value.
func TestParseSize_RejectsOverflow(t *testing.T) {
	if _, err := ParseSize("20000000000T"); err == nil {
		t.Error("expected overflow error for 20000000000T")
	}
	// A valid size still parses.
	if got, err := ParseSize("1T"); err != nil || got != 1<<40 {
		t.Errorf("ParseSize(1T) = %d, %v; want %d, nil", got, err, uint64(1)<<40)
	}
}
