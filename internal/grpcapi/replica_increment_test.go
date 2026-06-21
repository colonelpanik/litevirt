package grpcapi

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// memReaderAt is a fixed in-memory disk image for extent-read tests.
type memReaderAt struct{ data []byte }

func (m *memReaderAt) ReadAt(p []byte, off int64) (int, error) {
	for i := range p {
		p[i] = 0
	}
	if off < int64(len(m.data)) {
		copy(p, m.data[off:]) // zero-filled tail, like a sparse NBD export
	}
	return len(p), nil
}

func TestForkRawAndApply_Full(t *testing.T) {
	dir := t.TempDir()
	const size = 4096
	// A full push: base="", apply patches two regions.
	src := make([]byte, size)
	for i := 100; i < 200; i++ {
		src[i] = 0xAB
	}
	for i := 3000; i < 3010; i++ {
		src[i] = 0xCD
	}
	r := &memReaderAt{data: src}
	apply := func(f *os.File) error {
		return forEachExtentChunk(r, [][2]int64{{100, 100}, {3000, 10}}, size, func(off int64, data []byte) error {
			_, err := f.WriteAt(data, off)
			return err
		})
	}
	dest, err := forkRawAndApply(dir, "vm-root-T1.raw", "", size, apply)
	if err != nil {
		t.Fatalf("forkRawAndApply: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if len(got) != size {
		t.Fatalf("size = %d, want %d", len(got), size)
	}
	if !bytes.Equal(got, src) {
		t.Errorf("full push content mismatch")
	}
}

func TestForkRawAndApply_Incremental(t *testing.T) {
	dir := t.TempDir()
	const size = 8192
	// Base replica: 0x11 across [0,4096), zero elsewhere.
	base := make([]byte, size)
	for i := 0; i < 4096; i++ {
		base[i] = 0x11
	}
	if err := os.WriteFile(filepath.Join(dir, "vm-root-T1.raw"), base, 0o644); err != nil {
		t.Fatal(err)
	}

	// Incremental: only [5000,5100) changed to 0x22.
	srcNow := make([]byte, size)
	copy(srcNow, base)
	for i := 5000; i < 5100; i++ {
		srcNow[i] = 0x22
	}
	r := &memReaderAt{data: srcNow}
	apply := func(f *os.File) error {
		return forEachExtentChunk(r, [][2]int64{{5000, 100}}, size, func(off int64, data []byte) error {
			_, err := f.WriteAt(data, off)
			return err
		})
	}
	dest, err := forkRawAndApply(dir, "vm-root-T2.raw", "vm-root-T1.raw", size, apply)
	if err != nil {
		t.Fatalf("forkRawAndApply: %v", err)
	}
	got, _ := os.ReadFile(dest)
	// Result must equal the full current image: inherited base + patched extent.
	if !bytes.Equal(got, srcNow) {
		t.Errorf("incremental result != current image")
	}
	// Spot-check: inherited region intact, patched region applied.
	if got[0] != 0x11 || got[5050] != 0x22 || got[7000] != 0x00 {
		t.Errorf("inherit/patch boundaries wrong: [0]=%x [5050]=%x [7000]=%x", got[0], got[5050], got[7000])
	}
}

func TestForkRawAndApply_AtomicOnApplyError(t *testing.T) {
	dir := t.TempDir()
	_, err := forkRawAndApply(dir, "vm-root-T1.raw", "", 4096, func(*os.File) error {
		return os.ErrInvalid
	})
	if err == nil {
		t.Fatal("expected apply error to propagate")
	}
	// No partial replica left behind, and no stray temp files.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("unexpected leftover file after failed push: %s", e.Name())
	}
}

func TestForEachExtentChunk_SplitsLargeExtent(t *testing.T) {
	// A 2.5 MiB extent must split into 1 MiB chunks at correct offsets.
	const size = 4 << 20
	r := &memReaderAt{data: make([]byte, size)}
	var offs []int64
	var total int64
	err := forEachExtentChunk(r, [][2]int64{{1 << 20, (5 * (1 << 20)) / 2}}, size, func(off int64, data []byte) error {
		offs = append(offs, off)
		total += int64(len(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != (5*(1<<20))/2 {
		t.Errorf("total bytes = %d, want %d", total, (5*(1<<20))/2)
	}
	want := []int64{1 << 20, 2 << 20, 3 << 20}
	if len(offs) != len(want) {
		t.Fatalf("chunk count = %d, want %d", len(offs), len(want))
	}
	for i := range want {
		if offs[i] != want[i] {
			t.Errorf("chunk %d off = %d, want %d", i, offs[i], want[i])
		}
	}
}

func TestIsReplicaOf(t *testing.T) {
	cases := []struct {
		name, vm, disk string
		want           bool
	}{
		{"web-root-20260608-120000.qcow2", "web", "root", true},
		{"web-root-20260608-120000.raw", "web", "root", true},
		{"web-data-20260608-120000.qcow2", "web", "root", false},
		{"web-root-promoted-20260608.qcow2", "web", "root", true}, // still has the prefix
		{"other-root-20260608.qcow2", "web", "root", false},
		{"web-root-20260608.iso", "web", "root", false},
	}
	for _, c := range cases {
		if got := isReplicaOf(c.name, c.vm, c.disk); got != c.want {
			t.Errorf("isReplicaOf(%q,%q,%q) = %v, want %v", c.name, c.vm, c.disk, got, c.want)
		}
	}
}
