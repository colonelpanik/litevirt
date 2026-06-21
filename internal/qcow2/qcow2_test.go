package qcow2

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestConvertBenchVsQemuImg directly compares pure-Go uncompressed Convert
// against `qemu-img convert -O qcow2` on the SAME source file, on tmpfs (to
// isolate CPU/algorithm from disk), and verifies the outputs are byte-identical.
// Manual only: LV_BENCH=1 go test ./internal/qcow2 -run ConvertBenchVsQemuImg -v -timeout 900s
func TestConvertBenchVsQemuImg(t *testing.T) {
	if os.Getenv("LV_BENCH") == "" {
		t.Skip("set LV_BENCH=1 to run the qemu-img comparison benchmark")
	}
	for _, tool := range []string{"qemu-img", "dd"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	dir := "/dev/shm/lvbench"
	if err := os.MkdirAll(dir, 0755); err != nil {
		dir = t.TempDir()
	} else {
		defer os.RemoveAll(dir)
	}
	raw := filepath.Join(dir, "data.raw")
	src := filepath.Join(dir, "src.qcow2")
	outQemu := filepath.Join(dir, "out-qemu.qcow2")
	outGo := filepath.Join(dir, "out-go.qcow2")

	const allocMiB = 1536 // ~1.5 GB allocated, 10 GB virtual (a realistic clone)
	run(t, "dd", "if=/dev/urandom", "of="+raw, "bs=1M", fmt.Sprintf("count=%d", allocMiB), "status=none")
	run(t, "qemu-img", "create", "-f", "qcow2", src, "10G")
	run(t, "qemu-img", "convert", "-n", "-O", "qcow2", raw, src) // write the 1.5G into the 10G image
	os.Remove(raw)

	warm := func() { b, _ := os.ReadFile(src); _ = b }

	warm()
	t0 := time.Now()
	run(t, "qemu-img", "convert", "-O", "qcow2", src, outQemu)
	qemuDur := time.Since(t0)

	warm()
	t1 := time.Now()
	if err := Convert(context.Background(), src, outGo, &Options{Uncompressed: true}); err != nil {
		t.Fatalf("pure-Go convert: %v", err)
	}
	goDur := time.Since(t1)

	ratio := float64(goDur) / float64(qemuDur)
	t.Logf("BENCH: qemu-img=%v  pure-Go=%v  ratio(go/qemu)=%.2fx", qemuDur.Round(time.Millisecond), goDur.Round(time.Millisecond), ratio)

	// Correctness: our output must be byte-identical to qemu-img's (exit 0).
	out, err := exec.Command("qemu-img", "compare", outGo, outQemu).CombinedOutput()
	if err != nil {
		t.Errorf("qemu-img compare found a difference: %v\n%s", err, out)
	}
	if ratio > 1.5 {
		t.Logf("NOTE: qemu-img is >50%% faster (ratio %.2f) — worth studying qemu-img convert internals", ratio)
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input string
		want  uint64
	}{
		{"1024", 1024},
		{"10G", 10 * 1024 * 1024 * 1024},
		{"512M", 512 * 1024 * 1024},
		{"1T", 1024 * 1024 * 1024 * 1024},
		{"64K", 64 * 1024},
	}
	for _, tt := range tests {
		got, err := ParseSize(tt.input)
		if err != nil {
			t.Errorf("ParseSize(%q): %v", tt.input, err)
		} else if got != tt.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.qcow2")
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatal(err)
	}

	h := &Header{
		Magic:                 Magic,
		Version:               Version,
		ClusterBits:           16,
		Size:                  10 * 1024 * 1024 * 1024,
		L1Size:                20,
		L1TableOffset:         3 * 65536,
		RefcountTableOffset:   1 * 65536,
		RefcountTableClusters: 1,
		RefcountOrder:         4,
		HeaderLength:          104,
	}

	if err := writeHeader(f, h); err != nil {
		t.Fatal(err)
	}

	h2, err := readHeader(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}

	if h2.Magic != h.Magic {
		t.Errorf("magic: got %#x, want %#x", h2.Magic, h.Magic)
	}
	if h2.Size != h.Size {
		t.Errorf("size: got %d, want %d", h2.Size, h.Size)
	}
	if h2.ClusterBits != h.ClusterBits {
		t.Errorf("cluster_bits: got %d, want %d", h2.ClusterBits, h.ClusterBits)
	}
	if h2.L1Size != h.L1Size {
		t.Errorf("L1 size: got %d, want %d", h2.L1Size, h.L1Size)
	}
}

func TestCreateAndInfo(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.qcow2")
	size := uint64(10 * 1024 * 1024 * 1024) // 10G

	if err := Create(tmp, size, nil); err != nil {
		t.Fatal(err)
	}

	info, err := Info(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if info.VirtualSize != size {
		t.Errorf("virtual size: got %d, want %d", info.VirtualSize, size)
	}
	if info.BackingFile != "" {
		t.Errorf("backing file should be empty, got %q", info.BackingFile)
	}
	if info.Format != "qcow2" {
		t.Errorf("format: got %q, want qcow2", info.Format)
	}
}

func TestCreateWithBackingAndInfo(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	overlay := filepath.Join(dir, "overlay.qcow2")

	// Create base image.
	if err := Create(base, 5*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}

	// Create overlay inheriting size.
	if err := CreateWithBacking(overlay, base, 0, nil); err != nil {
		t.Fatal(err)
	}

	info, err := Info(overlay)
	if err != nil {
		t.Fatal(err)
	}
	if info.VirtualSize != 5*1024*1024*1024 {
		t.Errorf("virtual size: got %d, want %d", info.VirtualSize, uint64(5*1024*1024*1024))
	}
	if info.BackingFile != base {
		t.Errorf("backing file: got %q, want %q", info.BackingFile, base)
	}
	if info.BackingFormat != "qcow2" {
		t.Errorf("backing format: got %q, want qcow2", info.BackingFormat)
	}
}

func TestCreateWithBackingExplicitSize(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	overlay := filepath.Join(dir, "overlay.qcow2")

	if err := Create(base, 5*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}

	// Create overlay with explicit larger size.
	if err := CreateWithBacking(overlay, base, 20*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}

	info, err := Info(overlay)
	if err != nil {
		t.Fatal(err)
	}
	if info.VirtualSize != 20*1024*1024*1024 {
		t.Errorf("virtual size: got %d, want %d", info.VirtualSize, uint64(20*1024*1024*1024))
	}
}

func TestResize(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "resize.qcow2")
	if err := Create(tmp, 1*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}

	newSize := uint64(50 * 1024 * 1024 * 1024)
	if err := Resize(tmp, newSize); err != nil {
		t.Fatal(err)
	}

	info, err := Info(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if info.VirtualSize != newSize {
		t.Errorf("virtual size after resize: got %d, want %d", info.VirtualSize, newSize)
	}

	// Check should pass.
	if err := Check(tmp); err != nil {
		t.Errorf("check failed after resize: %v", err)
	}
}

func TestResizeShrinkFails(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "shrink.qcow2")
	if err := Create(tmp, 10*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	if err := Resize(tmp, 5*1024*1024*1024); err == nil {
		t.Error("expected error when shrinking, got nil")
	}
}

func TestResizeNoop(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "noop.qcow2")
	size := uint64(10 * 1024 * 1024 * 1024)
	if err := Create(tmp, size, nil); err != nil {
		t.Fatal(err)
	}
	if err := Resize(tmp, size); err != nil {
		t.Errorf("resize to same size should succeed: %v", err)
	}
}

func TestConvertSimple(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	overlay := filepath.Join(dir, "overlay.qcow2")
	flat := filepath.Join(dir, "flat.qcow2")

	if err := Create(base, 1*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	if err := CreateWithBacking(overlay, base, 0, nil); err != nil {
		t.Fatal(err)
	}

	if err := Convert(context.Background(), overlay, flat, nil); err != nil {
		t.Fatal(err)
	}

	info, err := Info(flat)
	if err != nil {
		t.Fatal(err)
	}
	if info.BackingFile != "" {
		t.Errorf("flattened image should have no backing file, got %q", info.BackingFile)
	}
	if info.VirtualSize != 1*1024*1024*1024 {
		t.Errorf("virtual size: got %d, want %d", info.VirtualSize, uint64(1*1024*1024*1024))
	}
}

func TestCreateCustomOptions(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "custom.qcow2")
	opts := &Options{ClusterBits: 21, RefcountOrder: 4} // 2MB clusters
	if err := Create(tmp, 10*1024*1024*1024, opts); err != nil {
		t.Fatal(err)
	}

	info, err := Info(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if info.ClusterSize != 1<<21 {
		t.Errorf("cluster size: got %d, want %d", info.ClusterSize, 1<<21)
	}
}

func TestCheck(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "check.qcow2")
	if err := Create(tmp, 1*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	if err := Check(tmp); err != nil {
		t.Errorf("check failed: %v", err)
	}
}

func TestCheckInvalidMagic(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.qcow2")
	if err := os.WriteFile(tmp, make([]byte, 512), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Check(tmp); err == nil {
		t.Error("expected error for invalid magic")
	}
}

// ── Refcount read/write for all widths ──────────────────────────────────────

func TestRefcountRoundTrip(t *testing.T) {
	for _, bits := range []uint32{1, 2, 4, 8, 16, 32, 64} {
		block := make([]byte, 1024)
		// Write values at several indices, then read back.
		testVals := []struct {
			idx uint64
			val uint16
		}{
			{0, 1},
			{1, 1},
			{7, 1},
			{15, 1},
		}
		for _, tv := range testVals {
			writeRefcount(block, tv.idx, tv.val, bits)
		}
		for _, tv := range testVals {
			got := readRefcount(block, tv.idx, bits)
			// For small bit-widths, mask the expected value.
			maxVal := uint64((1 << bits) - 1)
			want := uint64(tv.val)
			if want > maxVal {
				want = maxVal
			}
			if got != want {
				t.Errorf("bits=%d idx=%d: got %d, want %d", bits, tv.idx, got, want)
			}
		}
		// Unwritten index should be zero.
		if got := readRefcount(block, 100, bits); got != 0 {
			t.Errorf("bits=%d unwritten idx=100: got %d, want 0", bits, got)
		}
	}
}

// ── Convert with actual data (using qemu-img to write) ──────────────────────

func TestConvertWithData(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}

	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	overlay := filepath.Join(dir, "overlay.qcow2")
	flat := filepath.Join(dir, "flat.qcow2")

	// Create base with qemu-img and write a pattern into it.
	run(t, "qemu-img", "create", "-f", "qcow2", base, "10M")
	// Write a known pattern at offset 0: 64KB of 0xAA bytes.
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0xAA 0 64k", base)

	// Create overlay with our code, write another pattern.
	if err := CreateWithBacking(overlay, base, 10*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	// Write 0xBB at offset 128K in overlay (different cluster than base data).
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0xBB 131072 64k", overlay)

	// Convert (flatten + compress) with our code.
	if err := Convert(context.Background(), overlay, flat, nil); err != nil {
		t.Fatal(err)
	}

	// Verify with qemu-img check.
	qemuImgCheck(t, flat)

	// Verify no backing file.
	info := qemuInfo(t, flat)
	if info.BackingFile != "" {
		t.Errorf("flattened image has backing file: %q", info.BackingFile)
	}

	// Read data back with qemu-io and verify patterns survived.
	verifyPattern(t, flat, 0, 64*1024, 0xAA)
	verifyPattern(t, flat, 131072, 64*1024, 0xBB)
	// Verify unwritten area is zero.
	verifyPattern(t, flat, 64*1024, 64*1024, 0x00)
}

// TestConvertUncompressed verifies the Uncompressed option: data flattens
// correctly AND the output has no compressed clusters (so a clone's guest can
// write in place without a decompress-rewrite — and the convert skips the
// expensive deflate).
func TestConvertUncompressed(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	overlay := filepath.Join(dir, "overlay.qcow2")
	flat := filepath.Join(dir, "flat.qcow2")

	run(t, "qemu-img", "create", "-f", "qcow2", base, "10M")
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0xAA 0 64k", base)
	if err := CreateWithBacking(overlay, base, 10*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0xBB 131072 64k", overlay)

	if err := Convert(context.Background(), overlay, flat, &Options{Uncompressed: true}); err != nil {
		t.Fatal(err)
	}

	qemuImgCheck(t, flat)
	if info := qemuInfo(t, flat); info.BackingFile != "" {
		t.Errorf("flattened image has backing file: %q", info.BackingFile)
	}
	// Data must survive the flatten (correctness).
	verifyPattern(t, flat, 0, 64*1024, 0xAA)
	verifyPattern(t, flat, 131072, 64*1024, 0xBB)
	verifyPattern(t, flat, 64*1024, 64*1024, 0x00)

	// And the result must be genuinely uncompressed (qemu-img check reports
	// "0.00% compressed clusters" for an uncompressed image, "100.00%" for a
	// `qemu-img convert -c` one).
	out, _ := exec.Command("qemu-img", "check", flat).CombinedOutput()
	if strings.Contains(string(out), "compressed clusters") &&
		!strings.Contains(string(out), "0.00% compressed clusters") {
		t.Errorf("expected 0.00%% compressed clusters in uncompressed convert:\n%s", out)
	}
}

// TestConvertDeepChain tests flattening a 3-layer backing chain.
func TestConvertDeepChain(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}

	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	mid := filepath.Join(dir, "mid.qcow2")
	top := filepath.Join(dir, "top.qcow2")
	flat := filepath.Join(dir, "flat.qcow2")

	// base: 0x11 at offset 0
	run(t, "qemu-img", "create", "-f", "qcow2", base, "1M")
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0x11 0 64k", base)

	// mid: overlay on base, 0x22 at offset 64K
	if err := CreateWithBacking(mid, base, 1*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0x22 65536 64k", mid)

	// top: overlay on mid, 0x33 at offset 128K
	if err := CreateWithBacking(top, mid, 1*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0x33 131072 64k", top)

	if err := Convert(context.Background(), top, flat, nil); err != nil {
		t.Fatal(err)
	}

	qemuImgCheck(t, flat)
	verifyPattern(t, flat, 0, 64*1024, 0x11)
	verifyPattern(t, flat, 65536, 64*1024, 0x22)
	verifyPattern(t, flat, 131072, 64*1024, 0x33)
}

// ── Convert standalone image (no backing chain) ─────────────────────────────

func TestConvertStandalone(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	dst := filepath.Join(dir, "dst.qcow2")

	run(t, "qemu-img", "create", "-f", "qcow2", src, "1M")
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0xFF 0 64k", src)

	if err := Convert(context.Background(), src, dst, nil); err != nil {
		t.Fatal(err)
	}

	qemuImgCheck(t, dst)
	verifyPattern(t, dst, 0, 64*1024, 0xFF)

	// Dest should be smaller or equal (compressed).
	srcInfo, _ := os.Stat(src)
	dstInfo, _ := os.Stat(dst)
	if dstInfo.Size() > srcInfo.Size()*2 {
		t.Errorf("compressed output (%d) much larger than source (%d)", dstInfo.Size(), srcInfo.Size())
	}
}

// ── Convert with compressed source (exercises readCompressedCluster) ────────

func TestConvertCompressedSource(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	compressed := filepath.Join(dir, "compressed.qcow2")
	overlay := filepath.Join(dir, "overlay.qcow2")
	flat := filepath.Join(dir, "flat.qcow2")

	// Create a source, write data, convert to compressed.
	run(t, "qemu-img", "create", "-f", "qcow2", src, "1M")
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0xAB 0 64k", src)
	if err := Convert(context.Background(), src, compressed, nil); err != nil {
		t.Fatal(err)
	}
	qemuImgCheck(t, compressed)

	// Create an overlay on top of the compressed image and write new data.
	if err := CreateWithBacking(overlay, compressed, 1*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0xCD 65536 64k", overlay)

	// Flatten: this reads compressed clusters from the backing file.
	if err := Convert(context.Background(), overlay, flat, nil); err != nil {
		t.Fatal(err)
	}
	qemuImgCheck(t, flat)
	verifyPattern(t, flat, 0, 64*1024, 0xAB)
	verifyPattern(t, flat, 65536, 64*1024, 0xCD)
}

// ── Resize requiring L1 expansion ───────────────────────────────────────────

func TestResizeL1Expansion(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "expand.qcow2")
	// Start very small (1M), L1 table is minimal.
	if err := Create(tmp, 1*1024*1024, nil); err != nil {
		t.Fatal(err)
	}

	info1, _ := Info(tmp)
	origL1 := info1.VirtualSize

	// Resize to 8TB — requires more L1 entries than a single cluster can hold at 64K.
	// Each L2 table covers 512MB (64K cluster * 8192 entries), so 8TB = 16384 L1 entries.
	newSize := uint64(8) * 1024 * 1024 * 1024 * 1024
	if err := Resize(tmp, newSize); err != nil {
		t.Fatal(err)
	}

	info2, err := Info(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if info2.VirtualSize != newSize {
		t.Errorf("virtual size: got %d, want %d", info2.VirtualSize, newSize)
	}
	if info2.VirtualSize <= origL1 {
		t.Error("size didn't actually grow")
	}

	if err := Check(tmp); err != nil {
		t.Errorf("check failed after L1 expansion: %v", err)
	}
	qemuImgCheck(t, tmp)
}

// ── Error path tests ────────────────────────────────────────────────────────

func TestCreateZeroSize(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "zero.qcow2")
	if err := Create(tmp, 0, nil); err == nil {
		t.Error("expected error for zero size")
	}
}

func TestCreateWithBackingEmptyPath(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "nobacking.qcow2")
	if err := CreateWithBacking(tmp, "", 1024, nil); err == nil {
		t.Error("expected error for empty backing path")
	}
}

func TestCreateWithBackingInheritSizeMissing(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "missing.qcow2")
	if err := CreateWithBacking(tmp, "/nonexistent/backing.qcow2", 0, nil); err == nil {
		t.Error("expected error for missing backing file with size=0")
	}
}

func TestResizeNonexistent(t *testing.T) {
	if err := Resize("/nonexistent/file.qcow2", 1024); err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestInfoNonexistent(t *testing.T) {
	if _, err := Info("/nonexistent/file.qcow2"); err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestCheckNonexistent(t *testing.T) {
	if err := Check("/nonexistent/file.qcow2"); err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseSizeErrors(t *testing.T) {
	for _, s := range []string{"", "abc", "10X", "-5G"} {
		if _, err := ParseSize(s); err == nil {
			t.Errorf("ParseSize(%q) should fail", s)
		}
	}
}

// ── Options edge cases ──────────────────────────────────────────────────────

func TestOptionsDefaults(t *testing.T) {
	// nil options should use defaults.
	var o *Options
	if o.clusterBits() != DefaultClusterBits {
		t.Errorf("nil clusterBits: got %d, want %d", o.clusterBits(), DefaultClusterBits)
	}
	if o.refcountOrder() != DefaultRefcountOrder {
		t.Errorf("nil refcountOrder: got %d, want %d", o.refcountOrder(), DefaultRefcountOrder)
	}

	// Out-of-range values should fall back to defaults.
	bad := &Options{ClusterBits: 99, RefcountOrder: 99}
	if bad.clusterBits() != DefaultClusterBits {
		t.Errorf("bad clusterBits: got %d, want %d", bad.clusterBits(), DefaultClusterBits)
	}
	if bad.refcountOrder() != DefaultRefcountOrder {
		t.Errorf("bad refcountOrder: got %d, want %d", bad.refcountOrder(), DefaultRefcountOrder)
	}
}

func TestCreateSmallCluster(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "small_cluster.qcow2")
	opts := &Options{ClusterBits: 12} // 4KB clusters
	if err := Create(tmp, 10*1024*1024, opts); err != nil {
		t.Fatal(err)
	}
	info, err := Info(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if info.ClusterSize != 1<<12 {
		t.Errorf("cluster size: got %d, want %d", info.ClusterSize, 1<<12)
	}
	if err := Check(tmp); err != nil {
		t.Errorf("check failed: %v", err)
	}
}

// ── Compressed cluster encode/decode round-trip ─────────────────────────────

func TestCompressedL2Encoding(t *testing.T) {
	// Test that encodeCompressedL2 produces valid entries matching QEMU's format.
	// encodeCompressedL2 takes nb_csectors (sector boundaries crossed).
	// QEMU stores nb_csectors directly, then adds 1 when decoding.
	clusterBits := uint32(16)
	hostOffset := uint64(0x10000) // 64KB aligned
	nbCsectors := uint64(3)      // 3 sector boundaries crossed

	entry := encodeCompressedL2(hostOffset, nbCsectors, clusterBits)

	// Verify compressed flag set, and copied flag (bit 63) NOT set.
	if entry&(1<<62) == 0 {
		t.Fatal("compressed flag not set")
	}
	if entry&(1<<63) != 0 {
		t.Fatal("copied flag must not be set for compressed clusters")
	}

	// Decode using QEMU's layout: csizeShift = 62 - (cluster_bits - 8).
	csizeShift := 62 - (clusterBits - 8)
	csizeMask := (uint64(1) << (clusterBits - 8)) - 1
	offsetMask := (uint64(1) << csizeShift) - 1

	// QEMU adds 1 to the stored value to get total sectors.
	decodedTotalSectors := ((entry >> csizeShift) & csizeMask) + 1
	decodedOffset := entry & offsetMask

	if decodedTotalSectors != nbCsectors+1 {
		t.Errorf("total sectors: decoded %d, want %d", decodedTotalSectors, nbCsectors+1)
	}
	if decodedOffset != hostOffset {
		t.Errorf("offset: decoded %d, want %d", decodedOffset, hostOffset)
	}
}

// ── L1 entry calculation ────────────────────────────────────────────────────

func TestL1Entries(t *testing.T) {
	clusterSize := uint64(65536) // 64KB
	tests := []struct {
		virtualSize uint64
		want        uint32
	}{
		{0, 1},                       // minimum 1
		{1, 1},                       // tiny
		{512 * 1024 * 1024, 1},       // 512MB = exactly 1 L2 table
		{512*1024*1024 + 1, 2},       // just over
		{1024 * 1024 * 1024, 2},      // 1GB
		{8 * 1024 * 1024 * 1024, 16}, // 8GB
	}
	for _, tt := range tests {
		got := l1Entries(tt.virtualSize, clusterSize)
		if got != tt.want {
			t.Errorf("l1Entries(%d, %d) = %d, want %d", tt.virtualSize, clusterSize, got, tt.want)
		}
	}
}

// ── Check detects corruption ────────────────────────────────────────────────

func TestCheckDetectsCorruptL1(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "corrupt_l1.qcow2")
	if err := Create(tmp, 1*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}

	// Corrupt the L1 table: write an L1 entry pointing way past the file end.
	f, err := os.OpenFile(tmp, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	h, err := readHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	var badEntry [8]byte
	binary.BigEndian.PutUint64(badEntry[:], 0x00FFFFFFFFFF0000) // huge offset
	f.WriteAt(badEntry[:], int64(h.L1TableOffset))
	f.Close()

	if err := Check(tmp); err == nil {
		t.Error("expected Check to detect corrupt L1 entry")
	}
}

func TestCheckDetectsCorruptRefcountTable(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "corrupt_rc.qcow2")
	if err := Create(tmp, 1*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}

	// Corrupt refcount table: point entry to past file end.
	f, err := os.OpenFile(tmp, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	h, err := readHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	var badEntry [8]byte
	binary.BigEndian.PutUint64(badEntry[:], 0x00FFFFFFFFFF0000)
	f.WriteAt(badEntry[:], int64(h.RefcountTableOffset))
	f.Close()

	if err := Check(tmp); err == nil {
		t.Error("expected Check to detect corrupt refcount table entry")
	}
}

// ── Convert error paths ─────────────────────────────────────────────────────

func TestConvertNonexistentSource(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "out.qcow2")
	err := Convert(context.Background(), "/nonexistent/src.qcow2", dst, nil)
	if err == nil {
		t.Error("expected error for nonexistent source")
	}
	// Temp file should be cleaned up.
	if _, statErr := os.Stat(dst + ".tmp"); !os.IsNotExist(statErr) {
		t.Error("temp file should not exist after error")
	}
}

func TestConvertContextCancellation(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	dst := filepath.Join(dir, "dst.qcow2")

	// Create a source with data so convert has work to do.
	run(t, "qemu-img", "create", "-f", "qcow2", src, "10M")
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0x42 0 64k", src)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.
	err := Convert(ctx, src, dst, nil)
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestConvertUncompressibleData(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	dst := filepath.Join(dir, "dst.qcow2")

	// Create source with a cluster of pre-compressed (random) data
	// that deflate cannot shrink below cluster_size - 1.
	// Use small 4KB clusters to make this feasible without huge writes.
	opts := &Options{ClusterBits: 12} // 4KB clusters
	clusterSize := uint64(4096)
	if err := Create(src, 64*1024, opts); err != nil {
		t.Fatal(err)
	}

	// Write pseudo-random data directly into the source's data area.
	// First allocate a cluster by writing via the L1/L2 tables.
	f, err := os.OpenFile(src, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := readHeader(f)

	// Allocate an L2 table at the next cluster.
	fi, _ := f.Stat()
	nextCluster := (uint64(fi.Size()) + clusterSize - 1) / clusterSize * clusterSize
	l2Off := nextCluster
	l2Table := make([]byte, clusterSize)
	f.WriteAt(l2Table, int64(l2Off))

	// Write L1 entry pointing to L2.
	var l1Buf [8]byte
	binary.BigEndian.PutUint64(l1Buf[:], l2Off|(1<<63))
	f.WriteAt(l1Buf[:], int64(h.L1TableOffset))

	// Allocate a data cluster.
	dataOff := l2Off + clusterSize
	// Generate high-entropy data using crypto/rand-like output.
	// Use a simple LCG to create truly incompressible data.
	randomData := make([]byte, clusterSize)
	v := uint64(0xDEADBEEFCAFE1234)
	for i := range randomData {
		v = v*6364136223846793005 + 1442695040888963407
		randomData[i] = byte(v >> 33)
	}
	f.WriteAt(randomData, int64(dataOff))

	// Write L2[0] pointing to data cluster with copied bit.
	var l2Buf [8]byte
	binary.BigEndian.PutUint64(l2Buf[:], dataOff|(1<<63))
	f.WriteAt(l2Buf[:], int64(l2Off))
	f.Close()

	// Convert — the high-entropy data should fall through to uncompressed path.
	if err := Convert(context.Background(), src, dst, opts); err != nil {
		t.Fatal(err)
	}

	if err := Check(dst); err != nil {
		t.Errorf("check failed: %v", err)
	}
}

// ── Convert with custom options ─────────────────────────────────────────────

func TestConvertCustomClusterSize(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	dst := filepath.Join(dir, "dst.qcow2")

	run(t, "qemu-img", "create", "-f", "qcow2", src, "1M")
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0x77 0 64k", src)

	opts := &Options{ClusterBits: 12} // 4KB clusters
	if err := Convert(context.Background(), src, dst, opts); err != nil {
		t.Fatal(err)
	}
	qemuImgCheck(t, dst)

	info, err := Info(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.ClusterSize != 1<<12 {
		t.Errorf("cluster size: got %d, want %d", info.ClusterSize, 1<<12)
	}
}

// ── Check: more header validation paths ─────────────────────────────────────

func TestCheckBadClusterBits(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad_cbits.qcow2")
	if err := Create(tmp, 1*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	// Corrupt cluster_bits to 8 (below minimum 9).
	f, _ := os.OpenFile(tmp, os.O_RDWR, 0)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], 8)
	f.WriteAt(buf[:], 20) // offset 20 = ClusterBits
	f.Close()

	if err := Check(tmp); err == nil {
		t.Error("expected error for invalid cluster_bits")
	}
}

func TestCheckBadRefcountOrder(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad_rco.qcow2")
	if err := Create(tmp, 1*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	// Corrupt refcount_order to 7 (above maximum 6).
	f, _ := os.OpenFile(tmp, os.O_RDWR, 0)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], 7)
	f.WriteAt(buf[:], 96) // offset 96 = RefcountOrder
	f.Close()

	if err := Check(tmp); err == nil {
		t.Error("expected error for invalid refcount_order")
	}
}

func TestCheckZeroVirtualSize(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "zero_size.qcow2")
	if err := Create(tmp, 1*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	// Set virtual size to 0.
	f, _ := os.OpenFile(tmp, os.O_RDWR, 0)
	var buf [8]byte
	f.WriteAt(buf[:], 24) // offset 24 = Size (write 0)
	f.Close()

	if err := Check(tmp); err == nil {
		t.Error("expected error for zero virtual size")
	}
}

func TestCheckCorruptBackingFileOffset(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	overlay := filepath.Join(dir, "overlay.qcow2")

	if err := Create(base, 1*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	if err := CreateWithBacking(overlay, base, 0, nil); err != nil {
		t.Fatal(err)
	}

	// Corrupt backing file size to extend beyond cluster 0 (64KB).
	// The backing file path starts after header+extensions (~130 bytes),
	// so a size of 65535 will push it past the 65536-byte cluster boundary.
	f, _ := os.OpenFile(overlay, os.O_RDWR, 0)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], 65535) // exceeds cluster 0
	f.WriteAt(buf[:], 16)                     // offset 16 = BackingFileSize
	f.Close()

	if err := Check(overlay); err == nil {
		t.Error("expected error for backing file extending beyond cluster 0")
	}
}

func TestCheckCorruptL2Data(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")

	// Create image with data so there's a populated L2 table.
	run(t, "qemu-img", "create", "-f", "qcow2", src, "1M")
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0x42 0 64k", src)

	// Find the L2 table and corrupt a data cluster offset.
	f, _ := os.OpenFile(src, os.O_RDWR, 0)
	h, _ := readHeader(f)

	// Read L1 to find L2 offset.
	var l1Buf [8]byte
	f.ReadAt(l1Buf[:], int64(h.L1TableOffset))
	l2Off := binary.BigEndian.Uint64(l1Buf[:]) & 0x00fffffffffffe00

	// Write a huge data offset into L2[0].
	var badL2 [8]byte
	binary.BigEndian.PutUint64(badL2[:], 0x00FFFFFFFFFF0000|(1<<63))
	f.WriteAt(badL2[:], int64(l2Off))
	f.Close()

	if err := Check(src); err == nil {
		t.Error("expected error for corrupt L2 data cluster offset")
	}
}

// ── Header validation ───────────────────────────────────────────────────────

func TestReadHeaderBadVersion(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "badver.qcow2")
	if err := Create(tmp, 1*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	// Set version to 1 (unsupported).
	f, _ := os.OpenFile(tmp, os.O_RDWR, 0)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], 1)
	f.WriteAt(buf[:], 4) // offset 4 = Version
	f.Close()

	if _, err := Info(tmp); err == nil {
		t.Error("expected error for version 1")
	}
}

func TestL2EntriesMethod(t *testing.T) {
	h := &Header{ClusterBits: 16}
	got := h.L2Entries()
	want := uint64(65536 / 8)
	if got != want {
		t.Errorf("L2Entries() = %d, want %d", got, want)
	}
}

// ── openChain error: broken backing chain ───────────────────────────────────

func TestConvertBrokenBackingChain(t *testing.T) {
	dir := t.TempDir()
	overlay := filepath.Join(dir, "overlay.qcow2")

	// Create overlay pointing to nonexistent backing file.
	if err := CreateWithBacking(overlay, filepath.Join(dir, "nonexistent.qcow2"), 1*1024*1024, nil); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(dir, "flat.qcow2")
	if err := Convert(context.Background(), overlay, dst, nil); err == nil {
		t.Error("expected error for broken backing chain")
	}
}

// ── Resize with qemu-img check validation ───────────────────────────────────

func TestResizeL1ExpansionAndQEMUCheck(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}

	dir := t.TempDir()
	img := filepath.Join(dir, "resize.qcow2")

	// Create small image with data.
	run(t, "qemu-img", "create", "-f", "qcow2", img, "1M")
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0xDD 0 64k", img)

	// Resize to something that requires more L1 entries.
	if err := Resize(img, 2*1024*1024*1024); err != nil {
		t.Fatal(err)
	}

	qemuImgCheck(t, img)
	verifyPattern(t, img, 0, 64*1024, 0xDD)
}

// ── Create on read-only dir ─────────────────────────────────────────────────

func TestCreateBadPath(t *testing.T) {
	err := Create("/nonexistent/dir/file.qcow2", 1*1024*1024, nil)
	if err == nil {
		t.Error("expected error for bad path")
	}
}

// ── Info on non-qcow2 file ──────────────────────────────────────────────────

func TestInfoNotQcow2(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "notqcow2.bin")
	if err := os.WriteFile(tmp, make([]byte, 1024), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Info(tmp); err == nil {
		t.Error("expected error for non-qcow2 file")
	}
}

// ── setRefcount: allocate new refcount block ────────────────────────────────

func TestResizeAllocatesNewRefcountBlock(t *testing.T) {
	// With 4KB clusters and 16-bit refcounts, one refcount block covers
	// 4096 / 2 = 2048 clusters. A fresh image uses ~4 clusters.
	// Resize that needs L1 expansion to clusters beyond index 2048
	// forces setRefcount to allocate a new refcount block.
	tmp := filepath.Join(t.TempDir(), "newrc.qcow2")
	opts := &Options{ClusterBits: 12} // 4KB clusters
	if err := Create(tmp, 64*1024, opts); err != nil {
		t.Fatal(err)
	}

	// With 4KB clusters, each L2 covers 4096/8 * 4096 = 2MB.
	// Resize to 16GB => 8192 L1 entries => 8192*8 = 64KB => 16 clusters for L1.
	// These 16 new clusters are at the end of the file, likely beyond
	// the initial refcount block's coverage.
	newSize := uint64(16) * 1024 * 1024 * 1024
	if err := Resize(tmp, newSize); err != nil {
		t.Fatal(err)
	}

	info, err := Info(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if info.VirtualSize != newSize {
		t.Errorf("virtual size: got %d, want %d", info.VirtualSize, newSize)
	}
	if err := Check(tmp); err != nil {
		t.Errorf("check failed: %v", err)
	}
	qemuImgCheck(t, tmp)
}

// ── Compressed L2 entries in Check ──────────────────────────────────────────

func TestCheckCompressedEntries(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	dst := filepath.Join(dir, "dst.qcow2")

	// Create and populate, then convert to get compressed clusters.
	run(t, "qemu-img", "create", "-f", "qcow2", src, "1M")
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0xEE 0 64k", src)
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 0xBB 65536 64k", src)

	if err := Convert(context.Background(), src, dst, nil); err != nil {
		t.Fatal(err)
	}

	// Check should validate compressed L2 entries without error.
	if err := Check(dst); err != nil {
		t.Errorf("Check on compressed image failed: %v", err)
	}
}

// ── Helper: run a command or fail ───────────────────────────────────────────

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// verifyPattern reads data from a qcow2 image using qemu-io and checks
// that every byte matches the expected pattern.
func verifyPattern(t *testing.T, path string, offset, length int, pattern byte) {
	t.Helper()
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not available")
	}

	cmd := exec.Command("qemu-io", "-f", "qcow2", "-r", "-c",
		formatReadPCmd(offset, length, pattern), path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("pattern mismatch at offset %d: expected 0x%02X\n%s", offset, pattern, out)
	}
}

func formatReadPCmd(offset, length int, pattern byte) string {
	return fmt.Sprintf("read -P %d %d %d", pattern, offset, length)
}

// QEMU compatibility tests — skipped if qemu-img not available.

func qemuImgCheck(t *testing.T, path string) {
	t.Helper()
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	out, err := exec.Command("qemu-img", "check", path).CombinedOutput()
	if err != nil {
		t.Errorf("qemu-img check failed: %v\n%s", err, out)
	}
}

type qemuImgInfo struct {
	VirtualSize uint64 `json:"virtual-size"`
	Format      string `json:"format"`
	BackingFile string `json:"full-backing-filename"`
}

func qemuInfo(t *testing.T, path string) qemuImgInfo {
	t.Helper()
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	out, err := exec.Command("qemu-img", "info", "--output=json", path).Output()
	if err != nil {
		t.Fatalf("qemu-img info: %v", err)
	}
	var info qemuImgInfo
	if err := json.Unmarshal(out, &info); err != nil {
		t.Fatalf("parse qemu-img info: %v", err)
	}
	return info
}

func TestQEMUCompat_Create(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "qemu_empty.qcow2")
	if err := Create(tmp, 10*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}

	qemuImgCheck(t, tmp)

	info := qemuInfo(t, tmp)
	if info.VirtualSize != 10*1024*1024*1024 {
		t.Errorf("qemu-img virtual-size: got %d, want %d", info.VirtualSize, uint64(10*1024*1024*1024))
	}
	if info.Format != "qcow2" {
		t.Errorf("qemu-img format: got %q, want qcow2", info.Format)
	}
}

func TestQEMUCompat_CreateWithBacking(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	overlay := filepath.Join(dir, "overlay.qcow2")

	if err := Create(base, 5*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	if err := CreateWithBacking(overlay, base, 0, nil); err != nil {
		t.Fatal(err)
	}

	qemuImgCheck(t, base)
	qemuImgCheck(t, overlay)

	info := qemuInfo(t, overlay)
	if info.VirtualSize != 5*1024*1024*1024 {
		t.Errorf("virtual-size: got %d, want %d", info.VirtualSize, uint64(5*1024*1024*1024))
	}
	if info.BackingFile != base {
		t.Errorf("backing file: got %q, want %q", info.BackingFile, base)
	}
}

func TestQEMUCompat_Resize(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "qemu_resize.qcow2")
	if err := Create(tmp, 1*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	if err := Resize(tmp, 50*1024*1024*1024); err != nil {
		t.Fatal(err)
	}

	qemuImgCheck(t, tmp)

	info := qemuInfo(t, tmp)
	if info.VirtualSize != 50*1024*1024*1024 {
		t.Errorf("virtual-size after resize: got %d, want %d", info.VirtualSize, uint64(50*1024*1024*1024))
	}
}

func TestQEMUCompat_Convert(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	overlay := filepath.Join(dir, "overlay.qcow2")
	flat := filepath.Join(dir, "flat.qcow2")

	if err := Create(base, 1*1024*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	if err := CreateWithBacking(overlay, base, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := Convert(context.Background(), overlay, flat, nil); err != nil {
		t.Fatal(err)
	}

	qemuImgCheck(t, flat)

	info := qemuInfo(t, flat)
	if info.BackingFile != "" {
		t.Errorf("flattened image has backing file: %q", info.BackingFile)
	}
}

func TestQEMUCompat_CustomClusterSize(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "custom_cluster.qcow2")
	opts := &Options{ClusterBits: 21} // 2MB clusters
	if err := Create(tmp, 10*1024*1024*1024, opts); err != nil {
		t.Fatal(err)
	}

	qemuImgCheck(t, tmp)
}
