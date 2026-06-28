package lxc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCgroupV2RelPath(t *testing.T) {
	dir := t.TempDir()

	v2 := filepath.Join(dir, "cgroup_v2")
	if err := os.WriteFile(v2, []byte("0::/lxc.payload.web/init\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rel, err := cgroupV2RelPath(v2); err != nil || rel != "/lxc.payload.web/init" {
		t.Errorf("v2 rel = %q, err = %v; want /lxc.payload.web/init", rel, err)
	}

	// cgroup-v1 layout (per-controller hierarchies, no "0::" unified line).
	v1 := filepath.Join(dir, "cgroup_v1")
	if err := os.WriteFile(v1, []byte("12:cpu,cpuacct:/lxc/web\n11:memory:/lxc/web\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cgroupV2RelPath(v1); !errors.Is(err, ErrStatsUnavailable) {
		t.Errorf("v1-only cgroup should be ErrStatsUnavailable, got %v", err)
	}

	if _, err := cgroupV2RelPath(filepath.Join(dir, "missing")); !errors.Is(err, ErrStatsUnavailable) {
		t.Errorf("missing file should be ErrStatsUnavailable, got %v", err)
	}
}

func TestReadCPUUsageUsec(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cpu.stat")
	if err := os.WriteFile(f, []byte("usage_usec 12345\nuser_usec 1\nsystem_usec 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, err := readCPUUsageUsec(f); err != nil || v != 12345 {
		t.Errorf("usage_usec = %d, err = %v; want 12345", v, err)
	}
	// Missing usage_usec line → error (not a silent 0).
	if err := os.WriteFile(f, []byte("user_usec 1\nsystem_usec 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCPUUsageUsec(f); err == nil {
		t.Error("missing usage_usec should error")
	}
}

func TestReadUint(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "memory.current")
	if err := os.WriteFile(f, []byte("4096\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, err := readUint(f); err != nil || v != 4096 {
		t.Errorf("readUint = %d, err = %v; want 4096", v, err)
	}
	// "max" (unlimited) reads as 0.
	if err := os.WriteFile(f, []byte("max\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, err := readUint(f); err != nil || v != 0 {
		t.Errorf("readUint(max) = %d, err = %v; want 0", v, err)
	}
	if _, err := readUint(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file should error")
	}
}

// TestStats_PartialReadUnavailable: if only one of cpu.stat/memory.current reads,
// Stats reports ErrStatsUnavailable (never a half-filled sample with a bogus 0)
// and invalidates the cached path so the next scrape re-discovers.
func TestStats_PartialReadUnavailable(t *testing.T) {
	dir := t.TempDir()
	// cpu.stat present, memory.current absent → partial.
	if err := os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte("usage_usec 5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &LxcRunner{cgPathCache: map[string]string{"web": dir}}
	if _, err := r.Stats(context.Background(), "web"); !errors.Is(err, ErrStatsUnavailable) {
		t.Errorf("partial read = %v, want ErrStatsUnavailable", err)
	}
	if _, ok := r.cgPathCache["web"]; ok {
		t.Error("a stale cgroup path must be invalidated on a read failure")
	}
}

// TestStats_BothReadsSucceed: a fully-readable cgroup dir yields the sample.
func TestStats_BothReadsSucceed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte("usage_usec 7000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.current"), []byte("1048576\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &LxcRunner{cgPathCache: map[string]string{"web": dir}}
	st, err := r.Stats(context.Background(), "web")
	if err != nil {
		t.Fatal(err)
	}
	if st.CPUUsageUsec != 7_000_000 || st.MemBytes != 1_048_576 {
		t.Errorf("Stats = %+v, want {7000000, 1048576}", st)
	}
}
