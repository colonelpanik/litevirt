package storage

import (
	"context"
	"strings"
	"testing"
)

func testCtx() context.Context { return context.Background() }

// TestNew_DispatchesToEveryDriver locks the mapping in storage.New so a
// future rename can't silently route a config to the wrong backend.
func TestNew_DispatchesToEveryDriver(t *testing.T) {
	cases := []struct {
		driver string
		want   string
		extra  map[string]string
		source string
		target string
	}{
		{driver: "", want: "local"},
		{driver: "local", want: "local"},
		{driver: "LoCaL", want: "local"},
		{driver: "dir", want: "dir", target: "/tmp"},
		{driver: "nfs", want: "nfs", source: "srv:/exp"},
		{driver: "ceph", want: "ceph", source: "rbd"},
		{driver: "iscsi", want: "iscsi", source: "iqn.x"},
		{driver: "zfs", want: "zfs", source: "tank/litevirt"},
		{driver: "btrfs", want: "btrfs", source: "/mnt/btrfs"},
		{driver: "lvm-thin", want: "lvm-thin", source: "vg0", extra: map[string]string{"thinpool": "pool0"}},
		{driver: "lvmthin", want: "lvm-thin", source: "vg0", extra: map[string]string{"thinpool": "pool0"}},
	}
	for _, tc := range cases {
		d, err := New("/tmp/test", Config{
			Driver:  tc.driver,
			Source:  tc.source,
			Target:  tc.target,
			Options: tc.extra,
		})
		if err != nil {
			t.Errorf("New(%q): %v", tc.driver, err)
			continue
		}
		if d.String() != tc.want {
			t.Errorf("New(%q).String() = %q, want %q", tc.driver, d.String(), tc.want)
		}
	}
}

// TestSupportedDriversIsExhaustive ensures the user-facing list keeps in
// sync with the dispatcher; missing entries here lead to confusing
// "unknown storage driver" errors with no autocomplete hints.
func TestSupportedDriversIsExhaustive(t *testing.T) {
	want := []string{"local", "nfs", "iscsi", "ceph", "zfs", "btrfs", "lvm-thin", "dir"}
	got := strings.Join(SupportedDrivers, ",")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("SupportedDrivers missing %q (got %v)", w, SupportedDrivers)
		}
	}
}

// TestDir_PrepareValidatesPath verifies dirDriver rejects a missing target
// and accepts an existing directory.
func TestDir_PrepareValidatesPath(t *testing.T) {
	d, err := New("/tmp/dummy", Config{Driver: "dir", Target: "/nonexistent/path/zzz"})
	if err != nil {
		t.Fatalf("New(dir): %v", err)
	}
	if err := d.Prepare(testCtx()); err == nil {
		t.Error("expected dir Prepare to fail for missing target")
	}
	d2, _ := New("/tmp/dummy", Config{Driver: "dir", Target: "/tmp"})
	if err := d2.Prepare(testCtx()); err != nil {
		t.Errorf("dir Prepare on /tmp: %v", err)
	}
}

// TestDir_RequiresTarget verifies the dispatcher refuses an empty target.
func TestDir_RequiresTarget(t *testing.T) {
	if _, err := New("/tmp/dummy", Config{Driver: "dir"}); err == nil {
		t.Error("expected error when dir driver is used without Target")
	}
}

// TestLVMThin_RequiresThinpool verifies pool config validation catches
// the most common misconfiguration.
func TestLVMThin_RequiresThinpool(t *testing.T) {
	d, err := New("/tmp", Config{Driver: "lvm-thin", Source: "vg0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.Prepare(testCtx()); err == nil {
		t.Error("expected lvm-thin Prepare to fail without thinpool option")
	}
}
