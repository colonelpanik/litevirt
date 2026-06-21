package storage

import (
	"context"
	"testing"
)

// TestAsReplicator_DetectsCapableDrivers ensures the four send/recv-
// capable drivers (zfs, btrfs, ceph) report Replicator support, while
// the file-based drivers (local, dir, nfs) and external-allocation
// drivers (iscsi, lvm-thin) do not.
//
// The renderer's `if rep:= AsReplicator(d); rep != nil` is the
// documented branch the grpcapi layer uses; this test locks the
// per-driver answer.
func TestAsReplicator_DetectsCapableDrivers(t *testing.T) {
	cases := []struct {
		driver string
		want   bool
		// Source / target hint for New() so per-driver validation passes.
		source string
		target string
		opts   map[string]string
	}{
		{driver: "local", want: false},
		{driver: "dir", want: false, target: "/tmp"},
		{driver: "nfs", want: false, source: "host:/exp"},
		{driver: "iscsi", want: false, source: "iqn.x"},
		{driver: "ceph", want: true, source: "rbd"},
		{driver: "zfs", want: true, source: "tank/litevirt"},
		{driver: "btrfs", want: true, source: "/mnt/btrfs"},
		{driver: "lvm-thin", want: false, source: "vg0", opts: map[string]string{"thinpool": "p"}},
	}
	for _, tc := range cases {
		t.Run(tc.driver, func(t *testing.T) {
			d, err := New("/tmp/dummy", Config{
				Driver: tc.driver, Source: tc.source, Target: tc.target, Options: tc.opts,
			})
			if err != nil {
				t.Fatalf("New(%q): %v", tc.driver, err)
			}
			rep := AsReplicator(d)
			if (rep != nil) != tc.want {
				t.Errorf("AsReplicator(%q) = %v, want %v", tc.driver, rep != nil, tc.want)
			}
		})
	}
}

// TestReplicateOptions_RequiresRefs covers the validation each driver
// is required to perform — empty src/dst is a fast-fail.
func TestReplicateOptions_RequiresRefs(t *testing.T) {
	for _, tc := range []struct {
		driver, src, dst string
	}{
		{"zfs", "", "tank/dst"},
		{"zfs", "tank/src", ""},
		{"ceph", "", "rbd/dst"},
		{"ceph", "rbd/src", ""},
		{"btrfs", "", "/mnt/dst"},
	} {
		t.Run(tc.driver+"/"+tc.src+"_"+tc.dst, func(t *testing.T) {
			d, _ := New("/tmp", Config{Driver: tc.driver, Source: "x"})
			rep := AsReplicator(d)
			if rep == nil {
				t.Skip("driver doesn't implement Replicator")
			}
			err := rep.Replicate(context.Background(), ReplicateOptions{
				SrcRef: tc.src, DstRef: tc.dst,
			})
			if err == nil {
				t.Errorf("expected error for empty ref, got nil")
			}
		})
	}
}

// TestNowSnapTag formats a deterministic-ish stamp; we can't assert
// equality, but the shape (15 chars: "yyyymmdd-hhmmss") is stable.
func TestNowSnapTag(t *testing.T) {
	got := nowSnapTag()
	if len(got) != 15 || got[8] != '-' {
		t.Errorf("nowSnapTag = %q, want yyyymmdd-hhmmss", got)
	}
}
