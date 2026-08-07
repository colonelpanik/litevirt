package qcow2

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInfoRejectsHeaderControlledHugeAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostile.qcow2")
	if err := Create(path, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], ^uint32(0))
	if _, err := f.WriteAt(value[:], 36); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if _, err := Info(path); err == nil || !strings.Contains(err.Error(), "L1 table size") {
		t.Fatalf("Info error = %v, want bounded L1-table error", err)
	}
}

func TestConvertRejectsBackingChainCycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cycle.qcow2")
	if err := CreateWithBacking(path, path, 1<<20, nil); err != nil {
		t.Fatal(err)
	}

	err := Convert(context.Background(), path, filepath.Join(dir, "flat.qcow2"), nil)
	if err == nil || !strings.Contains(err.Error(), "backing chain cycle") {
		t.Fatalf("Convert error = %v, want cycle error", err)
	}
}

// TestConvertDetectsABackingCycleThroughASymlink.
//
// Pins the reason the lexical path comparison is enough, which is not obvious: a
// cycle closed through a symlink reaches the same FILE under two different names,
// and Abs+Clean resolves neither. It is still caught, because each file yields the
// same backing name every time — so the graph of names mirrors the graph of files
// and the repeat shows up one step later than it otherwise would.
//
// Worth a test rather than a comment because the property is easy to break: keying
// `seen` on anything that varies per visit, or resolving relative backing paths
// against the working directory instead of the image, loses it silently and the
// depth cap turns the loop into a misleading "exceeds maximum depth".
func TestConvertDetectsABackingCycleThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	link := filepath.Join(dir, "link.qcow2")

	// base's backing file is a symlink that points back at base.
	if err := CreateWithBacking(base, link, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err := Convert(context.Background(), base, filepath.Join(dir, "flat.qcow2"), nil)
	if err == nil {
		t.Fatal("a backing chain that closes through a symlink was walked without error")
	}
	if !strings.Contains(err.Error(), "backing chain cycle") {
		t.Fatalf("Convert error = %v\nwant the cycle named; comparing lexical paths cannot see "+
			"through a symlink, so the loop is only stopped by the depth cap and reported as "+
			"depth rather than as the loop it is", err)
	}
}
