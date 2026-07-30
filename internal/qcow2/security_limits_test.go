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
