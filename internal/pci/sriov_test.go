package pci

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListVFAddresses(t *testing.T) {
	tmp := t.TempDir()

	// Create fake virtfn symlinks
	vfDir := filepath.Join(tmp, "vf_targets", "0000:41:00.1")
	os.MkdirAll(vfDir, 0755)
	os.Symlink("../vf_targets/0000:41:00.1", filepath.Join(tmp, "virtfn0"))

	vfDir2 := filepath.Join(tmp, "vf_targets", "0000:41:00.2")
	os.MkdirAll(vfDir2, 0755)
	os.Symlink("../vf_targets/0000:41:00.2", filepath.Join(tmp, "virtfn1"))

	// Also create a non-virtfn entry that should be ignored
	os.WriteFile(filepath.Join(tmp, "vendor"), []byte("0x10de\n"), 0644)

	addrs := listVFAddresses(tmp)
	if len(addrs) != 2 {
		t.Fatalf("expected 2 VF addresses, got %d: %v", len(addrs), addrs)
	}

	found := map[string]bool{}
	for _, a := range addrs {
		found[a] = true
	}
	if !found["0000:41:00.1"] {
		t.Error("missing VF 0000:41:00.1")
	}
	if !found["0000:41:00.2"] {
		t.Error("missing VF 0000:41:00.2")
	}
}

func TestListVFAddresses_NoVFs(t *testing.T) {
	tmp := t.TempDir()
	addrs := listVFAddresses(tmp)
	if len(addrs) != 0 {
		t.Errorf("expected 0 VF addresses, got %d", len(addrs))
	}
}

func TestListVFAddresses_NonexistentDir(t *testing.T) {
	addrs := listVFAddresses("/nonexistent/path")
	if addrs != nil {
		t.Errorf("expected nil, got %v", addrs)
	}
}

func TestScanDevice_NotFound(t *testing.T) {
	_, err := ScanDevice("0000:ff:ff.f")
	if err == nil {
		t.Error("expected error for nonexistent device")
	}
}
