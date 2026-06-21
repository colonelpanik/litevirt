package image

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewStore(t *testing.T) {
	s := NewStore("/var/lib/litevirt")
	if s.imageDir != "/var/lib/litevirt/images" {
		t.Errorf("imageDir = %s", s.imageDir)
	}
	if s.diskDir != "/var/lib/litevirt/disks" {
		t.Errorf("diskDir = %s", s.diskDir)
	}
}

func TestStore_Init(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)

	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Verify directories exist
	for _, d := range []string{
		filepath.Join(dir, "images"),
		filepath.Join(dir, "disks"),
	} {
		info, err := os.Stat(d)
		if err != nil {
			t.Errorf("directory %s not created: %v", d, err)
		} else if !info.IsDir() {
			t.Errorf("%s is not a directory", d)
		}
	}
}

func TestStore_ImagePath(t *testing.T) {
	s := NewStore("/data")
	path := s.ImagePath("ubuntu-24")
	if path != "/data/images/ubuntu-24.qcow2" {
		t.Errorf("ImagePath = %s", path)
	}
}

func TestStore_ImageExists(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	// Doesn't exist yet
	if s.ImageExists("test-img") {
		t.Error("image should not exist")
	}

	// Create it
	imgPath := s.ImagePath("test-img")
	os.WriteFile(imgPath, []byte("fake image"), 0644)

	if !s.ImageExists("test-img") {
		t.Error("image should exist after creation")
	}
}

func TestStore_DiskDir(t *testing.T) {
	s := NewStore("/data")
	if d := s.DiskDir("myvm"); d != "/data/disks" {
		t.Errorf("DiskDir = %s", d)
	}
}

func TestStore_DiskPath(t *testing.T) {
	s := NewStore("/data")
	if p := s.DiskPath("myvm", "root"); p != "/data/disks/myvm-root.qcow2" {
		t.Errorf("DiskPath = %s", p)
	}
	if p := s.DiskPath("myvm", "data"); p != "/data/disks/myvm-data.qcow2" {
		t.Errorf("DiskPath = %s", p)
	}
}

func TestStore_DeleteVMDisks(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	// Create flat disk files
	os.WriteFile(s.DiskPath("test-vm", "root"), []byte("disk"), 0644)
	os.WriteFile(s.DiskPath("test-vm", "data"), []byte("disk"), 0644)

	// Verify they exist
	if _, err := os.Stat(s.DiskPath("test-vm", "root")); err != nil {
		t.Fatalf("root disk should exist: %v", err)
	}

	// Delete
	if err := s.DeleteVMDisks("test-vm"); err != nil {
		t.Fatalf("DeleteVMDisks: %v", err)
	}

	// Verify disk files removed
	if _, err := os.Stat(s.DiskPath("test-vm", "root")); !os.IsNotExist(err) {
		t.Error("root disk should be deleted")
	}
	if _, err := os.Stat(s.DiskPath("test-vm", "data")); !os.IsNotExist(err) {
		t.Error("data disk should be deleted")
	}
}

func TestStore_DeleteVMDisks_NonExistent(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)

	// Should not error on non-existent VM
	err := s.DeleteVMDisks("nonexistent")
	if err != nil {
		t.Errorf("DeleteVMDisks on nonexistent: %v", err)
	}
}

func TestStore_DiskInfo(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	// Create a fake disk file
	path := filepath.Join(dir, "test.qcow2")
	data := make([]byte, 4096)
	os.WriteFile(path, data, 0644)

	_, actual, err := s.DiskInfo(path)
	if err != nil {
		t.Fatalf("DiskInfo: %v", err)
	}
	if actual != 4096 {
		t.Errorf("actual size = %d, want 4096", actual)
	}
}

func TestStore_DiskInfo_NotFound(t *testing.T) {
	s := NewStore("/tmp")
	_, _, err := s.DiskInfo("/nonexistent/disk.qcow2")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}
