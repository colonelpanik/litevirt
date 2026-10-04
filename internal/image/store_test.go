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
	if err := s.deleteAllVMDisksForTest(t, "test-vm"); err != nil {
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
	err := s.deleteAllVMDisksForTest(t, "nonexistent")
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

// Everything deleted must be something the candidate list named.
//
// DeleteVMDisksIn used to finish with os.RemoveAll of the legacy per-VM
// directory: a recursive delete no candidate list contained and no reference
// check ever saw, sitting under a comment promising that one listing drove both
// the protection and the deletion. A legacy disk another VM still referenced
// was destroyed by a call whose keep set said to spare it.
func TestStore_LegacyDirectoryContentsGoThroughTheKeepSet(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	legacyDir := filepath.Join(dir, "disks", "test-vm")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(legacyDir, "root.qcow2")
	debris := filepath.Join(legacyDir, "scratch.qcow2")
	for _, p := range []string{protected, debris} {
		if err := os.WriteFile(p, []byte("disk"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	candidates, err := s.VMDiskCandidates("test-vm")
	if err != nil {
		t.Fatalf("VMDiskCandidates: %v", err)
	}
	named := map[string]bool{}
	for _, c := range candidates {
		named[c] = true
	}
	if !named[protected] || !named[debris] {
		t.Fatalf("the candidate list does not name the legacy directory's files (%v); anything "+
			"the delete removes that this list omits is removed unprotected", candidates)
	}

	if err := s.DeleteVMDisksIn("test-vm", candidates, map[string]bool{protected: true}); err != nil {
		t.Fatalf("DeleteVMDisksIn: %v", err)
	}

	if _, err := os.Stat(protected); err != nil {
		t.Errorf("a legacy disk the keep set protected was deleted anyway (%v) — another VM may "+
			"still name it as a backing file", err)
	}
	if _, err := os.Stat(debris); !os.IsNotExist(err) {
		t.Errorf("unprotected legacy debris survived (%v); the sweep did nothing, so this test "+
			"proves nothing about what it spares", err)
	}
	// The directory stays while something protected is still inside it.
	if _, err := os.Stat(legacyDir); err != nil {
		t.Errorf("the legacy directory was removed while a protected disk was still in it: %v", err)
	}
}

// deleteAllVMDisksForTest is the old re-listing DeleteVMDisks, kept only here.
//
// The production form is gone: it listed again, so what it deleted was not what
// the caller computed protection against. Tests that only want "remove this
// VM's disks" list once and pass the list, which is what every caller now does.
func (s *Store) deleteAllVMDisksForTest(t *testing.T, vmName string) error {
	t.Helper()
	candidates, err := s.VMDiskCandidates(vmName)
	if err != nil {
		return err
	}
	return s.DeleteVMDisksIn(vmName, candidates, nil)
}

// A symlinked legacy directory is not this sweep's to walk into.
//
// os.ReadDir FOLLOWS a symlink, so listing its contents as candidates would
// unlink files on whatever volume it points at, one by one. The os.RemoveAll
// this replaced removed only the link and left the target intact — so the
// "safer" rewrite was, for this one layout, strictly more destructive.
func TestStore_ALegacySymlinkIsNotWalkedInto(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	elsewhere := t.TempDir()
	victim := filepath.Join(elsewhere, "someone-elses.qcow2")
	if err := os.WriteFile(victim, []byte("disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "disks", "test-vm")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	candidates, err := s.VMDiskCandidates("test-vm")
	if err != nil {
		t.Fatalf("VMDiskCandidates: %v", err)
	}
	for _, c := range candidates {
		if c == victim {
			t.Fatalf("the candidate list reached through a symlink to %s; sweeping it would "+
				"delete files on another volume that this VM does not own", victim)
		}
	}
	if err := s.DeleteVMDisksIn("test-vm", candidates, nil); err != nil {
		t.Fatalf("DeleteVMDisksIn: %v", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("a file behind the symlink was deleted: %v", err)
	}
}

// The delete refuses a path outside the directories it owns.
//
// The name guard only constrains the path this function builds; everything it
// actually removes comes from a caller-supplied slice, and the sweep seam is
// package-internal, so a future caller can hand it anything.
func TestStore_DeleteVMDisksInRefusesAPathItDoesNotOwn(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	outside := filepath.Join(t.TempDir(), "not-ours.qcow2")
	if err := os.WriteFile(outside, []byte("disk"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := s.DeleteVMDisksIn("test-vm", []string{outside}, nil)
	if err == nil {
		t.Error("a path outside the disk directory was accepted silently")
	}
	if _, serr := os.Stat(outside); serr != nil {
		t.Errorf("a file outside the disk directory was deleted: %v", serr)
	}
}
