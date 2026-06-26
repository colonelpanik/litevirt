package image

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewStore_CustomDir(t *testing.T) {
	s := NewStore("/opt/litevirt")
	if s.imageDir != "/opt/litevirt/images" {
		t.Errorf("imageDir = %q", s.imageDir)
	}
	if s.diskDir != "/opt/litevirt/disks" {
		t.Errorf("diskDir = %q", s.diskDir)
	}
}

func TestStore_Init_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)

	// Init twice should not error
	if err := s.Init(); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	if err := s.Init(); err != nil {
		t.Fatalf("second Init: %v", err)
	}

	// Directories should still exist
	for _, sub := range []string{"images", "disks"} {
		info, err := os.Stat(filepath.Join(dir, sub))
		if err != nil {
			t.Errorf("%s not found: %v", sub, err)
		} else if !info.IsDir() {
			t.Errorf("%s is not a directory", sub)
		}
	}
}

func TestStore_ImageExists_NoInit(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)

	// Without Init, images dir doesn't exist, so ImageExists returns false
	if s.ImageExists("anything") {
		t.Error("should not exist without Init")
	}
}

func TestStore_ImageExists_MultipleImages(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	// Create several images
	images := []string{"ubuntu-24", "debian-12", "alpine-3.19"}
	for _, img := range images {
		os.WriteFile(s.ImagePath(img), []byte("fake"), 0644)
	}

	// All should exist
	for _, img := range images {
		if !s.ImageExists(img) {
			t.Errorf("image %q should exist", img)
		}
	}

	// Non-existent should not
	if s.ImageExists("fedora-40") {
		t.Error("fedora-40 should not exist")
	}
}

func TestStore_ImagePath_SpecialChars(t *testing.T) {
	s := NewStore("/data")
	// Image names with colons (like tags)
	path := s.ImagePath("myapp:v2.1")
	expected := "/data/images/myapp:v2.1.qcow2"
	if path != expected {
		t.Errorf("ImagePath = %q, want %q", path, expected)
	}
}

func TestStore_DiskPath_FlatNaming(t *testing.T) {
	s := NewStore("/var/lib/litevirt")
	p := s.DiskPath("stack-web-1", "root")
	if p != "/var/lib/litevirt/disks/stack-web-1-root.qcow2" {
		t.Errorf("DiskPath = %q", p)
	}
}

func TestStore_DeleteVMDisks_FlatFiles(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	// Create flat disk files for the VM
	for _, disk := range []string{"root", "data", "swap"} {
		os.WriteFile(s.DiskPath("multi-disk-vm", disk), []byte("disk content"), 0644)
	}

	// Verify files exist
	for _, disk := range []string{"root", "data", "swap"} {
		if _, err := os.Stat(s.DiskPath("multi-disk-vm", disk)); err != nil {
			t.Fatalf("disk %s should exist: %v", disk, err)
		}
	}

	// Delete
	if err := s.DeleteVMDisks("multi-disk-vm"); err != nil {
		t.Fatalf("DeleteVMDisks: %v", err)
	}

	// All disk files should be gone
	for _, disk := range []string{"root", "data", "swap"} {
		if _, err := os.Stat(s.DiskPath("multi-disk-vm", disk)); !os.IsNotExist(err) {
			t.Errorf("disk %s should be deleted", disk)
		}
	}
}

func TestStore_DiskInfo_LargerFile(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	path := filepath.Join(dir, "large.qcow2")
	data := make([]byte, 1024*1024) // 1 MiB
	os.WriteFile(path, data, 0644)

	_, actual, err := s.DiskInfo(path)
	if err != nil {
		t.Fatalf("DiskInfo: %v", err)
	}
	if actual != int64(1024*1024) {
		t.Errorf("actual size = %d, want %d", actual, 1024*1024)
	}
}

func TestStore_DiskInfo_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.qcow2")
	os.WriteFile(path, []byte{}, 0644)

	s := NewStore(dir)
	_, actual, err := s.DiskInfo(path)
	if err != nil {
		t.Fatalf("DiskInfo: %v", err)
	}
	if actual != 0 {
		t.Errorf("actual size = %d, want 0", actual)
	}
}

func TestStore_DiskDir_Consistency(t *testing.T) {
	s := NewStore("/data")
	// DiskDir should be a parent of DiskPath
	diskDir := s.DiskDir("myvm")
	diskPath := s.DiskPath("myvm", "root")
	if filepath.Dir(diskPath) != diskDir {
		t.Errorf("DiskPath dir %q != DiskDir %q", filepath.Dir(diskPath), diskDir)
	}
}

func TestStore_ImagePath_Consistency(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	imgName := "test-image"
	imgPath := s.ImagePath(imgName)

	// Write file at ImagePath, then ImageExists should find it
	os.WriteFile(imgPath, []byte("image data"), 0644)
	if !s.ImageExists(imgName) {
		t.Error("ImageExists should return true after writing to ImagePath")
	}
}

func TestStore_MultipleVMDisks_Independent(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	// Create flat disks for two VMs
	os.WriteFile(s.DiskPath("vm-a", "root"), []byte("disk"), 0644)
	os.WriteFile(s.DiskPath("vm-b", "root"), []byte("disk"), 0644)

	// Delete vm-a disks
	s.DeleteVMDisks("vm-a")

	// vm-b disk should still exist
	if _, err := os.Stat(s.DiskPath("vm-b", "root")); err != nil {
		t.Error("vm-b disks should still exist after deleting vm-a")
	}

	// vm-a disk should be gone
	if _, err := os.Stat(s.DiskPath("vm-a", "root")); !os.IsNotExist(err) {
		t.Error("vm-a disks should be deleted")
	}
}

// --- Pull function tests ---

func TestPull_Success(t *testing.T) {
	content := []byte("fake qcow2 image content for testing")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	ch := make(chan PullProgress, 100)
	err := Pull(s, "test-img", srv.URL+"/image.qcow2", "", PullOptions{}, ch)
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	// Image should exist now
	if !s.ImageExists("test-img") {
		t.Error("image should exist after pull")
	}

	// Verify content
	got, err := os.ReadFile(s.ImagePath("test-img"))
	if err != nil {
		t.Fatalf("read pulled image: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("pulled content mismatch")
	}

	// Check progress channel reported completion
	var lastStatus string
	for p := range ch {
		lastStatus = p.Status
	}
	if lastStatus != "complete" {
		t.Errorf("last status = %q, want complete", lastStatus)
	}
}

func TestPull_WithChecksum(t *testing.T) {
	content := []byte("image data with checksum verification")
	h := sha256.Sum256(content)
	checksum := "sha256:" + hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	ch := make(chan PullProgress, 100)
	err := Pull(s, "verified-img", srv.URL+"/image.qcow2", checksum, PullOptions{}, ch)
	if err != nil {
		t.Fatalf("Pull with valid checksum: %v", err)
	}
	// drain channel
	for range ch {
	}

	if !s.ImageExists("verified-img") {
		t.Error("image should exist after successful checksum pull")
	}
}

func TestPull_ChecksumMismatch(t *testing.T) {
	content := []byte("some image data")
	badChecksum := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	ch := make(chan PullProgress, 100)
	err := Pull(s, "bad-checksum", srv.URL+"/image.qcow2", badChecksum, PullOptions{}, ch)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	// drain channel
	for range ch {
	}

	if s.ImageExists("bad-checksum") {
		t.Error("image should not exist after checksum failure")
	}
}

func TestPull_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	ch := make(chan PullProgress, 100)
	err := Pull(s, "missing", srv.URL+"/notfound", "", PullOptions{}, ch)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	// drain channel
	for range ch {
	}
}

func TestPull_ChecksumWithoutPrefix(t *testing.T) {
	content := []byte("test content")
	h := sha256.Sum256(content)
	// Checksum without "sha256:" prefix
	checksum := hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	ch := make(chan PullProgress, 100)
	err := Pull(s, "no-prefix", srv.URL+"/img", checksum, PullOptions{}, ch)
	if err != nil {
		t.Fatalf("Pull with unprefixed checksum: %v", err)
	}
	for range ch {
	}

	if !s.ImageExists("no-prefix") {
		t.Error("image should exist")
	}
}

func TestPull_ProgressReporting(t *testing.T) {
	content := make([]byte, 10000)
	for i := range content {
		content[i] = byte(i % 256)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	s := NewStore(dir)
	s.Init()

	ch := make(chan PullProgress, 1000)
	err := Pull(s, "progress-test", srv.URL+"/img", "", PullOptions{}, ch)
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	var msgs []PullProgress
	for p := range ch {
		msgs = append(msgs, p)
	}

	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 progress messages, got %d", len(msgs))
	}

	// First message should be "downloading"
	if msgs[0].Status != "downloading" {
		t.Errorf("first status = %q, want downloading", msgs[0].Status)
	}

	// Last message should be "complete"
	if msgs[len(msgs)-1].Status != "complete" {
		t.Errorf("last status = %q, want complete", msgs[len(msgs)-1].Status)
	}
}

