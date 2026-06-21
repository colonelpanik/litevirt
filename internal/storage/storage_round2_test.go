package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── localDriver.DeleteDisk success with actual file ─────────────────────────

func TestLocalDriver_DeleteDisk_SuccessRound2(t *testing.T) {
	tmp := t.TempDir()
	diskFile := filepath.Join(tmp, "vm-root.qcow2")
	if err := os.WriteFile(diskFile, []byte("disk data"), 0644); err != nil {
		t.Fatal(err)
	}
	d := &localDriver{dataDir: tmp}
	if err := d.DeleteDisk(context.Background(), diskFile); err != nil {
		t.Fatalf("DeleteDisk: %v", err)
	}
	if _, err := os.Stat(diskFile); !os.IsNotExist(err) {
		t.Error("disk file should be deleted")
	}
}

// ── nfsDriver.DeleteDisk success with file ──────────────────────────────────

func TestNFSDriver_DeleteDisk_SuccessRound2(t *testing.T) {
	tmp := t.TempDir()
	diskFile := filepath.Join(tmp, "vm1-root.qcow2")
	if err := os.WriteFile(diskFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	d := &nfsDriver{}
	if err := d.DeleteDisk(context.Background(), diskFile); err != nil {
		t.Fatalf("DeleteDisk: %v", err)
	}
	if _, err := os.Stat(diskFile); !os.IsNotExist(err) {
		t.Error("file should be deleted")
	}
}

// ── cephDriver.DeleteDisk parsing ───────────────────────────────────────────

func TestCephDriver_DeleteDisk_BadPrefixNoSlashRound2(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{}}
	err := d.DeleteDisk(context.Background(), "not-rbd-format")
	if err == nil {
		t.Fatal("expected error for bad path format")
	}
	if !strings.Contains(err.Error(), "cannot parse") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

// ── cephImageName edge cases ────────────────────────────────────────────────

func TestCephImageName_NoRBDPrefixRound2(t *testing.T) {
	got := cephImageName("pool/image")
	if got != "image" {
		t.Errorf("cephImageName('pool/image') = %q, want 'image'", got)
	}
}

func TestCephPoolName_OnlySlashRound2(t *testing.T) {
	got := CephPoolName("rbd:/image")
	// After stripping "rbd:", we have "/image" -> parts[0]="" (empty pool)
	if got != "" {
		t.Errorf("CephPoolName('rbd:/image') = %q, want empty", got)
	}
}

// ── rbdArgs with only id ────────────────────────────────────────────────────

func TestRbdArgs_OnlyIDRound2(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{"id": "admin"}}
	args := d.rbdArgs("info", "rbd/img")
	foundID := false
	for i, a := range args {
		if a == "--id" && i+1 < len(args) && args[i+1] == "admin" {
			foundID = true
		}
		if a == "--conf" || a == "--keyring" {
			t.Errorf("unexpected flag %q in args", a)
		}
	}
	if !foundID {
		t.Errorf("expected --id in args: %v", args)
	}
	// Sub-args should be at the end.
	if args[len(args)-2] != "info" || args[len(args)-1] != "rbd/img" {
		t.Errorf("subcommand args wrong: %v", args)
	}
}

// ── iSCSI driver default LUN ────────────────────────────────────────────────

func TestISCSIDriver_CreateDisk_DefaultLUNRound2(t *testing.T) {
	d := &iscsiDriver{
		target: "iqn.2024-01.com.example:target",
		opts:   map[string]string{"portal": "10.0.0.1"},
	}
	path, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: "root"})
	if err != nil {
		t.Fatalf("CreateDisk: %v", err)
	}
	expected := "/dev/disk/by-path/ip-10.0.0.1-iscsi-iqn.2024-01.com.example:target-lun-0"
	if path != expected {
		t.Errorf("path = %q, want %q", path, expected)
	}
}

// ── Config fields round-trip ────────────────────────────────────────────────

func TestConfig_FieldsPreserved(t *testing.T) {
	cfg := Config{
		Driver:  "ceph",
		Source:  "my-pool",
		Options: map[string]string{"id": "user1", "conf": "/etc/ceph.conf", "keyring": "/etc/key"},
	}
	d, err := New("/data", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cd := d.(*cephDriver)
	if cd.pool != "my-pool" {
		t.Errorf("pool = %q", cd.pool)
	}
	if cd.opts["id"] != "user1" {
		t.Errorf("opts[id] = %q", cd.opts["id"])
	}
	if cd.opts["conf"] != "/etc/ceph.conf" {
		t.Errorf("opts[conf] = %q", cd.opts["conf"])
	}
	if cd.opts["keyring"] != "/etc/key" {
		t.Errorf("opts[keyring] = %q", cd.opts["keyring"])
	}
}

// ── nfsDriver mount base construction ───────────────────────────────────────

func TestNFSDriver_MountBaseFromDataDir(t *testing.T) {
	d, err := New("/var/lib/litevirt", Config{
		Driver: "nfs",
		Source: "10.0.0.1:/exports/vm",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	nd := d.(*nfsDriver)
	want := filepath.Join("/var/lib/litevirt", "mounts")
	if nd.mountBase != want {
		t.Errorf("mountBase = %q, want %q", nd.mountBase, want)
	}
}

// ── localDriver.CreateDisk ──────────────────────────────────────────────────

func TestLocalDriver_CreateDisk_PathConstruction(t *testing.T) {
	tmp := t.TempDir()
	d := &localDriver{dataDir: tmp}
	path, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName:    "test-vm",
		DiskName:  "data",
		SizeBytes: 1024 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("CreateDisk failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("disk file not found: %v", err)
	}
}

func TestLocalDriver_CreateDisk_WithSourceImage(t *testing.T) {
	tmp := t.TempDir()
	d := &localDriver{dataDir: tmp}
	path, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName:      "vm1",
		DiskName:    "root",
		SizeBytes:   10 * 1024 * 1024 * 1024,
		Format:      "qcow2",
		SourceImage: "/images/base.qcow2",
	})
	// With explicit size, backing file path is stored without validation
	// (matches QEMU behavior). The file is created successfully.
	if err != nil {
		t.Fatalf("CreateDisk with source image failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("disk file not found: %v", err)
	}
}

func TestLocalDriver_CreateDisk_RawFormat(t *testing.T) {
	tmp := t.TempDir()
	d := &localDriver{dataDir: tmp}
	path, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName:    "vm1",
		DiskName:  "root",
		SizeBytes: 1024 * 1024,
		Format:    "raw",
	})
	if err != nil {
		t.Fatalf("CreateDisk raw failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 1024*1024 {
		t.Errorf("raw disk size = %d, want %d", info.Size(), 1024*1024)
	}
}

// ── cephDriver.CreateDisk error paths ───────────────────────────────────────

func TestCephDriver_CreateDisk_ZeroSizeDefaults(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{}}
	_, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName:    "vm1",
		DiskName:  "root",
		SizeBytes: 0,
	})
	if err == nil {
		return
	}
	if !strings.Contains(err.Error(), "rbd create") {
		t.Errorf("error should reference rbd create, got: %v", err)
	}
}

func TestCephDriver_CreateDisk_SmallSize(t *testing.T) {
	d := &cephDriver{pool: "testpool", opts: map[string]string{}}
	_, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName:    "vm1",
		DiskName:  "data",
		SizeBytes: 500,
	})
	if err == nil {
		return
	}
	if !strings.Contains(err.Error(), "rbd create") {
		t.Errorf("error should reference rbd create, got: %v", err)
	}
}

func TestCephDriver_CreateDisk_WithSourceImage(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{}}
	_, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName:      "vm1",
		DiskName:    "root",
		SizeBytes:   10 * 1024 * 1024 * 1024,
		SourceImage: "rbd/base@snap1",
	})
	if err == nil {
		return
	}
	// Should fail at rbd create (no rbd binary), not at clone.
	if !strings.Contains(err.Error(), "rbd create") {
		t.Errorf("error should reference rbd create, got: %v", err)
	}
}

func TestCephDriver_CreateDisk_WithConfAndKeyring(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{
		"conf":    "/etc/ceph/ceph.conf",
		"keyring": "/etc/ceph/keyring",
	}}
	_, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName:    "vm1",
		DiskName:  "root",
		SizeBytes: 5 * 1024 * 1024 * 1024,
	})
	if err == nil {
		return
	}
	if !strings.Contains(err.Error(), "rbd create") {
		t.Errorf("error should reference rbd create, got: %v", err)
	}
}

// ── cephDriver.Prepare error path ───────────────────────────────────────────

func TestCephDriver_Prepare_Error(t *testing.T) {
	d := &cephDriver{pool: "nonexistent-pool", opts: map[string]string{}}
	err := d.Prepare(context.Background())
	if err == nil {
		return // rbd happened to be available and pool exists
	}
	if !strings.Contains(err.Error(), "not accessible") {
		t.Errorf("error should mention 'not accessible', got: %v", err)
	}
}

// ── nfsDriver.Prepare creates safe mount dir name ───────────────────────────

func TestNFSDriver_Prepare_SafeMountDirName(t *testing.T) {
	tmp := t.TempDir()
	d := &nfsDriver{
		source:    "192.168.1.10:/data/vms",
		mountBase: tmp,
		opts:      map[string]string{},
	}
	_ = d.Prepare(context.Background()) // will fail without NFS but mountDir set

	// The mount dir name should have slashes and colons replaced with underscores.
	safe := strings.NewReplacer("/", "_", ":", "_").Replace("192.168.1.10:/data/vms")
	expected := filepath.Join(tmp, safe)
	if d.mountDir != expected {
		t.Errorf("mountDir = %q, want %q", d.mountDir, expected)
	}
}

// ── nfsDriver.Prepare with custom options ───────────────────────────────────

func TestNFSDriver_Prepare_CustomOptions(t *testing.T) {
	tmp := t.TempDir()
	d := &nfsDriver{
		source:    "10.0.0.5:/share",
		mountBase: tmp,
		opts:      map[string]string{"options": "vers=4.2,hard,timeo=600"},
	}
	// Prepare will fail (no NFS), but should create dir and set mountDir.
	_ = d.Prepare(context.Background())
	if d.mountDir == "" {
		t.Error("mountDir should be set after Prepare")
	}
}
