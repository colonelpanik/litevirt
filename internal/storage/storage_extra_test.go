package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNew_CaseInsensitive(t *testing.T) {
	tests := []struct {
		driver   string
		wantName string
	}{
		{"LOCAL", "local"},
		{"Local", "local"},
		{"NFS", "nfs"},
		{"Nfs", "nfs"},
		{"CEPH", "ceph"},
		{"Ceph", "ceph"},
		{"ISCSI", "iscsi"},
		{"Iscsi", "iscsi"},
	}
	for _, tt := range tests {
		d, err := New("/tmp/test", Config{Driver: tt.driver})
		if err != nil {
			t.Fatalf("New(%q): %v", tt.driver, err)
		}
		if d.String() != tt.wantName {
			t.Errorf("New(%q).String() = %q, want %q", tt.driver, d.String(), tt.wantName)
		}
	}
}

func TestNew_UnknownDriver_ErrorMessage(t *testing.T) {
	_, err := New("/tmp/test", Config{Driver: "fictional"})
	if err == nil {
		t.Fatal("expected error for unknown driver")
	}
	if got := err.Error(); !strings.Contains(got, `unknown storage driver "fictional"`) {
		t.Errorf("error = %q, expected to mention the bad name", got)
	}
}

func TestLocalDriver_String(t *testing.T) {
	d := &localDriver{dataDir: "/tmp"}
	if d.String() != "local" {
		t.Errorf("String() = %q, want local", d.String())
	}
}

func TestNFSDriver_String(t *testing.T) {
	d := &nfsDriver{}
	if d.String() != "nfs" {
		t.Errorf("String() = %q, want nfs", d.String())
	}
}

func TestCephDriver_String(t *testing.T) {
	d := &cephDriver{}
	if d.String() != "ceph" {
		t.Errorf("String() = %q, want ceph", d.String())
	}
}

func TestISCSIDriver_String(t *testing.T) {
	d := &iscsiDriver{}
	if d.String() != "iscsi" {
		t.Errorf("String() = %q, want iscsi", d.String())
	}
}

func TestLocalDriver_Prepare_CreatesDisksDir(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "disks")
	d := &localDriver{dataDir: tmp}
	if err := d.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	info, err := os.Stat(tmp)
	if err != nil {
		t.Fatalf("dataDir not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected dataDir to be a directory")
	}
}

func TestLocalDriver_Prepare_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	d := &localDriver{dataDir: tmp}
	// Call twice — should not error.
	if err := d.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare 1: %v", err)
	}
	if err := d.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare 2: %v", err)
	}
}

func TestLocalDriver_DeleteDisk_ExistingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "disk.qcow2")
	if err := os.WriteFile(path, []byte("fake"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	d := &localDriver{dataDir: tmp}
	if err := d.DeleteDisk(context.Background(), path); err != nil {
		t.Fatalf("DeleteDisk: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should have been deleted")
	}
}

func TestNFSDriver_CreateDisk_NotPrepared_ErrorMsg(t *testing.T) {
	d := &nfsDriver{mountDir: ""}
	_, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm1", DiskName: "root"})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "NFS not prepared; call Prepare first" {
		t.Errorf("error = %q", err.Error())
	}
}

func TestNFSDriver_DeleteDisk_NotExist(t *testing.T) {
	d := &nfsDriver{}
	if err := d.DeleteDisk(context.Background(), "/nonexistent/disk.qcow2"); err != nil {
		t.Errorf("DeleteDisk non-existent: %v", err)
	}
}

func TestNFSDriver_DeleteDisk_ExistingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.qcow2")
	os.WriteFile(path, []byte("data"), 0644)
	d := &nfsDriver{}
	if err := d.DeleteDisk(context.Background(), path); err != nil {
		t.Fatalf("DeleteDisk: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be deleted")
	}
}

func TestNFSDriver_Prepare_MountDir(t *testing.T) {
	tmp := t.TempDir()
	d := &nfsDriver{
		source:    "10.0.0.1:/export/vms",
		mountBase: tmp,
		opts:      map[string]string{"options": "vers=4.1"},
	}
	// Prepare will fail (no NFS server), but mountDir should be set.
	_ = d.Prepare(context.Background())
	if d.mountDir == "" {
		t.Error("mountDir should be set after Prepare")
	}
	// Verify mount dir created.
	if _, err := os.Stat(d.mountDir); err != nil {
		t.Errorf("mount dir not created: %v", err)
	}
}

func TestISCSIDriver_CreateDisk_DevicePath(t *testing.T) {
	d := &iscsiDriver{
		target: "iqn.2024-01.com.example:target",
		opts:   map[string]string{"portal": "10.0.0.5", "lun": "3"},
	}
	path, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm1", DiskName: "root"})
	if err != nil {
		t.Fatalf("CreateDisk: %v", err)
	}
	expected := "/dev/disk/by-path/ip-10.0.0.5-iscsi-iqn.2024-01.com.example:target-lun-3"
	if path != expected {
		t.Errorf("path = %q, want %q", path, expected)
	}
}

func TestISCSIDriver_CreateDisk_DefaultLun(t *testing.T) {
	d := &iscsiDriver{
		target: "iqn.2024-01.com.example:target",
		opts:   map[string]string{"portal": "10.0.0.5"},
	}
	path, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm1", DiskName: "root"})
	if err != nil {
		t.Fatalf("CreateDisk: %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Errorf("path should be absolute, got %q", path)
	}
	// Default LUN is 0.
	if expected := "lun-0"; !contains(path, expected) {
		t.Errorf("path %q should contain %q", path, expected)
	}
}

func TestISCSIDriver_DeleteDisk_NoOp(t *testing.T) {
	d := &iscsiDriver{
		target: "iqn.2024-01.com.example:target",
		opts:   map[string]string{},
	}
	// iSCSI DeleteDisk is a no-op.
	if err := d.DeleteDisk(context.Background(), "/dev/sda"); err != nil {
		t.Errorf("DeleteDisk: %v", err)
	}
}

func TestCephImageName_EmptyPath(t *testing.T) {
	if got := cephImageName(""); got != "" {
		t.Errorf("cephImageName('') = %q, want empty", got)
	}
}

func TestCephImageName_RbdPrefix(t *testing.T) {
	got := cephImageName("rbd:pool/image")
	if got != "image" {
		t.Errorf("cephImageName = %q, want image", got)
	}
}

func TestCephPoolName_EmptyPath(t *testing.T) {
	if got := CephPoolName(""); got != "" {
		t.Errorf("CephPoolName('') = %q, want empty", got)
	}
}

func TestCephPoolName_NoSlash(t *testing.T) {
	if got := CephPoolName("rbd:poolonly"); got != "" {
		t.Errorf("CephPoolName('rbd:poolonly') = %q, want empty", got)
	}
}

func TestRbdArgs_Selective(t *testing.T) {
	// Test with only id set.
	d := &cephDriver{pool: "rbd", opts: map[string]string{"id": "admin"}}
	args := d.rbdArgs("info", "rbd/image")
	// Should have --id admin before subcommand.
	found := false
	for i, a := range args {
		if a == "--id" && i+1 < len(args) && args[i+1] == "admin" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected --id admin in args: %v", args)
	}
	// Should not have --conf or --keyring.
	for _, a := range args {
		if a == "--conf" || a == "--keyring" {
			t.Errorf("unexpected flag %q in args: %v", a, args)
		}
	}
}

func TestCephDriver_DeleteDisk_BadPath(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{}}
	err := d.DeleteDisk(context.Background(), "garbage")
	if err == nil {
		t.Error("expected error for unparseable ceph path")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
