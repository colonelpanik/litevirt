package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNew_Local(t *testing.T) {
	d, err := New("/tmp/test", Config{Driver: "local"})
	if err != nil || d == nil {
		t.Fatalf("New local: %v", err)
	}
	if d.String() != "local" {
		t.Errorf("expected 'local', got %q", d.String())
	}
}

func TestNew_NFS(t *testing.T) {
	d, err := New("/tmp/test", Config{Driver: "nfs", Source: "10.0.0.1:/exports"})
	if err != nil || d == nil {
		t.Fatalf("New nfs: %v", err)
	}
	if d.String() != "nfs" {
		t.Errorf("expected 'nfs', got %q", d.String())
	}
}

func TestNew_Ceph(t *testing.T) {
	d, err := New("/tmp/test", Config{Driver: "ceph", Source: "litevirt"})
	if err != nil || d == nil {
		t.Fatalf("New ceph: %v", err)
	}
	if d.String() != "ceph" {
		t.Errorf("expected 'ceph', got %q", d.String())
	}
}

func TestNew_ISCSI(t *testing.T) {
	d, err := New("/tmp/test", Config{Driver: "iscsi", Source: "iqn.2024-01.com.example:storage"})
	if err != nil || d == nil {
		t.Fatalf("New iscsi: %v", err)
	}
	if d.String() != "iscsi" {
		t.Errorf("expected 'iscsi', got %q", d.String())
	}
}

func TestNew_UnknownDriver(t *testing.T) {
	_, err := New("/tmp/test", Config{Driver: "glusterfs"})
	if err == nil {
		t.Error("expected error for unknown driver")
	}
}

func TestNew_EmptyDriver_IsLocal(t *testing.T) {
	d, err := New("/tmp/test", Config{Driver: ""})
	if err != nil {
		t.Fatalf("New empty: %v", err)
	}
	if d.String() != "local" {
		t.Errorf("expected 'local' for empty driver, got %q", d.String())
	}
}

func TestLocalDriver_Prepare(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "disks")
	d := &localDriver{dataDir: tmp}
	if err := d.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Errorf("expected dataDir to be created: %v", err)
	}
}

func TestLocalDriver_DeleteDisk_NotExist(t *testing.T) {
	d := &localDriver{dataDir: t.TempDir()}
	// Should not error if file doesn't exist.
	if err := d.DeleteDisk(context.Background(), "/nonexistent/path/disk.qcow2"); err != nil {
		t.Errorf("DeleteDisk non-existent: %v", err)
	}
}

func TestCephImageName(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"rbd:litevirt/vm1-root", "vm1-root"},
		{"rbd:rbd/vm2-data:conf=/etc/ceph/ceph.conf", "vm2-data"},
		{"rbd:pool/disk:conf=x:keyring=y", "disk"},
		{"invalid", ""},
	}
	for _, tc := range cases {
		got := cephImageName(tc.path)
		if got != tc.want {
			t.Errorf("cephImageName(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestNFSDriver_MountDir(t *testing.T) {
	tmp := t.TempDir()
	d := &nfsDriver{
		source:    "10.0.0.1:/exports/vms",
		mountBase: tmp,
		opts:      map[string]string{},
	}
	// Prepare will fail (no NFS server), but should create mount dir and attempt.
	_ = d.Prepare(context.Background())

	safe := strings.NewReplacer("/", "_", ":", "_").Replace(d.source)
	expected := filepath.Join(tmp, safe)
	if d.mountDir != expected {
		t.Errorf("expected mountDir %q, got %q", expected, d.mountDir)
	}
	// The directory should have been created.
	if _, err := os.Stat(d.mountDir); err != nil {
		t.Errorf("mount dir not created: %v", err)
	}
}

func TestNFSDriver_CreateDisk_NotPrepared(t *testing.T) {
	d := &nfsDriver{mountDir: ""}
	_, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm1", DiskName: "root"})
	if err == nil {
		t.Error("expected error when NFS not prepared")
	}
}
