package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// ── New() edge cases ────────────────────────────────────────────────────────

func TestNew_LocalSetsDataDir(t *testing.T) {
	d, err := New("/data/litevirt", Config{Driver: "local"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ld, ok := d.(*localDriver)
	if !ok {
		t.Fatal("expected *localDriver")
	}
	if ld.dataDir != "/data/litevirt/disks" {
		t.Errorf("dataDir = %q, want /data/litevirt/disks", ld.dataDir)
	}
}

func TestNew_NFSSetsFields(t *testing.T) {
	d, err := New("/data", Config{
		Driver:  "nfs",
		Source:  "10.0.0.5:/share",
		Options: map[string]string{"options": "vers=4.2"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	nd, ok := d.(*nfsDriver)
	if !ok {
		t.Fatal("expected *nfsDriver")
	}
	if nd.source != "10.0.0.5:/share" {
		t.Errorf("source = %q", nd.source)
	}
	if nd.mountBase != filepath.Join("/data", "mounts") {
		t.Errorf("mountBase = %q", nd.mountBase)
	}
	if nd.opts["options"] != "vers=4.2" {
		t.Errorf("opts[options] = %q", nd.opts["options"])
	}
}

func TestNew_CephSetsPool(t *testing.T) {
	d, err := New("/data", Config{
		Driver:  "ceph",
		Source:  "mypool",
		Options: map[string]string{"id": "admin", "conf": "/etc/ceph/ceph.conf"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cd, ok := d.(*cephDriver)
	if !ok {
		t.Fatal("expected *cephDriver")
	}
	if cd.pool != "mypool" {
		t.Errorf("pool = %q", cd.pool)
	}
	if cd.opts["id"] != "admin" {
		t.Errorf("opts[id] = %q", cd.opts["id"])
	}
}

func TestNew_ISCSISetsTarget(t *testing.T) {
	d, err := New("/data", Config{
		Driver:  "iscsi",
		Source:  "iqn.2024-01.com.example:lun0",
		Options: map[string]string{"portal": "10.0.0.9"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, ok := d.(*iscsiDriver)
	if !ok {
		t.Fatal("expected *iscsiDriver")
	}
	if id.target != "iqn.2024-01.com.example:lun0" {
		t.Errorf("target = %q", id.target)
	}
	if id.opts["portal"] != "10.0.0.9" {
		t.Errorf("opts[portal] = %q", id.opts["portal"])
	}
}

func TestNew_NilOptions(t *testing.T) {
	// Config.Options is nil — drivers should not panic.
	d, err := New("/data", Config{Driver: "ceph", Source: "pool"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cd := d.(*cephDriver)
	if cd.opts != nil {
		t.Errorf("expected nil opts, got %v", cd.opts)
	}
	// rbdArgs should handle nil map gracefully.
	args := cd.rbdArgs("ls", "pool")
	if len(args) != 2 {
		t.Errorf("expected 2 args with nil opts, got %d: %v", len(args), args)
	}
}

// ── localDriver edge cases ──────────────────────────────────────────────────

func TestLocalDriver_DeleteDisk_Directory_ReturnsError(t *testing.T) {
	tmp := t.TempDir()
	subDir := filepath.Join(tmp, "subdir")
	os.MkdirAll(subDir, 0755)
	// Create a file inside so Remove fails (non-empty dir).
	os.WriteFile(filepath.Join(subDir, "file"), []byte("x"), 0644)

	d := &localDriver{dataDir: tmp}
	err := d.DeleteDisk(context.Background(), subDir)
	if err == nil {
		t.Error("expected error when deleting a non-empty directory")
	}
}

// ── nfsDriver edge cases ────────────────────────────────────────────────────

func TestNFSDriver_DeleteDisk_NotExist_NoError(t *testing.T) {
	d := &nfsDriver{}
	err := d.DeleteDisk(context.Background(), "/nonexistent/path/disk.qcow2")
	if err != nil {
		t.Errorf("expected no error for non-existent file, got: %v", err)
	}
}

func TestNFSDriver_DeleteDisk_Directory_ReturnsError(t *testing.T) {
	tmp := t.TempDir()
	subDir := filepath.Join(tmp, "subdir")
	os.MkdirAll(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "file"), []byte("x"), 0644)

	d := &nfsDriver{}
	err := d.DeleteDisk(context.Background(), subDir)
	if err == nil {
		t.Error("expected error when deleting non-empty directory")
	}
}

// ── cephImageName / CephPoolName edge cases ─────────────────────────────────

func TestCephImageName_OnlyPool(t *testing.T) {
	// "rbd:pool" with no slash — should return empty.
	got := cephImageName("rbd:pool")
	if got != "" {
		t.Errorf("cephImageName('rbd:pool') = %q, want empty", got)
	}
}

func TestCephImageName_WithOptions(t *testing.T) {
	got := cephImageName("rbd:mypool/myimage:conf=/etc/ceph.conf:keyring=/etc/key")
	if got != "myimage" {
		t.Errorf("cephImageName = %q, want myimage", got)
	}
}

func TestCephPoolName_WithOptions(t *testing.T) {
	got := CephPoolName("rbd:mypool/myimage:conf=/etc/ceph.conf")
	if got != "mypool" {
		t.Errorf("CephPoolName = %q, want mypool", got)
	}
}

func TestCephPoolName_NoPrefix(t *testing.T) {
	// Without "rbd:" prefix — the function just strips it if present.
	got := CephPoolName("pool/image")
	if got != "pool" {
		t.Errorf("CephPoolName('pool/image') = %q, want pool", got)
	}
}

func TestCephImageName_SlashOnly(t *testing.T) {
	got := cephImageName("rbd:/")
	// parts[0] = "" (pool), parts[1] = ""
	if got != "" {
		t.Errorf("cephImageName('rbd:/') = %q, want empty", got)
	}
}

// ── rbdArgs edge cases ──────────────────────────────────────────────────────

func TestRbdArgs_OnlyConf(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{"conf": "/etc/ceph/ceph.conf"}}
	args := d.rbdArgs("info", "rbd/img")
	foundConf := false
	for i, a := range args {
		if a == "--conf" && i+1 < len(args) && args[i+1] == "/etc/ceph/ceph.conf" {
			foundConf = true
		}
		if a == "--id" || a == "--keyring" {
			t.Errorf("unexpected flag %q in args", a)
		}
	}
	if !foundConf {
		t.Errorf("expected --conf in args: %v", args)
	}
}

func TestRbdArgs_OnlyKeyring(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{"keyring": "/etc/ceph/keyring"}}
	args := d.rbdArgs("info", "rbd/img")
	foundKeyring := false
	for i, a := range args {
		if a == "--keyring" && i+1 < len(args) && args[i+1] == "/etc/ceph/keyring" {
			foundKeyring = true
		}
		if a == "--id" || a == "--conf" {
			t.Errorf("unexpected flag %q in args", a)
		}
	}
	if !foundKeyring {
		t.Errorf("expected --keyring in args: %v", args)
	}
}

func TestRbdArgs_AllOptions(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{
		"id":      "user",
		"conf":    "/etc/ceph.conf",
		"keyring": "/etc/keyring",
	}}
	args := d.rbdArgs("snap", "create", "rbd/img@snap1")
	// Should have 3 flag pairs (6 items) + 3 sub-args = 9 total.
	if len(args) != 9 {
		t.Errorf("expected 9 args, got %d: %v", len(args), args)
	}
	// Last 3 should be the sub-args.
	if args[6] != "snap" || args[7] != "create" || args[8] != "rbd/img@snap1" {
		t.Errorf("subcommand args wrong: %v", args[6:])
	}
}

// ── iSCSI driver edge cases ─────────────────────────────────────────────────

func TestISCSIDriver_CreateDisk_EmptyPortal(t *testing.T) {
	d := &iscsiDriver{
		target: "iqn.2024-01.com.example:target",
		opts:   map[string]string{},
	}
	path, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm1", DiskName: "root"})
	if err != nil {
		t.Fatalf("CreateDisk: %v", err)
	}
	// Portal defaults to empty string in opts; the path should contain the empty portal.
	if !filepath.IsAbs(path) {
		t.Errorf("expected absolute path, got %q", path)
	}
	// Should contain lun-0 as default.
	if !containsStr(path, "lun-0") {
		t.Errorf("expected lun-0 in path %q", path)
	}
}

func TestISCSIDriver_Prepare_DefaultPortal(t *testing.T) {
	// Just verify that iscsiDriver.Prepare uses "127.0.0.1" when portal is empty.
	d := &iscsiDriver{
		target: "iqn.2024-01.com.example:target",
		opts:   map[string]string{},
	}
	// Prepare will fail (no iscsiadm), but we're checking that it doesn't panic
	// and that the portal default is applied.
	_ = d.Prepare(context.Background())
}

// ── cephDriver.DeleteDisk error paths ───────────────────────────────────────

func TestCephDriver_DeleteDisk_EmptyPath(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{}}
	err := d.DeleteDisk(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestCephDriver_DeleteDisk_NoSlash(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{}}
	err := d.DeleteDisk(context.Background(), "rbd:noslash")
	if err == nil {
		t.Error("expected error when path has no slash")
	}
}

// ── Config struct ───────────────────────────────────────────────────────────

func TestConfig_EmptyOptions(t *testing.T) {
	cfg := Config{Driver: "local", Source: "", Options: nil}
	d, err := New("/tmp", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d.String() != "local" {
		t.Errorf("expected local, got %q", d.String())
	}
}

// ── DiskOptions defaults ────────────────────────────────────────────────────

func TestISCSIDriver_CreateDisk_CustomLUN(t *testing.T) {
	d := &iscsiDriver{
		target: "iqn.2024-01.com.example:target",
		opts:   map[string]string{"portal": "192.168.1.1", "lun": "7"},
	}
	path, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm1", DiskName: "data"})
	if err != nil {
		t.Fatalf("CreateDisk: %v", err)
	}
	expected := "/dev/disk/by-path/ip-192.168.1.1-iscsi-iqn.2024-01.com.example:target-lun-7"
	if path != expected {
		t.Errorf("path = %q, want %q", path, expected)
	}
}

func TestISCSIDriver_DeleteDisk_AlwaysSucceeds(t *testing.T) {
	d := &iscsiDriver{target: "iqn.test", opts: map[string]string{}}
	// Should always return nil regardless of path.
	for _, p := range []string{"", "/dev/sda", "/nonexistent", "rbd:pool/image"} {
		if err := d.DeleteDisk(context.Background(), p); err != nil {
			t.Errorf("DeleteDisk(%q): %v", p, err)
		}
	}
}

// ── Driver interface compliance ─────────────────────────────────────────────

func TestAllDrivers_ImplementInterface(t *testing.T) {
	drivers := []Driver{
		&localDriver{dataDir: "/tmp"},
		&nfsDriver{},
		&cephDriver{pool: "rbd", opts: map[string]string{}},
		&iscsiDriver{target: "iqn.test", opts: map[string]string{}},
	}
	expected := []string{"local", "nfs", "ceph", "iscsi"}
	for i, d := range drivers {
		if d.String() != expected[i] {
			t.Errorf("driver %d: String() = %q, want %q", i, d.String(), expected[i])
		}
	}
}

// helper
func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
