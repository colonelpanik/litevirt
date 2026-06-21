package storage

import "testing"

func TestCephImageName_Exported(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"rbd:litevirt/vm1-root", "vm1-root"},
		{"rbd:rbd/vm2-data:conf=/etc/ceph/ceph.conf", "vm2-data"},
		{"rbd:pool/disk:conf=x:keyring=y", "disk"},
		{"rbd:pool/image", "image"},
		{"invalid", ""},
		{"no-colon-slash", ""},
	}
	for _, tc := range tests {
		got := CephImageName(tc.path)
		if got != tc.want {
			t.Errorf("CephImageName(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestCephPoolName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"rbd:litevirt/vm1-root", "litevirt"},
		{"rbd:rbd/vm2-data:conf=/etc/ceph/ceph.conf", "rbd"},
		{"rbd:pool/disk:conf=x:keyring=y", "pool"},
		{"invalid", ""},
		{"rbd:noslash", ""},
	}
	for _, tc := range tests {
		got := CephPoolName(tc.path)
		if got != tc.want {
			t.Errorf("CephPoolName(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestRbdArgs(t *testing.T) {
	d := &cephDriver{
		pool: "litevirt",
		opts: map[string]string{
			"id":      "admin",
			"conf":    "/etc/ceph/ceph.conf",
			"keyring": "/etc/ceph/ceph.client.admin.keyring",
		},
	}

	args := d.rbdArgs("ls", "litevirt")

	// Should contain auth flags before subcommand args
	found := map[string]bool{}
	for i, a := range args {
		if a == "--id" && i+1 < len(args) {
			found["id"] = args[i+1] == "admin"
		}
		if a == "--conf" && i+1 < len(args) {
			found["conf"] = args[i+1] == "/etc/ceph/ceph.conf"
		}
		if a == "--keyring" && i+1 < len(args) {
			found["keyring"] = true
		}
	}
	if !found["id"] {
		t.Error("missing --id flag")
	}
	if !found["conf"] {
		t.Error("missing --conf flag")
	}
	if !found["keyring"] {
		t.Error("missing --keyring flag")
	}

	// Last two args should be the subcommand args
	if args[len(args)-2] != "ls" {
		t.Errorf("expected 'ls' near end, got %v", args)
	}
	if args[len(args)-1] != "litevirt" {
		t.Errorf("expected 'litevirt' at end, got %v", args)
	}
}

func TestRbdArgs_NoOpts(t *testing.T) {
	d := &cephDriver{pool: "rbd", opts: map[string]string{}}
	args := d.rbdArgs("ls", "rbd")
	if len(args) != 2 {
		t.Errorf("expected 2 args, got %d: %v", len(args), args)
	}
}
