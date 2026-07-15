package pci

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestCanonicalBDF(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"0000:41:00.0", "0000:41:00.0", true},
		{"41:00.0", "0000:41:00.0", true}, // short form → domain 0000
		{"AB:0C.1", "0000:ab:0c.1", true}, // uppercase → lowercase
		{"0000:41:00.7", "0000:41:00.7", true},
		{" 41:00.0 ", "0000:41:00.0", true}, // trimmed
		{"", "", false},
		{"garbage", "", false},
		{"41:00", "", false},             // no function
		{"41:00.8", "", false},           // function > 7
		{"41:20.0", "", false},           // device > 0x1f
		{"zz:00.0", "", false},           // non-hex
		{"0000:0000:41:00.0", "", false}, // too many colons
	}
	for _, c := range cases {
		got, ok := CanonicalBDF(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("CanonicalBDF(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// fakePF creates a fake sysfs PF dir with the given totalvfs + current numvfs and
// returns the sysfs root (already installed via SetSysDevices, restored on cleanup).
func fakePF(t *testing.T, pf string, totalVFs, numVFs int) string {
	t.Helper()
	root := t.TempDir()
	restore := SetSysDevices(root)
	t.Cleanup(restore)
	dir := filepath.Join(root, pf)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sriov_totalvfs"), []byte(strconv.Itoa(totalVFs)+"\n"), 0o644); err != nil {
		t.Fatalf("write totalvfs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sriov_numvfs"), []byte(strconv.Itoa(numVFs)+"\n"), 0o644); err != nil {
		t.Fatalf("write numvfs: %v", err)
	}
	return root
}

func TestCreateVFs_RejectsNonEmptyPool(t *testing.T) {
	fakePF(t, "0000:41:00.0", 8, 4) // already has 4 VFs
	_, err := CreateVFs("0000:41:00.0", 4)
	if err == nil {
		t.Fatal("CreateVFs on a non-empty pool must fail")
	}
}

func TestCreateVFs_RejectsOverHardwareMax(t *testing.T) {
	fakePF(t, "0000:41:00.0", 4, 0)
	_, err := CreateVFs("0000:41:00.0", 8) // hw max is 4
	if err == nil {
		t.Fatal("CreateVFs beyond hardware max must fail")
	}
}

func TestCreateVFs_NotSRIOVCapable(t *testing.T) {
	root := t.TempDir()
	restore := SetSysDevices(root)
	t.Cleanup(restore)
	_ = os.MkdirAll(filepath.Join(root, "0000:41:00.0"), 0o755) // no sriov_totalvfs file
	if _, err := CreateVFs("0000:41:00.0", 2); err == nil {
		t.Fatal("CreateVFs on a non-SR-IOV device must fail")
	}
}

func TestCreateVFs_ShortCreate_FailsAndRetainsPartial(t *testing.T) {
	root := fakePF(t, "0000:41:00.0", 8, 0)
	// No virtfn symlinks will appear after the write → the kernel "created" 0 of 2.
	got, err := CreateVFs("0000:41:00.0", 2)
	if err == nil {
		t.Fatal("a short VF creation must return an error")
	}
	if len(got) != 0 {
		t.Errorf("expected the (empty) partial pool returned, got %v", got)
	}
	// Never auto-zeroed: the numvfs write we made is retained (2), not reset to 0.
	if v := readSysInt(filepath.Join(root, "0000:41:00.0", "sriov_numvfs")); v != 2 {
		t.Errorf("short-create must not auto-zero the pool; sriov_numvfs = %d, want 2", v)
	}
}

func TestCreateVFs_HappyPath(t *testing.T) {
	root := fakePF(t, "0000:41:00.0", 8, 0)
	dir := filepath.Join(root, "0000:41:00.0")
	// Pre-seed the virtfn symlinks that the kernel would create post-write, so the
	// post-write discovery finds the full pool.
	for i, vf := range []string{"0000:41:00.1", "0000:41:00.2"} {
		_ = os.MkdirAll(filepath.Join(root, vf), 0o755)
		if err := os.Symlink("../"+vf, filepath.Join(dir, "virtfn"+strconv.Itoa(i))); err != nil {
			t.Fatalf("symlink: %v", err)
		}
	}
	got, err := CreateVFs("0000:41:00.0", 2)
	if err != nil {
		t.Fatalf("happy-path CreateVFs: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 VFs, got %v", got)
	}
}
