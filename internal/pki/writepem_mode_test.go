package pki

import (
	"os"
	"path/filepath"
	"testing"
)

// writePEM mints every private key litevirt generates, and it must not inherit
// the mode of a file that is already there.
//
// It used os.OpenFile(..., O_CREATE|O_TRUNC, 0600), which applies its mode only
// when it CREATES the file — so regenerating a CA or a host key over a PEM left
// 0644 by a restore, a config-management copy, or an earlier umask wrote the new
// private key straight into a world-readable file. Every copying site was fixed
// before this one, which is the site that produces the key in the first place.
func TestWritePEM_DoesNotInheritALooseExistingMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "host.key")
	if err := os.WriteFile(p, []byte("stale\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0644); err != nil { // explicit, not umask-dependent
		t.Fatal(err)
	}

	if err := writePEM(p, "EC PRIVATE KEY", []byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("writePEM: %v", err)
	}

	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("private key is mode %04o, not 0600; any local account can read it", perm)
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) == 0 {
		t.Fatalf("key not written: %q err=%v", b, err)
	}
	if string(b) == "stale\n" {
		t.Error("the PEM was not replaced")
	}
}

// And it must not widen a key an operator deliberately hardened.
func TestWritePEM_LeavesAStricterModeAlone(t *testing.T) {
	p := filepath.Join(t.TempDir(), "host.key")
	if err := os.WriteFile(p, []byte("stale\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0400); err != nil {
		t.Fatal(err)
	}
	if err := writePEM(p, "EC PRIVATE KEY", []byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("writePEM: %v", err)
	}
	if fi, _ := os.Stat(p); fi != nil && fi.Mode().Perm() != 0400 {
		t.Errorf("mode changed from 0400 to %04o; TestTightenPrivateKeys_LeavesTightKeysAlone "+
			"already established that 0400 must survive", fi.Mode().Perm())
	}
}
