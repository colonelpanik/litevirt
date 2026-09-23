package secretfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func permOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return fi.Mode().Perm()
}

// A new secret gets exactly the requested mode, whatever the ambient umask.
//
// os.WriteFile would give perm&^umask here, which is why every caller that
// "wrote 0600" could still end up with something else.
func TestWrite_NewFileGetsTheRequestedModeRegardlessOfUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	p := filepath.Join(t.TempDir(), "secret")
	if err := Write(p, []byte("s\n"), 0o644); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := permOf(t, p); got != 0o644 {
		t.Errorf("mode = %04o, want 0644 — the umask masked the requested mode", got)
	}
}

// The original bug: writing over a file left loose must not inherit its mode.
func TestWrite_TightensAPreExistingLooseFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil { // explicit: not umask-dependent
		t.Fatal(err)
	}

	if err := Write(p, []byte("fresh\n"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := permOf(t, p); got != 0o600 {
		t.Errorf("mode = %04o, want 0600; the secret stayed world-readable", got)
	}
	if b, _ := os.ReadFile(p); string(b) != "fresh\n" {
		t.Errorf("content = %q, want the new secret", b)
	}
}

// Never widen. An operator who hardened the file keeps their mode.
//
// internal/pki.TightenKeyMode already established this rule for key material
// ("0400 is stricter than 0600 and must survive"); a writer that force-set the
// declared mode would silently undo it on the next write.
func TestWrite_NeverWidensADeliberatelyStricterMode(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		existing, requested, want os.FileMode
	}{
		{"0400 key stays 0400", 0o400, 0o600, 0o400},
		{"0600 cert stays 0600", 0o600, 0o644, 0o600},
		{"loose file is tightened", 0o644, 0o600, 0o600},
		{"equal modes are unchanged", 0o644, 0o644, 0o644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "f")
			if err := os.WriteFile(p, []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, tc.existing); err != nil {
				t.Fatal(err)
			}
			if err := Write(p, []byte("new\n"), tc.requested); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if got := permOf(t, p); got != tc.want {
				t.Errorf("existing %04o + requested %04o -> %04o, want %04o",
					tc.existing, tc.requested, got, tc.want)
			}
		})
	}
}

// The reason chmod-after-write is not good enough.
//
// os.WriteFile truncates the file in place, so the new secret lands in the
// inode that was already world-readable. A descriptor opened before the write
// keeps reading it across any later chmod. Replacing the file by rename gives
// the new secret a new inode, and the old descriptor sees only the old bytes.
func TestWrite_ADescriptorOpenedBeforehandCannotSeeTheNewSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("old-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}

	// Someone opens the loose file and holds the descriptor.
	fd, err := os.Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer fd.Close()

	if err := Write(p, []byte("NEW-SECRET\n"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := make([]byte, 64)
	n, _ := fd.Read(got)
	if string(got[:n]) == "NEW-SECRET\n" {
		t.Error("a descriptor opened while the file was world-readable read the NEW secret; " +
			"tightening the mode after writing into the same inode does not close that window")
	}
}

// A failed write must not destroy the file that was there.
func TestWrite_LeavesNoTempBehindAndKeepsTheDirClean(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	if err := Write(p, []byte("a\n"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "secret" {
		names := []string{}
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want just the target; a temp file was left behind", names)
	}
}

// WriteOwned sets ownership on the file it is about to publish, not on a
// pathname afterwards.
//
// The pathname form is the bug: root writes into a directory the target user
// owns, then calls os.Chown(path, ...), which follows symlinks. Between the
// rename and the chown that user can replace the path with a symlink to any file
// on the system, and root hands it to them. Doing it on the open descriptor,
// before the file has a name anyone else can reach, removes the window entirely.
//
// Unprivileged tests cannot change ownership, so this pins the part that is
// observable here: -1/-1 means "leave it alone" and must still produce a correct
// file, and the call must not fail for an unprivileged caller.
func TestWriteOwned_NoOpOwnershipStillWritesCorrectly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := WriteOwned(p, []byte("v\n"), 0o600, -1, -1); err != nil {
		t.Fatalf("WriteOwned: %v", err)
	}
	if got := permOf(t, p); got != 0o600 {
		t.Errorf("mode = %04o, want 0600", got)
	}
	if b, _ := os.ReadFile(p); string(b) != "v\n" {
		t.Errorf("content = %q", b)
	}
}

// Write is WriteOwned with ownership left alone.
func TestWrite_KeepsEveryPropertyWhenOwnershipIsUnset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, []byte("new\n"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := permOf(t, p); got != 0o400 {
		t.Errorf("mode = %04o, want 0400 preserved through the WriteOwned path", got)
	}
}

// Ownership is really attempted, and a failure to set it is fatal.
//
// An unprivileged process cannot give a file away, so asking for an owner it
// cannot set must fail — and must not publish the file anyway. Without this, a
// dropped Chown is invisible: the bundle silently stays owned by root and the
// user it was installed for cannot read it.
func TestWriteOwned_FailsAndPublishesNothingWhenOwnershipCannotBeSet(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: every chown succeeds, so this proves nothing")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")

	err := WriteOwned(p, []byte("v\n"), 0o600, 12345, 12345)
	if err == nil {
		t.Fatal("WriteOwned reported success after an ownership change it cannot possibly " +
			"have made; a dropped Chown would look exactly like this")
	}
	if _, sErr := os.Stat(p); sErr == nil {
		t.Error("the file was published even though its ownership could not be set")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Errorf("temp file left behind after a failed write: %d entries", len(ents))
	}
}
