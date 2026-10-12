package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestChownDirNoFollow_RefusesASymlink is the sudo-host-init privilege
// transfer.
//
// installCLIClientBundle chowns the CLI PKI directory to the invoking user, and
// localCLIClientPKITargets places that directory beneath that same user's home
// — so the user controls the path. os.Chown follows symlinks, and MkdirAll
// neither guarantees the directory is newly created nor stops it being
// REPLACED afterwards. Between the writes and the final chown, the user renames
// the directory and drops a symlink to a root-owned one in its place; root
// follows it and hands that directory's ownership over.
//
// Opening with O_NOFOLLOW|O_DIRECTORY and chowning the descriptor closes it:
// the final component cannot be a symlink, and the ownership change lands on
// the inode that was opened rather than on whatever the name resolves to next.
func TestChownDirNoFollow_RefusesASymlink(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "root-owned")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	link := filepath.Join(base, "pki")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := chownDirNoFollow(link, os.Getuid(), os.Getgid())
	if err == nil {
		t.Fatal("chown followed a symlink standing in for the PKI directory; under sudo " +
			"that transfers ownership of the link's target to the invoking user")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "symbolic link") &&
		!strings.Contains(strings.ToLower(err.Error()), "too many levels") &&
		!strings.Contains(strings.ToLower(err.Error()), "not a directory") {
		t.Logf("refused with: %v", err) // any refusal is acceptable; record which
	}
}

// A real directory must still be chowned, or the fix simply breaks host init.
func TestChownDirNoFollow_AcceptsARealDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Same uid/gid: a no-op chown, which succeeds without privileges.
	if err := chownDirNoFollow(dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("a real directory was refused: %v", err)
	}
}

// A regular file in the directory's place must be refused too — O_DIRECTORY is
// what makes the descriptor's type part of the check rather than an assumption.
func TestChownDirNoFollow_RefusesARegularFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pki")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := chownDirNoFollow(f, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("a regular file standing in for the PKI directory was accepted")
	}
}
