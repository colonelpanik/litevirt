package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// installCLIClientBundle must not chown a FILE by pathname.
//
// This is the `sudo lv host init` path — target.chown is true whenever SUDO_USER
// is set — and it was covered by no test at all. Root writes into a directory the
// invoking user owns, so a pathname chown is a local privilege escalation: os.Chown
// follows symlinks, and between publishing the file and chowning it that user can
// replace the path with a symlink to any file on the system and have root hand it
// over. Ownership now rides along with the atomic write, on the descriptor, before
// the file has a name anyone else can reach.
//
// The directory chown is a separate matter and stays: it is created by MkdirAll
// here, not supplied by the caller — and, since that assumption does not hold
// either (MkdirAll neither guarantees a fresh directory nor stops it being
// replaced), the directory chown goes through a descriptor rather than a path.
// See TestChownDirNoFollow_RefusesASymlink.
func TestInstallCLIClientBundle_DoesNotChownFilesByPathname(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for _, n := range []string{"ca.crt", "client.crt", "client.key"} {
		if err := os.WriteFile(filepath.Join(src, n), []byte(n+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Two seams, observed separately. Pooling them would let the directory
	// chown drift back to chownPath (a pathname chown root resolves through a
	// symlink) and still pass, because both record the same path.
	var byPath, byDescriptor []string
	orig := chownPath
	chownPath = func(p string, uid, gid int) error { byPath = append(byPath, p); return nil }
	t.Cleanup(func() { chownPath = orig })
	// The DIRECTORY chown goes through chownDirNoFollow now — it opens the
	// directory with O_NOFOLLOW|O_DIRECTORY and chowns the descriptor, so the
	// pathname is never re-resolved. It still has to be observed here, or this
	// test would silently stop covering the one chown that does happen.
	origDir := chownDirNoFollow
	chownDirNoFollow = func(p string, uid, gid int) error { byDescriptor = append(byDescriptor, p); return nil }
	t.Cleanup(func() { chownDirNoFollow = origDir })

	// The CALLER's own uid/gid. Any process may "change" ownership to what it
	// already is; a hardcoded uid only works on a machine where that uid happens
	// to be the test runner, which is a test that passes for a reason unrelated
	// to the code.
	uid, gid := os.Getuid(), os.Getgid()
	if err := installCLIClientBundle(src, cliPKITarget{dir: dst, uid: uid, gid: gid, chown: true}); err != nil {
		t.Fatalf("installCLIClientBundle: %v", err)
	}

	for _, p := range byPath {
		t.Errorf("chowned by pathname: %s\n"+
			"root chowning a path inside a directory the target user controls can be "+
			"redirected with a symlink; ownership belongs on the descriptor", p)
	}
	if len(byDescriptor) != 1 || byDescriptor[0] != dst {
		t.Errorf("descriptor chowns = %q, want exactly the PKI directory %q; "+
			"without it the bundle is unreadable by the user it was installed for", byDescriptor, dst)
	}
}

// The mode guarantee still holds, and now on the path operators actually take.
func TestInstallCLIClientBundle_TightensAPreExistingLooseKey(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for _, n := range []string{"ca.crt", "client.crt", "client.key"} {
		if err := os.WriteFile(filepath.Join(src, n), []byte(n+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(dst, "client.key")
	if err := os.WriteFile(keyPath, []byte("stale\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Explicit, so the ambient umask cannot decide what this test proves.
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}

	if err := installCLIClientBundle(src, cliPKITarget{dir: dst}); err != nil {
		t.Fatalf("installCLIClientBundle: %v", err)
	}

	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat client.key: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("client.key is mode %04o, not 0600", perm)
	}
	if got, err := os.ReadFile(keyPath); err != nil || string(got) != "client.key\n" {
		t.Errorf("client.key content = %q (err %v)", got, err)
	}
}
