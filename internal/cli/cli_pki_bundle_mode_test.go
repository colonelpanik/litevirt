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
// here, not supplied by the caller.
func TestInstallCLIClientBundle_DoesNotChownFilesByPathname(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for _, n := range []string{"ca.crt", "client.crt", "client.key"} {
		if err := os.WriteFile(filepath.Join(src, n), []byte(n+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	var chowned []string
	orig := chownPath
	chownPath = func(p string, uid, gid int) error { chowned = append(chowned, p); return nil }
	t.Cleanup(func() { chownPath = orig })

	if err := installCLIClientBundle(src, cliPKITarget{dir: dst, uid: 1000, gid: 1000, chown: true}); err != nil {
		t.Fatalf("installCLIClientBundle: %v", err)
	}

	for _, p := range chowned {
		if p != dst {
			t.Errorf("chowned a file by pathname: %s\n"+
				"root chowning a path inside a directory the target user controls can be "+
				"redirected with a symlink; ownership belongs on the descriptor", p)
		}
	}
	if len(chowned) == 0 {
		t.Error("the PKI directory itself was never chowned; the bundle would be unreadable " +
			"by the user it was installed for")
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
