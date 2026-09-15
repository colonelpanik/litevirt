package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// installCLIClientBundle must leave client.key at 0600 even when the file it
// overwrites already existed with a looser mode.
//
// os.WriteFile applies its mode only when it CREATES the file. Re-running
// `lv host init` over a bundle whose client.key was left 0644 — by a restore
// that did not preserve modes, a config-management copy, or an earlier run under
// a different umask — rewrites the key contents and silently keeps 0644. The key
// authenticates the CLI to the cluster's gRPC API, so any local account on that
// machine can then act as the operator.
//
// The sibling write in this same file already handles exactly this and says so
// in a comment; this path did not. Upstream colonelpanik/litevirt#211.
func TestInstallCLIClientBundle_TightensAPreExistingLooseKey(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	for name, content := range map[string]string{
		"ca.crt":     "ca\n",
		"client.crt": "crt\n",
		"client.key": "key-material\n",
	} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	// The key is already there, world-readable.
	keyPath := filepath.Join(dst, "client.key")
	if err := os.WriteFile(keyPath, []byte("stale\n"), 0644); err != nil {
		t.Fatalf("pre-create client.key: %v", err)
	}
	if fi, err := os.Stat(keyPath); err != nil || fi.Mode().Perm() != 0644 {
		t.Fatalf("setup did not produce a 0644 key (umask?): %v %v", fi.Mode().Perm(), err)
	}

	if err := installCLIClientBundle(src, cliPKITarget{dir: dst}); err != nil {
		t.Fatalf("installCLIClientBundle: %v", err)
	}

	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat client.key: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("client.key is mode %04o, not 0600; it authenticates the CLI to the "+
			"cluster API, so any local account on this machine can act as the operator", perm)
	}
	if got, err := os.ReadFile(keyPath); err != nil || string(got) != "key-material\n" {
		t.Errorf("client.key content = %q (err %v); the copy itself must still happen", got, err)
	}
}
