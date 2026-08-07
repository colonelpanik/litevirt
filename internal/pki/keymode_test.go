package pki

import (
	"os"
	"path/filepath"
	"testing"
)

// The repair for a world-readable private key has to be reachable on a DEFAULT
// cluster.
//
// `lv host init root@<host>` — the form the docs tell you to use for anything
// multi-node — pushed /etc/litevirt/pki/host.key mode 0644, because CopyFile
// hardcoded that mode and the call site said nothing about it. host.key is the
// peer-mTLS identity, so any local user on such a node could impersonate it to
// the whole cluster, and sign audit rows in its name that every peer would
// accept: the certificate really does chain to the cluster CA and the CN really
// does match.
//
// Fixing the push path only helps nodes provisioned afterwards, and nobody
// re-provisions a running cluster. The repair was reachable only through
// LoadAuditKeyring, which the daemon calls solely when
// enforcement.audit_signature is on — a flag that defaults to false. So an
// operator who upgraded specifically to pick up this fix, and left the default,
// got no repair and no warning: the key stayed 0644 on every node.

// pkiWithKeys builds a directory holding the private keys a node can carry.
func pkiWithKeys(t *testing.T, mode os.FileMode, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte("-----BEGIN EC PRIVATE KEY-----\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatalf("chmod %s: %v", n, err)
		}
	}
	return dir
}

func permOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestTightenPrivateKeys_RepairsEveryKeyANodeHolds.
//
// host.key is the one that shipped loose, but the sweep covers all three: ca.key
// is the credential that can mint an identity for any host in the cluster, and
// audit-signing.key is what a rotation installs precisely because the previous
// key was exposed.
func TestTightenPrivateKeys_RepairsEveryKeyANodeHolds(t *testing.T) {
	names := []string{"ca.key", "host.key", AuditSigningKeyName}
	dir := pkiWithKeys(t, 0o644, names...)

	if err := TightenPrivateKeys(dir); err != nil {
		t.Fatalf("TightenPrivateKeys: %v", err)
	}
	for _, n := range names {
		if mode := permOf(t, filepath.Join(dir, n)); mode&0o077 != 0 {
			t.Errorf("%s is still mode %04o; any local user can read it and use it as this host", n, mode)
		}
	}
}

// TestTightenPrivateKeys_LeavesTightKeysAlone.
//
// This runs on every daemon start, so silently widening — or narrowing — an
// operator's deliberate mode would be its own surprise. 0400 is stricter than
// 0600 and must survive.
func TestTightenPrivateKeys_LeavesTightKeysAlone(t *testing.T) {
	dir := pkiWithKeys(t, 0o400, "host.key")
	if err := TightenPrivateKeys(dir); err != nil {
		t.Fatalf("TightenPrivateKeys: %v", err)
	}
	if got := permOf(t, filepath.Join(dir, "host.key")); got != 0o400 {
		t.Errorf("host key mode changed from 0400 to %04o", got)
	}
}

// TestTightenPrivateKeys_ToleratesKeysANodeDoesNotHold.
//
// Only the node that ran `lv host init` holds ca.key, and only a rotated node
// holds audit-signing.key. A missing file is the normal case, not an error — a
// sweep that failed on it would run at every start and report a problem on every
// healthy node, which is how a check gets ignored.
func TestTightenPrivateKeys_ToleratesKeysANodeDoesNotHold(t *testing.T) {
	dir := pkiWithKeys(t, 0o644, "host.key")
	if err := TightenPrivateKeys(dir); err != nil {
		t.Fatalf("TightenPrivateKeys on a node holding only host.key: %v", err)
	}
	if mode := permOf(t, filepath.Join(dir, "host.key")); mode&0o077 != 0 {
		t.Errorf("host.key is still mode %04o", mode)
	}
}
