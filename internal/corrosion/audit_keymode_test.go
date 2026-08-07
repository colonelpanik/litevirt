package corrosion

import (
	"os"
	"path/filepath"
	"testing"
)

// The audit signature is worth exactly the secrecy of the key behind it.
//
// This was not hypothetical. `lv host init root@<host>` — the form the docs
// tell you to use for anything multi-node — pushed /etc/litevirt/pki/host.key
// with mode 0644, because internal/ssh CopyFile hardcoded that mode and the
// call site said nothing about it. Every node provisioned that way had its
// cluster identity readable by any local user: enough to impersonate the host
// over peer mTLS AND to sign audit rows in its name that every peer would
// accept, since the certificate really does chain to the cluster CA and the CN
// really does match.
//
// Found by the e2e suite against the live lab, not by any in-process test —
// a file mode is invisible to a harness that mints its own PKI in a temp dir.

func TestLoadAuditKeyring_TightensAWorldReadableKey(t *testing.T) {
	dir := testPKI(t, "node-0")
	keyPath := filepath.Join(dir, "host.key")

	// The state every remotely-provisioned node was left in.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := LoadAuditKeyring(dir, "node-0"); err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}

	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("host key is still mode %04o after loading the keyring; the node keeps signing "+
			"with a key any local user can read, so its audit log is forgeable by anyone with "+
			"a shell", mode)
	}
}

// A key that is already tight must be left exactly as it is — this runs on
// every daemon start, and silently widening or narrowing an operator's
// deliberate mode would be its own surprise.
func TestLoadAuditKeyring_LeavesATightKeyAlone(t *testing.T) {
	dir := testPKI(t, "node-0")
	keyPath := filepath.Join(dir, "host.key")
	if err := os.Chmod(keyPath, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadAuditKeyring(dir, "node-0"); err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o400 {
		t.Errorf("host key mode changed from 0400 to %04o", got)
	}
}
