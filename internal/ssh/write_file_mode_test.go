package ssh

import (
	"strings"
	"testing"
)

// WriteFile ran `cat > path && chmod mode path`, so the file existed with its
// full contents at the remote umask — 0644 in a directory created 0755 — for
// the whole transfer, and permanently if the connection dropped between the
// two.
//
// The payload is host.key. CopyFileMode exists precisely because host.key was
// shipping 0644, and this is the same exposure one layer down.
//
// A plain `chmod` first does not fix it either: redirecting into an EXISTING
// file truncates it and keeps its old mode, so a re-provision over a loose file
// writes the new key at the old permissions. The content has to land somewhere
// private and be moved into place.
func TestWriteFileCmd_NeverExposesContentAtTheWrongMode(t *testing.T) {
	const path = "/etc/litevirt/pki/host.key"
	cmd := writeFileCmd(path, 0600)

	if strings.Contains(cmd, "cat > "+path) || strings.Contains(cmd, "cat >"+path) {
		t.Errorf("content is redirected straight at the destination, which exists "+
			"at the remote umask until the chmod lands:\n  %s", cmd)
	}
	if !strings.Contains(cmd, "mktemp") {
		t.Errorf("no private temporary file in:\n  %s", cmd)
	}
	if !strings.Contains(cmd, "mv") {
		t.Errorf("the staged file is never moved into place:\n  %s", cmd)
	}
	if !strings.Contains(cmd, "600") {
		t.Errorf("the requested mode never appears in:\n  %s", cmd)
	}

	// The chmod must happen before the move, or the destination is briefly
	// correct-content-wrong-mode all over again.
	chmodAt, mvAt := strings.Index(cmd, "chmod"), strings.LastIndex(cmd, "mv")
	if chmodAt < 0 || mvAt < 0 || chmodAt > mvAt {
		t.Errorf("chmod does not precede the move:\n  %s", cmd)
	}
}

// A path with a space must not split into two arguments.
func TestWriteFileCmd_QuotesThePath(t *testing.T) {
	cmd := writeFileCmd("/etc/lite virt/host.key", 0600)
	if strings.Contains(cmd, "/etc/lite virt/host.key") &&
		!strings.Contains(cmd, "'/etc/lite virt/host.key'") {
		t.Errorf("unquoted path with a space:\n  %s", cmd)
	}
}

// `mv src dest` where dest is a DIRECTORY moves src INSIDE it rather than
// failing. Process command lines are world-readable on a default Linux, so a
// local user on the target can read the destination path out of the running
// command, mkdir it first, let the staged file land inside, then rename their
// directory away and leave their own file at the path root is about to read.
//
// Randomising the destination name does not help: the attacker does not have
// to guess it, they can see it. -T makes the directory case an error.
func TestWriteFileCmd_RefusesToMoveIntoADirectory(t *testing.T) {
	cmd := writeFileCmd("/etc/litevirt/pki/host.key", 0600)

	if !strings.Contains(cmd, "mv -fT") && !strings.Contains(cmd, "mv -Tf") {
		t.Errorf("mv is not given -T, so a pre-created directory at the destination "+
			"silently captures the staged file:\n  %s", cmd)
	}
	if !strings.Contains(cmd, "--") {
		t.Errorf("mv is not given --, so a destination starting with '-' parses as options:\n  %s", cmd)
	}
}
