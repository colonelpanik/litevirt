package health

import (
	"os"
	"path/filepath"
	"testing"
)

// Phase 4 runtime markers: the DB's owner epoch is mirrored into a root-owned
// host-local marker so a rejoined node can tell that its local runtime state
// belongs to a superseded ownership generation WITHOUT trusting its own
// (possibly stale) replica — the exact blind spot behind the ~9s dual-run and
// the recurring equal-timestamp ownership fight observed live 2026-08-01.

func TestContainerOwnerEpochMarker_RoundTrip(t *testing.T) {
	root := t.TempDir()

	if err := WriteContainerOwnerEpochMarker(root, "ct1", 7); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, ok, err := ReadContainerOwnerEpochMarker(root, "ct1")
	if err != nil || !ok || got != 7 {
		t.Fatalf("read = (%d, %v, %v), want (7, true, nil)", got, ok, err)
	}

	// The marker is the host's private ownership attestation: 0600, root-owned
	// in production (ownership can't be asserted in tests; mode can).
	fi, err := os.Stat(filepath.Join(root, "ct1", "owner_epoch"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode = %o, want 0600", fi.Mode().Perm())
	}

	// Overwrite advances it (write-through on every landed transition).
	if err := WriteContainerOwnerEpochMarker(root, "ct1", 8); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if got, _, _ := ReadContainerOwnerEpochMarker(root, "ct1"); got != 8 {
		t.Fatalf("after rewrite: %d, want 8", got)
	}
}

func TestContainerOwnerEpochMarker_AbsentAndCorrupt(t *testing.T) {
	root := t.TempDir()

	// Absent marker: ok=false, no error — pre-epoch containers have none and
	// nothing may fail closed on that before owner_epoch_v1 latches.
	if _, ok, err := ReadContainerOwnerEpochMarker(root, "ghost"); ok || err != nil {
		t.Fatalf("absent: ok=%v err=%v, want false/nil", ok, err)
	}

	// Corrupt content reads as an ERROR, never as epoch 0: silently treating
	// garbage as the zero generation would make a damaged marker authorize
	// exactly the stale actions the marker exists to refuse.
	dir := filepath.Join(root, "ct1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "owner_epoch"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadContainerOwnerEpochMarker(root, "ct1"); err == nil {
		t.Fatal("corrupt marker must be an error, not a value")
	}

	// Path traversal in a container name must be refused outright.
	if err := WriteContainerOwnerEpochMarker(root, "../evil", 1); err == nil {
		t.Fatal("traversal name accepted")
	}
}
