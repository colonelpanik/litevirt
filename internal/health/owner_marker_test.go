package health

import (
	"errors"
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

// TestOwnerEpochMarker_AZeroOnDiskIsCorruptNotValid: a marker file containing
// "0" must not read back as a valid generation.
//
// The reader used to accept any parseable integer, so a zero read as
// (0, true, nil) -> classifyMarker's default arm -> MarkerValid. Against a DB
// row also at epoch 0 that satisfies the detector's equality test and condition
// 7 is suppressed silently — no grace, no finding, nothing to notice. Both this
// function's doc comment and the libvirt twin's already say epoch 0 is never a
// valid marker; this pins it.
func TestOwnerEpochMarker_AZeroOnDiskIsCorruptNotValid(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vm1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ownerEpochMarkerFile), []byte("0\n"), 0o600); err != nil {
		t.Fatalf("seed marker: %v", err)
	}

	epoch, found, err := readOwnerEpochMarker(root, "vm1")
	if err == nil {
		t.Fatalf("a zero marker read back cleanly as (%d, %v) — it must be an error, "+
			"because a zero that reads as valid suppresses the owner-epoch check "+
			"against any row still at the pre-epoch default", epoch, found)
	}
	if found {
		t.Error("found = true for a zero marker; a value that cannot mean anything is not a reading")
	}
}

// TestOwnerEpochMarker_ANegativeOnDiskIsCorrupt: same rule, other side of zero.
func TestOwnerEpochMarker_ANegativeOnDiskIsCorrupt(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vm1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ownerEpochMarkerFile), []byte("-5\n"), 0o600); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	if _, _, err := readOwnerEpochMarker(root, "vm1"); err == nil {
		t.Error("a negative marker read back cleanly; allocation starts at 1, so it is garbage")
	}
}

// TestWriteOwnerEpochMarker_RefusesAPreEpochValue: the writer must not create
// the file this reader now rejects.
//
// internal/health/reconciler.go's failover start path writes fresh.OwnerEpoch
// unconditionally, and that value can still be 0 today. Refusing at the writer
// means a zero marker cannot be produced in the first place; rejecting at the
// reader handles the ones already on disk.
func TestWriteOwnerEpochMarker_RefusesAPreEpochValue(t *testing.T) {
	root := t.TempDir()
	for _, epoch := range []int64{0, -1} {
		if err := writeOwnerEpochMarker(root, "vm1", epoch); err == nil {
			t.Errorf("writeOwnerEpochMarker accepted epoch %d; a marker that cannot name a "+
				"generation must never reach disk", epoch)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "vm1", ownerEpochMarkerFile)); err == nil {
		t.Error("a refused write still left a marker file behind")
	}
}

// TestOwnerEpochMarker_RoundTripsAValidEpoch guards against the refusals above
// being too broad — 1 is the first legal generation and must survive.
func TestOwnerEpochMarker_RoundTripsAValidEpoch(t *testing.T) {
	root := t.TempDir()
	if err := writeOwnerEpochMarker(root, "vm1", 1); err != nil {
		t.Fatalf("write epoch 1: %v", err)
	}
	epoch, found, err := readOwnerEpochMarker(root, "vm1")
	if err != nil || !found || epoch != 1 {
		t.Fatalf("round trip = (%d, %v, %v), want (1, true, nil)", epoch, found, err)
	}
}

// TestOwnerEpochMarker_ZeroAndNegativeAreDifferentKindsOfCorrupt pins the
// distinction runtimeSuperseded decides on.
//
// A marker of exactly 0 is a positive statement — "this runtime belongs to no
// generation" — and carries ErrPreEpochMarker so that check can treat it as
// generation 0 and refuse a self-heal restart when the row has moved on. A
// NEGATIVE is not a statement about anything: no allocator emits one, and
// deriving a decision from it would be computing with content this package
// calls garbage. Both are corrupt; only one is actionable.
func TestOwnerEpochMarker_ZeroAndNegativeAreDifferentKindsOfCorrupt(t *testing.T) {
	seed := func(t *testing.T, content string) error {
		t.Helper()
		root := t.TempDir()
		dir := filepath.Join(root, "vm1")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, ownerEpochMarkerFile), []byte(content), 0o600); err != nil {
			t.Fatalf("seed marker: %v", err)
		}
		_, _, err := readOwnerEpochMarker(root, "vm1")
		return err
	}

	zeroErr := seed(t, "0\n")
	if !errors.Is(zeroErr, ErrPreEpochMarker) {
		t.Errorf("a zero marker must carry ErrPreEpochMarker so runtimeSuperseded can act on "+
			"it; got %v", zeroErr)
	}
	negErr := seed(t, "-5\n")
	if negErr == nil {
		t.Fatal("a negative marker must still be corrupt")
	}
	if errors.Is(negErr, ErrPreEpochMarker) {
		t.Error("a negative marker must NOT carry ErrPreEpochMarker: it is garbage, and " +
			"coercing it to generation 0 would derive a decision from meaningless content")
	}
}
