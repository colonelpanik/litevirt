package grpcapi

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSweepStaleStagingTemps(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := now.Add(-2 * time.Hour)

	write := func(name string, mod time.Time) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(p, mod, mod)
	}

	// Stale staging temps (every prefix) — should be removed.
	stale := []string{".repl-abc.tmp", ".upload-xyz.tmp", "import-1.tmp", "restore-9.tmp"}
	for _, n := range stale {
		write(n, old)
	}
	// Must be kept: a recent (in-flight) temp, a real replica, an ISO, a qcow2.
	keep := []string{".repl-inflight.tmp", "web-root-20260608-120000.raw", "ubuntu.iso", "vm-disk.qcow2"}
	write(".repl-inflight.tmp", now) // recent → keep
	write("web-root-20260608-120000.raw", old)
	write("ubuntu.iso", old)
	write("vm-disk.qcow2", old)

	got := sweepStaleStagingTemps(dir, time.Hour, now)
	if got != len(stale) {
		t.Errorf("removed %d, want %d", got, len(stale))
	}
	for _, n := range stale {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Errorf("stale temp %s should have been removed", n)
		}
	}
	for _, n := range keep {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s must be kept: %v", n, err)
		}
	}
}
