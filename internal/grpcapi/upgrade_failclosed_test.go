package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/upgrade"
)

// TestApplyStagedBinary_FailClosed proves the sentinel is fail-closed: a new
// binary is NEVER swapped into place without its health-watchdog sentinel.
//   - On swap failure the sentinel is cleared (no orphan watchdog) and the
//     current binary is left untouched.
//   - On success the sentinel is present alongside the new binary.
func TestApplyStagedBinary_FailClosed(t *testing.T) {
	s := testServer(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "litevirt")
	if err := os.WriteFile(bin, []byte("CURRENT"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.SetBinaryPath(bin)
	s.SetVersion("v-old")
	ctx := context.Background()

	// Swap fails because the staging file doesn't exist → fail-closed.
	if err := s.applyStagedBinary(ctx, filepath.Join(dir, "missing.new")); err == nil {
		t.Fatal("expected error when staging binary is missing")
	}
	if _, ok := upgrade.Read(bin); ok {
		t.Fatal("sentinel must be cleared on swap failure (the new binary was never installed)")
	}
	if b, _ := os.ReadFile(bin); string(b) != "CURRENT" {
		t.Fatalf("binary must be unchanged on swap failure, got %q", b)
	}

	// Happy path: staging present → binary swapped AND sentinel armed.
	staging := bin + ".new"
	if err := os.WriteFile(staging, []byte("NEW"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.applyStagedBinary(ctx, staging); err != nil {
		t.Fatalf("applyStagedBinary (happy path): %v", err)
	}
	if b, _ := os.ReadFile(bin); string(b) != "NEW" {
		t.Fatalf("binary not swapped, got %q", b)
	}
	sent, ok := upgrade.Read(bin)
	if !ok {
		t.Fatal("sentinel must be armed after a successful swap — the new binary must never run unwatched")
	}
	if sent.PrevVersion != "v-old" {
		t.Errorf("sentinel prev_version = %q, want v-old", sent.PrevVersion)
	}
}
