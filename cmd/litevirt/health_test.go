package main

import (
	"errors"
	"fmt"
	"testing"
)

// TestHealthExitCode pins the scriptable contract documented in `lv health`:
// 0 healthy · 1 degraded or unknown · 2 critical. Unrecognized states map to 1
// (something is wrong enough that HEALTHY cannot be claimed).
func TestHealthExitCode(t *testing.T) {
	cases := map[string]int{
		"HEALTHY":  0,
		"DEGRADED": 1,
		"UNKNOWN":  1,
		"CRITICAL": 2,
		"":         1,
		"weird":    1,
	}
	for overall, want := range cases {
		if got := healthExitCode(overall); got != want {
			t.Errorf("healthExitCode(%q) = %d, want %d", overall, got, want)
		}
	}
}

// TestSilentExitError: the typed exit carries its code through error wrapping,
// and ordinary errors carry none — so main() prints Error: for real failures
// and stays SILENT for a health report that already said everything.
func TestSilentExitError(t *testing.T) {
	if code, ok := exitCodeOf(silentExitError{code: 2}); !ok || code != 2 {
		t.Fatalf("exitCodeOf(silent 2) = %d,%v want 2,true", code, ok)
	}
	wrapped := fmt.Errorf("context: %w", silentExitError{code: 1})
	if code, ok := exitCodeOf(wrapped); !ok || code != 1 {
		t.Fatalf("exitCodeOf(wrapped) = %d,%v want 1,true", code, ok)
	}
	if _, ok := exitCodeOf(errors.New("plain failure")); ok {
		t.Fatal("a plain error must not read as a silent exit")
	}
}
