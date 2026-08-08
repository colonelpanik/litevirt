package randid

import (
	"encoding/hex"
	"regexp"
	"testing"
)

// TestNewDecodesToExactlyEightBytes pins the wire format from the decoder's
// side: whatever New returns must round-trip through hex back to exactly
// Bytes bytes. Catches a size change and any non-hex encoding.
func TestNewDecodesToExactlyEightBytes(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := New()
		raw, err := hex.DecodeString(id)
		if err != nil {
			t.Fatalf("New() = %q, not decodable as hex: %v", id, err)
		}
		if len(raw) != 8 {
			t.Fatalf("New() = %q decodes to %d bytes, want 8", id, len(raw))
		}
	}
}

// TestNewLengthAndAlphabet pins the textual shape callers and operators see —
// 16 lowercase hex characters, nothing else. These ids are primary keys in
// replicated Corrosion tables, so a prefix, padding, uppercase hex, or a swap
// to base32/base64 would all be format breaks.
func TestNewLengthAndAlphabet(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{16}$`)
	for i := 0; i < 100; i++ {
		if id := New(); !re.MatchString(id) {
			t.Fatalf("New() = %q, want ^[0-9a-f]{16}$", id)
		}
	}
}

// TestNewUnique is the entropy test in practical terms: the realistic failure
// mode is not a biased generator but a generator that stopped generating (a
// zeroed buffer collapses every id to "0000000000000000"; a seeded math/rand
// repeats across runs).
func TestNewUnique(t *testing.T) {
	const draws = 10000
	seen := make(map[string]bool, draws)
	for i := 0; i < draws; i++ {
		id := New()
		if seen[id] {
			t.Fatalf("collision after %d draws: %q", i, id)
		}
		seen[id] = true
	}
}

// TestBytesConstantIsEight guards the constant itself. It is not redundant
// with the format tests: it is the one that fails with a message explaining
// why the size is pinned, if someone "harmlessly" tweaks it.
func TestBytesConstantIsEight(t *testing.T) {
	if Bytes != 8 {
		t.Fatalf("Bytes = %d, want 8 — these ids are primary keys in replicated "+
			"Corrosion tables and every existing row assumes 64 bits of entropy", Bytes)
	}
}
