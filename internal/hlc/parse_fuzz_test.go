package hlc

import (
	"testing"
)

// FuzzParse drives Timestamp.Parse with adversarial bytes. Property:
// (1) Parse never panics, (2) any Timestamp returned by Parse must
// re-serialise via String() and re-parse to an identical Timestamp
// (canonical-form round-trip is the only contract — node ID grammar
// is intentionally permissive because real host names contain dashes).
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"abc",
		"0000000000000-0000-",
		"0000000000000-0000-node1",
		"9999999999999-9999-node-with-dashes",
		"-1-0001-x",
		"0000000000000-FFFF-x",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ts, ok := Parse(s)
		if !ok {
			return
		}
		// If Parse said yes, the canonical String() must round-trip.
		if got := ts.String(); got != s {
			// Tolerate inputs whose components aren't canonical width —
			// we only assert that re-parsing the canonical form yields
			// the same Timestamp.
			ts2, ok2 := Parse(got)
			if !ok2 {
				t.Fatalf("re-parse of canonical %q failed", got)
			}
			if ts2 != ts {
				t.Fatalf("round-trip diverged: %+v -> %q -> %+v", ts, got, ts2)
			}
		}
	})
}
