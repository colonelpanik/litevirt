package corrosion

import (
	"testing"

	"github.com/litevirt/litevirt/internal/hlc"
)

// TestLocalWinsLWW is the A6 regression: LWW must not let a leftover RFC3339
// timestamp beat a newer HLC value during the migration window, while keeping
// correct chronological ordering for same-format comparisons.
func TestLocalWinsLWW(t *testing.T) {
	older := hlc.Timestamp{PhysicalMS: 1_700_000_000_000, Logical: 0, NodeID: "n1"}.String()
	newer := hlc.Timestamp{PhysicalMS: 1_700_000_001_000, Logical: 0, NodeID: "n1"}.String()
	rfc := "2026-06-04T08:00:00Z" // legacy pre-migration updated_at

	// Sanity: lexically, the RFC3339 string sorts ABOVE any HLC value — the
	// exact trap the old `>=` fell into.
	if !(rfc > newer) {
		t.Fatalf("test premise wrong: expected %q > %q lexically", rfc, newer)
	}

	cases := []struct {
		name            string
		local, incoming string
		wantKeep        bool // true → keep local (skip incoming)
	}{
		{"HLC newer local keeps", newer, older, true},
		{"HLC older local replaced", older, newer, false},
		{"equal HLC keeps local", newer, newer, true},
		{"legacy local loses to HLC incoming", rfc, newer, false}, // the bug: old code kept rfc
		{"HLC local beats legacy incoming", newer, rfc, true},
		{"both legacy: lexical newer wins", "2026-06-04T09:00:00Z", "2026-06-04T08:00:00Z", true},
		{"both legacy: lexical older loses", "2026-06-04T08:00:00Z", "2026-06-04T09:00:00Z", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := localWinsLWW(tc.local, tc.incoming); got != tc.wantKeep {
				t.Errorf("localWinsLWW(%q, %q) = %v, want %v", tc.local, tc.incoming, got, tc.wantKeep)
			}
		})
	}
}
