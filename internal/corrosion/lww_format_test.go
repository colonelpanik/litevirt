package corrosion

import (
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
)

// TestLocalWinsLWW verifies INSTANT-based cross-format ordering (the fix that replaced
// the old categorical "HLC always beats RFC3339" rule, which let a STALE HLC beat a
// FRESH RFC3339 — a lost update during a per-node HLC-emission canary). A value wins by
// its wall instant regardless of format; HLC wins over RFC3339 only at an exact-instant
// tie. Same-format comparisons are unaffected.
func TestLocalWinsLWW(t *testing.T) {
	base := time.Date(2026, 6, 4, 8, 0, 0, 0, time.UTC)
	baseMS := base.UnixMilli()

	hlcBase := hlc.Timestamp{PhysicalMS: baseMS, Logical: 0, NodeID: "n1"}.String()
	olderHLC := hlc.Timestamp{PhysicalMS: baseMS - 1000, Logical: 0, NodeID: "n1"}.String()
	newerHLC := hlc.Timestamp{PhysicalMS: baseMS + 1000, Logical: 0, NodeID: "n1"}.String()
	rfcEqual := base.Format(time.RFC3339)                 // exact same instant as hlcBase
	rfcOlder := base.Add(-time.Hour).Format(time.RFC3339) // an hour before hlcBase
	rfcNewer := base.Add(time.Hour).Format(time.RFC3339)  // an hour after hlcBase

	// Premise: the RFC3339 strings sort lexically ABOVE any HLC value — the trap the
	// old lexical `>=` fell into; instant-based ordering must ignore that.
	if !(rfcOlder > newerHLC) {
		t.Fatalf("test premise wrong: expected %q > %q lexically", rfcOlder, newerHLC)
	}

	cases := []struct {
		name            string
		local, incoming string
		wantKeep        bool // true → keep local (skip incoming)
	}{
		{"HLC newer local keeps", newerHLC, olderHLC, true},
		{"HLC older local replaced", olderHLC, newerHLC, false},
		{"equal HLC keeps local", hlcBase, hlcBase, true},
		// Cross-format is by INSTANT, not by format:
		{"newer RFC3339 local beats older HLC incoming", rfcNewer, hlcBase, true},
		{"older RFC3339 local loses to newer HLC incoming", rfcOlder, hlcBase, false},
		{"newer RFC3339 incoming beats older HLC local", hlcBase, rfcNewer, false},
		{"older RFC3339 incoming loses to newer HLC local", hlcBase, rfcOlder, true},
		// Exact-instant cross-format tie → HLC wins deterministically:
		{"exact-instant tie: HLC local keeps", hlcBase, rfcEqual, true},
		{"exact-instant tie: HLC incoming wins", rfcEqual, hlcBase, false},
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
