package corrosion

import (
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
)

func sign(n int) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	default:
		return 0
	}
}

// ms base for the fixtures.
var lwwBaseMS = time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC).UnixMilli()

func hlcAt(ms int64, logical uint16, node string) string {
	return hlc.Timestamp{PhysicalMS: ms, Logical: logical, NodeID: node}.String()
}
func rfcAt(ms int64, extra time.Duration) string {
	return time.UnixMilli(ms).UTC().Add(extra).Format(nowTSLayout)
}

// TestLWWOrder_CrossFormatInstantBased: the correctness of the migration hinges on
// cross-format ordering being by INSTANT, not "HLC always wins". A newer RFC3339Nano
// write — even sub-millisecond within the HLC's own millisecond — must win; an older
// HLC must lose; only an exact-instant tie falls to HLC.
func TestLWWOrder_CrossFormatInstantBased(t *testing.T) {
	h := hlcAt(lwwBaseMS, 0, "n1") // instant = lwwBaseMS, ns=0

	cases := []struct {
		name    string
		rfc     string
		wantRFC int // sign of lwwOrder(rfc, hlc): +1 rfc wins, -1 hlc wins, 0 tie
	}{
		{"rfc sub-ms later within the HLC ms beats older HLC", rfcAt(lwwBaseMS, 500*time.Microsecond), 1},
		{"rfc exactly on the ms boundary ties → HLC wins", rfcAt(lwwBaseMS, 0), -1},
		{"rfc an ms earlier loses to HLC", rfcAt(lwwBaseMS-1, 0), -1},
		{"rfc an ms later beats HLC", rfcAt(lwwBaseMS+1, 0), 1},
	}
	for _, tc := range cases {
		if got := sign(lwwOrder(tc.rfc, h)); got != tc.wantRFC {
			t.Errorf("%s: lwwOrder(rfc,hlc) sign=%d want %d", tc.name, got, tc.wantRFC)
		}
		// Anti-symmetry on the same pair.
		if got := sign(lwwOrder(h, tc.rfc)); got != -tc.wantRFC {
			t.Errorf("%s: lwwOrder(hlc,rfc) sign=%d want %d (anti-symmetry)", tc.name, got, -tc.wantRFC)
		}
	}
}

// TestLWWOrder_AntiSymmetryAndTransitivity across all format pairs — an asymmetric or
// intransitive comparator silently diverges WAL vs anti-entropy convergence.
func TestLWWOrder_AntiSymmetryAndTransitivity(t *testing.T) {
	vals := []string{
		hlcAt(lwwBaseMS, 0, "n1"),
		hlcAt(lwwBaseMS, 1, "n1"),
		hlcAt(lwwBaseMS, 0, "n2"), // same (phys,log), higher node id
		hlcAt(lwwBaseMS+1000, 0, "n1"),
		rfcAt(lwwBaseMS, 0),
		rfcAt(lwwBaseMS, 500*time.Microsecond),
		rfcAt(lwwBaseMS-1000, 0),
		rfcAt(lwwBaseMS+2000, 0),
		time.UnixMilli(lwwBaseMS).UTC().Format(time.RFC3339), // bare-second RFC3339
	}

	// Anti-symmetry: sign(order(a,b)) == -sign(order(b,a)).
	for _, a := range vals {
		for _, b := range vals {
			if s := sign(lwwOrder(a, b)); s != -sign(lwwOrder(b, a)) {
				t.Errorf("anti-symmetry violated: order(%q,%q)=%d order(%q,%q)=%d", a, b, s, b, a, lwwOrder(b, a))
			}
		}
	}
	// Transitivity of the weak order: a>=b and b>=c ⇒ a>=c.
	for _, a := range vals {
		for _, b := range vals {
			for _, c := range vals {
				if lwwOrder(a, b) >= 0 && lwwOrder(b, c) >= 0 && lwwOrder(a, c) < 0 {
					t.Errorf("transitivity violated: %q>=%q>=%q but order(a,c)<0", a, b, c)
				}
			}
		}
	}
}

// TestLWWOrder_BothHLCTotalOrder: two HLC values order by (physical, logical, node) —
// a same-(physical,logical) pair breaks deterministically by node id (no keep-local tie).
func TestLWWOrder_BothHLCTotalOrder(t *testing.T) {
	if lwwOrder(hlcAt(lwwBaseMS, 0, "n2"), hlcAt(lwwBaseMS, 0, "n1")) <= 0 {
		t.Fatal("equal (phys,log): higher node id must win deterministically (no 0 tie)")
	}
	if lwwOrder(hlcAt(lwwBaseMS, 1, "n1"), hlcAt(lwwBaseMS, 0, "n9")) <= 0 {
		t.Fatal("higher logical must win regardless of node id")
	}
}
