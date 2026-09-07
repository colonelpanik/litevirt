package main

import (
	"go/token"
	"strings"
	"testing"
)

// These cases drive newTableShapeGaps with a synthetic baseline and register, so
// they pin the guard's LOGIC rather than whatever this build's tables happen to
// be. The real baseline and register are asserted separately, below.
var (
	testBaseline = map[string]bool{"hosts": true, "vms": true}
	testAcks     = map[string]string{"widget_bindings": "behind a capability latch that cannot form mid-roll"}
)

func at(line int) token.Position { return token.Position{Filename: "x.go", Line: line} }

func TestNewTableShapeGaps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		shapes  []tableShape
		wantGap bool
	}{{
		name:    "a table the previous release already accepted",
		shapes:  []tableShape{{table: "hosts", pos: at(1), fn: "InsertHost"}},
		wantGap: false,
	}, {
		name:    "a first-ever shape with a recorded gating decision",
		shapes:  []tableShape{{table: "widget_bindings", pos: at(2), fn: "upsertWidgetBinding"}},
		wantGap: false,
	}, {
		// The finding this guard exists for: a table with no accepted shape at
		// the previous release, a shape now, and nobody having decided what
		// keeps it off an old peer's stream.
		name:    "a first-ever shape with no gating decision",
		shapes:  []tableShape{{table: "cluster", pos: at(3), fn: "EnsureClusterRecord"}},
		wantGap: true,
	}, {
		name: "a mix reports only the unacknowledged table",
		shapes: []tableShape{
			{table: "hosts", pos: at(1)},
			{table: "widget_bindings", pos: at(2)},
			{table: "cluster", pos: at(3), fn: "EnsureClusterRecord"},
		},
		wantGap: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			shapes := tc.shapes
			// Keep the register's own anti-rot check out of each case's subject:
			// it fires whenever widget_bindings is absent from the shape set.
			if !hasTable(shapes, "widget_bindings") {
				shapes = append(shapes, tableShape{table: "widget_bindings", pos: at(99)})
			}
			gaps := newTableShapeGaps(shapes, testBaseline, testAcks)
			if got := len(gaps) > 0; got != tc.wantGap {
				t.Fatalf("gap=%v, want %v (gaps=%v)", got, tc.wantGap, gaps)
			}
			if tc.wantGap {
				joined := strings.Join(gaps, "\n")
				if !strings.Contains(joined, `"cluster"`) {
					t.Fatalf("the failure must name the table, got %v", gaps)
				}
				if strings.Contains(joined, "widget_bindings") {
					t.Fatalf("an acknowledged table must not be reported, got %v", gaps)
				}
			}
		})
	}
}

// A register entry for a table nothing writes any more vouches for nothing, so
// it must fail rather than sit there — the same anti-rot rule
// knownUnwiredEmitters has.
func TestNewTableShapeGaps_RegisterCannotRot(t *testing.T) {
	gaps := newTableShapeGaps([]tableShape{{table: "hosts", pos: at(1)}}, testBaseline, testAcks)
	if !containsAll(gaps, "widget_bindings", "remove the acknowledgement") {
		t.Fatalf("a stale register entry must be reported; got %v", gaps)
	}
}

// An acknowledgement with no reason is not an acknowledgement. The whole point
// is that a human named the mechanism, so an empty string must not pass.
func TestNewTableShapeGaps_ReasonIsRequired(t *testing.T) {
	gaps := newTableShapeGaps(
		[]tableShape{{table: "widget_bindings", pos: at(2)}},
		testBaseline,
		map[string]string{"widget_bindings": ""})
	if !containsAll(gaps, "widget_bindings", "empty reason") {
		t.Fatalf("an empty reason must be reported; got %v", gaps)
	}
}

// The frozen baseline is a claim about the PREVIOUS RELEASE, so a change to it
// is a compatibility decision. Pin its size: silently widening it is exactly how
// the guard would be muted on the change it exists to flag.
func TestReplicatedTableBaselineIsFrozen(t *testing.T) {
	const want = 74
	if got := len(replicatedTableBaseline); got != want {
		t.Fatalf("replicatedTableBaseline has %d tables, frozen at %d.\n"+
			"It records which tables the PREVIOUS RELEASE accepts a replicated shape on. Regenerate "+
			"it from that release's stmtledger_generated.go + stmtledger_historical.go when a release "+
			"is cut — never to make a failing build pass.", got, want)
	}
	// A couple of anchors, so a wholesale replacement that kept the count fails.
	for _, table := range []string{"hosts", "vms", "ip_allocations", "quota_reservations"} {
		if !replicatedTableBaseline[table] {
			t.Errorf("baseline is missing %q", table)
		}
	}
	if replicatedTableBaseline["cluster"] {
		t.Error("`cluster` must NOT be in the baseline: the previous release accepts no statement " +
			"shape on it, which is why the startup heal writes it locally")
	}
}

func hasTable(shapes []tableShape, table string) bool {
	for _, s := range shapes {
		if s.table == table {
			return true
		}
	}
	return false
}

func containsAll(gaps []string, needles ...string) bool {
	for _, g := range gaps {
		ok := true
		for _, n := range needles {
			if !strings.Contains(g, n) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
