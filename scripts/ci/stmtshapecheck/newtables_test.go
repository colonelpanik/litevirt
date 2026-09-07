package main

import (
	"go/token"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
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

// firstShapeTables is the guard's PRODUCTION-facing half. newTableShapeGaps
// makes the decision, and the tests above pin it — but it only ever sees the
// (table, first site) pairs this reduction hands it, so a table this drops is a
// table the guard silently approves. That is the same failure mode the guard
// exists for: the `cluster` shape got through because nothing looked, and a
// reduction with a hole means nothing looks again.
//
// Driven with real builder statements, because the table has to come from the
// SAME authoritative parse that generates the ledger. A synthetic string would
// pin the reduction against a parser that may not resolve it at all, which is
// the one outcome this function treats as "skip".
const (
	sqlImages     = "INSERT OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	sqlImageHosts = "INSERT OR REPLACE INTO image_hosts (image_name, host_name, path, status, pulled_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
	sqlHosts      = "UPDATE hosts SET cert_serial = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL"
)

func TestFirstShapeTables_ResolvesTheTableAndSortsIt(t *testing.T) {
	// Precondition: these are real shapes, so a ledger change that stopped them
	// resolving would weaken the cases below rather than fail them.
	for _, sql := range []string{sqlImages, sqlImageHosts, sqlHosts} {
		if le, err := corrosion.LedgerEntryFor(sql); err != nil || le.Table == "" {
			t.Fatalf("fixture precondition: %q must resolve to a table (table=%q err=%v)",
				sql, le.Table, err)
		}
	}

	// Fed in an order that is NOT the answer, so the sort is doing work.
	got := firstShapeTables([]finding{
		{pos: at(1), fn: "UpsertImage", sql: sqlImages},
		{pos: at(2), fn: "UpsertImageHost", sql: sqlImageHosts},
		{pos: at(3), fn: "UpdateHostCertSerial", sql: sqlHosts},
	})

	var names []string
	for _, s := range got {
		names = append(names, s.table)
	}
	// Sorted by table, so the guard's output is stable across a scan whose walk
	// order is not — and image_hosts is its OWN table. A string scan for a
	// baseline name would find "hosts" inside "image_hosts" and report the wrong
	// table, which is a first-ever shape reported as an old one.
	if strings.Join(names, ",") != "hosts,image_hosts,images" {
		t.Fatalf("want the resolved tables sorted (hosts,image_hosts,images), got %v", names)
	}
}

func TestFirstShapeTables_KeepsTheFirstSitePerTable(t *testing.T) {
	// One table, two builders. The guard names a place for a human to look, so
	// it must be one place per table and it must be the first — a per-site
	// listing would make an acknowledged table re-report on every new writer.
	got := firstShapeTables([]finding{
		{pos: at(7), fn: "UpsertImage", sql: sqlImages},
		{pos: at(9), fn: "UpsertImageAgain", sql: sqlImages},
	})
	if len(got) != 1 {
		t.Fatalf("two builders on one table must reduce to one shape, got %d: %+v", len(got), got)
	}
	if got[0].pos.Line != 7 || got[0].fn != "UpsertImage" {
		t.Fatalf("the site kept must be the FIRST one, got line %d (%s)", got[0].pos.Line, got[0].fn)
	}
}

func TestFirstShapeTables_SkipsWhatItCannotDecideOn(t *testing.T) {
	// Each of these must contribute NOTHING, and each for its own reason. A
	// skip that leaked a table would make the guard demand an acknowledgement
	// for a statement nobody can read; a skip that swallowed a decidable one
	// would let a first-ever shape past. computeGaps already fails the
	// unreadable ones, so a second complaint naming the same line only buries
	// the first.
	for _, tc := range []struct {
		name string
		f    finding
	}{
		{"a runtime-built statement", finding{pos: at(1), sql: sqlImages, dynamic: true}},
		{"a batch that could not be enumerated", finding{pos: at(2), sql: sqlImages, unresolvedBatch: true}},
		{"a statement that failed to parse", finding{pos: at(3), sql: sqlImages, parseErr: "boom"}},
		{"a statement the ledger parser rejects", finding{pos: at(4), sql: "not sql at all"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstShapeTables([]finding{tc.f}); len(got) != 0 {
				t.Fatalf("must contribute no shape, got %+v", got)
			}
		})
	}

	// And the flags are per-finding, not per-run: an undecidable finding must
	// not suppress a decidable one that follows it.
	got := firstShapeTables([]finding{
		{pos: at(1), sql: sqlImages, dynamic: true},
		{pos: at(2), fn: "UpsertImageHost", sql: sqlImageHosts},
	})
	if len(got) != 1 || got[0].table != "image_hosts" {
		t.Fatalf("a skipped finding must not suppress the next one, got %+v", got)
	}
}
