package corrosion

import (
	"context"
	"encoding/json"
	"testing"
)

// TestSnapshotWritersNeverBindParentID is the self-enforcing guard for H1's identity-collapse
// assumption: snapshots.parent_id (a snapshot-chain self-reference) is UNWIRED — no production writer
// sets it — so the identity collapse can safely fail closed on a non-null incoming reference instead
// of rewriting references. This test drives every snapshot / container-snapshot writer, then parses
// EVERY statement they logged that targets those tables and asserts none names parent_id in its
// INSERT column list or UPDATE SET. If a future snapshot-chain writer starts binding parent_id, this
// fails — a signal that H1 must gain reference rewriting before that writer ships.
func TestSnapshotWritersNeverBindParentID(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)

	// Exercise every writer for the two identity tables.
	if err := InsertSnapshot(ctx, c, SnapshotRecord{VMName: "vm1", HostName: "h1", Name: "s1", State: "ready"}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}
	if err := DeleteSnapshot(ctx, c, "vm1", "s1"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if err := InsertContainerSnapshot(ctx, c, ContainerSnapshotRecord{CtName: "ct1", HostName: "h1", Name: "cs1", State: "ready"}); err != nil {
		t.Fatalf("InsertContainerSnapshot: %v", err)
	}
	if err := DeleteContainerSnapshot(ctx, c, "h1", "ct1", "cs1"); err != nil {
		t.Fatalf("DeleteContainerSnapshot: %v", err)
	}

	// The reference class must actually be declared (so the apply/collapse paths fail closed on it).
	if got := identityReferenceColumns["snapshots"]; len(got) != 1 || got[0] != "parent_id" {
		t.Fatalf("identityReferenceColumns[snapshots] = %v, want [parent_id] — the fail-closed reference guard must stay wired", got)
	}

	rows, err := c.Query(ctx, "SELECT stmts FROM mutation_log ORDER BY seq")
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	seen := 0
	for _, r := range rows {
		var stmts []Statement
		if err := json.Unmarshal([]byte(r.String("stmts")), &stmts); err != nil {
			t.Fatalf("unmarshal stmts: %v", err)
		}
		for _, s := range stmts {
			table := extractTableName(s.SQL)
			if table != "snapshots" && table != "container_snapshots" {
				continue
			}
			seen++
			sh, err := parseStmtShape(s.SQL, tablePrimaryKeys[table])
			if err != nil {
				t.Fatalf("snapshot writer emitted an unparseable statement %q: %v", s.SQL, err)
			}
			for _, col := range sh.InsertCols {
				if col == "parent_id" {
					t.Errorf("a snapshot INSERT binds parent_id (%q) — H1's identity collapse would orphan the reference; wire reference rewriting before shipping this", s.SQL)
				}
			}
			for _, a := range sh.SetAssigns {
				if a.Column == "parent_id" {
					t.Errorf("a snapshot UPDATE sets parent_id (%q) — H1's identity collapse would orphan the reference; wire reference rewriting before shipping this", s.SQL)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no snapshot/container_snapshot statements were captured — the test isn't exercising the writers")
	}
}
