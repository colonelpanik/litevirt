package corrosion

import (
	"context"
	"testing"
)

// Deleting a project used to leave its authority row behind with deleted_at NULL.
// The lab still carries four of them (/qa, /qa2, /qa3, /pre) for projects that no
// longer exist.
//
// That matters because project names are reusable. Recreating a deleted name would
// adopt whatever authority the old project left — including, for /qa, a row the
// nodes had actively disagreed about — so the new project's admissions would be
// decided by a holder nobody chose, derived from membership that may no longer
// include that host.

// liveAuthorityRowCount counts authority rows the admission path can still see.
func liveAuthorityRowCount(t *testing.T, c *Client, project string) int {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT authority_epoch FROM project_authority_epochs
		 WHERE project = ? AND deleted_at IS NULL`, project)
	if err != nil {
		t.Fatalf("count live authority rows: %v", err)
	}
	return len(rows)
}

// TestDeleteProject_RetiresItsAuthority pins that a deleted project stops carrying
// authority, so nothing can inherit it.
func TestDeleteProject_RetiresItsAuthority(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	if err := InsertProject(ctx, db, ProjectRecord{Name: "qa"}); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := ClaimInitialProjectAuthority(ctx, db, "qa", "node-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := DeleteProject(ctx, db, "qa"); err != nil {
		t.Fatalf("delete project: %v", err)
	}

	if n := liveAuthorityRowCount(t, db, "qa"); n != 0 {
		t.Fatalf("deleted project still has %d live authority row(s); a project recreated "+
			"under this name would inherit a holder nobody chose for it", n)
	}
	if _, ok, err := CurrentProjectAuthority(ctx, db, "qa"); err != nil || ok {
		t.Fatalf("CurrentProjectAuthority for a deleted project: ok=%v err=%v, want ok=false", ok, err)
	}
}

// TestClaimInitialProjectAuthority_MintsAboveEveryRetiredEpoch is the other half,
// and the reason retiring the rows is not safe on its own.
//
// Retiring leaves the tombstones in place — they are the record that the authority
// existed — and they still occupy their primary keys. A claim that mints the
// literal epoch 1, as this one used to, would then hit INSERT OR IGNORE against a
// tombstoned (project, 1) and write nothing at all, while the guard saw no live row
// and reported success. The project would be left with no authority and every
// admission unable to find a decider.
//
// Minting above the highest epoch the project has EVER held fixes that and
// preserves the monotonicity admission depends on: a holder from before the delete
// must never validate against what comes after it.
func TestClaimInitialProjectAuthority_MintsAboveEveryRetiredEpoch(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	if err := InsertProject(ctx, db, ProjectRecord{Name: "qa"}); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := ClaimInitialProjectAuthority(ctx, db, "qa", "node-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Hand it on, so the retired incarnation peaks above epoch 1.
	if _, applied, err := TakeoverProjectAuthority(ctx, db, "qa", "node-2", "planned", "", 1); err != nil || !applied {
		t.Fatalf("takeover: applied=%v err=%v", applied, err)
	}
	if err := DeleteProject(ctx, db, "qa"); err != nil {
		t.Fatalf("delete project: %v", err)
	}

	// The project name is live again as far as admission is concerned: nothing
	// holds authority, so the next admission for it claims afresh.
	applied, err := ClaimInitialProjectAuthority(ctx, db, "qa", "node-3")
	if err != nil || !applied {
		t.Fatalf("claim after retirement: applied=%v err=%v", applied, err)
	}

	cur, ok, err := CurrentProjectAuthority(ctx, db, "qa")
	if err != nil || !ok {
		t.Fatalf("no authority after a fresh claim (ok=%v err=%v) — the claim reported "+
			"success but a retired row's primary key swallowed the insert", ok, err)
	}
	if cur.Holder != "node-3" {
		t.Fatalf("holder = %q, want node-3", cur.Holder)
	}
	if cur.Epoch <= 2 {
		t.Fatalf("minted epoch %d, which the retired incarnation already used; a holder "+
			"from before the delete would still validate", cur.Epoch)
	}
}
