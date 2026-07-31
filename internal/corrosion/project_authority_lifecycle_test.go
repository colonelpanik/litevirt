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

// TestReconcileOrphanedProjectAuthority_RetiresRowsForGoneProjects covers the
// damage already done. Retiring on delete is forward-only, so every project
// deleted before that fix still holds live authority — the lab carries five, for
// projects that have not existed for hours. Nothing collects them: the operation
// reaper only touches terminal operations, and an authority row never becomes
// terminal on its own.
func TestReconcileOrphanedProjectAuthority_RetiresRowsForGoneProjects(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	// Two deleted projects still holding authority, plus one live project that
	// must be left completely alone.
	for _, name := range []string{"gone-a", "gone-b", "live"} {
		if err := InsertProject(ctx, db, ProjectRecord{Name: name}); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
		if _, err := ClaimInitialProjectAuthority(ctx, db, name, "node-1"); err != nil {
			t.Fatalf("claim %s: %v", name, err)
		}
	}
	// Tombstone the projects WITHOUT going through DeleteProject, which is what a
	// pre-fix delete left behind.
	for _, name := range []string{"gone-a", "gone-b"} {
		if err := db.Execute(ctx,
			`UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?`,
			"2026-01-01T00:00:00Z", db.NowTS(), name); err != nil {
			t.Fatalf("tombstone %s: %v", name, err)
		}
	}

	n, err := ReconcileOrphanedProjectAuthority(ctx, db)
	if err != nil {
		t.Fatalf("ReconcileOrphanedProjectAuthority: %v", err)
	}
	if n != 2 {
		t.Errorf("retired %d orphaned authorities, want 2", n)
	}
	for _, name := range []string{"gone-a", "gone-b"} {
		if got := liveAuthorityRowCount(t, db, name); got != 0 {
			t.Errorf("deleted project %s still holds %d live authority row(s)", name, got)
		}
	}
	if got := liveAuthorityRowCount(t, db, "live"); got != 1 {
		t.Fatalf("live project lost its authority (%d live rows); every admission for it "+
			"would now be unable to find a decider", got)
	}

	// Idempotent: the GC loop runs hourly and must not churn once clean.
	again, err := ReconcileOrphanedProjectAuthority(ctx, db)
	if err != nil || again != 0 {
		t.Fatalf("second pass retired %d (err=%v), want 0 — this runs hourly and would "+
			"rewrite rows forever", again, err)
	}
}

// TestReconcileOrphanedProjectAuthority_LeavesTheDefaultProjectAlone.
//
// _default is treated as always existing regardless of what the projects table
// says, so retiring its authority would leave every untenanted admission in the
// cluster with no decider — the widest blast radius this sweep could have.
//
// The setup tombstones a _default row directly rather than calling DeleteProject,
// which refuses. That is the point: the exemption is not there to second-guess
// DeleteProject, it is there for a replica that arrives holding a tombstone
// nothing local would have written. Seeding it the polite way leaves _default with
// no projects row at all, the JOIN excludes it for that reason instead, and the
// exemption goes untested.
func TestReconcileOrphanedProjectAuthority_LeavesTheDefaultProjectAlone(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	if _, err := ClaimInitialProjectAuthority(ctx, db, DefaultProject, "node-1"); err != nil {
		t.Fatalf("claim default: %v", err)
	}
	if err := InsertProject(ctx, db, ProjectRecord{Name: DefaultProject}); err != nil {
		t.Fatalf("insert default: %v", err)
	}
	if err := db.Execute(ctx,
		`UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		"2026-01-01T00:00:00Z", db.NowTS(), DefaultProject); err != nil {
		t.Fatalf("tombstone default: %v", err)
	}

	if _, err := ReconcileOrphanedProjectAuthority(ctx, db); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := liveAuthorityRowCount(t, db, DefaultProject); got != 1 {
		t.Fatalf("_default lost its authority (%d live rows); every untenanted admission "+
			"in the cluster would be unable to find a decider", got)
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
