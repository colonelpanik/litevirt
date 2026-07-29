package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
)

// D1 — project-admission authority. Project quota is a HARD admission guarantee, so
// one deterministic holder per NORMALIZED project serializes it. Authority is
// STICKY: the initial holder is minted once; it does not move merely because
// membership changes. A PLANNED handoff records an explicit transfer; an UNPLANNED
// takeover requires PROOF-GRADE fencing of the prior holder (a fence_proof_ref).
// Every transfer mints a monotonic authority_epoch; admission accepts reservations
// only from the CURRENT epoch, so a stale ex-holder's writes are rejected.

// ErrFenceProofRequired is returned when an unplanned ("fenced") takeover is
// attempted without a proof reference for the prior holder's fence.
var ErrFenceProofRequired = errors.New("corrosion: a fenced project-authority takeover requires a fence_proof_ref")

// DeriveProjectAuthorityHolder picks a project's INITIAL authority holder from the
// eligible hosts, deterministically.
//
// Every node claiming authority for ITSELF looks reasonable and is useless: each node
// serves its own creates, so each becomes the holder of its own replica, every
// admission stays local, and delegation never happens. Worse, the claims then collide
// — one epoch, two holders — and the cluster is back to two deciders while believing
// it has one. That is not a hypothetical: the lab produced exactly it, with node-1 and
// node-2 each holding /qa at epoch 1.
//
// Choosing by hash of the project name over the SORTED host list makes concurrent
// claimants mint an IDENTICAL row instead of competing ones, so the race stops
// mattering: the rows converge because they agree. It also spreads different projects
// across different hosts rather than piling every project onto one.
//
// Membership is itself eventually consistent, so two nodes with different views of the
// host list can still choose differently. That window is far narrower than claiming for
// self (which collides every single time) and heals the same way — the losing claim's
// node sees FailedPrecondition and retries against the winner.
func DeriveProjectAuthorityHolder(project string, candidates []string) string {
	eligible := append([]string(nil), candidates...)
	sort.Strings(eligible)
	if len(eligible) == 0 {
		return ""
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(projectOrDefault(project)))
	return eligible[int(h.Sum32()%uint32(len(eligible)))]
}

// ProjectAuthority is a project's admission-authority record. The CURRENT authority
// is the row with the maximum live authority_epoch for the project.
type ProjectAuthority struct {
	Project       string
	Epoch         int64
	Holder        string
	TransferKind  string // initial | planned | fenced
	FenceProofRef string
}

// CurrentProjectAuthority returns the highest live authority epoch for a project,
// or ok=false when the project has no authority yet.
func CurrentProjectAuthority(ctx context.Context, c *Client, project string) (ProjectAuthority, bool, error) {
	project = projectOrDefault(project)
	rows, err := c.Query(ctx,
		`SELECT project, authority_epoch, holder, transfer_kind, fence_proof_ref
		 FROM project_authority_epochs WHERE project = ? AND deleted_at IS NULL
		 ORDER BY authority_epoch DESC LIMIT 1`, project)
	if err != nil {
		return ProjectAuthority{}, false, err
	}
	if len(rows) == 0 {
		return ProjectAuthority{}, false, nil
	}
	r := rows[0]
	return ProjectAuthority{
		Project:       r.String("project"),
		Epoch:         r.Int64("authority_epoch"),
		Holder:        r.String("holder"),
		TransferKind:  r.String("transfer_kind"),
		FenceProofRef: r.String("fence_proof_ref"),
	}, true, nil
}

// ClaimInitialProjectAuthority mints the project's first authority epoch with
// holder, iff no LIVE authority exists yet. Returns applied=false (no error) if
// another node already established authority (the caller re-reads the current
// holder).
//
// The epoch is one above the highest this project has EVER held, counting retired
// (tombstoned) rows, rather than the literal 1. Deleting a project retires its
// authority but keeps the tombstones — they are the record that it existed — and
// they still occupy their primary keys, so a claim that reused epoch 1 would be
// swallowed by INSERT OR IGNORE while the guard, which only looks at live rows,
// reported success. It also keeps epochs monotonic across a project's whole
// history, so a holder from before a delete can never validate against what
// follows it.
func ClaimInitialProjectAuthority(ctx context.Context, c *Client, project, holder string) (applied bool, err error) {
	project = projectOrDefault(project)
	prevMax, err := maxProjectAuthorityEpoch(ctx, c, project)
	if err != nil {
		return false, err
	}
	epoch := prevMax + 1
	now, wall := c.NowTS(), nowRFC3339()
	// The guard re-checks BOTH halves inside the transaction: no live authority
	// (someone else may have claimed) and the same historical ceiling (someone else
	// may have retired or minted rows since the read above). Either miss returns
	// applied=false and the caller re-reads.
	guard := func(tx *sql.Tx) (bool, error) {
		var live int
		if qerr := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM project_authority_epochs WHERE project = ? AND deleted_at IS NULL`,
			project).Scan(&live); qerr != nil {
			return false, qerr
		}
		if live != 0 {
			return false, nil
		}
		var maxEpoch sql.NullInt64
		if qerr := tx.QueryRowContext(ctx,
			`SELECT MAX(authority_epoch) FROM project_authority_epochs WHERE project = ?`,
			project).Scan(&maxEpoch); qerr != nil {
			return false, qerr
		}
		return maxEpoch.Int64 == prevMax, nil
	}
	stmts := []Statement{{
		SQL: `INSERT OR IGNORE INTO project_authority_epochs
		      (project, authority_epoch, holder, transfer_kind, fence_proof_ref, created_at, updated_at, deleted_at)
		      VALUES (?, ?, ?, 'initial', '', ?, ?, NULL)`,
		Params: []interface{}{project, epoch, holder, wall, now},
	}}
	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// maxProjectAuthorityEpoch returns the highest epoch the project has ever held,
// INCLUDING retired rows, or 0 when it has never held any. Retired rows count
// because they still own their primary keys.
func maxProjectAuthorityEpoch(ctx context.Context, c *Client, project string) (int64, error) {
	rows, err := c.Query(ctx,
		`SELECT COALESCE(MAX(authority_epoch), 0) AS max_epoch
		 FROM project_authority_epochs WHERE project = ?`, projectOrDefault(project))
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	return rows[0].Int64("max_epoch"), nil
}

// RetireProjectAuthority tombstones every authority row for a project, so nothing
// holds authority for a name that no longer exists. Called when a project is
// deleted: an orphaned live row would otherwise let a later incarnation of the name
// inherit a holder nobody chose for it — possibly one the cluster had actively
// disagreed about. The rows themselves are kept, both because the table is
// append-only and because ClaimInitialProjectAuthority mints above them.
func RetireProjectAuthority(ctx context.Context, c *Client, project string) error {
	return c.Execute(ctx,
		`UPDATE project_authority_epochs SET deleted_at = ?, updated_at = ?
		 WHERE project = ? AND deleted_at IS NULL`,
		nowRFC3339(), c.NowTS(), projectOrDefault(project))
}

// TakeoverProjectAuthority mints epoch = expectedPrevEpoch+1 with the new holder.
// transferKind must be "planned" (an explicit relinquish/handoff) or "fenced" (an
// unplanned takeover, which REQUIRES fenceProofRef — proof the prior holder was
// fenced). Returns applied=false (no error) on a CAS miss (the current epoch is no
// longer expectedPrevEpoch — someone else transferred first).
func TakeoverProjectAuthority(ctx context.Context, c *Client, project, holder, transferKind, fenceProofRef string, expectedPrevEpoch int64) (newEpoch int64, applied bool, err error) {
	project = projectOrDefault(project)
	switch transferKind {
	case "planned":
	case "fenced":
		if fenceProofRef == "" {
			return 0, false, ErrFenceProofRequired
		}
	default:
		return 0, false, fmt.Errorf("corrosion: invalid project-authority transfer_kind %q (want planned|fenced)", transferKind)
	}
	newEpoch = expectedPrevEpoch + 1
	now, wall := c.NowTS(), nowRFC3339()
	guard := func(tx *sql.Tx) (bool, error) {
		var maxEpoch sql.NullInt64
		qerr := tx.QueryRowContext(ctx,
			`SELECT MAX(authority_epoch) FROM project_authority_epochs WHERE project = ? AND deleted_at IS NULL`, project).Scan(&maxEpoch)
		if qerr != nil {
			return false, qerr
		}
		return maxEpoch.Valid && maxEpoch.Int64 == expectedPrevEpoch, nil
	}
	stmts := []Statement{{
		SQL: `INSERT OR IGNORE INTO project_authority_epochs
		      (project, authority_epoch, holder, transfer_kind, fence_proof_ref, created_at, updated_at, deleted_at)
		      VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		Params: []interface{}{project, newEpoch, holder, transferKind, fenceProofRef, wall, now},
	}}
	applied, err = c.ExecuteBatchGuarded(ctx, guard, stmts)
	return newEpoch, applied, err
}

// ValidateProjectAuthority reports whether (project, epoch, holder) is the CURRENT
// authority — the admission check that rejects a stale ex-holder's reservation.
func ValidateProjectAuthority(ctx context.Context, c *Client, project string, epoch int64, holder string) (bool, error) {
	cur, ok, err := CurrentProjectAuthority(ctx, c, project)
	if err != nil || !ok {
		return false, err
	}
	return cur.Epoch == epoch && cur.Holder == holder, nil
}
