package corrosion

import (
	"context"
	"fmt"
)

// reseedInProgressDDL records that a reseed has deleted this node's state and
// has not yet finished restoring it.
//
// A reseed is three steps that cannot be one transaction: discard the
// replicated tables, merge the operator dump, merge the SENSITIVE dump. The
// middle step restores users and their password hashes; the last one restores
// user_2fa. A process that dies between them leaves a node that can
// authenticate every enrolled account with a password alone, because
// LocalRealm.Authenticate sets Requires2FA from len(factors) > 0 and an empty
// user_2fa is indistinguishable there from nobody having enrolled.
//
// DiscardReplicatedStateForReseed's own comment already names this hazard and
// states the mitigation as a contract on the caller ("MUST repopulate them in
// the same operation"). A crash does not honour contracts, so this marker
// enforces it: set before the discard, cleared only once the sensitive merge
// has committed, and consulted by the pre-session login paths, which refuse
// while it is set.
//
// Created by the framework rather than listed in schemaDDL, following
// appliedMigrationsDDL and acknowledgedTiesDDL and for the same reasons: it
// costs no schema version and it is LOCAL-ONLY. Every write goes through
// execLocal (no mutation_log row) and the table is absent from sync.go's
// tableNames, so peers never replicate it — which is also why the discard loop
// cannot delete it, since that loop walks exactly those replicated names.
// Replicating it would be actively wrong: it describes one node's interrupted
// operation, not a fact about the cluster.
//
// One row, pinned by CHECK (id = 1): "is this node mid-reseed" is a single
// fact, and a table that could hold two of them could disagree with itself.
const reseedInProgressDDL = `CREATE TABLE IF NOT EXISTS reseed_in_progress (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	started_at TEXT NOT NULL,
	source     TEXT NOT NULL
)`

// BeginReseed marks this node as mid-reseed. It must be called and must have
// COMMITTED before the discard, because the window it guards opens with the
// first DELETE.
//
// INSERT OR REPLACE, not INSERT: a repeat reseed is the documented recovery
// path out of an interrupted one, so it has to be callable while the marker is
// already set, and it must leave behind the source it is actually pulling from
// rather than the one that failed.
func (c *Client) BeginReseed(ctx context.Context, source string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// ONE transaction. The two writes were separate execLocal calls, and the
	// fence's safety then rested entirely on their ORDER: a reader that saw the
	// generation already bumped while the marker was not yet set would be
	// admitted and stamped with the post-reseed value, and the mint would later
	// compare equal against a cleared marker. That ordering was stated nowhere
	// and pinned by nothing — exactly the "argument that has to be re-derived
	// whenever either side moves" that the single-statement read was meant to
	// eliminate. A transaction removes the dependency instead of documenting it.
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin reseed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO reseed_in_progress (id, started_at, source) VALUES (1, ?, ?)`,
		c.NowTS(), source); err != nil {
		return 0, fmt.Errorf("mark reseed in progress: %w", err)
	}
	// Bumped for every reseed that STARTS, including a repeat of one that failed,
	// and never reset: a caller holding the old value must be able to see that
	// something happened even if the reseed has since finished.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO reseed_generation (id, generation) VALUES (1, 1)
		 ON CONFLICT(id) DO UPDATE SET generation = reseed_generation.generation + 1`); err != nil {
		return 0, fmt.Errorf("bump reseed generation: %w", err)
	}
	var generation int64
	if err := tx.QueryRowContext(ctx,
		`SELECT generation FROM reseed_generation WHERE id = 1`).Scan(&generation); err != nil {
		return 0, fmt.Errorf("read the minted reseed generation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit reseed start: %w", err)
	}
	// Returned so the caller can name the reseed it started. FinishReseed clears
	// the marker only for that one.
	return generation, nil
}

// FinishReseed clears the marker for the reseed that minted `generation`, and
// only for that one.
//
// The unconditional DELETE it used to be is unsafe once two reseeds can
// overlap: the FIRST to finish cleared the marker while the second still had
// the credential tables mid-discard, so the login gate lifted over an
// incomplete node and an enrolled account could be served a password-only
// session — the whole condition the marker exists to signal.
func (c *Client) FinishReseed(ctx context.Context, generation int64) error {
	// Conditional on the marker still belonging to THIS reseed. One statement,
	// so the check and the delete cannot be separated: a later reseed starting
	// between a read and an unconditional delete would have its marker removed
	// by the read's verdict.
	//
	// A generation that has been overtaken deletes nothing, which is success —
	// the node is still mid-reseed and the marker naming the newer one is
	// exactly what should remain.
	if err := c.execLocal(ctx,
		`DELETE FROM reseed_in_progress
		 WHERE id = 1
		   AND (SELECT generation FROM reseed_generation WHERE id = 1) = ?`,
		generation); err != nil {
		return fmt.Errorf("clear reseed marker: %w", err)
	}
	return nil
}

// ReseedIncomplete reports whether a reseed deleted this node's state and never
// finished restoring it, naming the source it was pulling from.
//
// A read failure is reported, never folded into "no reseed pending". This is the
// same fail-closed rule LocalRealm.Authenticate already applies to the 2FA
// enrollment lookup, and for the same reason: the caller is a login gate, and an
// unreadable marker must not read as permission to serve.
func (c *Client) ReseedIncomplete(ctx context.Context) (bool, string, error) {
	rows, err := c.Query(ctx, `SELECT source FROM reseed_in_progress WHERE id = 1`)
	if err != nil {
		return false, "", fmt.Errorf("read reseed marker: %w", err)
	}
	if len(rows) == 0 {
		return false, "", nil
	}
	return true, rows[0].String("source"), nil
}

// reseedGenerationDDL counts reseeds that have STARTED on this node, and only
// ever increases.
//
// The marker alone cannot close the window a credential check opens. A login
// reads the marker, spends a deliberately-slow bcrypt verifying a password, and
// only then reads user_2fa — so an entire reseed can start AND finish inside one
// request, and re-reading the boolean would find it clear and conclude nothing
// had happened. A caller that captures this number before it reads any
// credential state and re-checks it before granting anything sees the reseed
// either way.
//
// Local-only and framework-created, like the marker beside it: it describes this
// node's own history, costs no schema version, and survives the discard by being
// absent from the replicated table lists that loop walks.
const reseedGenerationDDL = `CREATE TABLE IF NOT EXISTS reseed_generation (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	generation INTEGER NOT NULL
)`

// ReseedFence reports whether a reseed is currently incomplete, the source it
// was pulling from, and the monotone count of reseeds started on this node.
//
// ONE statement, deliberately. The two values are read in a single SELECT so
// they describe the same instant: SQLite evaluates a statement against one
// snapshot, so no reseed can land between them.
//
// It read twice before — ReseedIncomplete, then a separate SELECT — and that
// was the whole bug, one layer below where it was first looked for. A reseed
// beginning between the two reads set the marker and bumped the generation
// after the marker had already been read as clear, so the value stamped on the
// admitted request was the POST-reseed generation; when the reseed then also
// finished, the mint compared equal generations against a cleared marker and
// concluded nothing had happened. A 2FA-enrolled account got a password-only
// session, which is the exact race the generation was introduced to close.
// TestReseedFence_IsASingleRead pins the shape; ordering the reads
// generation-first would also be sound, but only by an argument that has to be
// re-derived whenever either side moves.
//
// A read failure is reported rather than folded into "no reseed pending": the
// caller is a credential gate, and an unreadable fence must not read as
// permission to serve.
func (c *Client) ReseedFence(ctx context.Context) (incomplete bool, source string, generation int64, err error) {
	rows, qerr := c.Query(ctx, `SELECT
		(SELECT COUNT(*) FROM reseed_in_progress WHERE id = 1)                 AS incomplete,
		COALESCE((SELECT source FROM reseed_in_progress WHERE id = 1), '')     AS source,
		COALESCE((SELECT generation FROM reseed_generation WHERE id = 1), 0)   AS generation`)
	if qerr != nil {
		return false, "", 0, fmt.Errorf("read reseed fence: %w", qerr)
	}
	if len(rows) == 0 {
		// A scalar-subquery SELECT with no FROM always yields exactly one row;
		// no rows means the read did not happen as written, which a credential
		// gate must not read as "no reseed pending".
		return false, "", 0, fmt.Errorf("read reseed fence: no row")
	}
	return rows[0].Int64("incomplete") > 0, rows[0].String("source"), rows[0].Int64("generation"), nil
}
