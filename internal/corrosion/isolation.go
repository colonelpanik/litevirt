package corrosion

import (
	"context"
	"errors"
	"fmt"
)

// Isolation epoch (§A). A node whose local state was produced OUTSIDE the
// cluster's current compatibility regime — rolled back below a latched
// capability token, or isolated by an operator — must not be able to inject
// that state back. The epoch is CLUSTER state about a host: replicated, so
// every peer independently refuses the quarantined node's replication, and
// peer-written, because a node that cannot be trusted to replicate cannot be
// trusted to record its own quarantine.

// Isolation reasons. Kept as a closed set so the admission refusal and the
// operator surfaces can be reasoned about (and so a typo can't invent a state).
const (
	IsolationRolledBackLatch = "rolled_back_latch" // below a token this node had latched
	IsolationManual          = "manual"            // operator-driven (lv host isolate)
	IsolationSchemaForward   = "schema_forward"    // local schema ahead of the cluster
)

var isolationReasons = map[string]bool{
	IsolationRolledBackLatch: true,
	IsolationManual:          true,
	IsolationSchemaForward:   true,
}

// ErrSelfIsolation rejects a node recording its OWN isolation. The whole point
// of putting the epoch in cluster state is that the observation comes from a
// healthy peer; a self-write would let a node that is lying about its state
// also control the record of that state.
var ErrSelfIsolation = errors.New("a node may not record its own isolation — a healthy peer must observe it")

// ErrIsolationNotMonotone rejects an epoch that would not increase. The column
// is monotone by contract: re-isolating an already-isolated host is a no-op
// rather than a fresh epoch, and nothing may lower it except a verified reseed.
var ErrIsolationNotMonotone = errors.New("isolation epoch must increase")

// IsolateHost records host as isolated at the next cluster-wide epoch. observer
// is the host making the observation and MUST NOT be the subject.
//
// The epoch is cluster-wide-max + 1 rather than per-host + 1 so the value
// orders isolations across the cluster: an operator reading two isolated hosts
// can tell which was quarantined later without a separate timestamp column
// (which a rolled-back node's clock could poison).
func IsolateHost(ctx context.Context, c *Client, observer, host, reason string) error {
	if observer == "" || host == "" {
		return invalidf("isolation requires an observer and a subject host")
	}
	if observer == host {
		return fmt.Errorf("%w (observer=%s)", ErrSelfIsolation, observer)
	}
	if !isolationReasons[reason] {
		return invalidf("isolation reason %q: want rolled_back_latch|manual|schema_forward", reason)
	}
	next, err := nextIsolationEpoch(ctx, c)
	if err != nil {
		return err
	}
	now := c.NowTS()
	// On the local-guard question raised by the project-authority review (#126,
	// finding 1): the guard below is a LOCAL transaction, so two healthy peers
	// observing the same quarantined node concurrently can both pass it and
	// both write. That is fatal for project_authority_epochs — an immutable
	// merge table whose PK includes the epoch, where two writers leave a
	// permanent immutable_conflict and two holders. It is SAFE here for a
	// reason worth stating rather than assuming: `hosts` is a plain LWW table
	// (no customMergeTables entry), and both writers produce the same
	// semantic fact — a nonzero epoch with the same reason — so LWW converges
	// on a valid isolation instead of a conflict. The admission gate reads
	// "nonzero", never a specific value.
	//
	// The one visible consequence is that two peers computing different epochs
	// (different replicated views of the cluster max) converge on whichever
	// wrote later, so a reseed that pinned the other value clears nothing and
	// reports "a newer isolation may have been recorded — re-run it". That is
	// the fail-safe direction and is already handled at the clear site.
	//
	// Guarded on NOT-ALREADY-ISOLATED. The detector runs every sweep, so an
	// already-isolated host must keep its ORIGINAL epoch: re-stamping a fresh
	// one on each pass would make the number meaningless (it is supposed to
	// order isolations), rewrite the row forever, and — worse — move the epoch
	// out from under a reseed that pinned it, so a verified reseed could never
	// clear anything. Two peers racing to isolate the same node converge for
	// the same reason: the first write wins, the second is a no-op.
	n, err := c.ExecuteRows(ctx,
		`UPDATE hosts SET isolation_epoch = ?, isolation_reason = ?, updated_at = ?
		 WHERE name = ? AND deleted_at IS NULL AND isolation_epoch = 0`,
		next, reason, now, host)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrIsolationNotMonotone
	}
	return nil
}

// nextIsolationEpoch reads the cluster-wide maximum and returns max+1.
func nextIsolationEpoch(ctx context.Context, c *Client) (int64, error) {
	rows, err := c.Query(ctx, `SELECT COALESCE(MAX(isolation_epoch), 0) AS m FROM hosts`)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 1, nil
	}
	return rows[0].Int64("m") + 1, nil
}

// ClearHostIsolation is the ONLY writer that lowers the epoch, and exists for
// exactly one caller: a reseed that has VERIFIED convergence. expectedEpoch
// pins the isolation the reseed actually reconciled, so an isolation recorded
// while the reseed was running is not silently cleared by it — the node stays
// quarantined and the operator reseeds again against the newer fact.
func ClearHostIsolation(ctx context.Context, c *Client, host string, expectedEpoch int64) error {
	if host == "" || expectedEpoch <= 0 {
		return invalidf("clearing isolation requires a host and the epoch being cleared")
	}
	now := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE hosts SET isolation_epoch = 0, isolation_reason = '', updated_at = ?
		 WHERE name = ? AND deleted_at IS NULL AND isolation_epoch = ?`,
		now, host, expectedEpoch)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// reseedKeepTables are NOT discarded by a reseed. Everything else in the
// replicated set is, because replacing it is the entire point.
//
//   - the audit tables: this host's OWN signed evidence, including the record
//     of the reseed itself. Discarding it would destroy the chain that proves
//     what this node did while it was incompatible — the opposite of what an
//     operator investigating an isolation needs.
//   - hosts: carries the isolation record being reconciled and the peer
//     addressing this node needs to keep talking to the cluster. The dump
//     merged immediately afterwards re-establishes it from the source anyway.
var reseedKeepTables = map[string]bool{
	"audit_log":           true,
	"audit_chain_heads":   true,
	"audit_signing_keys":  true,
	"audit_key_lifecycle": true,
	"hosts":               true,
}

// ReseedKeepsTable reports whether a reseed KEEPS this table's local rows. It
// is exported because the convergence verifier must skip exactly these: a table
// we deliberately did not replace cannot be expected to match the source, and
// comparing it would fail every reseed. Keeping the two derived from one set is
// the point — they drifted once (audit_signing_keys was kept but still
// compared, and the lab caught it as a reseed that could never verify).
func ReseedKeepsTable(name string) bool { return reseedKeepTables[name] }

// DiscardReplicatedStateForReseed drops this node's replicated rows so a state
// dump pulled from a healthy peer becomes AUTHORITATIVE rather than merely
// merged. Without it a reseed cannot do its job: an LWW merge is additive, so
// rows the isolated node produced outside the compatibility regime — the exact
// rows the quarantine exists to contain — would survive it and be re-injected
// the moment the epoch cleared. (Found on the lab: a reseed that only merged
// failed its own convergence check, correctly, because the stale rows were
// still there.)
//
// LOCAL ONLY (execLocal, no mutation_log rows): this must never replicate. It
// is one node rebuilding its own view, not a cluster-wide removal — broadcasting
// it would erase the cluster from every peer.
//
// Callers MUST already hold the dump they intend to merge (fetch → discard →
// merge): the gap between discard and merge is the one moment this node has no
// cluster state, and a fetch failure there would strand it.
func (c *Client) DiscardReplicatedStateForReseed(ctx context.Context) (int, error) {
	cleared := 0
	for _, table := range tableNames {
		if reseedKeepTables[table] {
			continue
		}
		// full-state-delete-ok: a reseed replaces this node's whole view from
		// an authoritative peer; the merge that follows repopulates it.
		if err := c.execLocal(ctx, `DELETE FROM `+table); err != nil {
			return cleared, fmt.Errorf("discard %s: %w", table, err)
		}
		cleared++
	}
	if err := c.retireOutboundBacklog(ctx); err != nil {
		return cleared, err
	}
	return cleared, nil
}

// retireOutboundBacklog stops this node's PRE-RESEED writes from ever reaching
// a peer.
//
// This is the half that made the quarantine only a delay. A refused push does
// not advance the per-peer watermark (by design — a transient refusal must not
// lose entries), so while a node is isolated its out-of-regime writes pile up
// in mutation_log. Discarding the local rows does not touch that queue, so the
// instant a reseed cleared the epoch the whole backlog replayed onto every
// peer — carrying its ORIGINAL timestamps, which is how the lab caught it: a
// container the peers had refused for half an hour appeared on all of them
// seconds after the reseed, created_at intact.
//
// After a reseed this node's entire state came from a healthy peer, so it has
// nothing legitimate left to push from before that point. We advance every
// peer watermark to the current head instead of deleting rows: the log stays
// intact as local history (and seq numbering keeps its meaning for peers that
// track it), while nothing before the reseed is ever selected for push again.
func (c *Client) retireOutboundBacklog(ctx context.Context) error {
	var head int64
	if err := c.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq), 0) FROM mutation_log`).Scan(&head); err != nil {
		return fmt.Errorf("read mutation log head: %w", err)
	}
	if err := c.execLocal(ctx,
		`UPDATE replication_watermarks SET last_seq = ?, updated_at = ? WHERE last_seq < ?`,
		head, nowRFC3339(), head); err != nil {
		return fmt.Errorf("retire outbound backlog: %w", err)
	}
	// Advancing the CURRENT peers' watermarks is not sufficient on its own: a
	// peer that joins later gets a fresh watermark at 0 and would be served the
	// pre-reseed entries that are still in the log (the pruner only removes
	// them once its retention window has also passed). A new node is precisely
	// the node that was not around to refuse them.
	//
	// So drop them outright. seq is AUTOINCREMENT, so deletion never reuses a
	// number and peers tracking our sequence are unaffected; this is the same
	// removal pruneMutationLog performs on its own schedule, taken immediately
	// because a reseed has already superseded every one of these entries with
	// state pulled from a healthy peer.
	if err := c.execLocal(ctx,
		`DELETE FROM mutation_log WHERE seq <= ?`, head); err != nil { // full-state-delete-ok
		return fmt.Errorf("drop pre-reseed mutation log: %w", err)
	}
	return nil
}

// HostIsolation reports a host's recorded isolation. A host row that is absent
// reports NOT isolated: absence is an unknown host (a fresh peer, a removed
// one), which the mTLS/admission layers judge on their own terms — inventing
// an isolation here would refuse legitimate first contact.
func HostIsolation(ctx context.Context, c *Client, host string) (epoch int64, reason string, err error) {
	rows, err := c.Query(ctx,
		`SELECT isolation_epoch AS e, COALESCE(isolation_reason, '') AS r
		 FROM hosts WHERE name = ? AND deleted_at IS NULL`, host)
	if err != nil {
		return 0, "", err
	}
	if len(rows) == 0 {
		return 0, "", nil
	}
	return rows[0].Int64("e"), rows[0].String("r"), nil
}
