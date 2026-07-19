package corrosion

import (
	"database/sql"
	"log/slog"
	"sort"
	"strings"
)

// Unresolved-tie tracking.
//
// An unresolved tie is kept local on purpose. We track (table,PK)->sorted
// content-hash-pair so lww_tie_unresolved counts DISTINCT rows (re-observing the
// same divergence is a no-op) and the alert fires once. The entry is cleared
// when the row's content changes — a real new write on either side (the
// remediation path, e.g. repair-owner re-stamping ownership with a fresh
// timestamp), a convergent merge, or a local write to the PK — so a later
// genuine divergence re-alerts and the count reflects reality after repair.
//
// NOTE: a divergent table is NOT suppressed from anti-entropy re-pulls here.
// Table-level suppression could hide an unrelated divergent row in the same
// table; a correct, row-proofed bound (only suppress when EVERY remaining
// differing PK matches a tracked unresolved content-pair) is a deferred
// follow-up. Until then a persistently-unresolved table may be re-pulled each
// cycle — a bounded cost paid only by genuinely-stuck rows awaiting repair, and
// strictly safer than risking hidden divergence.

func unresolvedKey(table, pk string) string { return table + "\x00" + pk }

// deferAfterCommit records fn to run only after the given transaction commits (via
// runDeferredEffects). A nil tx runs fn immediately (direct callers with no commit boundary). Used
// for tracker mutations and orphan alerts, which must not take effect if the tx later rolls back.
func (c *Client) deferAfterCommit(tx *sql.Tx, fn func()) {
	if tx == nil {
		fn()
		return
	}
	c.txEffectsMu.Lock()
	if c.txEffects == nil {
		c.txEffects = make(map[*sql.Tx][]func())
	}
	c.txEffects[tx] = append(c.txEffects[tx], fn)
	c.txEffectsMu.Unlock()
}

// runDeferredEffects runs and removes every effect registered for tx — call it right AFTER a
// successful tx.Commit(). Ordering is registration order.
func (c *Client) runDeferredEffects(tx *sql.Tx) {
	c.txEffectsMu.Lock()
	fns := c.txEffects[tx]
	delete(c.txEffects, tx)
	c.txEffectsMu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// dropDeferredEffects discards any effects registered for tx WITHOUT running them — call it on
// every rollback / early-return path (a deferred dropDeferredEffects is the safe default; a
// successful runDeferredEffects empties the map first, so the deferred drop then no-ops).
func (c *Client) dropDeferredEffects(tx *sql.Tx) {
	c.txEffectsMu.Lock()
	delete(c.txEffects, tx)
	c.txEffectsMu.Unlock()
}

// contentPair returns a stable, order-independent fingerprint of the two rows'
// content, so the same divergence (regardless of which side is "local") maps to
// one key.
func contentPair(local, incoming []interface{}) string {
	a, b := encodeRowCells(local), encodeRowCells(incoming)
	pair := []string{a, b}
	sort.Strings(pair)
	return strings.Join(pair, "\x01")
}

// anyUnresolved is the lock-free fast path for the clear-on-write hooks.
func (c *Client) anyUnresolved() bool { return c.unresolvedLen.Load() > 0 }

// trackUnresolved records an unresolved tie. It increments lww_tie_unresolved and
// logs an alert ONCE per distinct (table,PK,content-pair); re-observing the same
// divergence is a no-op (bounded). Safe to call with c.mu held (uses its own lock).
func (c *Client) trackUnresolved(table, pk string, local, incoming []interface{}, path resolveTiePath, category string) {
	c.trackUnresolvedPair(table, pk, contentPair(local, incoming), path, category)
}

// trackUnresolvedPair is trackUnresolved with a precomputed content-pair fingerprint, so a caller
// that needs a projection-independent / order-invariant key (identity faults, where local is the
// full row but the incoming may be a subset/reordered statement) can supply a stable one instead
// of the positional (local,incoming) pair.
func (c *Client) trackUnresolvedPair(table, pk, pair string, path resolveTiePath, category string) {
	key := unresolvedKey(table, pk)

	c.tieMu.Lock()
	if c.unresolvedTies == nil {
		c.unresolvedTies = make(map[string]string)
	}
	prev, existed := c.unresolvedTies[key]
	isNew := !existed || prev != pair
	if isNew {
		c.unresolvedTies[key] = pair
	}
	if !existed {
		c.unresolvedLen.Store(int64(len(c.unresolvedTies)))
		// Export the gauge WHILE holding tieMu so concurrent track/clear exports
		// serialize in mutation order — the gauge can never settle on a stale
		// (backwards) value due to callback reordering. The prometheus Set is a
		// cheap atomic store and never re-enters our locks.
		c.observeUnresolvedTieCurrent(len(c.unresolvedTies))
	}
	c.tieMu.Unlock()

	if isNew {
		c.observeTieUnresolved(table, string(path), category)
		slog.Warn("lww: unresolved equal-timestamp tie (kept local, needs repair)",
			"table", table, "pk", pk, "category", category, "path", string(path))
	}
}

// clearUnresolved drops the tracked entry for (table,PK) — called when the row
// converges or is repaired so a future genuine divergence re-alerts.
func (c *Client) clearUnresolved(table, pk string) {
	c.tieMu.Lock()
	if _, ok := c.unresolvedTies[unresolvedKey(table, pk)]; ok {
		delete(c.unresolvedTies, unresolvedKey(table, pk))
		c.unresolvedLen.Store(int64(len(c.unresolvedTies)))
		// Export under the lock (see trackUnresolved) so the gauge can't regress.
		c.observeUnresolvedTieCurrent(len(c.unresolvedTies))
	}
	c.tieMu.Unlock()
}

// clearUnresolvedFromShape clears the tracked unresolved entry for the row a full-PK statement
// mutates, keyed off the PARSED shape's resolved PK parameter indices (pkValuesFromShape) — NOT a
// string heuristic. The WAL apply path passes the shape it already parsed. A fresh/newer write (the
// remediation path) thus drops the stale tracking. Lock-free when nothing is tracked; a no-op for a
// shape with no full-PK identity or whose bound param count doesn't match.
func (c *Client) clearUnresolvedFromShape(sh StmtShape, s Statement) {
	if !c.anyUnresolved() {
		return
	}
	if sh.Table == "" || sh.ParamCount != len(s.Params) {
		return
	}
	vals, ok := pkValuesFromShape(sh, s)
	if !ok {
		return
	}
	c.clearUnresolved(sh.Table, pkKey(vals))
}

// clearUnresolvedFromLocalStmt is the local-write counterpart: a locally-executed statement does not
// arrive with a parsed shape, so this is the table-first structural parse entrypoint — extract and
// validate the table, obtain tablePrimaryKeys[table], parse the shape (which finalizes the PK
// parameter mapping), then clear via clearUnresolvedFromShape. A statement that doesn't parse to a
// full-PK shape is simply not cleared (the tracker self-heals on the next converging write).
func (c *Client) clearUnresolvedFromLocalStmt(s Statement) {
	if !c.anyUnresolved() {
		return
	}
	table := extractTableName(s.SQL)
	if table == "" || len(tablePrimaryKeys[table]) == 0 {
		return
	}
	sh, err := parseStmtShape(s.SQL, tablePrimaryKeys[table])
	if err != nil {
		return
	}
	c.clearUnresolvedFromShape(sh, s)
}

// UnresolvedTieCount returns the number of distinct currently-tracked unresolved
// ties (test/observability helper).
func (c *Client) UnresolvedTieCount() int {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	return len(c.unresolvedTies)
}

// UnresolvedTieTables returns the count of currently-tracked unresolved ties per table
// (keys are the `table\x00pk` unresolvedKey form — split on the NUL). Lets a divergence
// report attribute a cross-host hash mismatch to a deliberate safety-fault tie vs real drift.
func (c *Client) UnresolvedTieTables() map[string]int {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	out := make(map[string]int, len(c.unresolvedTies))
	for k := range c.unresolvedTies {
		if i := strings.IndexByte(k, 0); i > 0 {
			out[k[:i]]++
		}
	}
	return out
}
