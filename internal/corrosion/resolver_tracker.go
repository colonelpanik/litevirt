package corrosion

import (
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
	pair := contentPair(local, incoming)
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

// clearUnresolvedFromStmt clears the tracked unresolved entry for the row a
// statement mutates — the hook for the WAL apply path and local writes, so a
// fresh/newer write (the remediation path) drops the stale tracking. Lock-free
// when nothing is tracked.
func (c *Client) clearUnresolvedFromStmt(s Statement) {
	if !c.anyUnresolved() {
		return
	}
	table := extractTableName(s.SQL)
	if table == "" {
		return
	}
	pkCols := tablePrimaryKeys[table]
	if len(pkCols) == 0 {
		return
	}
	vals := extractPKValues(table, pkCols, s)
	if len(vals) != len(pkCols) {
		return
	}
	c.clearUnresolved(table, pkKey(vals))
}

// UnresolvedTieCount returns the number of distinct currently-tracked unresolved
// ties (test/observability helper).
func (c *Client) UnresolvedTieCount() int {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	return len(c.unresolvedTies)
}
