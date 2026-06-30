package corrosion

import (
	"log/slog"
	"sort"
	"strings"
)

// Bounded unresolved-tie state.
//
// An unresolved tie keeps the row divergent on purpose, so the table digest
// stays mismatched and naive anti-entropy would re-pull and re-merge that table
// every cycle — exactly the no-op resync this work removes. Two bounds:
//
//  1. unresolvedTies records (table,PK)->sorted-content-hash-pair. lww_tie_unresolved
//     is emitted only when this transitions to a NEW pair (a genuinely new
//     divergence), so the metric counts distinct rows and the alert fires once.
//     A real new write on either side changes the content → re-runs the resolver.
//  2. reconciledDivergent memoizes (peer,table)->digest-pair so the AE loop skips
//     re-pulling a table whose only delta is a known, unchanged unresolved tie.

func unresolvedKey(table, pk string) string   { return table + "\x00" + pk }
func reconciledKey(peer, table string) string { return peer + "\x00" + table }

// contentPair returns a stable, order-independent fingerprint of the two rows'
// content, so the same divergence (regardless of which side is "local") maps to
// one key.
func contentPair(local, incoming []interface{}) string {
	a, b := encodeRowCells(local), encodeRowCells(incoming)
	pair := []string{a, b}
	sort.Strings(pair)
	return strings.Join(pair, "\x01")
}

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
	c.tieMu.Unlock()

	if isNew {
		c.observeTieUnresolved(table, string(path), category)
		slog.Warn("lww: unresolved equal-timestamp tie (kept local, needs repair)",
			"table", table, "pk", pk, "category", category, "path", string(path))
	}
}

// clearUnresolved drops the tracked entry for (table,PK) — call when the row
// converges or is repaired so a future genuine divergence re-alerts.
func (c *Client) clearUnresolved(table, pk string) {
	c.tieMu.Lock()
	delete(c.unresolvedTies, unresolvedKey(table, pk))
	c.tieMu.Unlock()
}

// UnresolvedTieCount returns the number of distinct currently-tracked unresolved
// ties (test/observability helper).
func (c *Client) UnresolvedTieCount() int {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	return len(c.unresolvedTies)
}

// hasUnresolvedForTable reports whether any tracked unresolved tie belongs to the
// given table (used to decide whether a persistent digest mismatch is explainable
// by intentional divergence).
func (c *Client) hasUnresolvedForTable(table string) bool {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	prefix := table + "\x00"
	for k := range c.unresolvedTies {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// markReconciledDivergent memoizes that (peer,table) at this exact digest pair has
// already been reconciled as far as it can be (a known unresolved divergence
// remains). The AE loop consults isReconciledDivergent to avoid re-pulling.
func (c *Client) markReconciledDivergent(peer, table, localHash, remoteHash string) {
	c.tieMu.Lock()
	if c.reconciledDivergent == nil {
		c.reconciledDivergent = make(map[string]string)
	}
	c.reconciledDivergent[reconciledKey(peer, table)] = localHash + "\x00" + remoteHash
	c.tieMu.Unlock()
}

// isReconciledDivergent reports whether (peer,table) at this digest pair was
// already reconciled to a known unresolved divergence — so the mismatch is
// intentional and must not trigger another full-table pull/merge. Any change to
// either hash invalidates the memo (a real new write to re-sync).
func (c *Client) isReconciledDivergent(peer, table, localHash, remoteHash string) bool {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	v, ok := c.reconciledDivergent[reconciledKey(peer, table)]
	return ok && v == localHash+"\x00"+remoteHash
}

// clearReconciledDivergent forgets the memo for (peer,table) — call when a merge
// converges the table so a later genuine drift re-syncs normally.
func (c *Client) clearReconciledDivergent(peer, table string) {
	c.tieMu.Lock()
	delete(c.reconciledDivergent, reconciledKey(peer, table))
	c.tieMu.Unlock()
}
