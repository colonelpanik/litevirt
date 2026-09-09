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

// unresolvedTie is one row whose merge was left unresolved: the order-independent
// fingerprint of the two conflicting versions, plus what the conflict was ABOUT.
type unresolvedTie struct {
	pair     string
	category string
}

// The two categories immutableMergeKeepLocalRow splits its conflicts into.
//
// One category was not enough, and that is the whole reason this split exists.
// immutableMergeKeepLocalRow serves operations, operation_steps AND
// leader_lease_terms. A contested lease term must NOT withhold owner_epoch_v1 —
// it is not evidence about any workload's owner epoch — while an
// operation_steps conflict MUST, because owner_epoch is part of that table's
// primary key, so a conflict there is by construction a conflict about an owner
// epoch. A single "immutable_conflict" category forced every consumer to answer
// that question from the table name instead, in a package that cannot see this
// schema.
const (
	tieCategoryImmutableOwnership = "immutable_ownership_conflict"
	tieCategoryImmutableLedger    = "immutable_ledger_conflict"
)

// ownershipBearingTables are the tables whose rows carry a workload's or
// project's owner epoch. A tie on one of them can hide an ownership decision
// from a reader of that epoch.
//
// It lives HERE, beside schemaDDL, so its completeness is testable against the
// schema — TestOwnershipBearingTables_CoverEveryOwnerEpochColumn derives the
// expected set by scanning the DDL. The previous version of this classification
// lived in internal/grpcapi as a table-name map whose own comment admitted the
// hazard ("Adding an owner_epoch column to a table WITHOUT adding it here
// silently narrows one") with nothing able to enforce it from there.
var ownershipBearingTables = map[string]bool{
	"vms":                      true, // vms.vm_owner_epoch
	"containers":               true, // containers.owner_epoch
	"operations":               true, // operations.vm_owner_epoch
	"operation_steps":          true, // operation_steps.owner_epoch, IN the primary key
	"project_authority_epochs": true, // project_authority_epochs.authority_epoch
	"runtime_action_proofs":    true, // runtime_action_proofs.owner_epoch
}

// immutableTieCategory classifies one immutable-row conflict by whether the
// table carries an owner epoch. An UNKNOWN table gets the ownership category:
// fail closed, because the consumer of this answer is a monotone latch that
// never re-opens, and withholding a capability is recoverable while latching
// over a live ownership dispute is not.
func immutableTieCategory(table string) string {
	if ownershipBearingTables[table] {
		return tieCategoryImmutableOwnership
	}
	if table == "leader_lease_terms" {
		return tieCategoryImmutableLedger
	}
	return tieCategoryImmutableOwnership
}

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
		c.unresolvedTies = make(map[string]unresolvedTie)
	}
	// An acknowledged pair is not a tie any more, as far as the register is
	// concerned. Checked BEFORE the map is touched so an acknowledged conflict
	// costs no gauge movement and no repeated warning on every sweep.
	if ack, ok := c.acknowledgedTies[key]; ok {
		if ack == pair {
			c.tieMu.Unlock()
			return
		}
		// A different divergence on the same row: the acknowledgement described
		// something else and must not cover this.
		delete(c.acknowledgedTies, key)
	}
	prev, existed := c.unresolvedTies[key]
	isNew := !existed || prev.pair != pair
	if isNew {
		c.unresolvedTies[key] = unresolvedTie{pair: pair, category: category}
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
// arrive with a parsed shape, so this does the two-stage structural parse (parseResolved) to get the
// table + PK metadata from the VALIDATED parse — never a comment-sensitive string scan — then clears
// via clearUnresolvedFromShape. A statement that doesn't parse to a full-PK shape is simply not
// cleared (the tracker self-heals on the next converging write).
func (c *Client) clearUnresolvedFromLocalStmt(s Statement) {
	if !c.anyUnresolved() {
		return
	}
	sh, _, err := parseResolved(s.SQL)
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

// AcknowledgeUnresolvedTie records that an operator has seen the tie currently
// tracked for (table,PK), and drops it from the live register. Reports whether
// such a tie was tracked.
//
// It exists because one class of tie can never clear on its own.
// clearUnresolved fires when a remediating write lands on the row — the right
// contract for a mutable table — but leader_lease_terms rows are immutable by
// design, so no such write is ever coming. Without this the register, the state
// digest and the ha.lww.unresolved health condition stay dirty for as long as
// the two rows disagree, which is forever, and no restart helps (see
// acknowledgedTies).
//
// It clears EVIDENCE TRACKING, never the conflict. Both rows stay exactly as
// they are, and the caller is expected to write an audit record naming who
// acknowledged what. DO NOT extend this to delete a losing row: nothing here
// knows which claim was legitimate, and implying otherwise is the one thing
// this table's merge exists to avoid.
func (c *Client) AcknowledgeUnresolvedTie(table, pk string) bool {
	key := unresolvedKey(table, pk)
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	t, ok := c.unresolvedTies[key]
	if !ok {
		return false
	}
	if c.acknowledgedTies == nil {
		c.acknowledgedTies = make(map[string]string, 1)
	}
	c.acknowledgedTies[key] = t.pair
	delete(c.unresolvedTies, key)
	c.unresolvedLen.Store(int64(len(c.unresolvedTies)))
	c.observeUnresolvedTieCurrent(len(c.unresolvedTies))
	return true
}

// AcknowledgeLeaseTermTie acknowledges the contested-term tie for (key, term).
//
// The PK key spelling belongs to this package — it is whatever pkKeyAt produced
// when the merge tracked the tie — so callers name the lease and the term and
// never construct it. A caller that built its own string would silently
// acknowledge nothing the day the encoding changed.
func (c *Client) AcknowledgeLeaseTermTie(key string, term int64) bool {
	return c.AcknowledgeUnresolvedTie("leader_lease_terms", pkKey([]interface{}{key, term}))
}

// UnresolvedTieCategories totals the live unresolved ties by CATEGORY.
//
// The caller decides which categories disqualify it; this function does not, so
// adding a category cannot silently widen or narrow anyone's predicate — it
// shows up as an unclassified key at the consumer instead.
//
// Read under ONE lock acquisition together with nothing else. A consumer that
// wants both this and UnresolvedTieCount must derive the total by summing these
// counts rather than calling both: two acquisitions can straddle a concurrent
// merge and produce a snapshot where a subset count exceeds its own superset.
func (c *Client) UnresolvedTieCategories() map[string]int {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	out := make(map[string]int, len(c.unresolvedTies))
	for _, t := range c.unresolvedTies {
		out[t.category]++
	}
	return out
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
