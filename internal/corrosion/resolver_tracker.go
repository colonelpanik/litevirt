package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
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

// contentPair returns a stable, order-independent encoding of the two rows'
// content, so the same divergence (regardless of which side is "local") maps to
// one key.
//
// This is RAW CONTENT, not a digest — encodeRowCells is a length-prefixed
// concatenation of cell values. trackUnresolvedPair digests it on the way into
// the register (pairFingerprint), which is where the invariant lives, so
// nothing here or in trackIdentityFault has to remember to hash.
func contentPair(local, incoming []interface{}) string {
	a, b := encodeRowCells(local), encodeRowCells(incoming)
	pair := []string{a, b}
	sort.Strings(pair)
	return strings.Join(pair, "\x01")
}

// pairFingerprint reduces a row-content pair to a fixed-size digest. Every pair
// entering the register goes through it, which is the invariant: NO ROW CONTENT
// IS EVER RETAINED, in memory, on disk, or in a log line.
//
// The two producers both hand over raw content today. contentPair joins two
// encodeRowCells outputs and trackIdentityFault passes an encodeRowCellsV2 of
// the whole local row; both encodings are length-prefixed concatenations of RAW
// CELL VALUES, not hashes, despite the "content-hash pair" wording this file
// and client.go have carried since before this branch. In memory that was
// merely mislabelled. Once acknowledgements became durable it stopped being
// cosmetic: acknowledged_ties.content_pair persisted the plaintext of both
// conflicting row versions.
//
// Secret-bearing rows do reach the tracker. user_2fa and recovery_codes end
// their resolver chains in ruleUnresolved("auth_factor") — whose own comment is
// "a differing secret/epoch is fail-to-human" — and lb_token ends in
// decideUnresolved("lb_token"). AcknowledgeUnresolvedTie is exported and takes
// an arbitrary (table, pk), so acknowledging such a tie wrote TOTP secrets,
// recovery material or a bearer token as cleartext into a local table that no
// redaction covers, that has no GC path, that loadAcknowledgedTies re-reads
// wholesale at every startup, and that rides along in any copy of the database
// file or any support bundle.
//
// A digest costs nothing here because the pair is only ever compared for
// equality — never parsed, displayed, or used to reconstruct a row.
func pairFingerprint(pair string) string {
	sum := sha256.Sum256([]byte(pair))
	return hex.EncodeToString(sum[:])
}

// anyUnresolved is the lock-free fast path for the clear-on-write hooks.
func (c *Client) anyUnresolved() bool { return c.unresolvedLen.Load() > 0 }

// unresolvedTie is one row whose merge was left unresolved: the order-independent
// fingerprint of the two conflicting versions, plus what the conflict was ABOUT.
type unresolvedTie struct {
	pair     string
	category string
	// acknowledged: an operator has stated they have seen THIS pair. The entry
	// stays tracked so the state digest can still attribute a hash mismatch to
	// it (the rows still disagree), but it stops driving decisions — the
	// owner-epoch latch, the tie counts and the gauge all skip it.
	acknowledged bool
}

// Tie categories: what a tie is ABOUT. A consumer decides which of these
// disqualify it; nothing here decides that.
//
// Constants, and enumerated in KnownTieCategories, because the consumer that
// matters — the owner-epoch readiness latch — is monotone and never re-opens,
// so a category it has never heard of must be a build failure rather than a
// silent default. They were bare string literals at a dozen emission sites, and
// the grpcapi-side classification was missing three of them on arrival.
//
// These are RULE-level categories, the ones that actually reach trackUnresolved.
// They are not the table-level `category:` field in resolverTables: "content"
// and "host-control-plane" appear there but can never be tracked, because those
// chains end in ruleContentMax and resolve.
const (
	TieCategoryRuntimeOwned     = "runtime_owned"              // host_name, pending_action_id, active_operation_id
	TieCategoryTenancy          = "tenancy"                    // a project column
	TieCategoryControlPlane     = "control_plane"              // hosts.state/address/role — the voting roster itself
	TieCategoryPolicy           = "policy"                     // projects, roles, role_bindings, users, tokens, ...
	TieCategoryOpaque           = "opaque"                     // vms.spec, containers.create_spec
	TieCategoryAuthFactor       = "auth_factor"                // user_2fa, recovery_codes
	TieCategoryAuthPointer      = "auth_pointer"               // an auth pointer column
	TieCategoryLBToken          = "lb_token"                   // an LB bearer token
	TieCategoryUncategorized    = "uncategorized"              // the resolver's own fallback
	TieCategoryIdentityContent  = "identity_content_conflict"  // an identity fault
	TieCategoryWorkloadIdentity = "workload_identity_conflict" // an authority-merge identity hash split

	// The two categories immutableMergeKeepLocalRow splits its conflicts into,
	// and one category was not enough — that split is the whole reason this
	// enumeration got written down.
	//
	// immutableMergeKeepLocalRow serves operations, operation_steps AND
	// leader_lease_terms. A contested lease term must NOT withhold
	// owner_epoch_v1 — it is not evidence about any workload's owner epoch —
	// while an operation_steps conflict MUST, because owner_epoch is part of
	// that table's primary key, so a conflict there is by construction a
	// conflict about an owner epoch. A single "immutable_conflict" category
	// forced every consumer to answer that question from a table name, in a
	// package that cannot see this schema.
	TieCategoryImmutableOwnership = "immutable_ownership_conflict"
	TieCategoryImmutableLedger    = "immutable_ledger_conflict"
)

// KnownTieCategories is every category an emission site can pass to
// trackUnresolved. TestKnownTieCategories_CoverEveryEmissionSite scans this
// package's source and fails if a site names one that is not here, and
// grpcapi's TestOwnershipTieCategory_PartitionsEveryKnownCategory fails if a
// category here is classified by neither of its maps.
//
// The two exported-by-value immutable categories are included: a consumer
// filters on the string, so a partition test has to see all of them.
var KnownTieCategories = []string{
	TieCategoryRuntimeOwned, TieCategoryTenancy, TieCategoryControlPlane,
	TieCategoryPolicy, TieCategoryOpaque, TieCategoryAuthFactor,
	TieCategoryAuthPointer, TieCategoryLBToken, TieCategoryUncategorized,
	TieCategoryIdentityContent, TieCategoryWorkloadIdentity,
	TieCategoryImmutableOwnership, TieCategoryImmutableLedger,
}

// immutableTieCategory classifies one immutable-row conflict.
//
// immutableMergeKeepLocalRow has exactly three tables (customMergeTables):
// operations and operation_steps, whose rows carry an owner epoch —
// operation_steps has it IN the primary key, so a conflict there is by
// construction a conflict about an owner epoch — and leader_lease_terms, which
// carries none. The only question is therefore whether this is the lease
// ledger, and an unknown table fails closed to ownership, because the consumer
// is a monotone latch that never re-opens: withholding a capability wrongly is
// recoverable, latching over a live ownership dispute is not.
//
// An earlier version asked ownershipBearingTables first, which was a lookup
// that could not change the answer — both that branch and the fallthrough
// returned the ownership category — so the map, and the schema-completeness
// test built on it, tested nothing. Worse, the map was wrong about
// project_authority_epochs, which merges through authorityMergeRow: that
// converges deterministically and calls observeTieBreak, never trackUnresolved,
// so it contributes no ties at all and the map's claim about it was false.
// TestImmutableMergeTables_AreAllClassified is the guard that replaces it, and
// it derives its table set from customMergeTables.
func immutableTieCategory(table string) string {
	if table == "leader_lease_terms" {
		return TieCategoryImmutableLedger
	}
	return TieCategoryImmutableOwnership
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
	pair = pairFingerprint(pair)

	c.tieMu.Lock()
	if c.unresolvedTies == nil {
		c.unresolvedTies = make(map[string]unresolvedTie)
	}
	// An acknowledged pair is not a tie any more, as far as the register is
	// concerned. Checked BEFORE the map is touched so an acknowledged conflict
	// costs no gauge movement and no repeated warning on every sweep.
	//
	// A DIFFERENT pair on the same row falls straight through and registers:
	// the acknowledgement describes one observed divergence and cannot cover
	// another. The acknowledgement itself is deliberately left in place, in
	// memory and in acknowledged_ties.
	//
	// THIS FUNCTION MUST NEVER ISSUE A DATABASE WRITE. It used to delete the
	// superseded acknowledgement here, and that was a self-deadlock: it runs
	// inside mergeChunk, which holds c.mu across the chunk, every local write
	// path takes c.mu (execLocal does), and sync.RWMutex is not reentrant. The
	// merge wedged permanently the first time a third distinct version reached
	// an acknowledged row, and wedged while holding tieMu, so every tie read
	// stopped with it — including the inventory collector behind readiness.
	// TestAcknowledgedTie_ANewDivergenceDoesNotDeadlockTheMerge holds the line.
	//
	// Keeping the superseded row is also the more correct answer, which is why
	// the fix costs nothing. Suppression demands an exact pair match, so a
	// stale acknowledgement is inert — it cannot mask the live divergence. And
	// if the acknowledged pair is ever observed again, the operator did
	// acknowledge precisely that, so staying quiet is the answer they gave.
	ack, hasAck := c.acknowledgedTies[key]
	acknowledged := hasAck && ack == pair

	// An acknowledged tie is still TRACKED, marked. It is not deleted and not
	// skipped, because "is this row currently divergent" and "should this
	// divergence drive a decision" are different questions and one register
	// answers both:
	//
	//   - UnresolvedTieTables feeds the cluster state digest, whose documented
	//     job is to let a divergence report attribute a cross-host hash
	//     mismatch to a deliberate safety-fault tie rather than real drift. The
	//     two rows still disagree after an acknowledgement — that is the point,
	//     the evidence stays — so this node's digest still mismatches every
	//     peer. Dropping the entry left that mismatch looking like unattributed
	//     drift, which is a worse answer than the permanently-dirty condition
	//     the acknowledgement exists to clear.
	//   - UnresolvedTieCategories feeds the owner-epoch latch and the tie
	//     counts behind ha.lww.unresolved, which are DECISIONS. Those skip
	//     acknowledged entries, and so does the gauge, or the operator's remedy
	//     would clear nothing.
	prev, existed := c.unresolvedTies[key]
	isNew := !existed || prev.pair != pair

	// An ACKNOWLEDGED observation must never displace a tracked UNACKNOWLEDGED
	// one for the same row. The register holds a single entry per (table, PK),
	// so a plain overwrite let a routine re-merge of an already-answered pair
	// erase a live conflict: with three versions in play, an operator
	// acknowledges A–B, a merge from C registers the unacknowledged A–C, and the
	// next ordinary merge from B puts {A–B, acknowledged} back in its place. The
	// unacknowledged divergence then vanished from liveTieCountLocked, from
	// UnresolvedTieCategories, and so from the owner-epoch latch and
	// ha.lww.unresolved — with no repair and no operator ever answering for it.
	//
	// This is the case the comment above says cannot happen ("a stale
	// acknowledgement is inert — it cannot mask the live divergence"). Exact-pair
	// suppression does make it inert on the SUPPRESSION path; masking came in
	// through the overwrite instead.
	//
	// Keeping prev does not strand the remedy. Acknowledgement is single-slot
	// per row, so acknowledging A–C moves the slot there, and the next
	// observation of A–C finds acknowledged=true and marks the entry — while
	// A–B, no longer covered by any acknowledgement, is correctly free to
	// register as live again.
	supersededByAck := existed && acknowledged && !prev.acknowledged && prev.pair != pair

	livenessMoved := !existed
	if !supersededByAck && (isNew || prev.acknowledged != acknowledged) {
		c.unresolvedTies[key] = unresolvedTie{pair: pair, category: category, acknowledged: acknowledged}
		livenessMoved = livenessMoved || (existed && prev.acknowledged != acknowledged)
	}
	if !existed {
		// unresolvedLen mirrors EVERY entry, acknowledged included: it is the
		// lock-free fast path for the clear-on-write hooks, and an acknowledged
		// entry must still be cleared when its row converges — otherwise the
		// digest keeps attributing a tie to a table that is now clean.
		c.unresolvedLen.Store(int64(len(c.unresolvedTies)))
	}
	// Re-export whenever the LIVE count can have moved, which is on a new entry
	// AND on an existing entry whose acknowledged state flipped. Gating this on
	// !existed alone left the gauge stale in the direction that matters: after an
	// acknowledgement drops it to zero, a fresh unacknowledged pair on that same
	// row makes the register live again while the gauge kept reading zero until
	// some unrelated operation happened to refresh it — so metric-based alerting
	// missed the new contest entirely.
	//
	// Exported WHILE holding tieMu so concurrent track/clear exports serialize in
	// mutation order — the gauge can never settle on a stale (backwards) value
	// due to callback reordering. The prometheus Set is a cheap atomic store and
	// never re-enters our locks.
	if livenessMoved {
		c.observeUnresolvedTieCurrent(c.liveTieCountLocked())
	}
	c.tieMu.Unlock()

	// Neither alerted nor counted as a new tie when the operator has already
	// answered for this exact divergence: a restart re-observes every
	// acknowledged tie, and re-alerting on each one is the noise the durable
	// acknowledgement exists to stop.
	if isNew && !acknowledged {
		c.observeTieUnresolved(table, string(path), category)
		slog.Warn("lww: unresolved equal-timestamp tie (kept local, needs repair)",
			"table", table, "pk", pk, "category", category, "path", string(path))
	}
}

// liveTieCountLocked counts the tracked ties that still drive a decision — the
// unacknowledged ones. Caller holds tieMu.
func (c *Client) liveTieCountLocked() int {
	n := 0
	for _, t := range c.unresolvedTies {
		if !t.acknowledged {
			n++
		}
	}
	return n
}

// clearUnresolved drops the tracked entry for (table,PK) — called when the row
// converges or is repaired so a future genuine divergence re-alerts.
func (c *Client) clearUnresolved(table, pk string) {
	c.tieMu.Lock()
	if _, ok := c.unresolvedTies[unresolvedKey(table, pk)]; ok {
		delete(c.unresolvedTies, unresolvedKey(table, pk))
		c.unresolvedLen.Store(int64(len(c.unresolvedTies)))
		// Export under the lock (see trackUnresolved) so the gauge can't regress.
		c.observeUnresolvedTieCurrent(c.liveTieCountLocked())
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
	return c.liveTieCountLocked()
}

// TrackedTieCount counts every tracked tie, acknowledged ones included — the
// "is this row currently divergent" question, as against
// UnresolvedTieCount's "is there something to act on".
func (c *Client) TrackedTieCount() int {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	return len(c.unresolvedTies)
}

// AcknowledgeUnresolvedTie records that an operator has seen the tie currently
// tracked for (table,PK), and drops it from the live register.
//
// true means the acknowledgement was RECORDED, which is very nearly the same
// thing as "the register was cleared" but not exactly: if a merge replaces the
// entry with a different divergence while the durable write is in flight, the
// acknowledgement still stands for the pair the operator saw and the newer
// conflict stays tracked. false means there was no tracked tie to acknowledge —
// see TieAcknowledged to tell that from "already acknowledged".
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
// ackPersistedHook is a test-only seam fired after an acknowledgement's durable
// write lands and BEFORE tieMu is re-acquired — precisely the window in which a
// merge can replace the tracked pair. Nil in production. Same shape as
// mergeChunkHook in sync.go, and for the same reason: the race is a two-lock
// interleaving that no amount of goroutine scheduling reproduces reliably.
var ackPersistedHook func()

func (c *Client) AcknowledgeUnresolvedTie(ctx context.Context, table, pk, by string) (bool, error) {
	key := unresolvedKey(table, pk)

	c.tieMu.Lock()
	t, ok := c.unresolvedTies[key]
	c.tieMu.Unlock()
	if !ok {
		return false, nil
	}
	if t.acknowledged {
		// Already acknowledged. The entry is RETAINED rather than deleted (see
		// unresolvedTie.acknowledged), so unlike the earlier delete-on-clear
		// version a retry finds it right here — and must not re-record it,
		// which would overwrite the original acknowledged_at and acknowledged_by
		// with a later operator's. Nothing to write and nothing to clear.
		//
		// The answer is the same false a never-tracked tie gets, because in
		// both cases this call changed nothing; TieAcknowledged is how a caller
		// tells them apart, which is what lets the RPC re-emit a lost audit
		// record on retry.
		return false, nil
	}

	// Persist FIRST, and fail the whole operation if it does not stick. An
	// acknowledgement that cleared the register but not the table would look
	// like it worked and silently come back on the next restart — the exact
	// failure this table exists to prevent, made harder to notice.
	//
	// execLocal: local-only, never replicated. See acknowledgedTiesDDL.
	if err := c.execLocal(ctx,
		`INSERT INTO acknowledged_ties (table_name, pk, content_pair, acknowledged_at, acknowledged_by)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(table_name, pk) DO UPDATE SET
		   content_pair = excluded.content_pair,
		   acknowledged_at = excluded.acknowledged_at,
		   acknowledged_by = excluded.acknowledged_by`,
		table, pk, t.pair, time.Now().UTC().Format(time.RFC3339), by); err != nil {
		return false, fmt.Errorf("persist acknowledgement of %s/%s: %w", table, pk, err)
	}
	if ackPersistedHook != nil {
		ackPersistedHook()
	}

	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	if c.acknowledgedTies == nil {
		c.acknowledgedTies = make(map[string]string, 1)
	}
	c.acknowledgedTies[key] = t.pair

	// Re-compare the PAIR before clearing anything, not just the key's
	// presence. tieMu was released for the durable write, and a merge in that
	// window can replace the register entry with a DIFFERENT divergence on the
	// same row. Deleting whatever is there now would clear a conflict the
	// operator never saw and report it acknowledged: the register would read
	// clean until the next sweep put it back, and the audit row would name a
	// pair nobody inspected.
	//
	// An entry that has vanished entirely is the other outcome and needs no
	// action: a concurrent clearUnresolved (a real repair) removed it, and an
	// acknowledgement of a pair that is no longer tracked is inert.
	cur, still := c.unresolvedTies[key]
	if still && cur.pair != t.pair {
		slog.Warn("a different divergence appeared on this row while the acknowledgement was "+
			"being recorded; the acknowledgement stands for the pair the operator saw and the "+
			"new conflict stays tracked",
			"table", table, "pk", pk,
			"acknowledged_fingerprint", t.pair, "tracked_fingerprint", cur.pair)
		return true, nil
	}
	if still {
		// MARKED, not deleted. The row is still divergent, so the digest's
		// attribution must keep seeing it; what the acknowledgement stops is
		// its effect on decisions. See unresolvedTie.acknowledged.
		cur.acknowledged = true
		c.unresolvedTies[key] = cur
		c.observeUnresolvedTieCurrent(c.liveTieCountLocked())
	}
	return true, nil
}

// TieAcknowledged reports whether this node holds an acknowledgement for
// (table,PK), whatever pair it names.
//
// It exists so a caller can tell "already acknowledged" from "never a tie
// here": AcknowledgeUnresolvedTie answers false to both, because both leave
// the register untouched. The distinction matters to anything that has to be
// written AFTER the acknowledgement commits — an audit record, say — and would
// otherwise be unrepairable on a retry, since the retry sees only that false.
func (c *Client) TieAcknowledged(table, pk string) bool {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	_, ok := c.acknowledgedTies[unresolvedKey(table, pk)]
	return ok
}

// LeaseTermTieAcknowledged is TieAcknowledged for a contested lease term, with
// the PK spelling owned here for the same reason AcknowledgeLeaseTermTie owns
// it.
func (c *Client) LeaseTermTieAcknowledged(key string, term int64) bool {
	return c.TieAcknowledged("leader_lease_terms", pkKey([]interface{}{key, term}))
}

// loadAcknowledgedTies primes the in-memory acknowledgement set from the
// local-only table. Called by InitSchema.
func (c *Client) loadAcknowledgedTies(ctx context.Context) error {
	rows, err := c.Query(ctx, `SELECT table_name, pk, content_pair FROM acknowledged_ties`)
	if err != nil {
		return err
	}
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	if c.acknowledgedTies == nil {
		c.acknowledgedTies = make(map[string]string, len(rows))
	}
	for _, r := range rows {
		c.acknowledgedTies[unresolvedKey(r.String("table_name"), r.String("pk"))] = r.String("content_pair")
	}
	return nil
}

// AcknowledgeLeaseTermTie acknowledges the contested-term tie for (key, term).
//
// The PK key spelling belongs to this package — it is whatever pkKeyAt produced
// when the merge tracked the tie — so callers name the lease and the term and
// never construct it. A caller that built its own string would silently
// acknowledge nothing the day the encoding changed.
func (c *Client) AcknowledgeLeaseTermTie(ctx context.Context, key string, term int64, by string) (bool, error) {
	return c.AcknowledgeUnresolvedTie(ctx, "leader_lease_terms", pkKey([]interface{}{key, term}), by)
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
		// Acknowledged ties are excluded: this map drives the owner-epoch latch
		// and the counts behind ha.lww.unresolved, and an acknowledgement is
		// exactly the statement that those must stop firing. The digest's
		// attribution still sees them, via UnresolvedTieTables.
		if t.acknowledged {
			continue
		}
		out[t.category]++
	}
	return out
}

// UnresolvedTieTables returns the count of currently-tracked unresolved ties per table
// (keys are the `table\x00pk` unresolvedKey form — split on the NUL). Lets a divergence
// report attribute a cross-host hash mismatch to a deliberate safety-fault tie vs real drift.
//
// ACKNOWLEDGED ties are INCLUDED, unlike in UnresolvedTieCategories. An
// acknowledgement does not converge the rows — both claims stay in the table by
// design — so this node's digest still mismatches its peers afterwards, and
// this map is the only thing that explains why. Excluding them turned a
// deliberate, operator-reviewed safety fault into unattributed drift.
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
