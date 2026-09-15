package corrosion

// Compatibility ledger: the checked-in set of stmtshape/v1 fingerprints the cluster
// accepts, keyed by fingerprint. It is the single source of truth consumed by BOTH the
// runtime authorization path (reject an incoming statement whose fingerprint is unknown)
// and the stmtshapecheck CI guard (prove every builder's shape is registered), so the two
// cannot drift.
//
// Every fingerprint accepted anywhere within the supported upgrade + WAL-retention horizon
// must be present — including shapes emitted only by older binaries still in flight — so an
// entry is removed only once no supported version can still emit it (enforced by the guard,
// which fails if a current builder's fingerprint is missing). Each entry carries the
// activation/version conditions Part C/H consume (disposition before/after a capability
// activation, concurrency category for a bulk update, an optional legacy transformer, and a
// removal horizon).

// Disposition is how the apply path treats a statement whose fingerprint matches this entry.
type Disposition string

const (
	DispPlainInsert         Disposition = "plain_insert"           // rewrite to a PK-aware upsert
	DispExplicitUpsert      Disposition = "explicit_upsert"        // apply verbatim (leading algo normalized)
	DispFullPKUpdate        Disposition = "full_pk_update"         // LWW-gate by updated_at, guards retained
	DispFullPKUpdateNoClock Disposition = "full_pk_update_noclock" // full-PK UPDATE that does NOT bind updated_at (audit reseal / session touch / token last_used_at): apply verbatim by PK, no LWW gate (the builder's WHERE keeps it idempotent/monotone)
	DispBulkUpdate          Disposition = "bulk_update"            // apply per ConcurrencyCategory
	DispDeleteRetention     Disposition = "delete_retention"       // hard delete on a registered retention table
	DispAppendOnly          Disposition = "append_only"            // INSERT OR IGNORE, no LWW
	DispCustomMerge         Disposition = "custom_merge"           // runtime_action_proofs / operations / …
	// DispAuditReseal applies an audit_log hash-chain reseal through the
	// signature-guarded form of the statement, WHATEVER shape arrived.
	//
	// The pre-v45 shape has no signature predicate, and it stays on the wire for
	// the rolling-upgrade horizon. Applied verbatim it is a cluster-wide eraser:
	// a node that rewrote its own signed rows could emit the old shape and every
	// peer would overwrite its good content_hash by primary key, with no clock
	// compare and no way back — reseal refuses to touch signed rows, so nothing
	// can restore the correct hash afterwards. Rewriting the statement on the
	// receiver keeps the legacy sender working (legacy rows carry no signature,
	// so the guard is a no-op for everything it was ever meant to reach) while
	// making a signed row unreachable by any reseal, local or replicated.
	DispAuditReseal Disposition = "audit_reseal"
	// DispGuardedReplace applies one statement of a guarded VM-name replacement
	// (`lv cutover`) VERBATIM, once its workload_replace_v1 guard has matched.
	//
	// Verbatim is the point. Every statement in the batch carries the SAME guard, so
	// the guard's single decision is what orders the transition; LWW-gating the
	// individual writes on top of it would let a receiver apply the parent and skip
	// a child on its own clock, leaving the contested name holding some of the
	// replacement's devices and not others. The target-row shape re-states its own
	// incarnation/authority ordering in SQL, so it still fails closed if it is ever
	// reached without the guard.
	DispGuardedReplace Disposition = "guarded_replace"
	// DispCreateBegin applies one of the exact, audited workload-create
	// resurrection UPSERTs verbatim after workload_create_begin_v1 matches.
	// Their owner/generation WHERE is the ordering rule; an unrelated receiver
	// clock must not override that semantic ABA fence.
	DispCreateBegin Disposition = "create_begin"
	// DispGuardedTransition applies an exact, authority-guarded workload
	// terminal transition verbatim. The workload guard is the ordering rule;
	// unrelated receiver clocks must not split the transition from the
	// hardware/journal statements earlier in the same transaction.
	DispGuardedTransition Disposition = "guarded_transition"
	// DispWorkloadDelete applies an exact authority-fenced parent tombstone
	// verbatim. The workload owner/generation guard prevents delayed deletes
	// from crossing a recreate epoch; equal-authority deletes remain valid.
	DispWorkloadDelete Disposition = "workload_delete"
	// DispLegacyWorkloadDelete accepts retained pre-authority delete shapes only
	// for rows whose owner/generation axes are still both zero. The old wire
	// shape cannot prove authority, so it must never cross into a v44 identity.
	DispLegacyWorkloadDelete Disposition = "legacy_workload_delete"
	// DispReject always back-pressures. Used as the BEFORE-activation disposition of a
	// capability-gated shape (RequiresCapability + DispositionAfter): the shape is not authorized
	// until its capability is active on this receiver, so a prematurely-emitted write fails closed.
	DispReject Disposition = "reject"
	// DispCanonicalRegistry applies the Part H2 canonical registry-credential upsert. Before the
	// LWW apply it VERIFIES the deterministic-ID contract — id == RegistryCredentialID(scope,
	// owner,registry) from the SAME statement's params — so an approved shape carrying an id
	// inconsistent with its triple (a builder bug / malformed entry) can't insert a noncanonical
	// row or update a different credential's secret. Then applies as an explicit upsert (LWW).
	DispCanonicalRegistry Disposition = "canonical_registry"
)

// ConcurrencyCategory qualifies a DispBulkUpdate entry (see Part C). Empty for non-bulk.
type ConcurrencyCategory string

const (
	CatNone      ConcurrencyCategory = ""            // non-bulk entry
	CatPerRowLWW ConcurrencyCategory = "per_row_lww" // receiver-side per-row LWW expansion (the ONLY valid bulk category)
	// CatUnsupported is never emitted into a ledger — deriveDisposition returns an error for an
	// unsafe bulk update, so generation fails. It is retained only so the runtime dispatch can
	// reject it (and any unknown category) as defense against corrupt or historical ledger data.
	CatUnsupported ConcurrencyCategory = "unsupported"
)

// LedgerEntry is one accepted fingerprint plus its activation/version conditions.
type LedgerEntry struct {
	Fingerprint string
	Kind        string // "insert" | "update" | "delete" (from the parsed shape)
	Table       string // best-effort, for operator readability; not authoritative
	Disposition Disposition
	Category    ConcurrencyCategory // for DispBulkUpdate

	// Activation/version conditions (Part H). MinSchema/MaxSchema bound the schema lane in
	// which this shape is valid (0 = unbounded). RequiresCapability names a capability that
	// must be active for DispositionAfter to apply; before activation, Disposition applies.
	MinSchema, MaxSchema int
	RequiresCapability   string
	DispositionAfter     Disposition // disposition once RequiresCapability is active ("" = same)
	TransformerID        string      // optional entry-level legacy transformer (Part H)
	RemovalHorizon       string      // release/version after which this entry may be removed

	// Provenance for the mixed-version horizon (Part B). FirstEmitter/LastEmitter are the
	// earliest/latest supported releases that emit this shape ("" LastEmitter ⇒ still emitted
	// by the current build). The CI guard forbids deleting an entry whose emitter is still a
	// supported peer. Empty on current-build entries (the guard proves those against source).
	FirstEmitter, LastEmitter string

	// MonotoneColumn, set on a DispFullPKUpdateNoClock entry via an explicit audited policy,
	// names a timestamp column the receiver must only ADVANCE. The apply path adds a guard so
	// an out-of-order replicated write can't move it backwards (session/token last_used_at).
	// Empty ⇒ the no-clock update is idempotent/terminal and applies verbatim (audit reseal,
	// a guarded one-shot revoke).
	MonotoneColumn string
}

// LedgerLookup returns the entry for a fingerprint, if registered — in the current-build
// ledger or the checked-in historical ledger (prior-release shapes still in the supported
// upgrade/WAL-retention horizon). A fingerprint absent from BOTH is an unknown shape and the
// apply path back-pressures it; there is no runtime derivation fallback.
func LedgerLookup(fp string) (LedgerEntry, bool) {
	if e, ok := stmtLedger[fp]; ok {
		return e, true
	}
	e, ok := historicalLedger[fp]
	return e, ok
}

// CurrentLedgerHas reports whether a fingerprint is in the CURRENT-build ledger only (not the
// historical ledger). The historical generator uses this to decide whether a candidate shape
// is historical-only — LedgerLookup would report every already-generated historical entry as
// present and yield an empty regeneration.
func CurrentLedgerHas(fp string) bool {
	_, ok := stmtLedger[fp]
	return ok
}

// stmtLedger is populated in stmtledger_entries.go (generated from the builders via
// `stmtshapecheck -report`, then annotated). Kept in a separate file so the entry list can
// be regenerated without touching this logic.

// relayStatement reports whether a committed statement should be written to
// mutation_log, i.e. replayed by every peer.
//
// Everything is relayed except ONE case: a create-only statement that changed
// no row here. `changed` is that statement's own RowsAffected from the
// transaction that just committed.
//
// Why that case is different. mutation_log carries statements, not rows, so a
// peer REPLAYS what it is given. An INSERT OR IGNORE that matched an existing
// primary key was rejected locally — the row already here won — and relaying it
// asks every peer to apply content this node just declined. A peer that has not
// yet received the genuine row applies the relayed one, and then INSERT OR
// IGNORE drops the genuine row on the primary key when it does arrive. The two
// nodes now disagree permanently, because DispAppendOnly means exactly that
// there is no LWW rule to heal them.
//
// That is the hole a caller could drive with a forged, caller-supplied id: the
// local write is safely a no-op and looks refused, while the forgery replicates.
// It is reachable from ~50 INSERT OR IGNORE sites, several of them audit tables.
//
// Suppressing the relay is safe because a row that exists locally got here by a
// path that already replicates — its own mutation_log entry, or a merge from the
// peer that created it — and anti-entropy is the backstop for any gap. The
// statement being dropped would add nothing a converged cluster does not have.
//
// Scoped deliberately to create-only shapes. A zero-row UPDATE or DELETE is
// still relayed: those dispositions are LWW-gated or per-category, so the
// receiver decides for itself, and the row the statement targets may be one
// this node simply does not hold. An UNCLASSIFIED shape is relayed too —
// unknown means "not known to be create-only", and silently withholding a
// statement whose semantics we cannot name is the more dangerous default.
func relayStatement(s Statement, changed bool) bool {
	if changed {
		return true
	}
	return !createOnlyStatement(s.SQL)
}

// createOnlyStatement reports whether sql's registered shape is append-only —
// INSERT OR IGNORE with no LWW rule.
//
// DispositionAfter counts as well as Disposition. A capability-gated shape
// reads DispReject until its token is active and its real disposition after, so
// consulting only the first field would miss the append-only shapes during
// exactly the rollout window when peers are most likely to be missing rows.
func createOnlyStatement(sql string) bool {
	fp, err := FingerprintSQL(sql)
	if err != nil {
		return false
	}
	e, ok := LedgerLookup(fp)
	if !ok {
		return false
	}
	return e.Disposition == DispAppendOnly || e.DispositionAfter == DispAppendOnly
}
