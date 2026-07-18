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
)

// ConcurrencyCategory qualifies a DispBulkUpdate entry (see Part C). Empty for non-bulk.
type ConcurrencyCategory string

const (
	CatNone        ConcurrencyCategory = ""
	CatMonotonic   ConcurrencyCategory = "monotonic"   // verbatim apply provably safe
	CatPerRowLWW   ConcurrencyCategory = "per_row_lww" // receiver-side per-row LWW expansion
	CatUnsupported ConcurrencyCategory = "unsupported" // back-pressure; builder must be row-scoped
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

// PolicyLookup returns a dynamic-SQL policy's finite set of allowed expansion fingerprints.
// A genuinely runtime-built statement (whose SQL text is not a compile-time constant) is
// authorized only via a policy: the builder's call site carries a //stmtshape:policy <id>
// directive, the CI guard confirms the policy is registered, and at apply time the concrete
// statement's fingerprint must be one of the policy's expansions (each of which is also a
// ledger entry). Populated in stmtledger_entries.go alongside the ledger.
func PolicyLookup(id string) ([]string, bool) {
	fps, ok := stmtPolicies[id]
	return fps, ok
}

// stmtLedger is populated in stmtledger_entries.go (generated from the builders via
// `stmtshapecheck -report`, then annotated). Kept in a separate file so the entry list can
// be regenerated without touching this logic.
