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
	DispPlainInsert     Disposition = "plain_insert"     // rewrite to a PK-aware upsert
	DispExplicitUpsert  Disposition = "explicit_upsert"  // apply verbatim (leading algo normalized)
	DispFullPKUpdate    Disposition = "full_pk_update"   // LWW-gate by updated_at, guards retained
	DispBulkUpdate      Disposition = "bulk_update"      // apply per ConcurrencyCategory
	DispDeleteRetention Disposition = "delete_retention" // hard delete on a registered retention table
	DispAppendOnly      Disposition = "append_only"      // INSERT OR IGNORE, no LWW
	DispCustomMerge     Disposition = "custom_merge"     // runtime_action_proofs / operations / …
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
}

// LedgerLookup returns the entry for a fingerprint, if registered.
func LedgerLookup(fp string) (LedgerEntry, bool) {
	e, ok := stmtLedger[fp]
	return e, ok
}

// stmtLedger is populated in stmtledger_entries.go (generated from the builders via
// `stmtshapecheck -report`, then annotated). Kept in a separate file so the entry list can
// be regenerated without touching this logic.
