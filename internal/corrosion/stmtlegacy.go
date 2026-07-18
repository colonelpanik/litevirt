package corrosion

import (
	"context"
	"database/sql"
	"strings"
)

// Legacy mutation transformers: a BOUNDED, exact-match allowlist for the handful of statement
// shapes a supported PRIOR release emits that the current strict parser deliberately rejects
// (receiver-evaluated expressions like datetime('now'), unmodelled predicates like the tsMs
// CASE). Without them, a v1.3.0 peer's crl_versions or spent-proof-GC WAL mutation would
// parse-error on an upgraded node and back-pressure that peer's whole stream during a rolling
// upgrade. Each transformer matches ONE exact historical statement, validates its arity and
// identity, and normalizes it into the CURRENT safe apply — it never executes the legacy SQL
// verbatim when that SQL is non-deterministic (datetime('now')).
//
// The match is on the WHITESPACE-NORMALIZED statement: SQL whitespace is not semantic, so this
// is exact for statement identity while being robust to source-formatting of the byte-frozen
// original.
//
// HORIZON: these exist ONLY for the v1.3.0 → next upgrade + WAL-retention window and MUST be
// removed once v1.3.0 is no longer a supported peer (tracked by legacyTransformerHorizon).
const legacyTransformerHorizon = "v1.3.0" // remove these transformers once this release is no longer a supported peer

// legacyTransformer normalizes one exact historical statement the strict parser can't accept.
type legacyTransformer struct {
	id      string   // stable metric label (litevirt_legacy_mutation_transformed_total{transformer})
	table   string   // expected target table (defense-in-depth against a key collision)
	kind    StmtKind // expected statement kind
	nParams int      // expected bound-parameter arity
	apply   func(r *Replicator, ctx context.Context, tx *sql.Tx, s Statement, incomingHLC string) error
}

// normalizeLegacyWS collapses every run of whitespace to a single space and trims, giving a
// canonical form for exact statement-identity matching that is insensitive to source layout.
func normalizeLegacyWS(sql string) string {
	return strings.Join(strings.Fields(sql), " ")
}

// legacyCRLVersionsKey is v1.3.0's crl_versions writer: an INSERT OR REPLACE stamping
// updated_at with the receiver-evaluated datetime('now') (rejected by the parser, and
// non-deterministic across nodes). Two bound params: host, version.
var legacyCRLVersionsKey = normalizeLegacyWS(
	`INSERT OR REPLACE INTO crl_versions (host, version, updated_at) VALUES (?, ?, datetime('now'))`)

// legacyGCReapKey is v1.3.0's spent-proof GC: a bulk tombstone on runtime_action_proofs whose
// WHERE carries the tsMs CASE age expression (unmodelled by the parser). Three bound params:
// deleted_at (wall), updated_at (LWW clock), age cutoff (ms).
var legacyGCReapKey = normalizeLegacyWS(
	`UPDATE runtime_action_proofs SET deleted_at = ?, updated_at = ? ` +
		`WHERE deleted_at IS NULL AND status IN ('completed','failed') AND ` + tsMsSQL("updated_at") + ` < ?`)

var legacyTransformers = map[string]legacyTransformer{
	legacyCRLVersionsKey: {
		id: "crl_versions_datetime_now", table: "crl_versions", kind: KindInsert, nParams: 2,
		apply: (*Replicator).applyLegacyCRLVersions,
	},
	legacyGCReapKey: {
		id: "gc_spent_proof_tsms", table: "runtime_action_proofs", kind: KindUpdate, nParams: 3,
		apply: (*Replicator).applyLegacyGCReap,
	},
}

// legacyTransformerFor returns the transformer for a statement, if it is a registered legacy
// shape. Matched by whitespace-normalized identity.
func legacyTransformerFor(sql string) (legacyTransformer, bool) {
	lt, ok := legacyTransformers[normalizeLegacyWS(sql)]
	return lt, ok
}

// applyLegacy validates arity, runs the transformer, and records the bounded metric.
func (r *Replicator) applyLegacy(ctx context.Context, tx *sql.Tx, lt legacyTransformer, s Statement, incomingHLC string) error {
	if len(s.Params) != lt.nParams {
		return invalidf("legacy %s: parameter arity mismatch (want %d, got %d)", lt.id, lt.nParams, len(s.Params))
	}
	if err := lt.apply(r, ctx, tx, s, incomingHLC); err != nil {
		return err
	}
	r.client.observeLegacyTransformed(lt.id)
	return nil
}

// applyLegacyCRLVersions normalizes v1.3.0's datetime('now') crl_versions write into the
// current bound-timestamp, PK-aware LWW upsert: it binds the mutation's own HLC as updated_at
// (deterministic across nodes, unlike a receiver-evaluated clock) and applies through the same
// LWW-gated insert path as the current builder. Params: host, version.
func (r *Replicator) applyLegacyCRLVersions(ctx context.Context, tx *sql.Tx, s Statement, incomingHLC string) error {
	if coerceString(s.Params[0]) == "" {
		return invalidf("legacy crl_versions: empty host primary key")
	}
	pkCols := tablePrimaryKeys["crl_versions"]
	ns := Statement{
		SQL:    "INSERT INTO crl_versions (host, version, updated_at) VALUES (?, ?, ?)",
		Params: []interface{}{s.Params[0], s.Params[1], incomingHLC},
	}
	sh, err := parseStmtShape(ns.SQL, pkCols)
	if err != nil {
		return err
	}
	return r.applyLWWGated(ctx, tx, ns, sh, "crl_versions", pkCols, incomingHLC)
}

// applyLegacyGCReap applies v1.3.0's spent-proof tombstone through the custom-merge path for
// runtime_action_proofs: the statement is executed verbatim (its WHERE — status IN the terminal
// set, plus deleted_at IS NULL and the age cutoff — keeps it monotone, and SQLite evaluates the
// tsMs CASE natively; only the structural parser can't model it). Params: deleted_at (wall),
// updated_at (LWW clock), age cutoff.
func (r *Replicator) applyLegacyGCReap(ctx context.Context, tx *sql.Tx, s Statement, incomingHLC string) error {
	res, err := tx.ExecContext(ctx, s.SQL, s.Params...)
	if err == nil && rowsChanged(res) {
		r.client.clearUnresolvedFromStmt(s)
	}
	return err
}
