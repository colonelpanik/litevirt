package corrosion

import (
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

// oracleDBSeq gives each fuzz iteration a distinct in-memory DB name so shared-cache instances
// don't bleed state across iterations.
var oracleDBSeq atomic.Int64

// Gap 1 — execution oracle for the parser's safety-critical claims.
//
// The structural parser is the replication security boundary: the apply path trusts its
// StmtShape claims (HasFullPKIdentity ⇒ single-row LWW-gateable; ConflictClause.IsFullImage ⇒
// the upsert copies exactly the supplied row image) to decide whether a statement is safe to
// LWW-gate or to resolve a tie over. FuzzParseStmtShape only proves the parser is deterministic
// and never panics — it never checks those claims are TRUE against SQLite's actual execution
// semantics. A parseable-but-mis-classified statement (parser says single-row when the
// predicate matches many; says full-image when a column is dropped) would sail through.
//
// These tests execute statements against a real in-memory SQLite and assert the parser's claim
// matches observed behaviour. They are a standing guard against a future parser change that
// silently widens what HasFullPKIdentity / IsFullImage accept.

const oracleSchema = `
CREATE TABLE t (
	k1 TEXT NOT NULL,
	k2 TEXT NOT NULL,
	a  TEXT,
	b  TEXT,
	note TEXT,               -- receiver-only: never in a replicated insert's column list
	updated_at TEXT,
	deleted_at TEXT,
	PRIMARY KEY (k1, k2)
);`

// seedOracleRows inserts four rows over the composite PK, all sharing the non-key sentinel
// 'm' in a/b/note so that a predicate which does NOT truly pin the full PK will match more than
// one row when its spare parameters are bound to 'm'.
func seedOracleRows(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, k := range [][2]string{{"A", "1"}, {"A", "2"}, {"B", "1"}, {"B", "2"}} {
		if _, err := db.Exec(
			`INSERT INTO t (k1, k2, a, b, note, updated_at, deleted_at) VALUES (?, ?, 'm', 'm', 'm', '100', NULL)`,
			k[0], k[1]); err != nil {
			t.Fatalf("seed (%s,%s): %v", k[0], k[1], err)
		}
	}
}

func openOracleDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := openMem(t, fmt.Sprintf("oracle_%s", strings.ReplaceAll(t.Name(), "/", "_")))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(oracleSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

func rowsAffected(t *testing.T, res sql.Result) int64 {
	t.Helper()
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("RowsAffected: %v", err)
	}
	return n
}

// TestApplyOracle_FullPKIdentityIsSingleRow drives representative UPDATE/DELETE statements
// through SQLite and asserts the parser's HasFullPKIdentity claim matches reality: a claimed
// full-PK statement affects at most one row; a claimed bulk statement is genuinely able to
// affect more than one (so it is correctly kept off the single-row LWW path).
func TestApplyOracle_FullPKIdentityIsSingleRow(t *testing.T) {
	pk := []string{"k1", "k2"}
	cases := []struct {
		name        string
		sql         string
		params      []any // bound so the PK conjuncts pin row (A,1); spare params are 'm'
		wantFullPK  bool
		wantMaxRows int64
	}{
		{
			name:        "full-PK update with soft-delete guard",
			sql:         `UPDATE t SET a = ?, updated_at = ? WHERE k1 = ? AND k2 = ? AND deleted_at IS NULL`,
			params:      []any{"z", "200", "A", "1"},
			wantFullPK:  true,
			wantMaxRows: 1,
		},
		{
			name:        "full-PK delete",
			sql:         `DELETE FROM t WHERE k1 = ? AND k2 = ?`,
			params:      []any{"A", "1"},
			wantFullPK:  true,
			wantMaxRows: 1,
		},
		{
			// Partial PK (only k1): NOT single-row. Bound to 'A' it matches two rows — proving
			// the parser must NOT classify it as full-PK (it would LWW-gate two rows as one).
			name:        "partial-PK update is bulk",
			sql:         `UPDATE t SET a = ?, updated_at = ? WHERE k1 = ?`,
			params:      []any{"z", "200", "A"},
			wantFullPK:  false,
			wantMaxRows: 2,
		},
		{
			// A disjunction is not a set of AND conjuncts: must be bulk. Bound so both arms hit
			// different rows.
			name:        "disjunction is bulk",
			sql:         `UPDATE t SET a = ?, updated_at = ? WHERE k1 = ? OR b = ?`,
			params:      []any{"z", "200", "A", "m"},
			wantFullPK:  false,
			wantMaxRows: 4,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sh, err := parseStmtShape(tc.sql, pk)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if sh.HasFullPKIdentity != tc.wantFullPK {
				t.Fatalf("HasFullPKIdentity = %v, want %v", sh.HasFullPKIdentity, tc.wantFullPK)
			}
			db := openOracleDB(t)
			seedOracleRows(t, db)
			res, err := db.Exec(tc.sql, tc.params...)
			if err != nil {
				t.Fatalf("exec: %v", err)
			}
			got := rowsAffected(t, res)
			if tc.wantFullPK && got > 1 {
				t.Fatalf("parser claims full-PK single-row but SQLite affected %d rows: %q", got, tc.sql)
			}
			if got != tc.wantMaxRows {
				t.Fatalf("affected %d rows, want %d: %q", got, tc.wantMaxRows, tc.sql)
			}
		})
	}
}

// TestApplyOracle_FullImageUpsertCopiesExactly asserts the ConflictClause.IsFullImage claim
// against execution: applying a full-image upsert onto a pre-existing conflicting row sets
// every supplied non-PK column to the incoming value AND leaves the receiver-only column
// (`note`, absent from the insert list) untouched. A partial upsert must NOT be full-image.
func TestApplyOracle_FullImageUpsertCopiesExactly(t *testing.T) {
	pk := []string{"k1", "k2"}

	full := `INSERT INTO t (k1, k2, a, b, updated_at) VALUES (?, ?, ?, ?, ?) ` +
		`ON CONFLICT(k1, k2) DO UPDATE SET a = excluded.a, b = excluded.b, updated_at = excluded.updated_at`
	sh, err := parseStmtShape(full, pk)
	if err != nil {
		t.Fatalf("parse full: %v", err)
	}
	if sh.OnConflict == nil || !sh.OnConflict.IsFullImage {
		t.Fatalf("expected IsFullImage upsert, got OnConflict=%+v", sh.OnConflict)
	}
	db := openOracleDB(t)
	seedOracleRows(t, db) // (A,1) exists with a=b=note='m'
	if _, err := db.Exec(full, "A", "1", "newA", "newB", "300"); err != nil {
		t.Fatalf("apply full upsert: %v", err)
	}
	var a, b, note, updatedAt string
	if err := db.QueryRow(`SELECT a, b, note, updated_at FROM t WHERE k1='A' AND k2='1'`).
		Scan(&a, &b, &note, &updatedAt); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if a != "newA" || b != "newB" || updatedAt != "300" {
		t.Fatalf("full-image upsert did not copy the supplied image: a=%q b=%q updated_at=%q", a, b, updatedAt)
	}
	if note != "m" {
		t.Fatalf("full-image upsert clobbered the receiver-only column note=%q, want preserved 'm'", note)
	}

	// A partial upsert (omits b from DO UPDATE) is NOT full-image: a tie must keep local, not
	// synthesize a row from a claimed-complete image.
	partial := `INSERT INTO t (k1, k2, a, b, updated_at) VALUES (?, ?, ?, ?, ?) ` +
		`ON CONFLICT(k1, k2) DO UPDATE SET a = excluded.a, updated_at = excluded.updated_at`
	psh, err := parseStmtShape(partial, pk)
	if err != nil {
		t.Fatalf("parse partial: %v", err)
	}
	if psh.OnConflict == nil || psh.OnConflict.IsFullImage {
		t.Fatalf("partial upsert wrongly classified IsFullImage=%v", psh.OnConflict.IsFullImage)
	}
}

// FuzzApplyOracle_FullPKImpliesSingleRow explores the WHERE-predicate space and asserts the
// core invariant holds for every parseable statement the parser accepts as full-PK: SQLite
// affects at most one row. The PK conjuncts are bound (via PKParamIdx) to an existing row and
// every spare parameter to the sentinel 'm' present in all four rows' non-key columns — so a
// predicate the parser mis-accepts as full-PK reveals itself by matching more than one row.
func FuzzApplyOracle_FullPKImpliesSingleRow(f *testing.F) {
	for _, w := range []string{
		"k1 = ? AND k2 = ?",
		"k1 = ? AND k2 = ? AND deleted_at IS NULL",
		"k1 = ?",
		"k1 = ? OR k2 = ?",
		"(k1 = ? AND k2 = ?) OR b = ?",
		"k1 = ? AND (k2 = ? OR a = ?)",
		"NOT (k1 = ? AND k2 = ?)",
		"b = ?",
	} {
		f.Add(w)
	}
	pk := []string{"k1", "k2"}
	f.Fuzz(func(t *testing.T, where string) {
		for _, verb := range []string{
			"UPDATE t SET a = ?, updated_at = ? WHERE ",
			"DELETE FROM t WHERE ",
		} {
			sql := verb + where
			sh, err := parseStmtShape(sql, pk)
			if err != nil {
				continue // unparseable ⇒ fail-closed upstream; not this invariant's concern
			}
			if !sh.HasFullPKIdentity {
				continue // only the positive single-row claim is safety-critical here
			}
			if len(sh.PKParamIdx) != len(pk) {
				t.Fatalf("HasFullPKIdentity but PKParamIdx=%v for %q", sh.PKParamIdx, sql)
			}

			db, err := openMem(t, fmt.Sprintf("fuzzpk_%d", oracleDBSeq.Add(1)))
			if err != nil {
				return // a transient open failure is not a counterexample
			}
			db.SetMaxOpenConns(1) // keep the named in-memory DB alive for the whole iteration
			if _, err := db.Exec(oracleSchema); err != nil {
				db.Close()
				t.Fatalf("schema: %v", err)
			}
			seedOracleRows(t, db)
			defer db.Close()

			params := make([]any, sh.ParamCount)
			for i := range params {
				params[i] = "m" // sentinel shared by all rows' non-key columns
			}
			// Pin the PK conjuncts to the existing row (A,1). A literal-PK column has index -1.
			pinTo := []string{"A", "1"}
			for i, idx := range sh.PKParamIdx {
				if idx >= 0 && idx < len(params) {
					params[idx] = pinTo[i]
				}
			}
			res, err := db.Exec(sql, params...)
			if err != nil {
				continue // a binding that SQLite rejects is not a counterexample to the invariant
			}
			if n := rowsAffected(t, res); n > 1 {
				t.Fatalf("parser claims full-PK single-row but SQLite affected %d rows\n  sql:    %q\n  params: %v", n, sql, params)
			}
		}
	})
}
