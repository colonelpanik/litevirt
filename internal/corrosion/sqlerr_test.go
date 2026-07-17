package corrosion

import (
	"database/sql"
	"errors"
	"testing"
)

func TestClassifySQLiteError(t *testing.T) {
	db, err := sql.Open("sqlite", "file:sqlerrtest?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("pragma: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE parent (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t (
		id INTEGER PRIMARY KEY,
		u  TEXT UNIQUE,
		nn TEXT NOT NULL,
		ck INTEGER CHECK (ck >= 0),
		fk INTEGER REFERENCES parent(id)
	)`); err != nil {
		t.Fatalf("create t: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t (id, u, nn, ck, fk) VALUES (1, 'a', 'x', 0, NULL)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	trigger := func(sql string, args ...interface{}) error {
		_, err := db.Exec(sql, args...)
		if err == nil {
			t.Fatalf("expected error from %q", sql)
		}
		return err
	}

	cases := []struct {
		name string
		err  error
		cls  sqliteClass
		kind constraintKind
	}{
		{"unique", trigger(`INSERT INTO t (id, u, nn, ck) VALUES (2, 'a', 'y', 0)`), classConstraint, constraintUnique},
		{"primary_key", trigger(`INSERT INTO t (id, u, nn, ck) VALUES (1, 'b', 'y', 0)`), classConstraint, constraintPrimaryKey},
		{"not_null", trigger(`INSERT INTO t (id, u, nn, ck) VALUES (3, 'c', NULL, 0)`), classConstraint, constraintNotNull},
		{"check", trigger(`INSERT INTO t (id, u, nn, ck) VALUES (4, 'd', 'y', -1)`), classConstraint, constraintCheck},
		{"foreign_key", trigger(`INSERT INTO t (id, u, nn, ck, fk) VALUES (5, 'e', 'y', 0, 999)`), classConstraint, constraintForeignKey},
		{"non-sqlite", errors.New("boom"), classOther, constraintNone},
		{"nil", nil, classOther, constraintNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cls, kind := classifySQLiteError(c.err)
			if cls != c.cls || kind != c.kind {
				t.Fatalf("classify(%v) = (%v,%q), want (%v,%q)", c.err, cls, kind, c.cls, c.kind)
			}
		})
	}
}

// FuzzParseStmtShape asserts the parser is a safe boundary: it never panics on arbitrary
// input, is deterministic, and produces a stable fingerprint for anything it accepts.
func FuzzParseStmtShape(f *testing.F) {
	seeds := []string{
		"INSERT INTO t (a, b) VALUES (?, ?)",
		"INSERT OR REPLACE INTO t (a) VALUES (?) ON CONFLICT(a) DO UPDATE SET a=excluded.a",
		"UPDATE t SET a = ?, b = coalesce(nullif(?,''), b) WHERE id = ? AND deleted_at IS NULL",
		"DELETE FROM t WHERE id = ?",
		"INSERT INTO t (a) VALUES (datetime('now'))",
		"INSERT INTO t (a) VALUES ('x;y') -- c\n",
		"UPDATE t SET a = ? WHERE (b = ? OR c = ?) AND d = ?",
		"weird ( ) '' /* */ ?; ; ;",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sql string) {
		sh1, err1 := parseStmtShape(sql, []string{"id"})
		sh2, err2 := parseStmtShape(sql, []string{"id"}) // determinism
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("nondeterministic parse ok-ness for %q", sql)
		}
		if err1 != nil {
			return
		}
		if stmtCanonical(sh1) != stmtCanonical(sh2) {
			t.Fatalf("nondeterministic canonical for %q", sql)
		}
		if stmtFingerprint(sh1) != stmtFingerprint(sh2) {
			t.Fatalf("nondeterministic fingerprint for %q", sql)
		}
	})
}
