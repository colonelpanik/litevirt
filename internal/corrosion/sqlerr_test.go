package corrosion

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestClassifySQLiteError(t *testing.T) {
	db, err := openMem(t, "sqlerrtest")
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
		// a wrapped constraint error must still classify via errors.As
		{"wrapped-unique", fmt.Errorf("apply row: %w", trigger(`INSERT INTO t (id, u, nn, ck) VALUES (6, 'a', 'z', 0)`)), classConstraint, constraintUnique},
		// a generic SQLite error (SQLITE_ERROR, e.g. no such table) is NOT a row constraint
		{"generic-sqlite", trigger(`INSERT INTO nope (x) VALUES (1)`), classOther, constraintNone},
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

// TestClassifySQLiteError_Operational triggers a real SQLITE_BUSY by holding a write
// transaction on one file-DB handle while a second, independent handle (busy_timeout 0)
// tries to write, and confirms it classifies as operational (never a keep-local rejection).
// Two SEPARATE *sql.DB handles on a temp file are used (not a shared in-memory cache, which
// deadlocks the driver's internal mutex), and the contended write runs in a goroutine gated
// by a select-timeout so it can never hang the suite regardless of driver behavior.
func TestClassifySQLiteError_Operational(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "busy.db")
	holder, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	defer holder.Close()
	contender, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open contender: %v", err)
	}
	// NOTE: no deferred Close on the contender — if the contended write blocks in the
	// driver (platform-dependent), Close would wait on it; we leak it and Skip instead.
	if _, err := holder.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := contender.Exec(`PRAGMA busy_timeout=0`); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	// Hold a write lock on the holder handle.
	tx, err := holder.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO t (id, v) VALUES (1, 'held')`); err != nil {
		t.Fatalf("acquire write lock: %v", err)
	}

	ch := make(chan error, 1)
	go func() {
		_, e := contender.Exec(`INSERT INTO t (id, v) VALUES (2, 'x')`)
		ch <- e
	}()
	select {
	case busyErr := <-ch:
		if busyErr == nil {
			t.Skip("could not induce a BUSY condition on this platform")
		}
		if cls, _ := classifySQLiteError(busyErr); cls != classOperational {
			t.Fatalf("classify(%v) = %v, want classOperational", busyErr, cls)
		}
		contender.Close()
	case <-time.After(5 * time.Second):
		t.Skip("contended write blocked instead of returning BUSY on this platform")
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
