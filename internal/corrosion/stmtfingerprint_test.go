package corrosion

import (
	"strings"
	"testing"
)

// TestStmtCanon_GoldenVectors BYTE-FREEZES the canonical pre-hash encoding across the
// syntax that matters most for compatibility: plain/OR REPLACE inserts, UPDATE with a
// guard, DELETE, full-image and DO NOTHING and WHERE-guarded upserts, a nested predicate,
// and a mixed literal/parameter insert. If any of these strings must change, the
// fingerprint tag MUST bump to stmtshape/v2 (a silent v1 change would reject older
// binaries' in-flight statements matched against the ledger).
func TestStmtCanon_GoldenVectors(t *testing.T) {
	cases := []struct {
		sql   string
		pk    []string
		canon string
	}{
		{
			"INSERT INTO vms (name, host_name, state, updated_at) VALUES (?, ?, ?, ?)", []string{"name"},
			"k=6:insert;t=3:vms;algo=0:;cols=31:name,host_name,state,updated_at;vals=7:?,?,?,?;conflict=4:none;",
		},
		{
			"INSERT OR REPLACE INTO storage_pools (host_name, name, driver, updated_at, deleted_at) VALUES (?, ?, ?, ?, NULL)", []string{"host_name", "name"},
			"k=6:insert;t=13:storage_pools;algo=10:OR REPLACE;cols=43:host_name,name,driver,updated_at,deleted_at;vals=12:?,?,?,?,NULL;conflict=4:none;",
		},
		{
			"UPDATE vms SET state = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL", []string{"name"},
			"k=6:update;t=3:vms;set=32:5:state=2:p;;10:updated_at=2:p;;;where=55:AND[14:L10:d4:name=p;30:L26:d10:deleted_atd2:isd4:null];",
		},
		{
			"DELETE FROM vm_events WHERE id = ?", []string{"id"},
			"k=6:delete;t=9:vm_events;where=11:L8:d2:id=p;;",
		},
		{ // full-image upsert
			"INSERT INTO t (id, a, b) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET a=excluded.a, b=excluded.b", []string{"id"},
			"k=6:insert;t=1:t;algo=0:;cols=6:id,a,b;vals=5:?,?,?;conflict=85:targets=id;do=update;set=48:1:a=16:d8:excluded.d1:a;1:b=16:d8:excluded.d1:b;;where=0:;",
		},
		{ // DO NOTHING
			"INSERT INTO seen (id) VALUES (?) ON CONFLICT(id) DO NOTHING", []string{"id"},
			"k=6:insert;t=4:seen;algo=0:;cols=2:id;vals=1:?;conflict=30:targets=id;do=nothing;where=0:;",
		},
		{ // WHERE-guarded, transformed-then-copied upsert
			"INSERT INTO ip_allocations (network, ip, vm_name, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(network, ip) DO UPDATE SET vm_name=excluded.vm_name, updated_at=excluded.updated_at WHERE ip_allocations.deleted_at IS NOT NULL", []string{"network", "ip"},
			"k=6:insert;t=14:ip_allocations;algo=0:;cols=29:network,ip,vm_name,updated_at;vals=7:?,?,?,?;conflict=181:targets=network,ip;do=update;set=80:7:vm_name=22:d8:excluded.d7:vm_name;10:updated_at=26:d8:excluded.d10:updated_at;;where=55:L51:d14:ip_allocations.d10:deleted_atd2:isd3:notd4:null;",
		},
		{ // nested predicate (OR group under a top-level AND)
			"UPDATE t SET a = ? WHERE (b = ? OR c = ?) AND id = ?", []string{"id"},
			"k=6:update;t=1:t;set=9:1:a=2:p;;;where=52:AND[30:OR[10:L7:d1:b=p;10:L7:d1:c=p;]11:L8:d2:id=p;];",
		},
		{ // mixed literal / parameter INSERT
			"INSERT INTO t (a, b) VALUES (?, 0)", []string{"a"},
			"k=6:insert;t=1:t;algo=0:;cols=3:a,b;vals=4:?,i0;conflict=4:none;",
		},
	}
	for _, c := range cases {
		sh, err := parseStmtShape(c.sql, c.pk)
		if err != nil {
			t.Fatalf("parse %q: %v", c.sql, err)
		}
		if got := stmtCanonical(sh); got != c.canon {
			t.Fatalf("canonical drift for %q:\n got %q\nwant %q", c.sql, got, c.canon)
		}
		if fp := stmtFingerprint(sh); !strings.HasPrefix(fp, "stmtshape/v1:") || len(fp) != len("stmtshape/v1:")+64 {
			t.Fatalf("fingerprint shape wrong: %q", fp)
		}
	}
}

// TestStmtFingerprint_Distinctness proves the fingerprint keys on the full statement, not a
// sorted column set, and — critically — that it does not collide ACROSS token types.
func TestStmtFingerprint_Distinctness(t *testing.T) {
	fp := func(sql string, pk []string) string {
		sh, err := parseStmtShape(sql, pk)
		if err != nil {
			t.Fatalf("parse %q: %v", sql, err)
		}
		return stmtFingerprint(sh)
	}
	pairs := [][2]string{
		// REGRESSION (review finding 1): an integer literal 1 vs an identifier named i1 in a
		// SET RHS must NOT share a fingerprint.
		{"UPDATE t SET a = 1 WHERE id = ?", "UPDATE t SET a = i1 WHERE id = ?"},
		// same columns, different SET expressions (literal NULL vs bound param)
		{"UPDATE lb_backends SET deleted_at = NULL, updated_at = ? WHERE lb_name = ? AND name = ?",
			"UPDATE lb_backends SET deleted_at = ?, updated_at = ? WHERE lb_name = ? AND name = ?"},
		// same INSERT columns, different literal values
		{"INSERT INTO t (a, b) VALUES (?, 0)", "INSERT INTO t (a, b) VALUES (?, 1)"},
		// literal string vs literal string, different content
		{"INSERT INTO t (a, b) VALUES (?, '')", "INSERT INTO t (a, b) VALUES (?, 'deleted')"},
		// int literal vs string literal of the same digits
		{"INSERT INTO t (a, b) VALUES (?, 1)", "INSERT INTO t (a, b) VALUES (?, '1')"},
		// different predicate operators
		{"DELETE FROM t WHERE a = ?", "DELETE FROM t WHERE a < ?"},
	}
	for i, p := range pairs {
		if fp(p[0], []string{"a"}) == fp(p[1], []string{"a"}) {
			t.Fatalf("pair %d collided: %q vs %q", i, p[0], p[1])
		}
	}
	// review 5d: conflict-shape + placeholder-position distinctness (evaluated with pk=id).
	confPairs := [][2]string{
		// changed placeholder position (the ? moves between cells; a literal takes the other)
		{"INSERT INTO t (a, b) VALUES (?, 0)", "INSERT INTO t (a, b) VALUES (0, ?)"},
		// DO NOTHING vs DO UPDATE (same conflict target)
		{"INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO NOTHING",
			"INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET a=excluded.a"},
		// different conflict TARGET
		{"INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO NOTHING",
			"INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(a) DO NOTHING"},
		// different conflict ASSIGNMENT (which column DO UPDATE sets)
		{"INSERT INTO t (id, a, b) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET a=excluded.a",
			"INSERT INTO t (id, a, b) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET b=excluded.b"},
	}
	for i, p := range confPairs {
		if fp(p[0], []string{"id"}) == fp(p[1], []string{"id"}) {
			t.Fatalf("conflict pair %d collided: %q vs %q", i, p[0], p[1])
		}
	}
	// Identifier case is normalized (case-insensitive) ⇒ same fingerprint.
	if fp("INSERT INTO T (A, B) VALUES (?, ?)", []string{"a"}) != fp("insert into t (a, b) values (?, ?)", []string{"a"}) {
		t.Fatal("identifier case should normalize to the same fingerprint")
	}
}

// TestStmtFingerprint_WhitespaceAndCommentNormalization proves the fingerprint is a function
// of structure, not formatting: extra whitespace and comments must not change it.
func TestStmtFingerprint_WhitespaceAndCommentNormalization(t *testing.T) {
	fp := func(sql string) string {
		sh, err := parseStmtShape(sql, []string{"id"})
		if err != nil {
			t.Fatalf("parse %q: %v", sql, err)
		}
		return stmtFingerprint(sh)
	}
	base := "UPDATE t SET a = ?, b = ? WHERE id = ? AND deleted_at IS NULL"
	variants := []string{
		"UPDATE   t   SET a=?,b=?   WHERE id=? AND deleted_at IS NULL",
		"UPDATE t SET a = ? , b = ? WHERE id = ? AND deleted_at IS NULL -- trailing comment\n",
		"UPDATE t /* c */ SET a = ?, b = ? WHERE id = ? AND deleted_at IS NULL",
		"update T set A = ?, B = ? where ID = ? and DELETED_AT is null",
	}
	want := fp(base)
	for _, v := range variants {
		if got := fp(v); got != want {
			t.Fatalf("formatting changed fingerprint:\n base %q\n var  %q", base, v)
		}
	}
}
