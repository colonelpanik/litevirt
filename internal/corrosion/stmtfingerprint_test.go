package corrosion

import (
	"strings"
	"testing"
)

// TestStmtCanon_GoldenVectors BYTE-FREEZES the canonical pre-hash encoding. If any of
// these strings must change, the fingerprint tag MUST bump to stmtshape/v2 (a silent v1
// change would reject older binaries' in-flight statements matched against the ledger).
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
			"INSERT OR REPLACE INTO storage_pools (host_name, name, updated_at, deleted_at) VALUES (?, ?, ?, NULL)", []string{"host_name", "name"},
			"k=6:insert;t=13:storage_pools;algo=10:OR REPLACE;cols=36:host_name,name,updated_at,deleted_at;vals=10:?,?,?,NULL;conflict=4:none;",
		},
		{
			"UPDATE vms SET state = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL", []string{"name"},
			"k=6:update;t=3:vms;set=30:5:state=1:?;10:updated_at=1:?;;where=44:AND[11:L8:name = ?22:L18:deleted_at is null];",
		},
		{
			"DELETE FROM vm_events WHERE id = ?", []string{"id"},
			"k=6:delete;t=9:vm_events;where=9:L6:id = ?;",
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

// TestStmtFingerprint_Distinctness proves the fingerprint keys on the full statement, not
// a sorted column set: statements differing only in a SET expression / literal value /
// placeholder position / predicate must not collide.
func TestStmtFingerprint_Distinctness(t *testing.T) {
	fp := func(sql string, pk []string) string {
		sh, err := parseStmtShape(sql, pk)
		if err != nil {
			t.Fatalf("parse %q: %v", sql, err)
		}
		return stmtFingerprint(sh)
	}
	pairs := [][2]string{
		// same columns, different SET expressions (literal NULL vs bound param)
		{"UPDATE lb_backends SET deleted_at = NULL, updated_at = ? WHERE lb_name = ? AND name = ?",
			"UPDATE lb_backends SET deleted_at = ?, updated_at = ? WHERE lb_name = ? AND name = ?"},
		// same INSERT columns, different literal values
		{"INSERT INTO t (a, b) VALUES (?, 0)", "INSERT INTO t (a, b) VALUES (?, 1)"},
		// literal string vs literal string, different content
		{"INSERT INTO t (a, b) VALUES (?, '')", "INSERT INTO t (a, b) VALUES (?, 'deleted')"},
		// different predicate operators
		{"DELETE FROM t WHERE a = ?", "DELETE FROM t WHERE a < ?"},
	}
	for i, p := range pairs {
		if fp(p[0], []string{"a"}) == fp(p[1], []string{"a"}) {
			t.Fatalf("pair %d collided: %q vs %q", i, p[0], p[1])
		}
	}
	// Identifier case is normalized (case-insensitive) ⇒ same fingerprint.
	if fp("INSERT INTO T (A, B) VALUES (?, ?)", []string{"a"}) != fp("insert into t (a, b) values (?, ?)", []string{"a"}) {
		t.Fatal("identifier case should normalize to the same fingerprint")
	}
}
