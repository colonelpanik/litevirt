package corrosion

import (
	"database/sql"
	"errors"
	"testing"
)

// openMem opens a fresh in-memory SQLite DB (modernc driver) for a test.
func openMem(t *testing.T, name string) (*sql.DB, error) {
	t.Helper()
	return sql.Open("sqlite", "file:"+name+"?mode=memory&cache=shared")
}

func mustParse(t *testing.T, sql string, pk []string) StmtShape {
	t.Helper()
	sh, err := parseStmtShape(sql, pk)
	if err != nil {
		t.Fatalf("parseStmtShape(%q) unexpected error: %v", sql, err)
	}
	return sh
}

func mustInvalid(t *testing.T, sql string, pk []string) {
	t.Helper()
	_, err := parseStmtShape(sql, pk)
	if err == nil {
		t.Fatalf("parseStmtShape(%q) = ok, want ErrInvalidStmt", sql)
	}
	if !errors.Is(err, ErrInvalidStmt) {
		t.Fatalf("parseStmtShape(%q) error %v is not ErrInvalidStmt", sql, err)
	}
}

func TestParse_Insert_Plain(t *testing.T) {
	sh := mustParse(t, "INSERT INTO vms (name, host_name, state, updated_at) VALUES (?, ?, ?, ?)", []string{"name"})
	if sh.Kind != KindInsert || sh.Table != "vms" {
		t.Fatalf("kind/table = %v/%q", sh.Kind, sh.Table)
	}
	if sh.LeadingAlgo != "" {
		t.Fatalf("LeadingAlgo=%q", sh.LeadingAlgo)
	}
	if !sh.HasFullPKIdentity || len(sh.PKParamIdx) != 1 || sh.PKParamIdx[0] != 0 {
		t.Fatalf("pk identity=%v idx=%v", sh.HasFullPKIdentity, sh.PKParamIdx)
	}
	if sh.UpdatedAtParamIdx != 3 {
		t.Fatalf("updated_at idx=%d", sh.UpdatedAtParamIdx)
	}
}

func TestParse_Insert_OrReplace_LiteralNull_CompositePK(t *testing.T) {
	sh := mustParse(t,
		"INSERT OR REPLACE INTO storage_pools (host_name, name, driver, updated_at, deleted_at) VALUES (?, ?, ?, ?, NULL)",
		[]string{"host_name", "name"})
	if sh.LeadingAlgo != "OR REPLACE" {
		t.Fatalf("LeadingAlgo=%q", sh.LeadingAlgo)
	}
	if !sh.HasFullPKIdentity || len(sh.PKParamIdx) != 2 || sh.PKParamIdx[0] != 0 || sh.PKParamIdx[1] != 1 {
		t.Fatalf("pk idx=%v", sh.PKParamIdx)
	}
	if sh.UpdatedAtParamIdx != 3 {
		t.Fatalf("updated_at idx=%d", sh.UpdatedAtParamIdx)
	}
	last := sh.InsertVals[4]
	if last.isParam() || last.Literal.Kind != LitNull {
		t.Fatalf("last value = %+v, want literal NULL", last)
	}
}

func TestParse_Insert_OrIgnore(t *testing.T) {
	sh := mustParse(t, "INSERT OR IGNORE INTO audit_log (id, updated_at) VALUES (?, ?)", []string{"id"})
	if sh.LeadingAlgo != "OR IGNORE" {
		t.Fatalf("LeadingAlgo=%q", sh.LeadingAlgo)
	}
}

func TestParse_Upsert_FullImage(t *testing.T) {
	sh := mustParse(t,
		"INSERT INTO t (a, b, c) VALUES (?, ?, ?) ON CONFLICT(a) DO UPDATE SET b=excluded.b, c=excluded.c",
		[]string{"a"})
	if sh.OnConflict == nil || !sh.OnConflict.IsFullImage {
		t.Fatalf("expected full-image upsert, got %+v", sh.OnConflict)
	}
}

func TestParse_Upsert_PartialImage_PreservesOmittedColumn(t *testing.T) {
	// ObservePCIDevice shape: vm_name is supplied on insert but deliberately omitted from
	// DO UPDATE — must NOT be classified full-image (so a tie keeps local, not resolveTie).
	sh := mustParse(t,
		"INSERT INTO host_pci_devices (host_name, address, vm_name, vendor_id, updated_at) VALUES (?, ?, '', ?, ?) "+
			"ON CONFLICT(host_name, address) DO UPDATE SET vendor_id=excluded.vendor_id, updated_at=excluded.updated_at",
		[]string{"host_name", "address"})
	if sh.OnConflict == nil {
		t.Fatal("expected ON CONFLICT")
	}
	if sh.OnConflict.IsFullImage {
		t.Fatal("upsert omitting vm_name from DO UPDATE must NOT be full-image")
	}
}

func TestParse_Upsert_WhereGuarded_NotFullImage(t *testing.T) {
	sh := mustParse(t,
		"INSERT INTO ip_allocations (network, ip, vm_name, updated_at) VALUES (?, ?, ?, ?) "+
			"ON CONFLICT(network, ip) DO UPDATE SET vm_name=excluded.vm_name, updated_at=excluded.updated_at "+
			"WHERE ip_allocations.deleted_at IS NOT NULL",
		[]string{"network", "ip"})
	if sh.OnConflict == nil || sh.OnConflict.Where.Node == nil {
		t.Fatalf("expected a WHERE-guarded upsert, got %+v", sh.OnConflict)
	}
	if sh.OnConflict.IsFullImage {
		t.Fatal("WHERE-guarded upsert must NOT be full-image")
	}
}

func TestParse_Update_FullPK_WithDeletedAtGuard(t *testing.T) {
	sh := mustParse(t, "UPDATE vms SET state = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL", []string{"name"})
	if sh.Kind != KindUpdate {
		t.Fatalf("kind=%v", sh.Kind)
	}
	if !sh.HasFullPKIdentity || len(sh.PKParamIdx) != 1 || sh.PKParamIdx[0] != 2 {
		t.Fatalf("pk identity=%v idx=%v", sh.HasFullPKIdentity, sh.PKParamIdx)
	}
	if sh.UpdatedAtParamIdx != 1 {
		t.Fatalf("updated_at idx=%d", sh.UpdatedAtParamIdx)
	}
}

func TestParse_Update_CAS_FullPK(t *testing.T) {
	sh := mustParse(t,
		"UPDATE vms SET spec = ?, spec_generation = spec_generation + 1, active_operation_id = ?, updated_at = ? "+
			"WHERE name = ? AND active_operation_id = '' AND vm_owner_epoch = ? AND spec_generation = ?",
		[]string{"name"})
	if !sh.HasFullPKIdentity || len(sh.PKParamIdx) != 1 || sh.PKParamIdx[0] != 3 {
		t.Fatalf("pk identity=%v idx=%v (want [3])", sh.HasFullPKIdentity, sh.PKParamIdx)
	}
	if sh.UpdatedAtParamIdx != 2 {
		t.Fatalf("updated_at idx=%d (want 2)", sh.UpdatedAtParamIdx)
	}
}

func TestParse_Update_Bulk_NoFullPK(t *testing.T) {
	// vm_interfaces PK is (vm_name, network_name); this cascade keys only vm_name ⇒ bulk.
	sh := mustParse(t, "UPDATE vm_interfaces SET deleted_at = ?, updated_at = ? WHERE vm_name = ?",
		[]string{"vm_name", "network_name"})
	if sh.HasFullPKIdentity {
		t.Fatal("partial-PK cascade must NOT have full-PK identity")
	}
}

func TestParse_Update_OrGroup_NotFullPK(t *testing.T) {
	sh := mustParse(t, "UPDATE host_health SET deleted_at = ? WHERE observer = ? OR target = ?",
		[]string{"observer", "target"})
	if sh.HasFullPKIdentity {
		t.Fatal("an OR at the top must NOT yield full-PK identity")
	}
}

func TestParse_Delete_FullPK(t *testing.T) {
	sh := mustParse(t, "DELETE FROM vm_events WHERE id = ?", []string{"id"})
	if sh.Kind != KindDelete || !sh.HasFullPKIdentity || sh.PKParamIdx[0] != 0 {
		t.Fatalf("delete identity: kind=%v full=%v idx=%v", sh.Kind, sh.HasFullPKIdentity, sh.PKParamIdx)
	}
}

func TestParse_Invalid(t *testing.T) {
	cases := map[string]string{
		"receiver-evaluated func": "INSERT INTO crl_versions (host, version, updated_at) VALUES (?, ?, datetime('now'))",
		"RETURNING":               "INSERT INTO t (a) VALUES (?) RETURNING a",
		"INSERT SELECT":           "INSERT INTO t (a) SELECT x FROM y",
		"multi-row":               "INSERT INTO t (a) VALUES (?), (?)",
		"quoted table":            "INSERT INTO \"t\" (a) VALUES (?)",
		"quoted column":           "INSERT INTO t (\"a\") VALUES (?)",
		"schema-qualified":        "INSERT INTO main.t (a) VALUES (?)",
		"duplicate column":        "INSERT INTO t (a, a) VALUES (?, ?)",
		"col/val mismatch":        "INSERT INTO t (a, b) VALUES (?)",
		"unterminated string":     "INSERT INTO t (a) VALUES ('x)",
		"unterminated comment":    "INSERT INTO t (a) VALUES (?) /* oops",
		"trailing statement":      "INSERT INTO t (a) VALUES (?); DROP TABLE t",
		"numbered param":          "INSERT INTO t (a) VALUES (?1)",
		"named param":             "INSERT INTO t (a) VALUES (:a)",
		"empty column list":       "INSERT INTO t () VALUES ()",
		"bad OR algo":             "INSERT OR ABORT INTO t (a) VALUES (?)",
		"BETWEEN in WHERE":        "DELETE FROM t WHERE a BETWEEN ? AND ?",
		// review 5c: ON CONFLICT tail must be exactly one complete clause.
		"truncated ON CONFLICT":    "INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT",
		"second conflict clause":   "INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO NOTHING ON CONFLICT(a) DO NOTHING",
		"incomplete DO UPDATE":     "INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO UPDATE",
		"incomplete DO UPDATE SET": "INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET",
		"trailing after conflict":  "INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO NOTHING garbage",
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) { mustInvalid(t, sql, []string{"a"}) })
	}
}

func TestParse_ParamArity(t *testing.T) {
	sh := mustParse(t, "UPDATE t SET a = ?, b = ? WHERE id = ?", []string{"id"})
	if sh.ParamCount != 3 {
		t.Fatalf("ParamCount=%d, want 3", sh.ParamCount)
	}
	if err := sh.ValidateParamArity(3); err != nil {
		t.Fatalf("arity 3 should be valid: %v", err)
	}
	if err := sh.ValidateParamArity(2); err == nil { // missing
		t.Fatal("arity 2 (missing) should be invalid")
	}
	if err := sh.ValidateParamArity(4); err == nil { // excess
		t.Fatal("arity 4 (excess) should be invalid")
	}
	// literals do not count as parameters
	sh2 := mustParse(t, "INSERT INTO t (a, b, c) VALUES (?, 0, NULL)", []string{"a"})
	if sh2.ParamCount != 1 {
		t.Fatalf("ParamCount=%d, want 1 (literals excluded)", sh2.ParamCount)
	}
}

func TestParse_FullImage_ExactSet(t *testing.T) {
	// exact non-PK set copied ⇒ full image
	full := mustParse(t, "INSERT INTO t (id, a, b) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET a=excluded.a, b=excluded.b", []string{"id"})
	if !full.OnConflict.IsFullImage {
		t.Fatal("exact non-PK copy should be full-image")
	}
	// an assignment to a column NOT in the supplied row (receiver-only) ⇒ NOT full image
	extra := mustParse(t, "INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET a=excluded.a, ro=excluded.ro", []string{"id"})
	if extra.OnConflict.IsFullImage {
		t.Fatal("assigning a receiver-only column must NOT be full-image")
	}
	// assigning the PK/conflict column ⇒ NOT full image
	pkAssign := mustParse(t, "INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET id=excluded.id, a=excluded.a", []string{"id"})
	if pkAssign.OnConflict.IsFullImage {
		t.Fatal("assigning the PK column must NOT be full-image")
	}
	// a supplied non-PK column omitted from DO UPDATE ⇒ NOT full image
	omit := mustParse(t, "INSERT INTO t (id, a, b) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET a=excluded.a", []string{"id"})
	if omit.OnConflict.IsFullImage {
		t.Fatal("omitting a supplied non-PK column must NOT be full-image")
	}
}

func TestParse_DuplicateSetTargets(t *testing.T) {
	cases := []string{
		"UPDATE t SET updated_at = ?, updated_at = NULL WHERE id = ?",                         // dup updated_at
		"UPDATE t SET id = ?, id = ? WHERE x = ?",                                             // dup pk
		"UPDATE t SET a = ?, a = ? WHERE id = ?",                                              // dup ordinary
		"INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET a=excluded.a, a=?", // dup in DO UPDATE
	}
	for _, sql := range cases {
		mustInvalid(t, sql, []string{"id"})
	}
}

func TestStripLeadingAlgo(t *testing.T) {
	cases := []string{
		"INSERT OR REPLACE INTO t (a, b) VALUES (?, 'x;y') -- c\n",
		"INSERT OR IGNORE INTO t (a, b) VALUES (?, ?)",
		"INSERT OR REPLACE INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET a=excluded.a WHERE t.deleted_at IS NOT NULL",
	}
	for _, sql := range cases {
		sh := mustParse(t, sql, []string{"id"})
		stripped := stripLeadingAlgo(sql, sh)
		sh2, err := parseStmtShape(stripped, []string{"id"})
		if err != nil {
			t.Fatalf("stripped %q did not parse: %v", stripped, err)
		}
		if sh2.LeadingAlgo != "" {
			t.Fatalf("stripped statement still has algo %q: %q", sh2.LeadingAlgo, stripped)
		}
		// structural equivalence: same table/cols/values/conflict, only the algo removed.
		if sh2.Table != sh.Table || len(sh2.InsertCols) != len(sh.InsertCols) || len(sh2.InsertVals) != len(sh.InsertVals) {
			t.Fatalf("strip changed structure: %q -> %q", sql, stripped)
		}
		if (sh.OnConflict == nil) != (sh2.OnConflict == nil) {
			t.Fatalf("strip changed ON CONFLICT presence: %q", stripped)
		}
	}
	// a plain INSERT (no algo) is returned unchanged.
	plain := "INSERT INTO t (a) VALUES (?)"
	if got := stripLeadingAlgo(plain, mustParse(t, plain, []string{"a"})); got != plain {
		t.Fatalf("plain insert changed: %q", got)
	}
}

// TestSetInsertOrIgnore verifies the structural "INSERT OR IGNORE" rewrite (replacement for the old
// substring replaceInsertStrategy): a plain INSERT gains OR IGNORE, an existing algo is replaced, and
// the rest of the statement (columns, values, ON CONFLICT tail, comments) is preserved.
func TestSetInsertOrIgnore(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"INSERT INTO t (a, b) VALUES (?, ?)", "INSERT OR IGNORE INTO t (a, b) VALUES (?, ?)"},
		{"INSERT OR REPLACE INTO t (a) VALUES (?)", "INSERT OR IGNORE INTO t (a) VALUES (?)"},
		{"INSERT OR IGNORE INTO t (a) VALUES (?)", "INSERT OR IGNORE INTO t (a) VALUES (?)"},
		{"INSERT INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO NOTHING", "INSERT OR IGNORE INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO NOTHING"},
	}
	for _, c := range cases {
		got := setInsertOrIgnore(c.in, mustParse(t, c.in, []string{"id"}))
		if got != c.want {
			t.Errorf("setInsertOrIgnore(%q):\n  got  %q\n  want %q", c.in, got, c.want)
		}
		// The result must parse as a valid INSERT OR IGNORE.
		sh, err := parseStmtShape(got, []string{"id"})
		if err != nil {
			t.Fatalf("rewritten %q did not parse: %v", got, err)
		}
		if sh.LeadingAlgo != "OR IGNORE" {
			t.Errorf("rewritten statement has algo %q, want OR IGNORE: %q", sh.LeadingAlgo, got)
		}
	}
}

func TestStripLeadingAlgo_ExecuteEquivalence(t *testing.T) {
	// The stripped plain-INSERT + ON CONFLICT must execute equivalently to the original
	// OR REPLACE form for the common same-PK conflict.
	db, err := openMem(t, "stripexec")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, b TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t (id, a, b) VALUES (1, 'orig', 'keep')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	orig := "INSERT OR REPLACE INTO t (id, a) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET a=excluded.a"
	sh := mustParse(t, orig, []string{"id"})
	stripped := stripLeadingAlgo(orig, sh)
	if _, err := db.Exec(stripped, 1, "new"); err != nil {
		t.Fatalf("exec stripped %q: %v", stripped, err)
	}
	var a, b string
	if err := db.QueryRow(`SELECT a, b FROM t WHERE id = 1`).Scan(&a, &b); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if a != "new" || b != "keep" { // b (receiver-only here) preserved by the DO UPDATE
		t.Fatalf("got a=%q b=%q, want a=new b=keep", a, b)
	}
}

func TestParse_CommentsAndSemicolonInStringDoNotBreakBoundary(t *testing.T) {
	// a semicolon inside a string literal is not a statement terminator; a trailing line
	// comment is fine; both parse as one statement.
	sh := mustParse(t, "INSERT INTO t (a, b) VALUES (?, 'x;y') -- trailing\n", []string{"a"})
	if sh.Table != "t" || len(sh.InsertVals) != 2 || sh.InsertVals[1].Literal.Str != "x;y" {
		t.Fatalf("string/semicolon/comment handling wrong: %+v", sh.InsertVals)
	}
	// single trailing ';' is allowed
	mustParse(t, "INSERT INTO t (a) VALUES (?);", []string{"a"})
}
