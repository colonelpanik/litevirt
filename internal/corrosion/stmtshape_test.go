package corrosion

import (
	"errors"
	"testing"
)

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
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) { mustInvalid(t, sql, []string{"a"}) })
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
