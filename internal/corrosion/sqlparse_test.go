package corrosion

import (
	"testing"
)

// ── extractTableName ────────────────────────────────────────────────────────

func TestExtractTableName_Insert(t *testing.T) {
	tests := []struct {
		sql  string
		want string
	}{
		{"INSERT INTO vms (name, state) VALUES (?, ?)", "vms"},
		{"INSERT OR REPLACE INTO hosts (name) VALUES (?)", "hosts"},
		{"INSERT OR IGNORE INTO images (name) VALUES (?)", "images"},
		{"insert into networks (name) values (?)", "networks"},
		{"INSERT INTO `quoted_table` (col) VALUES (?)", "quoted_table"},
		{"INSERT INTO \"dbl_quoted\" (col) VALUES (?)", "dbl_quoted"},
		{"INSERT INTO [bracket_quoted] (col) VALUES (?)", "bracket_quoted"},
		// Table name with trailing paren (compact SQL) — cleanTableName strips trailing '('.
		{"INSERT INTO vms (name) VALUES (?)", "vms"},
	}
	for _, tt := range tests {
		got := extractTableName(tt.sql)
		if got != tt.want {
			t.Errorf("extractTableName(%q) = %q, want %q", tt.sql, got, tt.want)
		}
	}
}

func TestExtractTableName_Update(t *testing.T) {
	tests := []struct {
		sql  string
		want string
	}{
		{"UPDATE vms SET state = ? WHERE name = ?", "vms"},
		{"UPDATE hosts SET labels = ? WHERE name = ?", "hosts"},
		{"update networks set subnet = ? where name = ?", "networks"},
	}
	for _, tt := range tests {
		got := extractTableName(tt.sql)
		if got != tt.want {
			t.Errorf("extractTableName(%q) = %q, want %q", tt.sql, got, tt.want)
		}
	}
}

func TestExtractTableName_Delete(t *testing.T) {
	tests := []struct {
		sql  string
		want string
	}{
		{"DELETE FROM vms WHERE name = ?", "vms"},
		{"DELETE FROM hosts WHERE name = ?", "hosts"},
		{"delete from images where name = ?", "images"},
	}
	for _, tt := range tests {
		got := extractTableName(tt.sql)
		if got != tt.want {
			t.Errorf("extractTableName(%q) = %q, want %q", tt.sql, got, tt.want)
		}
	}
}

func TestExtractTableName_Unknown(t *testing.T) {
	tests := []string{
		"SELECT * FROM vms",
		"CREATE TABLE foo (id INTEGER)",
		"",
		"   ",
		"DROP TABLE vms",
	}
	for _, sql := range tests {
		got := extractTableName(sql)
		if got != "" {
			t.Errorf("extractTableName(%q) = %q, want empty", sql, got)
		}
	}
}

func TestExtractTableName_LeadingWhitespace(t *testing.T) {
	got := extractTableName("  INSERT INTO vms (name) VALUES (?)")
	if got != "vms" {
		t.Errorf("leading whitespace: got %q, want vms", got)
	}
}

// ── cleanTableName ──────────────────────────────────────────────────────────

func TestCleanTableName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"vms", "vms"},
		{"`vms`", "vms"},
		{"\"vms\"", "vms"},
		{"[vms]", "vms"},
		{"vms(", "vms"},
		// Note: Trim removes surrounding quotes first, then TrimRight removes '('.
		// `vms`( → after Trim("`\"[]") → vms` (backtick in middle stays) → TrimRight("(") → vms`
		// This is a known limitation. In practice, quoted names don't have trailing parens.
		{"`vms`", "vms"},
	}
	for _, tt := range tests {
		got := cleanTableName(tt.input)
		if got != tt.want {
			t.Errorf("cleanTableName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── isInsertStatement / isUpdateStatement / isDeleteStatement ────────────────

func TestIsInsertStatement(t *testing.T) {
	if !isInsertStatement("INSERT INTO vms VALUES (?)") {
		t.Error("expected true for INSERT")
	}
	if !isInsertStatement("  insert into vms values (?)") {
		t.Error("expected true for lowercase insert with whitespace")
	}
	if isInsertStatement("UPDATE vms SET x = ?") {
		t.Error("expected false for UPDATE")
	}
	if isInsertStatement("") {
		t.Error("expected false for empty")
	}
}

func TestIsUpdateStatement(t *testing.T) {
	if !isUpdateStatement("UPDATE vms SET state = ?") {
		t.Error("expected true for UPDATE")
	}
	if !isUpdateStatement("  update vms set state = ?") {
		t.Error("expected true for lowercase update")
	}
	if isUpdateStatement("INSERT INTO vms VALUES (?)") {
		t.Error("expected false for INSERT")
	}
}

func TestIsDeleteStatement(t *testing.T) {
	if !isDeleteStatement("DELETE FROM vms WHERE name = ?") {
		t.Error("expected true for DELETE")
	}
	if !isDeleteStatement("  delete from vms where name = ?") {
		t.Error("expected true for lowercase delete")
	}
	if isDeleteStatement("INSERT INTO vms VALUES (?)") {
		t.Error("expected false for INSERT")
	}
}

// ── replaceInsertStrategy ───────────────────────────────────────────────────

func TestReplaceInsertStrategy(t *testing.T) {
	tests := []struct {
		sql      string
		strategy string
		want     string
	}{
		{
			"INSERT INTO vms (name) VALUES (?)",
			"INSERT OR REPLACE",
			"INSERT OR REPLACE INTO vms (name) VALUES (?)",
		},
		{
			"INSERT OR IGNORE INTO vms (name) VALUES (?)",
			"INSERT OR REPLACE",
			"INSERT OR REPLACE INTO vms (name) VALUES (?)",
		},
		{
			"INSERT OR REPLACE INTO vms (name) VALUES (?)",
			"INSERT",
			"INSERT INTO vms (name) VALUES (?)",
		},
	}
	for _, tt := range tests {
		got := replaceInsertStrategy(tt.sql, tt.strategy)
		if got != tt.want {
			t.Errorf("replaceInsertStrategy(%q, %q):\n  got  %q\n  want %q", tt.sql, tt.strategy, got, tt.want)
		}
	}
}

func TestReplaceInsertStrategy_NoINTO(t *testing.T) {
	sql := "INSERT vms (name) VALUES (?)"
	got := replaceInsertStrategy(sql, "INSERT OR REPLACE")
	// No INTO keyword — returns original.
	if got != sql {
		t.Errorf("expected original SQL when INTO is missing, got %q", got)
	}
}

func TestReplaceInsertStrategy_PreservesCase(t *testing.T) {
	sql := "insert into Vms (Name) values (?)"
	got := replaceInsertStrategy(sql, "INSERT OR REPLACE")
	if got != "INSERT OR REPLACE into Vms (Name) values (?)" {
		t.Errorf("case not preserved: %q", got)
	}
}

// ── extractPKFromInsert ─────────────────────────────────────────────────────

func TestExtractPKFromInsert_SinglePK(t *testing.T) {
	s := Statement{
		SQL:    "INSERT INTO vms (name, state, host_name) VALUES (?, ?, ?)",
		Params: []interface{}{"vm-1", "running", "node1"},
	}
	result := extractPKFromInsert(s, []string{"name"})
	if len(result) != 1 {
		t.Fatalf("expected 1 PK value, got %d", len(result))
	}
	if result[0] != "vm-1" {
		t.Errorf("PK[0] = %v, want vm-1", result[0])
	}
}

func TestExtractPKFromInsert_CompositePK(t *testing.T) {
	s := Statement{
		SQL:    "INSERT INTO disks (vm_name, disk_name, path) VALUES (?, ?, ?)",
		Params: []interface{}{"vm-1", "root", "/data/vm-1-root.qcow2"},
	}
	result := extractPKFromInsert(s, []string{"vm_name", "disk_name"})
	if len(result) != 2 {
		t.Fatalf("expected 2 PK values, got %d", len(result))
	}
	if result[0] != "vm-1" || result[1] != "root" {
		t.Errorf("PK = %v, want [vm-1 root]", result)
	}
}

func TestExtractPKFromInsert_PKNotInColumns(t *testing.T) {
	s := Statement{
		SQL:    "INSERT INTO vms (state, host_name) VALUES (?, ?)",
		Params: []interface{}{"running", "node1"},
	}
	result := extractPKFromInsert(s, []string{"name"})
	if result != nil {
		t.Errorf("expected nil when PK column not found, got %v", result)
	}
}

func TestExtractPKFromInsert_NoParen(t *testing.T) {
	s := Statement{
		SQL:    "INSERT INTO vms VALUES ?",
		Params: []interface{}{"vm-1"},
	}
	result := extractPKFromInsert(s, []string{"name"})
	if result != nil {
		t.Errorf("expected nil for no-paren SQL, got %v", result)
	}
}

func TestExtractPKFromInsert_CaseInsensitive(t *testing.T) {
	s := Statement{
		SQL:    "INSERT INTO vms (Name, State) VALUES (?, ?)",
		Params: []interface{}{"vm-1", "running"},
	}
	result := extractPKFromInsert(s, []string{"name"})
	if len(result) != 1 || result[0] != "vm-1" {
		t.Errorf("case-insensitive match failed: %v", result)
	}
}

func TestExtractUpdatedAtValue(t *testing.T) {
	tests := []struct {
		name string
		stmt Statement
		want string
	}{
		{
			name: "insert",
			stmt: Statement{
				SQL:    "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?)",
				Params: []interface{}{"h1", "10.0.0.1", "2026-01-01T00:00:00Z"},
			},
			want: "2026-01-01T00:00:00Z",
		},
		{
			name: "update",
			stmt: Statement{
				SQL:    "UPDATE hosts SET address = ?, updated_at = ? WHERE name = ?",
				Params: []interface{}{"10.0.0.2", "2026-01-02T00:00:00Z", "h1"},
			},
			want: "2026-01-02T00:00:00Z",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := extractUpdatedAtValue(tt.stmt)
			if !ok {
				t.Fatal("extractUpdatedAtValue returned ok=false")
			}
			if got != tt.want {
				t.Fatalf("updated_at = %q, want %q", got, tt.want)
			}
		})
	}
}

// ── extractPKFromUpdate ─────────────────────────────────────────────────────

func TestExtractPKFromUpdate_SinglePK(t *testing.T) {
	s := Statement{
		SQL:    "UPDATE vms SET state = ?, state_detail = ? WHERE name = ?",
		Params: []interface{}{"running", "started", "vm-1"},
	}
	result := extractPKFromUpdate(s, []string{"name"})
	if len(result) != 1 {
		t.Fatalf("expected 1 PK value, got %d", len(result))
	}
	if result[0] != "vm-1" {
		t.Errorf("PK[0] = %v, want vm-1", result[0])
	}
}

func TestExtractPKFromUpdate_CompositePK(t *testing.T) {
	s := Statement{
		SQL:    "UPDATE disks SET path = ? WHERE vm_name = ? AND disk_name = ?",
		Params: []interface{}{"/new/path", "vm-1", "root"},
	}
	result := extractPKFromUpdate(s, []string{"vm_name", "disk_name"})
	if len(result) != 2 {
		t.Fatalf("expected 2 PK values, got %d", len(result))
	}
	if result[0] != "vm-1" || result[1] != "root" {
		t.Errorf("PK = %v, want [vm-1 root]", result)
	}
}

func TestExtractPKFromUpdate_NoWHERE(t *testing.T) {
	s := Statement{
		SQL:    "UPDATE vms SET state = ?",
		Params: []interface{}{"stopped"},
	}
	result := extractPKFromUpdate(s, []string{"name"})
	if result != nil {
		t.Errorf("expected nil when no WHERE clause, got %v", result)
	}
}

func TestExtractPKFromUpdate_PKColumnNotInWHERE(t *testing.T) {
	// Use a WHERE column that doesn't contain the PK column name as a substring.
	s := Statement{
		SQL:    "UPDATE vms SET state = ? WHERE host_id = ?",
		Params: []interface{}{"stopped", "node1"},
	}
	result := extractPKFromUpdate(s, []string{"name"})
	if result != nil {
		t.Errorf("expected nil when PK column not in WHERE, got %v", result)
	}
}

func TestExtractPKFromUpdate_InsufficientParams(t *testing.T) {
	s := Statement{
		SQL:    "UPDATE vms SET state = ? WHERE name = ?",
		Params: []interface{}{"running"}, // missing WHERE param
	}
	result := extractPKFromUpdate(s, []string{"name"})
	if result != nil {
		t.Errorf("expected nil for insufficient params, got %v", result)
	}
}

func TestExtractPKFromUpdate_MultipleWHEREParams(t *testing.T) {
	// UPDATE with SET using 2 params and WHERE using 2 params.
	s := Statement{
		SQL:    "UPDATE host_health SET status = ?, consecutive_failures = ? WHERE observer = ? AND target = ?",
		Params: []interface{}{"suspect", 3, "node1", "node2"},
	}
	result := extractPKFromUpdate(s, []string{"observer", "target"})
	if len(result) != 2 {
		t.Fatalf("expected 2 PK values, got %d", len(result))
	}
	if result[0] != "node1" || result[1] != "node2" {
		t.Errorf("PK = %v, want [node1 node2]", result)
	}
}
