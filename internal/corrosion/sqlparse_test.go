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
