package main

import (
	"strings"
	"testing"
)

func TestNonAdditiveAlter(t *testing.T) {
	cases := []struct {
		alter   string
		wantBad bool
	}{
		{`ALTER TABLE vms ADD COLUMN project TEXT`, false},                          // nullable add — fine
		{`ALTER TABLE vms ADD COLUMN role TEXT NOT NULL DEFAULT 'worker'`, false},   // NOT NULL + DEFAULT — fine
		{`ALTER TABLE vms ADD COLUMN x INTEGER NOT NULL`, true},                     // NOT NULL, no DEFAULT — bad
		{`ALTER TABLE vms DROP COLUMN project`, true},                               // drop — bad
		{`ALTER TABLE vms RENAME COLUMN project TO proj`, true},                     // rename col — bad
		{`ALTER TABLE vms RENAME TO virtual_machines`, true},                        // rename table — bad
		{`ALTER TABLE vms ALTER COLUMN project SET DEFAULT 'x'`, true},              // alter col — bad
	}
	for _, c := range cases {
		got := nonAdditiveAlter(c.alter)
		if (got != "") != c.wantBad {
			t.Errorf("nonAdditiveAlter(%q) = %q, wantBad=%v", c.alter, got, c.wantBad)
		}
	}
}

func facts(ddl, mig []string) schemaFacts {
	return schemaFacts{ddlStmts: ddl, migStmts: mig}
}

func TestNonAdditiveViolations_TableDiff(t *testing.T) {
	base := []string{`CREATE TABLE IF NOT EXISTS foo (
		id    TEXT PRIMARY KEY,
		name  TEXT,
		count INTEGER NOT NULL DEFAULT 0
	)`}

	cases := []struct {
		name    string
		headDDL string
		wantBad bool
	}{
		{"clean add column", `CREATE TABLE IF NOT EXISTS foo (
			id TEXT PRIMARY KEY, name TEXT, count INTEGER NOT NULL DEFAULT 0, extra TEXT
		)`, false},
		{"drop/rename column", `CREATE TABLE IF NOT EXISTS foo (
			id TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0
		)`, true},
		{"type change", `CREATE TABLE IF NOT EXISTS foo (
			id TEXT PRIMARY KEY, name INTEGER, count INTEGER NOT NULL DEFAULT 0
		)`, true},
		{"pk change", `CREATE TABLE IF NOT EXISTS foo (
			id TEXT, name TEXT, count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (id, name)
		)`, true},
		{"table removed", `CREATE TABLE IF NOT EXISTS other (id TEXT PRIMARY KEY)`, true},
	}
	for _, c := range cases {
		v := nonAdditiveViolations(facts(base, nil), facts([]string{c.headDDL}, nil))
		if (len(v) > 0) != c.wantBad {
			t.Errorf("%s: violations=%v, wantBad=%v", c.name, v, c.wantBad)
		}
	}
}

// A non-additive change to a LOCAL-ONLY (non-replicated) table is allowed.
func TestNonAdditiveViolations_LocalOnlyExempt(t *testing.T) {
	base := []string{`CREATE TABLE IF NOT EXISTS schema_state (id INTEGER PRIMARY KEY, version INTEGER NOT NULL, updated_at TEXT NOT NULL)`}
	head := []string{`CREATE TABLE IF NOT EXISTS schema_state (id INTEGER PRIMARY KEY)`} // dropped cols
	if v := nonAdditiveViolations(facts(base, nil), facts(head, nil)); len(v) != 0 {
		t.Errorf("local-only table must be exempt; got %v", v)
	}
}

func TestNonAdditiveViolations_MigrationDiff(t *testing.T) {
	clean := facts(nil, []string{`ALTER TABLE vms ADD COLUMN project TEXT NOT NULL DEFAULT '_default'`})
	if v := nonAdditiveViolations(facts(nil, nil), clean); len(v) != 0 {
		t.Errorf("clean additive migration flagged: %v", v)
	}
	bad := facts(nil, []string{`ALTER TABLE vms DROP COLUMN project`})
	if v := nonAdditiveViolations(facts(nil, nil), bad); len(v) == 0 || !strings.Contains(v[0], "DROP COLUMN") {
		t.Errorf("DROP COLUMN migration not flagged: %v", v)
	}
}

// parseTables must correctly model the real litevirt CREATE-TABLE style
// (multi-line, inline + table-level PRIMARY KEY, -- comments).
func TestParseTables_RealStyle(t *testing.T) {
	tm := parseTables([]string{`CREATE TABLE IF NOT EXISTS vm_interfaces (
		vm_name         TEXT NOT NULL,
		network_name    TEXT NOT NULL,
		mac             TEXT NOT NULL,
		security_groups TEXT,                    -- JSON []string of SG names
		PRIMARY KEY (vm_name, network_name)
	)`})
	got, ok := tm["vm_interfaces"]
	if !ok {
		t.Fatal("vm_interfaces not parsed")
	}
	if _, ok := got.cols["security_groups"]; !ok {
		t.Error("security_groups column not parsed (comment handling?)")
	}
	if strings.Join(got.pk, ",") != "network_name,vm_name" { // sorted
		t.Errorf("PK = %v, want [network_name vm_name]", got.pk)
	}
}
