package corrosion

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Gap 4 — reject-metric label safety.
//
// litevirt_merge_apply_rejected_total is labelled {table, path, reason}. A malformed or
// hostile peer controls the statement text and the dump's table names, so if any of those
// reached a Prometheus label verbatim it would (a) blow up label cardinality and (b) leak
// SQL / parameter values into metrics. The contract is: labels are drawn from a BOUNDED
// vocabulary only — table is a known replicated table or "unknown"; path is ae/wal; reason is
// one of a fixed set. These tests pin that contract at the label producers AND at every call
// site.

// knownBoundedReasons is the closed set of reason labels the apply path may emit (WAL literals,
// AE literals, walRejectReason outputs, and the SQLite constraint-kind enum). The constraint
// kinds are pulled from the in-package constants so this set can't drift from classifySQLiteError.
var knownBoundedReasons = func() map[string]bool {
	m := map[string]bool{
		// WAL entry-level
		"decode": true, "empty": true,
		// walRejectReason non-constraint arms
		"schema_missing": true, "invalid_shape": true, "operational": true, "other": true,
		// AE structural keep-local
		"unknown_table": true, "unexpected_columns": true, "duplicate_columns": true,
		"missing_pk": true, "no_pk": true, "missing_updated_at": true, "identity_collapse_rejected": true,
	}
	// SQLite constraint kinds (string(kind)) — shared by WAL and AE.
	for _, k := range []constraintKind{
		constraintUnique, constraintPrimaryKey, constraintNotNull,
		constraintCheck, constraintForeignKey, constraintGeneric,
	} {
		m[string(k)] = true
	}
	return m
}()

// TestRejectLabel_TableAlwaysBounded feeds hostile table names and statements through the two
// table-label producers and asserts the result is always a known replicated table or "unknown"
// — never the attacker's string.
func TestRejectLabel_TableAlwaysBounded(t *testing.T) {
	hostileTables := []string{
		"vms; DROP TABLE vms",
		"'; DELETE FROM hosts; --",
		strings.Repeat("A", 100000),
		"vms\n\t\x00weird",
		"10.0.0.5",           // an IP-looking value
		"secret-workload-01", // a workload-looking value
		"",
		"VmS", // wrong case ⇒ not the canonical known name
	}
	for _, tbl := range hostileTables {
		got := boundedTableLabel(tbl)
		if got != "unknown" {
			if _, known := tablePrimaryKeys[got]; !known {
				t.Errorf("boundedTableLabel(%.40q) = %q, which is neither a known table nor \"unknown\"", tbl, got)
			}
		}
		if got != "unknown" && got != tbl {
			t.Errorf("boundedTableLabel returned a transformed non-\"unknown\" label %q for input %.40q", got, tbl)
		}
	}

	hostileSQL := []string{
		`INSERT INTO vms (name) VALUES ('secret-workload-01')`, // real data in the statement
		`UPDATE hosts SET ipmi_pass = '10.0.0.5' WHERE name = 'node-01'`,
		`DELETE FROM ` + strings.Repeat("x", 50000),
		"this is not sql at all -- " + strings.Repeat("junk ", 1000),
		"",
		`INSERT INTO nonexistent_table (a) VALUES (?)`,
		`UPDATE vms SET state = 'running' WHERE name = ?`, // a valid known-table statement
	}
	labelRe := regexp.MustCompile(`^[a-z_][a-z0-9_]*$`) // a table label is a bare identifier or "unknown"
	for _, sql := range hostileSQL {
		got := structuralTableLabel(sql)
		if !labelRe.MatchString(got) {
			t.Errorf("structuralTableLabel(%.40q) = %q, not a bare bounded identifier — SQL/data may have leaked into the label", sql, got)
		}
		if got != "unknown" {
			if _, known := tablePrimaryKeys[got]; !known {
				t.Errorf("structuralTableLabel(%.40q) = %q, neither a known table nor \"unknown\"", sql, got)
			}
		}
		if len(got) > 64 {
			t.Errorf("structuralTableLabel produced an over-long label (%d chars) — a bounded label must be short", len(got))
		}
	}
}

// TestRejectLabel_ReasonAlwaysBounded asserts walRejectReason maps any error — including a real
// SQLite constraint error and an arbitrary opaque error — to a reason in the closed vocabulary.
func TestRejectLabel_ReasonAlwaysBounded(t *testing.T) {
	// A real UNIQUE-constraint error from SQLite, so string(kind) is exercised, not a mock.
	db, err := openMem(t, "rejectreason")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE u (k TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO u (k) VALUES ('x')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, dupErr := db.Exec(`INSERT INTO u (k) VALUES ('x')`) // UNIQUE violation
	if dupErr == nil {
		t.Fatal("expected a UNIQUE constraint error")
	}

	for _, err := range []error{
		dupErr,
		ErrInvalidStmt,
		invalidf("unregistered shape for %s", "some_table"),
		errAny("connection reset by peer: secret-host-01 10.0.0.5"),
	} {
		got := walRejectReason(err)
		if !knownBoundedReasons[got] {
			t.Errorf("walRejectReason(%v) = %q, not in the bounded reason vocabulary", err, got)
		}
		if strings.ContainsAny(got, " '\"\n\t;()") {
			t.Errorf("walRejectReason produced a reason with SQL/whitespace metacharacters: %q", got)
		}
	}
}

// TestRejectLabel_EveryCallSiteUsesBoundedTable is a source guard: every observeMergeRejected
// call must pass a BOUNDED table producer as its first argument — boundedTableLabel(...),
// structuralTableLabel(...), or a string literal — never a raw peer-supplied table/SQL string.
// This catches a future regression that passes an unbounded name (the exact shape of the two
// sites this change hardened).
func TestRejectLabel_EveryCallSiteUsesBoundedTable(t *testing.T) {
	call := regexp.MustCompile(`observeMergeRejected\(\s*([^,]+?)\s*,`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	found := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range call.FindAllStringSubmatch(string(src), -1) {
			arg := strings.TrimSpace(m[1])
			// The definition/interface signatures use the parameter name `table`; skip those.
			if arg == "table" && (f == "client.go") {
				continue
			}
			found++
			bounded := strings.HasPrefix(arg, "boundedTableLabel(") ||
				strings.HasPrefix(arg, "structuralTableLabel(") ||
				(strings.HasPrefix(arg, `"`) && strings.HasSuffix(arg, `"`))
			if !bounded {
				t.Errorf("%s: observeMergeRejected first arg %q is not a bounded table producer "+
					"(use boundedTableLabel(...)/structuralTableLabel(...) or a literal) — an unbounded "+
					"peer table/SQL string must never become a metric label", f, arg)
			}
		}
	}
	if found == 0 {
		t.Fatal("source guard found no observeMergeRejected call sites — the scan is broken")
	}
}

// errAny is a minimal opaque error used to exercise the walRejectReason default arm.
type errAny string

func (e errAny) Error() string { return string(e) }
