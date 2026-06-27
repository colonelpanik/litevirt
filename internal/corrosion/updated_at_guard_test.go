package corrosion

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// writeTargetRe pulls the table name out of an UPDATE/INSERT statement. It also
// matches a dynamically-built fragment like `UPDATE hosts SET %s` (fmt.Sprintf),
// so a guard scanning a function's string literals catches dynamic SQL too.
var writeTargetRe = regexp.MustCompile(`(?is)(?:UPDATE|INTO)\s+([a-z_0-9]+)`)

// replicatedLWWTables is the set whose updated_at is a last-writer-wins key: the
// public anti-entropy set minus append-only audit_log, plus the push-replicated
// secret-bearing tables. Restart tables (vm_restarts/container_restarts) are
// host-local and not in tableNames, so they're excluded.
func replicatedLWWTables() map[string]bool {
	m := map[string]bool{
		"registry_credentials": true,
		"notification_targets": true,
		"notification_routes":  true,
	}
	for _, n := range tableNames {
		if n == "audit_log" { // append-only, RFC3339Nano timestamp, not LWW-merged
			continue
		}
		m[n] = true
	}
	return m
}

// writesReplicatedUpdatedAt reports whether a function's collected string
// literals write updated_at to a replicated/sensitive table. It is deliberately
// literal-based (not param-aware) so it catches BOTH a single SQL literal and a
// dynamically-assembled statement (one literal names the table, another carries
// `updated_at = ?`), e.g. ConfigureHost's `fmt.Sprintf("UPDATE hosts SET %s …")`
// + `"updated_at = ?"`.
func writesReplicatedUpdatedAt(literals []string, replicated map[string]bool) bool {
	writesReplicated, mentionsUpdatedAt := false, false
	for _, lit := range literals {
		if strings.Contains(lit, "updated_at") {
			mentionsUpdatedAt = true
		}
		if m := writeTargetRe.FindStringSubmatch(lit); m != nil && replicated[m[1]] {
			writesReplicated = true
		}
	}
	return writesReplicated && mentionsUpdatedAt
}

// TestReplicatedUpdatedAtUsesNowTS is a tripwire (not a parser): a function that
// writes updated_at to a replicated/sensitive table — where updated_at is the
// LWW key — must generate that value with Client.NowTS() (monotonic sub-second),
// never bare second-resolution time.RFC3339, which ties two same-second writes
// and strands the loser on a peer. It scans string literals via the AST, so it
// also catches dynamically-built SQL (the class the old backtick-only scan
// missed). It is function-scoped: it ensures a writer references NowTS at all,
// not that every statement does — append-only / non-LWW columns (created_at,
// deleted_at markers, expiry, retention cutoffs, audit_log, vm_events) are out
// of scope by design.
func TestReplicatedUpdatedAtUsesNowTS(t *testing.T) {
	replicated := replicatedLWWTables()
	root, err := filepath.Abs("..") // internal/
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		f, perr := parser.ParseFile(fset, path, src, 0)
		if perr != nil {
			return nil // unparseable (generated/partial) — skip
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			lits := funcStringLiterals(fn)
			if !writesReplicatedUpdatedAt(lits, replicated) {
				continue
			}
			body := string(src[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
			if !strings.Contains(body, "NowTS(") {
				t.Errorf("internal/%s: %s writes updated_at to a replicated table but never calls "+
					"NowTS() — replicated updated_at must use Client.NowTS() (monotonic), not bare time.RFC3339",
					rel, fn.Name.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// funcStringLiterals returns the unquoted value of every string literal (backtick
// or double-quoted) inside a function — comments are excluded by construction.
func funcStringLiterals(fn *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fn, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			if v, err := strconv.Unquote(bl.Value); err == nil {
				out = append(out, v)
			}
		}
		return true
	})
	return out
}

// TestWritesReplicatedUpdatedAt_Detection gives the tripwire teeth on the cases
// the old version missed: a dynamic SQL builder, a tombstone writer, and the
// non-flag cases (read-only, host-local restart table).
func TestWritesReplicatedUpdatedAt_Detection(t *testing.T) {
	repl := replicatedLWWTables()
	cases := []struct {
		name     string
		literals []string
		want     bool
	}{
		{"dynamic builder (ConfigureHost shape)", []string{`UPDATE hosts SET %s WHERE name = ?`, `updated_at = ?`}, true},
		{"tombstone writer (dns DeleteRecord)", []string{`UPDATE dns_records SET deleted_at = ?, updated_at = ? WHERE name = ?`}, true},
		{"plain insert", []string{`INSERT INTO vms (name, created_at, updated_at) VALUES (?, ?, ?)`}, true},
		{"insert or replace", []string{`INSERT OR REPLACE INTO notification_targets (id, updated_at) VALUES (?, ?)`}, true},
		{"read-only select (no write)", []string{`SELECT updated_at FROM hosts WHERE name = ?`}, false},
		{"host-local restart table (not replicated)", []string{`UPDATE vm_restarts SET updated_at = ?`}, false},
		{"write without updated_at", []string{`UPDATE hosts SET state = ? WHERE name = ?`}, false},
	}
	for _, c := range cases {
		if got := writesReplicatedUpdatedAt(c.literals, repl); got != c.want {
			t.Errorf("%s: writesReplicatedUpdatedAt = %v, want %v", c.name, got, c.want)
		}
	}
}
