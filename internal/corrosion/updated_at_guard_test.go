package corrosion

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// sqlLiteralRe extracts backtick-delimited string literals (this codebase writes
// SQL as raw `…` literals).
var sqlLiteralRe = regexp.MustCompile("`[^`]*`")

// writeTargetRe pulls the table name out of an UPDATE/INSERT statement.
var writeTargetRe = regexp.MustCompile(`(?is)(?:UPDATE|INTO)\s+([a-z_0-9]+)`)

// TestReplicatedUpdatedAtUsesNowTS is a tripwire (not a parser): a function that
// writes `updated_at` to a CRDT-replicated or push-replicated table — where
// updated_at is the last-writer-wins key — must generate that value with
// Client.NowTS() (monotonic sub-second), never bare second-resolution
// time.RFC3339, which can tie two same-second writes and strand the loser on a
// peer. It is intentionally function-scoped + regex-based: it catches a wholly
// unconverted writer, not every per-statement mistake. Append-only / non-LWW
// timestamp columns (audit_log, vm_events, mutation_log, created_at, deleted_at,
// expiry, retention cutoffs) are deliberately out of scope.
func TestReplicatedUpdatedAtUsesNowTS(t *testing.T) {
	// LWW-keyed replicated tables: the public anti-entropy set minus the
	// append-only audit_log, plus the push-replicated secret-bearing tables.
	replicated := map[string]bool{
		"registry_credentials": true,
		"notification_targets": true,
		"notification_routes":  true,
	}
	for _, n := range tableNames {
		if n == "audit_log" {
			continue // append-only, RFC3339Nano timestamp, not LWW-merged
		}
		replicated[n] = true
	}

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
			if !ok {
				continue
			}
			body := string(src[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
			if !writesReplicatedUpdatedAt(body, replicated) {
				continue
			}
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

// writesReplicatedUpdatedAt reports whether the function source contains a SQL
// literal that writes `updated_at` to one of the replicated tables.
func writesReplicatedUpdatedAt(funcSrc string, replicated map[string]bool) bool {
	for _, lit := range sqlLiteralRe.FindAllString(funcSrc, -1) {
		if !strings.Contains(lit, "updated_at") {
			continue
		}
		m := writeTargetRe.FindStringSubmatch(lit)
		if m != nil && replicated[m[1]] {
			return true
		}
	}
	return false
}
