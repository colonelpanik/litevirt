package corrosion

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// sanctionedSpecWriters is the CLOSED set of functions in the corrosion package
// permitted to write vms.spec / vms.cpu_actual / vms.mem_actual. Every other spec
// write must route through MutateDesiredSpec (desired spec, barrier-checked, bumps
// spec_generation) or UpdateObservedActuals (cpu_actual/mem_actual, owner/gen CAS,
// no bump) — the v41 F1 discipline that keeps a blind writer from bypassing the
// mutation barrier or the generation counter. If you add a legitimate new writer,
// add it here WITH a comment justifying why it can't use the sanctioned APIs.
var sanctionedSpecWriters = map[string]string{
	"InsertVM":                  "creates the row",
	"RenameVM":                  "structural rename — changes the primary key, can't use a name-keyed CAS",
	"BeginVMOperation":          "F1 op-start: sets desired spec + bumps generation + claims the barrier atomically",
	"MutateDesiredSpec":         "THE sanctioned desired-spec writer",
	"UpdateObservedActuals":     "THE sanctioned cpu_actual/mem_actual writer",
	"migrateVMSpecNetworkNames": "one-time schema migration, runs before serving (no barrier to honor)",
}

// TestSpecWritersAreSanctioned fails if any function in the corrosion package
// writes vms.spec/cpu_actual/mem_actual without being on the allowlist. This is the
// CI guard against a direct unmarshal→marshal→write that bypasses MutateDesiredSpec.
func TestSpecWritersAreSanctioned(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	found := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if writesVMSpecColumns(lit.Value) {
					found[fn.Name.Name] = true
				}
				return true
			})
		}
	}

	var unsanctioned []string
	for name := range found {
		if _, ok := sanctionedSpecWriters[name]; !ok {
			unsanctioned = append(unsanctioned, name)
		}
	}
	sort.Strings(unsanctioned)
	if len(unsanctioned) > 0 {
		t.Fatalf("unsanctioned vms.spec/cpu_actual/mem_actual writer(s): %v\n"+
			"route spec changes through MutateDesiredSpec and actuals through UpdateObservedActuals, "+
			"or add the function to sanctionedSpecWriters with a justification", unsanctioned)
	}

	// Guard the guard: every allowlisted name must still exist as a real writer, so a
	// renamed/removed writer can't leave a stale allowlist entry masking a new one.
	for name := range sanctionedSpecWriters {
		if !found[name] {
			t.Errorf("sanctionedSpecWriters lists %q but it no longer writes the spec/actual columns; remove the stale entry", name)
		}
	}
}

// writesVMSpecColumns reports whether a SQL string literal writes the vms.spec,
// cpu_actual, or mem_actual column — either an INSERT INTO vms (which always sets
// the initial spec) or an UPDATE vms that sets one of those columns.
func writesVMSpecColumns(sqlLiteral string) bool {
	if strings.Contains(sqlLiteral, "INSERT INTO vms ") || strings.Contains(sqlLiteral, "INSERT INTO vms(") {
		return true
	}
	if !strings.Contains(sqlLiteral, "UPDATE vms SET") {
		return false
	}
	return strings.Contains(sqlLiteral, "spec ") || strings.Contains(sqlLiteral, "spec=") ||
		strings.Contains(sqlLiteral, "cpu_actual") || strings.Contains(sqlLiteral, "mem_actual")
}
