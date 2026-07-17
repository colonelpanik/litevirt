// Command stmtshapecheck is the source-linked half of the replication apply-safety
// guard. It statically enumerates every replicated SQL statement our own builders emit —
// calls to the corrosion Client's replicating Execute* methods (resolved by TYPE, so
// text/template.Execute and other unrelated Execute methods are not matched) — computes
// each one's stmtshape/v1 fingerprint with the SAME shared primitive the runtime uses at
// apply time (corrosion.FingerprintSQL), and checks it against the checked-in compatibility
// ledger (corrosion.LedgerLookup). Because CI and the runtime share the fingerprint
// function and the ledger, they cannot drift: a builder whose shape is not registered fails
// CI here rather than silently back-pressuring at apply time.
//
// Dynamically-built SQL (a non-string-literal argument) cannot be fingerprinted statically;
// such a call site must carry a `//stmtshape:policy <id>` directive naming a registered
// parameterized policy, or the guard flags it.
//
// Usage:
//
//	stmtshapecheck -root .            # check every builder against the ledger; exit 1 on any gap
//	stmtshapecheck -root . -report    # print every builder's fingerprint + shape (seeds the ledger)
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const corrosionPkgPath = "github.com/litevirt/litevirt/internal/corrosion"

// replicatingMethods are the corrosion Client methods that write a mutation_log row (i.e.
// replicate). execLocal*/raw db.Exec do not replicate and are not scanned.
var replicatingMethods = map[string]bool{
	"Execute":             true,
	"ExecuteRows":         true,
	"ExecuteDeferred":     true,
	"ExecuteBatch":        true,
	"ExecuteBatchGuarded": true,
}

type finding struct {
	pos      token.Position
	sql      string
	dynamic  bool
	policy   string
	fp       string
	parseErr string
}

func main() {
	root := flag.String("root", ".", "repository root to scan")
	report := flag.Bool("report", false, "print every builder's fingerprint + shape instead of checking")
	flag.Parse()

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir:   *root,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./internal/...")
	if err != nil {
		fmt.Fprintf(os.Stderr, "stmtshapecheck: load: %v\n", err)
		os.Exit(2)
	}
	if packages.PrintErrors(pkgs) > 0 {
		os.Exit(2)
	}

	var findings []finding
	for _, pkg := range pkgs {
		findings = append(findings, scanPkg(pkg)...)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].pos.Filename != findings[j].pos.Filename {
			return findings[i].pos.Filename < findings[j].pos.Filename
		}
		return findings[i].pos.Line < findings[j].pos.Line
	})

	if *report {
		for _, f := range findings {
			switch {
			case f.dynamic:
				fmt.Printf("%s\tDYNAMIC\tpolicy=%q\n", loc(f.pos), f.policy)
			case f.parseErr != "":
				fmt.Printf("%s\tPARSE-ERR\t%s\t%q\n", loc(f.pos), f.parseErr, f.sql)
			default:
				fmt.Printf("%s\t%s\t%q\n", loc(f.pos), f.fp, f.sql)
			}
		}
		return
	}

	var gaps []string
	for _, f := range findings {
		switch {
		case f.dynamic:
			if f.policy == "" {
				gaps = append(gaps, fmt.Sprintf("%s: dynamically-built replicated SQL with no //stmtshape:policy directive", loc(f.pos)))
			}
		case f.parseErr != "":
			gaps = append(gaps, fmt.Sprintf("%s: replicated SQL does not parse as a supported shape (%s): %q", loc(f.pos), f.parseErr, f.sql))
		default:
			if _, ok := corrosion.LedgerLookup(f.fp); !ok {
				gaps = append(gaps, fmt.Sprintf("%s: replicated statement not in the compatibility ledger (fp %s): %q", loc(f.pos), f.fp, f.sql))
			}
		}
	}
	if len(gaps) == 0 {
		fmt.Printf("stmtshapecheck: %d replicated builder statement(s) all registered; OK\n", len(findings))
		return
	}
	fmt.Fprintf(os.Stderr, "stmtshapecheck: FAIL — %d unregistered/unparseable replicated statement(s):\n", len(gaps))
	for _, g := range gaps {
		fmt.Fprintf(os.Stderr, "  %s\n", g)
	}
	fmt.Fprintf(os.Stderr, "\nAdd a ledger entry (run with -report to get the fingerprint) or a //stmtshape:policy\n"+
		"directive for a dynamic builder. An unregistered shape would back-pressure at apply time.\n")
	os.Exit(1)
}

func loc(p token.Position) string { return fmt.Sprintf("%s:%d", p.Filename, p.Line) }

func scanPkg(pkg *packages.Package) []finding {
	var out []finding
	policyAt := harvestPolicyDirectives(pkg)
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !replicatingMethods[sel.Sel.Name] {
				return true
			}
			// Resolve the selection: only a method on *corrosion.Client counts.
			selection := pkg.TypesInfo.Selections[sel]
			if selection == nil || selection.Kind() != types.MethodVal || !isCorrosionClient(selection.Recv()) {
				return true
			}
			callStart := pkg.Fset.Position(call.Pos()).Line
			callEnd := pkg.Fset.Position(call.End()).Line
			pol := policyBetween(policyAt, pkg.Fset.Position(call.Pos()).Filename, callStart, callEnd)
			for _, sqlExpr := range sqlArgsOf(sel.Sel.Name, call) {
				pos := pkg.Fset.Position(sqlExpr.Pos())
				lit, isLit := stringLit(sqlExpr)
				if !isLit {
					out = append(out, finding{pos: pos, dynamic: true, policy: pol})
					continue
				}
				f := finding{pos: pos, sql: lit}
				if fp, err := corrosion.FingerprintSQL(lit); err != nil {
					f.parseErr = err.Error()
				} else {
					f.fp = fp
				}
				out = append(out, f)
			}
			return true
		})
	}
	return out
}

// isCorrosionClient reports whether t is *corrosion.Client (or corrosion.Client).
func isCorrosionClient(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == "Client" && obj.Pkg() != nil && obj.Pkg().Path() == corrosionPkgPath
}

type policyDirective struct {
	file string
	line int
	id   string
}

func harvestPolicyDirectives(pkg *packages.Package) []policyDirective {
	var out []policyDirective
	for _, file := range pkg.Syntax {
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if idx := strings.Index(c.Text, "stmtshape:policy"); idx >= 0 {
					id := strings.TrimSpace(strings.TrimPrefix(c.Text[idx:], "stmtshape:policy"))
					p := pkg.Fset.Position(c.Slash)
					out = append(out, policyDirective{file: p.Filename, line: p.Line, id: id})
				}
			}
		}
	}
	return out
}

func policyBetween(dirs []policyDirective, file string, start, end int) string {
	for _, d := range dirs {
		if d.file == file && d.line >= start && d.line <= end {
			return d.id
		}
	}
	return ""
}

func sqlArgsOf(method string, call *ast.CallExpr) []ast.Expr {
	switch method {
	case "Execute", "ExecuteRows", "ExecuteDeferred":
		if len(call.Args) >= 2 {
			return []ast.Expr{call.Args[1]}
		}
	case "ExecuteBatch", "ExecuteBatchGuarded":
		var out []ast.Expr
		for _, a := range call.Args {
			if e := statementSQLField(a); e != nil {
				out = append(out, e)
			}
		}
		return out
	}
	return nil
}

func statementSQLField(a ast.Expr) ast.Expr {
	if u, ok := a.(*ast.UnaryExpr); ok {
		a = u.X
	}
	cl, ok := a.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "SQL" {
			return kv.Value
		}
	}
	return nil
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}
