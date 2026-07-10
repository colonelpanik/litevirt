// Command writecheck enforces litevirt's "no fail-open state write" rule: the
// result of an authoritative Corrosion ownership/state/image write MUST NOT be
// discarded. In a masterless, CRDT-replicated cluster, failover, the reconciler,
// the restart engine, and the split-brain gate all READ these rows, so a silently
// dropped write lets peers act on stale state (stale/dual ownership, an operator-
// stopped VM auto-restarted, an image invisible to placement).
//
// It flags, in production .go files, any call to one of the guarded
// corrosion.<Fn> writers whose return value is discarded — either a bare call
// statement, or an assignment where every left-hand side is `_`. The correct forms
// are `if err := corrosion.X(...); err != nil { ... }` or `return corrosion.X(...)`.
//
// A specific line may opt out with a trailing `//writecheck:allow <reason>`
// comment (use sparingly, only for a genuinely best-effort write with a stated
// reason).
//
// Usage:
//
//	writecheck -root .        # walk <root> for production .go files; exit 1 on any violation
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// guarded is the closed set of corrosion write FUNCTION names whose error must be
// checked. This is the authoritative list (there is no single symbol in
// internal/corrosion to diff against — writeobs.go names the metric ops, not these
// functions), so when you add an authoritative state/ownership/image writer to
// internal/corrosion, add it here too.
var guarded = map[string]bool{
	"UpdateVMState":                 true,
	"UpdateVMStateStrict":           true,
	"UpdateVMHost":                  true,
	"UpdateDiskHostAndPath":         true,
	"CommitMigrationOwnership":      true,
	"InsertImage":                   true,
	"InsertImageHost":               true,
	"UpdateImageHostStatus":         true,
	"SetContainerState":             true,
	"SetContainerStateStrict":       true,
	"SetContainerStateDetail":       true,
	"SetContainerStateDetailStrict": true,
}

type violation struct {
	file string
	line int
	fn   string
}

func main() {
	root := flag.String("root", ".", "repository root to scan for production .go files")
	flag.Parse()

	var violations []violation
	err := filepath.WalkDir(*root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip vendor, generated, and VCS trees.
			switch d.Name() {
			case "vendor", ".git", "gen":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		vs, perr := scanFile(path)
		if perr != nil {
			return perr
		}
		violations = append(violations, vs...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "writecheck: %v\n", err)
		os.Exit(2)
	}

	if len(violations) == 0 {
		fmt.Println("writecheck: no discarded authoritative corrosion writes; OK")
		return
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].file != violations[j].file {
			return violations[i].file < violations[j].file
		}
		return violations[i].line < violations[j].line
	})
	fmt.Fprintf(os.Stderr, "writecheck: FAIL — %d authoritative corrosion write(s) with a discarded result:\n", len(violations))
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "  %s:%d: corrosion.%s(...) result discarded\n", v.file, v.line, v.fn)
	}
	fmt.Fprintf(os.Stderr,
		"\nThese writes are read by failover / the reconciler / the split-brain gate, so a\n"+
			"dropped write causes stale or dual ownership. Check the error:\n"+
			"    if err := corrosion.%s(...); err != nil { /* fail closed / log + metric */ }\n"+
			"or `return corrosion.%s(...)`. Only if the write is genuinely best-effort, add a\n"+
			"trailing `//writecheck:allow <reason>` on the call line.\n",
		"UpdateVMState", "UpdateVMState")
	os.Exit(1)
}

// scanFile parses one Go file and returns violations: guarded corrosion.<Fn>
// calls whose result is discarded (bare statement, or assignment to only `_`),
// excluding lines carrying a //writecheck:allow directive.
func scanFile(path string) ([]violation, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	allow := map[int]bool{}
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			if strings.Contains(c.Text, "writecheck:allow") {
				allow[fset.Position(c.Slash).Line] = true
			}
		}
	}

	var out []violation
	// report anchors the violation at the call's FIRST line, but honors a
	// //writecheck:allow directive on ANY line the statement spans — a guarded
	// write is usually a multi-line call (a struct-literal arg), and the natural
	// place for the directive is the trailing `})` line, not the opening one.
	report := func(n ast.Node, fn string) {
		start := fset.Position(n.Pos()).Line
		end := fset.Position(n.End()).Line
		for ln := start; ln <= end; ln++ {
			if allow[ln] {
				return
			}
		}
		out = append(out, violation{file: path, line: start, fn: fn})
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ExprStmt:
			if fn := corrosionWrite(s.X); fn != "" {
				report(s, fn)
			}
		case *ast.AssignStmt:
			if len(s.Rhs) != 1 {
				return true
			}
			if fn := corrosionWrite(s.Rhs[0]); fn != "" && allBlank(s.Lhs) {
				report(s, fn)
			}
		case *ast.GoStmt:
			// `go corrosion.X(...)` inherently discards the return.
			if fn := corrosionWrite(s.Call); fn != "" {
				report(s, fn)
			}
		case *ast.DeferStmt:
			// `defer corrosion.X(...)` inherently discards the return.
			if fn := corrosionWrite(s.Call); fn != "" {
				report(s, fn)
			}
		}
		return true
	})
	return out, nil
}

// corrosionWrite returns the guarded function name if expr is a call of the form
// corrosion.<GuardedFn>(...), else "".
func corrosionWrite(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "corrosion" {
		return ""
	}
	if guarded[sel.Sel.Name] {
		return sel.Sel.Name
	}
	return ""
}

// allBlank reports whether every left-hand side is the blank identifier `_`.
func allBlank(lhs []ast.Expr) bool {
	for _, e := range lhs {
		id, ok := e.(*ast.Ident)
		if !ok || id.Name != "_" {
			return false
		}
	}
	return len(lhs) > 0
}
