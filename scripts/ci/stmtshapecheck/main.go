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
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const corrosionPkgPath = "github.com/litevirt/litevirt/internal/corrosion"

type finding struct {
	pos             token.Position
	sql             string
	dynamic         bool // SQL is not a compile-time constant (runtime-built)
	unresolvedBatch bool // an ExecuteBatch arg that could not be statically enumerated
	policy          string
	fp              string
	parseErr        string
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
			case f.unresolvedBatch:
				fmt.Printf("%s\tUNRESOLVED-BATCH\tpolicy=%q\n", loc(f.pos), f.policy)
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
		case f.unresolvedBatch:
			if !policyOK(f.policy) {
				gaps = append(gaps, fmt.Sprintf("%s: ExecuteBatch argument could not be statically enumerated and has no valid //stmtshape:policy", loc(f.pos)))
			}
		case f.dynamic:
			if !policyOK(f.policy) {
				gaps = append(gaps, fmt.Sprintf("%s: dynamically-built replicated SQL with no valid //stmtshape:policy directive", loc(f.pos)))
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
	pol := func(n ast.Node) string {
		return policyBetween(policyAt, pkg.Fset.Position(n.Pos()).Filename,
			pkg.Fset.Position(n.Pos()).Line, pkg.Fset.Position(n.End()).Line)
	}
	// Index package funcs so a batch built by a helper can be resolved one level deep.
	funcByName := map[string]*ast.FuncDecl{}
	for _, file := range pkg.Syntax {
		for _, d := range file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				funcByName[fd.Name.Name] = fd
			}
		}
	}

	for _, file := range pkg.Syntax {
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			// Skip the corrosion Client's own Execute*/exec* plumbing: it constructs
			// Statement values from its parameters, and those are not builders.
			if isPlumbingMethod(pkg, fd) {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				method := sel.Sel.Name
				if !isReplicatingMethod(method) {
					return true
				}
				selection := pkg.TypesInfo.Selections[sel]
				if selection == nil || selection.Kind() != types.MethodVal || !isCorrosionClient(selection.Recv()) {
					return true
				}
				// Fresh scanner (fresh recursion-visited set) per call site.
				s := &scanner{pkg: pkg, funcByName: funcByName, pol: pol, fn: fd, visited: map[*ast.FuncDecl]bool{}}
				switch method {
				case "Execute", "ExecuteRows", "ExecuteDeferred":
					if len(call.Args) >= 2 {
						out = append(out, resolveSQL(pkg, call.Args[1], pol(call)))
					}
				case "ExecuteBatch": // (ctx, stmts)
					if len(call.Args) >= 2 {
						out = append(out, s.resolveBatchArg(call.Args[1], pol(call))...)
					}
				case "ExecuteBatchGuarded": // (ctx, guard, stmts)
					if len(call.Args) >= 3 {
						out = append(out, s.resolveBatchArg(call.Args[2], pol(call))...)
					}
				}
				return true
			})
		}
	}
	return out
}

func isReplicatingMethod(m string) bool {
	switch m {
	case "Execute", "ExecuteRows", "ExecuteDeferred", "ExecuteBatch", "ExecuteBatchGuarded":
		return true
	}
	return false
}

// isPlumbingMethod reports whether fd is a *corrosion.Client method that itself constructs/
// applies Statements (the Execute* wrappers, executeBatchInternal, execLocal*/execBatchLocal),
// as opposed to a builder that calls them.
func isPlumbingMethod(pkg *packages.Package, fd *ast.FuncDecl) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	if !isCorrosionClient(pkg.TypesInfo.TypeOf(fd.Recv.List[0].Type)) {
		return false
	}
	switch fd.Name.Name {
	case "Execute", "ExecuteRows", "ExecuteDeferred", "ExecuteBatch", "ExecuteBatchGuarded",
		"executeBatchInternal", "execLocal", "execLocalRows", "execBatchLocal":
		return true
	}
	return false
}

// scanner carries the context for resolving one function's batch arguments.
type scanner struct {
	pkg        *packages.Package
	funcByName map[string]*ast.FuncDecl
	pol        func(ast.Node) string
	fn         *ast.FuncDecl
	visited    map[*ast.FuncDecl]bool // helper-recursion guard, shared across nested scanners
}

// resolveBatchArg resolves the []Statement argument of an ExecuteBatch* call to the concrete
// statements it carries, following an inline slice literal, a local variable's assignment +
// appends, and one level of helper return. Anything it cannot resolve fails closed.
func (s *scanner) resolveBatchArg(arg ast.Expr, pol string) []finding {
	switch e := arg.(type) {
	case *ast.CompositeLit: // []Statement{ elt, elt, ... }
		var out []finding
		for _, elt := range e.Elts {
			out = append(out, s.resolveStmtElt(elt, pol)...)
		}
		if len(out) == 0 {
			out = append(out, finding{pos: s.pkg.Fset.Position(e.Pos()), unresolvedBatch: true, policy: pol})
		}
		return out
	case *ast.Ident: // a local variable built via `:= []Statement{...}` and/or append(...)
		if obj := s.pkg.TypesInfo.ObjectOf(e); obj != nil {
			if fs := s.resolveSliceVar(obj, pol); fs != nil {
				return fs
			}
		}
	case *ast.CallExpr: // a helper returning []Statement
		if fs := s.resolveHelperReturn(e, pol); fs != nil {
			return fs
		}
	}
	return []finding{{pos: s.pkg.Fset.Position(arg.Pos()), unresolvedBatch: true, policy: pol}}
}

// resolveStmtElt resolves one element of a []Statement literal: a Statement{SQL:...}
// composite, a local Statement variable (traced to its assignment), or a helper call
// returning a Statement.
func (s *scanner) resolveStmtElt(elt ast.Expr, pol string) []finding {
	if u, ok := elt.(*ast.UnaryExpr); ok {
		elt = u.X
	}
	switch e := elt.(type) {
	case *ast.CompositeLit:
		if isCorrosionStatement(s.pkg.TypesInfo.Types[e].Type) {
			if sqlExpr := statementSQLField(e); sqlExpr != nil {
				return []finding{resolveSQL(s.pkg, sqlExpr, pol)}
			}
			// ONLY an entirely empty Statement{} is the intentional zero-value / error-path
			// return (`return Statement{}, err`). Any other composite that lacks a
			// statically-resolvable SQL field (e.g. Statement{Params: …}, or a keyless one)
			// must fail closed rather than be assumed harmless.
			if len(e.Elts) == 0 {
				return []finding{}
			}
			return []finding{{pos: s.pkg.Fset.Position(e.Pos()), unresolvedBatch: true, policy: pol}}
		}
	case *ast.CallExpr:
		if fs := s.resolveHelperReturn(e, pol); fs != nil {
			return fs
		}
	case *ast.Ident:
		if obj := s.pkg.TypesInfo.ObjectOf(e); obj != nil {
			if fs := s.resolveStmtVar(obj, pol); fs != nil {
				return fs
			}
		}
	}
	return []finding{{pos: s.pkg.Fset.Position(elt.Pos()), unresolvedBatch: true, policy: pol}}
}

// assignsTo reports whether any LHS ident of as refers to the SAME object (not merely the
// same name — this defeats shadowing, review finding 2). Uses go/types object identity.
func (s *scanner) assignsTo(as *ast.AssignStmt, target types.Object) bool {
	for _, l := range as.Lhs {
		if lid, ok := l.(*ast.Ident); ok && s.pkg.TypesInfo.ObjectOf(lid) == target {
			return true
		}
	}
	return false
}

// resolveStmtVar traces a local Statement variable (by object identity) to the Statement
// composite or helper call assigned to it within the enclosing function. Over-approximates
// across branches (every assignment to the object is included); any unresolvable assignment
// yields an unresolved finding, so the batch fails closed.
func (s *scanner) resolveStmtVar(target types.Object, pol string) []finding {
	var out []finding
	found := false
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || !s.assignsTo(as, target) {
			return true
		}
		found = true
		out = append(out, s.resolveStmtElt(as.Rhs[0], pol)...)
		return true
	})
	if !found {
		return nil
	}
	if out == nil {
		out = []finding{}
	}
	return out
}

// resolveSliceVar collects statements assigned to a []Statement local (by object identity)
// via `:=`/`=` initialization and `append(v, …)` within the enclosing function.
func (s *scanner) resolveSliceVar(target types.Object, pol string) []finding {
	var out []finding
	found := false
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || !s.assignsTo(as, target) {
			return true
		}
		switch rhs := as.Rhs[0].(type) {
		case *ast.CompositeLit: // v := []Statement{...}
			found = true
			for _, elt := range rhs.Elts {
				out = append(out, s.resolveStmtElt(elt, pol)...)
			}
		case *ast.CallExpr:
			found = true
			if fn, ok := rhs.Fun.(*ast.Ident); ok && fn.Name == "append" { // v = append(v, …)
				for _, a := range rhs.Args[1:] {
					out = append(out, s.resolveStmtElt(a, pol)...)
				}
			} else if fn, ok := rhs.Fun.(*ast.Ident); ok && fn.Name == "make" {
				// v := make([]Statement, …) — an empty init; the appends carry the statements.
			} else if fs := s.resolveHelperReturn(rhs, pol); fs != nil { // v = buildStmts()
				out = append(out, fs...)
			} else {
				out = append(out, finding{pos: s.pkg.Fset.Position(rhs.Pos()), unresolvedBatch: true, policy: pol})
			}
		default:
			found = true
			out = append(out, finding{pos: s.pkg.Fset.Position(as.Rhs[0].Pos()), unresolvedBatch: true, policy: pol})
		}
		return true
	})
	if !found {
		return nil
	}
	if out == nil {
		out = []finding{}
	}
	return out
}

// resolveHelperReturn resolves a call to a package-local helper that returns []Statement or
// Statement by following its `return` expressions one level.
func (s *scanner) resolveHelperReturn(call *ast.CallExpr, pol string) []finding {
	id, ok := call.Fun.(*ast.Ident)
	if !ok {
		return nil
	}
	// Resolve by object identity: only a package-level function (not a local var of the
	// same name, and not a method) is followed.
	if _, isFunc := s.pkg.TypesInfo.ObjectOf(id).(*types.Func); !isFunc {
		return nil
	}
	fd := s.funcByName[id.Name]
	if fd == nil || fd.Body == nil {
		return nil
	}
	if s.visited == nil {
		s.visited = map[*ast.FuncDecl]bool{}
	}
	if s.visited[fd] {
		return nil // recursion guard
	}
	s.visited[fd] = true
	inner := &scanner{pkg: s.pkg, funcByName: s.funcByName, pol: s.pol, fn: fd, visited: s.visited}
	var out []finding
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		r0 := ret.Results[0]
		t := s.pkg.TypesInfo.TypeOf(r0)
		switch {
		case isCorrosionStatement(t):
			found = true
			out = append(out, inner.resolveStmtElt(r0, pol)...)
		case isStatementSlice(t):
			found = true
			out = append(out, inner.resolveBatchArg(r0, pol)...)
		}
		return true
	})
	if !found {
		return nil
	}
	if out == nil {
		out = []finding{}
	}
	return out
}

// isStatementSlice reports whether t is []corrosion.Statement.
func isStatementSlice(t types.Type) bool {
	sl, ok := t.(*types.Slice)
	return ok && isCorrosionStatement(sl.Elem())
}

// resolveSQL turns one SQL argument expression into a finding: a compile-time constant
// string is fingerprinted; anything else is dynamic (authorized only via a policy).
func resolveSQL(pkg *packages.Package, e ast.Expr, pol string) finding {
	pos := pkg.Fset.Position(e.Pos())
	s, ok := constString(pkg, e)
	if !ok {
		return finding{pos: pos, dynamic: true, policy: pol}
	}
	f := finding{pos: pos, sql: s}
	if fp, err := corrosion.FingerprintSQL(s); err != nil {
		f.parseErr = err.Error()
	} else {
		f.fp = fp
	}
	return f
}

// isCorrosionClient reports whether t is *corrosion.Client (or corrosion.Client).
func isCorrosionClient(t types.Type) bool {
	return isCorrosionNamed(t, "Client")
}

// isCorrosionStatement reports whether t is corrosion.Statement (or *corrosion.Statement).
func isCorrosionStatement(t types.Type) bool {
	return isCorrosionNamed(t, "Statement")
}

func isCorrosionNamed(t types.Type, name string) bool {
	if t == nil {
		return false
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == name && obj.Pkg() != nil && obj.Pkg().Path() == corrosionPkgPath
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

// statementSQLField extracts the SQL field value expression from a Statement{SQL: ...}
// composite-literal element (possibly &Statement{...}); returns nil if the element is not a
// composite with a keyed SQL field (e.g. a variable spliced into the slice).
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

// constString returns e's value if it is any compile-time constant string — a string
// literal, a const identifier, or a constant concatenation — so a builder using a `const`
// SQL string is treated as static, not dynamic.
func constString(pkg *packages.Package, e ast.Expr) (string, bool) {
	tv, ok := pkg.TypesInfo.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

// policyOK reports whether a //stmtshape:policy directive names a registered policy that is
// nonempty and whose every declared expansion fingerprint exists in the ledger. This does
// NOT prove the builder's dynamic expression can only produce those fingerprints — that
// requires either refactoring the builder to finite constant statements or a structured
// expression policy (tracked with the four dynamic builders); a bare ID is not enough.
func policyOK(id string) bool {
	if id == "" {
		return false
	}
	fps, ok := corrosion.PolicyLookup(id)
	if !ok || len(fps) == 0 {
		return false
	}
	for _, fp := range fps {
		if _, ok := corrosion.LedgerLookup(fp); !ok {
			return false
		}
	}
	return true
}
