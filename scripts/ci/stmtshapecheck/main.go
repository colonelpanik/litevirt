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
	fn              string // enclosing builder function (for diagnostics/tests)
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
	emitLedger := flag.Bool("emit-ledger", false, "print the generated stmtledger_generated.go (redirect to that file)")
	emitHistorical := flag.Bool("emit-historical", false, "print the generated stmtledger_historical.go (redirect to that file)")
	flag.Parse()

	if *emitHistorical {
		if err := emitHistoricalLedger(); err != nil {
			fmt.Fprintf(os.Stderr, "stmtshapecheck: emit-historical: %v\n", err)
			os.Exit(1)
		}
		return
	}

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

	if *emitLedger {
		if err := emitGeneratedLedger(findings); err != nil {
			fmt.Fprintf(os.Stderr, "stmtshapecheck: emit-ledger: %v\n", err)
			os.Exit(1)
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

// dispIdent / catIdent map a derived disposition/category back to its Go identifier so the
// generated ledger references the exported constants rather than opaque string values.
var dispIdent = map[corrosion.Disposition]string{
	corrosion.DispPlainInsert:         "DispPlainInsert",
	corrosion.DispExplicitUpsert:      "DispExplicitUpsert",
	corrosion.DispFullPKUpdate:        "DispFullPKUpdate",
	corrosion.DispFullPKUpdateNoClock: "DispFullPKUpdateNoClock",
	corrosion.DispBulkUpdate:          "DispBulkUpdate",
	corrosion.DispDeleteRetention:     "DispDeleteRetention",
	corrosion.DispAppendOnly:          "DispAppendOnly",
	corrosion.DispCustomMerge:         "DispCustomMerge",
	corrosion.DispReject:              "DispReject",
	corrosion.DispCanonicalRegistry:   "DispCanonicalRegistry",
}

var catIdent = map[corrosion.ConcurrencyCategory]string{
	corrosion.CatMonotonic:   "CatMonotonic",
	corrosion.CatPerRowLWW:   "CatPerRowLWW",
	corrosion.CatUnsupported: "CatUnsupported",
}

// emitHistoricalLedger expands the parameterized historical shape families
// (corrosion.HistoricalShapes — prior-release shapes the current tree no longer emits) into
// checked-in historical ledger entries with provenance, and prints stmtledger_historical.go.
// Shapes whose fingerprint is already in the current ledger are skipped (not historical-only).
func emitHistoricalLedger() error {
	byFP := map[string]string{}
	family := map[string][]string{}
	for _, hs := range corrosion.HistoricalShapes() {
		le, err := corrosion.LedgerEntryFor(hs.SQL)
		if err != nil {
			return fmt.Errorf("derive historical entry for %q: %w", hs.SQL, err)
		}
		if corrosion.CurrentLedgerHas(le.Fingerprint) {
			continue // already a CURRENT-build shape; not historical-only (must not use
			// LedgerLookup here — it also matches already-generated historical entries)
		}
		le.FirstEmitter, le.RemovalHorizon = hs.FirstEmitter, hs.Removal
		rendered, err := renderLedgerEntry(le)
		if err != nil {
			return fmt.Errorf("%q: %w", hs.SQL, err)
		}
		if prev, dup := byFP[le.Fingerprint]; dup {
			if prev != rendered {
				return fmt.Errorf("fingerprint %s derived two different historical entries", le.Fingerprint)
			}
			continue
		}
		byFP[le.Fingerprint] = rendered
		family[hs.Family] = append(family[hs.Family], le.Fingerprint)
	}

	fps := make([]string, 0, len(byFP))
	for fp := range byFP {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	fams := make([]string, 0, len(family))
	for f := range family {
		fams = append(fams, f)
	}
	sort.Strings(fams)

	var b strings.Builder
	b.WriteString("// Code generated by \"stmtshapecheck -emit-historical\"; DO NOT EDIT.\n\n")
	b.WriteString("package corrosion\n\n")
	b.WriteString("// historicalLedger holds prior-release statement shapes the current tree no longer\n")
	b.WriteString("// emits, expanded from the parameterized families in stmthistorical.go. A CI rule forbids\n")
	b.WriteString("// deleting an entry whose FirstEmitter is still a supported peer.\n")
	b.WriteString("var historicalLedger = map[string]LedgerEntry{\n")
	for _, fp := range fps {
		fmt.Fprintf(&b, "\t%q: %s,\n", fp, byFP[fp])
	}
	b.WriteString("}\n\n")
	b.WriteString("// historicalPolicies groups each historical shape family's expansion fingerprints, so the\n")
	b.WriteString("// no-delete rule can reason per family.\n")
	b.WriteString("var historicalPolicies = map[string][]string{\n")
	for _, f := range fams {
		list := family[f]
		sort.Strings(list)
		fmt.Fprintf(&b, "\t%q: {\n", f)
		for _, fp := range list {
			fmt.Fprintf(&b, "\t\t%q,\n", fp)
		}
		b.WriteString("\t},\n")
	}
	b.WriteString("}\n")
	fmt.Print(b.String())
	return nil
}

// renderLedgerEntry renders a LedgerEntry as a Go composite literal, emitting every field the
// apply path relies on (Disposition, Category, MonotoneColumn, and any provenance) so a
// generated entry never silently drops one.
func renderLedgerEntry(le corrosion.LedgerEntry) (string, error) {
	di, ok := dispIdent[le.Disposition]
	if !ok {
		return "", fmt.Errorf("unknown disposition %q", le.Disposition)
	}
	parts := []string{
		fmt.Sprintf("Fingerprint: %q", le.Fingerprint),
		fmt.Sprintf("Kind: %q", le.Kind),
		fmt.Sprintf("Table: %q", le.Table),
		"Disposition: " + di,
	}
	if le.Category != corrosion.CatNone {
		ci := catIdent[le.Category]
		if ci == "" {
			return "", fmt.Errorf("unknown category %q", le.Category)
		}
		parts = append(parts, "Category: "+ci)
	}
	if le.MonotoneColumn != "" {
		parts = append(parts, fmt.Sprintf("MonotoneColumn: %q", le.MonotoneColumn))
	}
	// Activation/version conditions (Part H). Rendered whenever set so regeneration never
	// silently drops them once H1/H2 begins populating them.
	if le.MinSchema != 0 {
		parts = append(parts, fmt.Sprintf("MinSchema: %d", le.MinSchema))
	}
	if le.MaxSchema != 0 {
		parts = append(parts, fmt.Sprintf("MaxSchema: %d", le.MaxSchema))
	}
	if le.RequiresCapability != "" {
		parts = append(parts, fmt.Sprintf("RequiresCapability: %q", le.RequiresCapability))
	}
	if le.DispositionAfter != "" {
		da, ok := dispIdent[le.DispositionAfter]
		if !ok {
			return "", fmt.Errorf("unknown DispositionAfter %q", le.DispositionAfter)
		}
		parts = append(parts, "DispositionAfter: "+da)
	}
	if le.TransformerID != "" {
		parts = append(parts, fmt.Sprintf("TransformerID: %q", le.TransformerID))
	}
	if le.FirstEmitter != "" {
		parts = append(parts, fmt.Sprintf("FirstEmitter: %q", le.FirstEmitter))
	}
	if le.LastEmitter != "" {
		parts = append(parts, fmt.Sprintf("LastEmitter: %q", le.LastEmitter))
	}
	if le.RemovalHorizon != "" {
		parts = append(parts, fmt.Sprintf("RemovalHorizon: %q", le.RemovalHorizon))
	}
	return "{" + strings.Join(parts, ", ") + "}", nil
}

// emitGeneratedLedger derives a ledger entry for every resolved builder statement and prints
// stmtledger_generated.go. It fails if any statement is dynamic/unparseable/unresolved (the
// ledger would be incomplete) or if two builders share a fingerprint with conflicting
// dispositions (a derivation bug).
func emitGeneratedLedger(findings []finding) error {
	byFP := map[string]string{}
	for _, f := range findings {
		if f.unresolvedBatch || f.dynamic || f.parseErr != "" {
			return fmt.Errorf("%s: statement not statically resolvable; refusing to emit an incomplete ledger", loc(f.pos))
		}
		le, err := corrosion.LedgerEntryFor(f.sql)
		if err != nil {
			return fmt.Errorf("%s: derive ledger entry: %w (%q)", loc(f.pos), err, f.sql)
		}
		rendered, err := renderLedgerEntry(le)
		if err != nil {
			return fmt.Errorf("%s: %w", loc(f.pos), err)
		}
		if prev, dup := byFP[le.Fingerprint]; dup && prev != rendered {
			return fmt.Errorf("fingerprint %s derived two different entries: %s vs %s", le.Fingerprint, prev, rendered)
		}
		byFP[le.Fingerprint] = rendered
	}

	fps := make([]string, 0, len(byFP))
	for fp := range byFP {
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	var b strings.Builder
	b.WriteString("// Code generated by \"stmtshapecheck -emit-ledger\"; DO NOT EDIT.\n\n")
	b.WriteString("package corrosion\n\n")
	b.WriteString("// stmtLedger is the checked-in compatibility ledger: every replicated builder\n")
	b.WriteString("// statement's stmtshape/v1 fingerprint and the disposition the apply path uses. A\n")
	b.WriteString("// fingerprint absent here is an unknown shape and is rejected (back-pressured).\n")
	b.WriteString("var stmtLedger = map[string]LedgerEntry{\n")
	for _, fp := range fps {
		fmt.Fprintf(&b, "\t%q: %s,\n", fp, byFP[fp])
	}
	b.WriteString("}\n")
	fmt.Print(b.String())
	return nil
}

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
				// Fresh scanner (fresh recursion-visited set) per call site; only
				// assignments before this call may define its batch argument.
				s := &scanner{pkg: pkg, funcByName: funcByName, pol: pol, fn: fd, callPos: call.Pos(), visited: map[*ast.FuncDecl]bool{}}
				var got []finding
				switch method {
				case "Execute", "ExecuteRows", "ExecuteDeferred":
					if len(call.Args) >= 2 {
						got = []finding{resolveSQL(pkg, call.Args[1], pol(call))}
					}
				case "ExecuteBatch": // (ctx, stmts)
					if len(call.Args) >= 2 {
						got = s.resolveBatchArg(call.Args[1], pol(call))
					}
				case "ExecuteBatchGuarded": // (ctx, guard, stmts)
					if len(call.Args) >= 3 {
						got = s.resolveBatchArg(call.Args[2], pol(call))
					}
				}
				for i := range got {
					got[i].fn = fd.Name.Name // attribute to the calling builder
				}
				out = append(out, got...)
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
	callPos    token.Pos              // only assignments BEFORE this position may define the batch arg
	visited    map[*ast.FuncDecl]bool // helper-recursion guard, shared across nested scanners
}

// isLocalDefinable reports whether obj is a function-local variable whose value at the call
// can be established from assignments in the body. Parameters, results, the receiver, and
// package-level globals are rejected (conservative, review finding 1): their value can enter
// from outside or be set on a non-dominating path, so they cannot be proven resolved here.
func (s *scanner) isLocalDefinable(obj types.Object) bool {
	if obj == nil || obj.Parent() == s.pkg.Types.Scope() {
		return false
	}
	inFields := func(fl *ast.FieldList) bool {
		if fl == nil {
			return false
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				if s.pkg.TypesInfo.ObjectOf(n) == obj {
					return true
				}
			}
		}
		return false
	}
	if inFields(s.fn.Recv) || inFields(s.fn.Type.Params) || inFields(s.fn.Type.Results) {
		return false
	}
	return true
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
	if !s.isLocalDefinable(target) {
		return nil // param/global/result ⇒ cannot prove; caller fails closed
	}
	if s.escapes(target, false) {
		// A field write (stmt.SQL=…) or address escape (&stmt) can change the executed SQL
		// after the composite was fingerprinted ⇒ fail closed (finding: in-place mutation).
		return []finding{{pos: s.pkg.Fset.Position(target.Pos()), unresolvedBatch: true, policy: pol}}
	}
	var out []finding
	found := false
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || !s.precedesCall(as) || !s.assignsTo(as, target) {
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

// precedesCall reports whether n occurs before the call being resolved. Combined with the
// param/global rejection this is a conservative stand-in for reaching-definition dominance:
// an assignment after the call, or to a value that can enter from outside, cannot count.
func (s *scanner) precedesCall(n ast.Node) bool {
	return s.callPos == token.NoPos || n.Pos() < s.callPos
}

// escapes reports whether the tracked value is mutated in place, or its identity escapes to
// code the guard cannot see, BEFORE the call — so the SQL actually executed may differ from
// the composite the resolver fingerprinted, and it must fail closed. It detects, before the
// call: a field/element write rooted at the object (x.SQL=…, s[i]=…, s[i].SQL=…); taking its
// address (&x, &s[i], &x.SQL); and — for a slice, whose backing array is shared — passing it
// to any call other than a mutation-safe builtin / a read-only Execute* sink.
func (s *scanner) escapes(target types.Object, isSlice bool) bool {
	escaped := false
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		if escaped || n == nil {
			return !escaped
		}
		if !s.precedesCall(n) {
			return true
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if _, plain := l.(*ast.Ident); plain {
					continue // plain reassignment of the root is modeled by the resolvers
				}
				if s.rootsAt(l, target) {
					escaped = true // x.SQL = …, s[i] = …, s[i].SQL = …
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && s.rootsAt(x.X, target) {
				escaped = true // &x / &s[i] / &x.SQL — the value can be mutated through the pointer
			}
		case *ast.CallExpr:
			if isMutationSafeCall(x) {
				return true
			}
			for _, a := range x.Args {
				if id, ok := a.(*ast.Ident); ok && isSlice && s.pkg.TypesInfo.ObjectOf(id) == target {
					escaped = true // a slice shares its backing array → the callee may mutate it
				}
			}
		}
		return true
	})
	return escaped
}

// rootsAt reports whether the root identifier of an lvalue/address expression is target.
func (s *scanner) rootsAt(e ast.Expr, target types.Object) bool {
	id := rootIdent(e)
	return id != nil && s.pkg.TypesInfo.ObjectOf(id) == target
}

func rootIdent(e ast.Expr) *ast.Ident {
	for {
		switch x := e.(type) {
		case *ast.Ident:
			return x
		case *ast.SelectorExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		default:
			return nil
		}
	}
}

// isMutationSafeCall whitelists calls that cannot mutate a tracked value's SQL: the append/
// make/len/cap builtins and a read-only corrosion Execute* sink.
func isMutationSafeCall(x *ast.CallExpr) bool {
	switch fn := x.Fun.(type) {
	case *ast.Ident:
		switch fn.Name {
		case "append", "make", "len", "cap":
			return true
		}
	case *ast.SelectorExpr:
		if isReplicatingMethod(fn.Sel.Name) {
			return true
		}
	}
	return false
}

// resolveSliceVar collects statements assigned to a []Statement local (by object identity)
// via `:=`/`=` initialization and `append(v, …)` within the enclosing function.
func (s *scanner) resolveSliceVar(target types.Object, pol string) []finding {
	if !s.isLocalDefinable(target) {
		return nil // param/global/result ⇒ cannot prove; caller fails closed
	}
	if s.escapes(target, true) {
		// An element write (stmts[i]=…), address escape (&stmts[i]), or passing the slice —
		// whose backing array is shared — to unknown code can change the executed SQL after
		// the composite was fingerprinted ⇒ fail closed.
		return []finding{{pos: s.pkg.Fset.Position(target.Pos()), unresolvedBatch: true, policy: pol}}
	}
	var out []finding
	found := false
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || !s.precedesCall(as) || !s.assignsTo(as, target) {
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
		return nil // on the active call stack ⇒ genuine recursion; stop
	}
	// Stack semantics: mark for the duration of THIS descent, then pop — so the same
	// non-recursive helper called twice in one batch is not mistaken for recursion.
	s.visited[fd] = true
	defer delete(s.visited, fd)
	inner := &scanner{pkg: s.pkg, funcByName: s.funcByName, pol: s.pol, fn: fd, visited: s.visited}
	var out []finding
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		r0 := ret.Results[0]
		// Within the helper, its own statements are built before this return.
		inner.callPos = ret.Pos()
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
	return checkPolicy(fps, ok, func(fp string) bool {
		_, has := corrosion.LedgerLookup(fp)
		return has
	})
}

// checkPolicy is the pure validation: a policy is acceptable only if it is registered,
// nonempty, and every expansion fingerprint exists in the ledger. (Injectable for tests.)
func checkPolicy(fps []string, registered bool, ledgerHas func(string) bool) bool {
	if !registered || len(fps) == 0 {
		return false
	}
	for _, fp := range fps {
		if !ledgerHas(fp) {
			return false
		}
	}
	return true
}
