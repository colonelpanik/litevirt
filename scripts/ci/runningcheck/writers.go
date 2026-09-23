package main

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Rule 6: every FUNCTION that executes SQL writing vms.state must be classified.
//
// Rule 5 inventories STATEMENTS, which closes "somebody added a new state
// write" — but not "somebody added a new FUNCTION that runs an existing one".
// That gap was real and total: rule 5 saw SQL it already knew and passed it,
// while rules 1-4 never looked at the new function because its name was in none
// of their maps. An unrouted call to it published a running VM with no marker
// and CI stayed green.
//
// This pass is type-aware where rules 1-5 are syntax-only, because it has to be.
// Half these statements are package-level consts referenced across files
// (vmCreateBeginSQL, vmCreateCommitSQL), so resolving "what SQL does this
// function execute" needs go/types constant folding — exactly what
// stmtshapecheck already does for the replicated-shape ledger. A statement's
// text is read through TypesInfo, so a literal, a const identifier and a
// constant concatenation all resolve alike.
//
// Deliberately NOT built on corrosion.StmtShape: its parser is unexported, and
// exporting a core replication package's internals to serve a CI guard is a
// bigger decision than this rule needs. writesVMState answers the only question
// asked here — does the SET clause assign `state`, or does the INSERT name it.

// nonPublishingWriters are functions that mention state-writing SQL without
// publishing a runtime with it. Each entry is a claim that has to stay true.
//
// The replication machinery is the whole population: it names statements to
// derive ledger fingerprints or to recognize an inbound shape, never to execute
// a local transition. A function that starts doing both belongs in nonMinting or
// minting instead, and removing it from here is how it gets there.
var nonPublishingWriters = map[string]string{
	"HistoricalShapes":                   "the frozen receive-only shape registry; emits nothing",
	"isGuardedTransitionSQL":             "matches the create-commit statement to recognize it",
	"validateGuardedMutationEntry":       "validates an INBOUND replicated entry against a known shape",
	"validateGuardedCreateBeginEntry":    "validates an INBOUND create-begin entry",
	"validateGuardedTransitionStatement": "validates an INBOUND transition statement",
	"guardedEntryRoleAllowed":            "decides whether a peer role may send a known shape",
	"validateGuardedVMReplaceEntry":      "validates an INBOUND guarded replace batch against its known shapes",
	"vmReplaceStatements":                "builds the cutover batch; ReplaceVM executes it and is registered in minting, where its call site is policed",
}

// literalNonRunningWriters DO execute a state write, but their statement
// hardcodes a state that is not "running", so no call site of theirs can publish
// a runtime. The claim is CHECKED: a test asserts each one's statement assigns
// state a literal other than 'running'. Turning that literal into a bound `?`
// parameter fails the build, which is the edit that would otherwise quietly make
// one of these a publisher.
var literalNonRunningWriters = map[string]string{
	"WriteVMRescheduleProof": "state = 'pending'",
	"FailActionProof":        "state = 'error'",
	"BeginVMCreateOperation": "INSERT ... VALUES (..., 'creating', ...)",
}

// checkWriters loads the module and returns a violation per unclassified writer.
func checkWriters(root string) ([]violation, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir:   root,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./internal/...")
	if err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return nil, fmt.Errorf("%d package load error(s)", n)
	}

	var out []violation
	for _, pkg := range pkgs {
		out = append(out, writersInPkg(pkg)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out, nil
}

func writersInPkg(pkg *packages.Package) []violation {
	var out []violation
	for _, file := range pkg.Syntax {
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if classified(name) {
				continue
			}
			// Only the FIRST offending statement is reported: one violation per
			// function is the actionable unit, and a writer with four statements
			// would otherwise produce four identical messages.
			if sql, pos, found := stateWriteIn(pkg, fd); found {
				p := pkg.Fset.Position(pos)
				out = append(out, violation{
					file: p.Filename,
					line: p.Line,
					msg: fmt.Sprintf("%s executes SQL that writes vms.state but no rule classifies it. "+
						"Add it to nonMinting, minting or clientMethods so its call sites are policed — "+
						"or, if it only NAMES the statement without publishing a runtime, to "+
						"nonPublishingWriters with the reason. Statement: %s", name, shorten(sql)),
				})
			}
		}
	}
	return out
}

// classified reports whether any rule already governs this function name.
func classified(name string) bool {
	if _, ok := nonMinting[name]; ok {
		return true
	}
	if _, ok := minting[name]; ok {
		return true
	}
	if _, ok := clientMethods[name]; ok {
		return true
	}
	if _, ok := nonPublishingWriters[name]; ok {
		return true
	}
	_, ok := literalNonRunningWriters[name]
	return ok
}

// stateWriteIn returns the first constant SQL string in fd that writes vms.state.
func stateWriteIn(pkg *packages.Package, fd *ast.FuncDecl) (string, token.Pos, bool) {
	var sql string
	var pos token.Pos
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if found || n == nil {
			return !found
		}
		e, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		tv, ok := pkg.TypesInfo.Types[e]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			return true
		}
		// Descending into a resolved constant string adds nothing: its operands
		// are fragments, and a leading `UPDATE vms SET state = ?,` fragment
		// matches on its own.
		text := constant.StringVal(tv.Value)
		if writesVMState(normalizeSQL(text)) {
			sql, pos, found = text, e.Pos(), true
		}
		return false
	})
	return sql, pos, found
}

// shorten keeps a violation message to one readable line.
func shorten(sql string) string {
	s := normalizeSQL(sql)
	if len(s) > 90 {
		return s[:87] + "..."
	}
	return s
}

// staleExemptions returns exemption entries that no longer match any function
// executing a state write. A stale one silently excuses whatever function later
// takes the name — the same self-defeating allowlist the //runningcheck:allow
// directives are checked for.
func staleExemptions(seen map[string]bool) []string {
	var stale []string
	for _, m := range []map[string]string{nonPublishingWriters, literalNonRunningWriters} {
		for name := range m {
			if !seen[name] {
				stale = append(stale, name)
			}
		}
	}
	sort.Strings(stale)
	return stale
}

// stateAssignments returns every value assigned to the state column by a
// normalized statement — `'pending'`, `?`, or an INSERT's positional value.
//
// Used to CHECK literalNonRunningWriters rather than trust it: an exemption
// whose statement has quietly become parameterized is an exemption that now
// covers a publisher.
func stateAssignments(sql string) []string {
	var out []string
	if rest, ok := strings.CutPrefix(sql, "update vms set "); ok {
		if where := strings.Index(rest, " where "); where >= 0 {
			rest = rest[:where]
		}
		for _, assign := range strings.Split(rest, ",") {
			target, value, found := strings.Cut(assign, "=")
			if found && strings.TrimSpace(target) == "state" {
				out = append(out, strings.TrimSpace(value))
			}
		}
		return out
	}
	m := insertVMsRe.FindStringSubmatch(sql)
	if m == nil {
		return nil
	}
	idx := -1
	cols := strings.Split(m[1], ",")
	for i, c := range cols {
		if strings.TrimSpace(c) == "state" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	vi := strings.Index(sql, " values (")
	if vi < 0 {
		return nil
	}
	tail := sql[vi+len(" values ("):]
	if close := strings.Index(tail, ")"); close >= 0 {
		tail = tail[:close]
	}
	vals := strings.Split(tail, ",")
	if idx < len(vals) {
		out = append(out, strings.TrimSpace(vals[idx]))
	}
	return out
}

// stateWritingFuncs returns every function name that executes a state write,
// for the staleness check above and for tests.
func stateWritingFuncs(root string) (map[string]bool, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir:   root,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./internal/...")
	if err != nil {
		return nil, err
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return nil, fmt.Errorf("%d package load error(s)", n)
	}
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			for _, d := range file.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				if _, _, found := stateWriteIn(pkg, fd); found {
					seen[fd.Name.Name] = true
				}
			}
		}
	}
	return seen, nil
}

// asFuncDecl is a test helper kept beside the pass it exercises.
func asFuncDecl(d ast.Decl) *ast.FuncDecl {
	fd, ok := d.(*ast.FuncDecl)
	if !ok || fd.Body == nil {
		return nil
	}
	return fd
}
