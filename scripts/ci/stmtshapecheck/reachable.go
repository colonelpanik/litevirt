package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"unicode"

	"golang.org/x/tools/go/packages"
)

// A replicated statement can only ever reach a peer if something CALLS the
// function that builds it. Registration in the ledger proves the shape is
// understood; it proves nothing about the shape being emitted.
//
// That gap is not hypothetical. deleteContainerGuarded / deleteVMGuarded were
// added on 2026-07-28 with their authority-bearing tombstone shapes, were
// unit-tested, entered the ledger — and had no production caller. Every delete
// kept going out on the pre-authority shape, which a receiver silently discards
// once its own row carries an ownership generation. The result was a relocation
// whose source row stayed live on every peer, found on the lab a week later.
//
// So: an UNEXPORTED function that builds replicated SQL and is referenced
// nowhere in its own package is a door that was built and never opened.
// (Unexported is the tractable case — its callers can only be in the same
// package, so this needs no whole-program call graph. An exported writer with no
// caller is a dead API, which is a different and much less dangerous mistake.)
//
// References are resolved through go/types OBJECT IDENTITY, not by counting
// identifier names: a same-named local variable, struct field, or function in
// another package resolves to a different types.Object and does not vouch for
// the builder. (The first version of this guard counted bare identifier
// occurrences across every loaded package into one map, so ANY name collision
// anywhere under internal/... silently exempted a genuinely uncalled builder —
// the exact bug class it exists to catch.) A builder's references from inside
// its OWN body (recursion) are likewise discounted: a function that only calls
// itself is still unreachable.
//
// Tests deliberately do NOT count as callers: the load runs with Tests: false,
// so test files never enter the type information at all. A shape exercised only
// by tests is exactly the failure this guard exists to name.
func unreachableEmitters(pkgs []*packages.Package, findings []finding) []string {
	// Builder function name -> where it builds a replicated statement.
	builders := map[string]token.Position{}
	for _, f := range findings {
		if f.fn == "" || isExportedName(f.fn) {
			continue
		}
		if _, seen := builders[f.fn]; !seen {
			builders[f.fn] = f.pos
		}
	}
	return unreachableFrom(builders, builderReferences(pkgs, builders), knownUnwiredEmitters)
}

// builderDecl is one builder function's resolved declaration: the type-checker
// object every real reference resolves to, plus the source span of its own body
// (so self-references can be discounted).
type builderDecl struct {
	name               string
	file               string
	beginLine, endLine int
}

// builderReferences reports which builders have at least one reference from
// outside their own body, by object identity.
func builderReferences(pkgs []*packages.Package, builders map[string]token.Position) map[string]bool {
	// Resolve each builder name to its types.Object: the FuncDecl whose body
	// CONTAINS the finding's position (same file, enclosing line span). Matching
	// by declaration position rather than by name keeps a same-named method in
	// the same file from standing in for the builder.
	decls := map[types.Object]builderDecl{}
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			for _, d := range file.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Name == nil {
					continue
				}
				want, isBuilder := builders[fd.Name.Name]
				if !isBuilder {
					continue
				}
				begin := pkg.Fset.Position(fd.Pos())
				end := pkg.Fset.Position(fd.End())
				if begin.Filename != want.Filename ||
					want.Line < begin.Line || want.Line > end.Line {
					continue
				}
				if obj := pkg.TypesInfo.Defs[fd.Name]; obj != nil {
					decls[obj] = builderDecl{
						name: fd.Name.Name, file: begin.Filename,
						beginLine: begin.Line, endLine: end.Line,
					}
				}
			}
		}
	}

	referenced := map[string]bool{}
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for id, obj := range pkg.TypesInfo.Uses {
			decl, isBuilder := decls[obj]
			if !isBuilder {
				continue
			}
			use := pkg.Fset.Position(id.Pos())
			if use.Filename == decl.file &&
				use.Line >= decl.beginLine && use.Line <= decl.endLine {
				continue // the builder referencing itself proves nothing
			}
			referenced[decl.name] = true
		}
	}
	return referenced
}

// unreachableFrom is the guard's decision, split from the package scan so it is
// unit-testable (mirroring computeGaps).
func unreachableFrom(builders map[string]token.Position, referenced map[string]bool, exempt map[string]string) []string {
	var gaps []string

	// Known unwired emitters, each needing its own slice rather than a silent
	// weakening of the guard. An entry that is no longer a builder — wired up, or
	// deleted — becomes a failure of its own, so this list cannot quietly rot.
	for name, why := range exempt {
		if _, isBuilder := builders[name]; !isBuilder {
			gaps = append(gaps, fmt.Sprintf(
				"knownUnwiredEmitters lists %s (%s) but it no longer builds a replicated "+
					"statement — remove the exemption", name, why))
		}
	}

	for name, pos := range builders {
		if referenced[name] {
			continue
		}
		if _, known := exempt[name]; known {
			continue
		}
		gaps = append(gaps, fmt.Sprintf(
			"%s: %s builds a replicated statement but nothing in its package calls it — "+
				"a registered shape with no emitter never reaches a peer (see deleteContainerGuarded, 2026-07-28). "+
				"Wire it to its caller, or delete it and drop its ledger entry",
			loc(pos), name))
	}
	return gaps
}

func isExportedName(s string) bool {
	if s == "" {
		return false
	}
	return unicode.IsUpper([]rune(s)[0])
}

// knownUnwiredEmitters are replicated-statement builders with no production
// caller that are NOT being fixed in the change that introduced this guard.
// Each is a real finding; the value maps the name to what wiring it needs.
var knownUnwiredEmitters = map[string]string{
	// Empty. checkClockSkew — the finding this guard produced on 2026-08-02 —
	// is wired; it rides the capability path's fresh Ping. Add an entry only for
	// a builder whose wiring genuinely belongs in a different change, and expect
	// to justify it: an unemitted shape is a feature that silently does nothing.
}
