package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
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
// nowhere else in its own package is a door that was built and never opened.
// (Unexported is the tractable case — its callers can only be in the same
// package, so this needs no whole-program call graph. An exported writer with no
// caller is a dead API, which is a different and much less dangerous mistake.)
//
// Tests deliberately do NOT count as callers: a shape exercised only by tests is
// exactly the failure this guard exists to name.
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
	// Count every identifier occurrence in non-test source. A declaration is one
	// occurrence; anything referenced by real code appears at least twice.
	uses := map[string]int{}
	for _, pkg := range pkgs {
		for i, file := range pkg.Syntax {
			if i < len(pkg.CompiledGoFiles) && strings.HasSuffix(pkg.CompiledGoFiles[i], "_test.go") {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				switch id := n.(type) {
				case *ast.Ident:
					uses[id.Name]++
				case *ast.SelectorExpr:
					uses[id.Sel.Name]++
				}
				return true
			})
		}
	}

	return unreachableFrom(builders, uses, knownUnwiredEmitters)
}

// unreachableFrom is the guard's decision, split from the package scan so it is
// unit-testable (mirroring computeGaps).
func unreachableFrom(builders map[string]token.Position, uses map[string]int, exempt map[string]string) []string {
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
		if uses[name] > 1 {
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
