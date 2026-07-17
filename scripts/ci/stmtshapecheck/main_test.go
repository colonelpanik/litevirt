package main

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestScanPkg_Fixtures loads the testdata fixture package with type info and asserts the
// guard classifies each call/dataflow pattern correctly: direct calls, const SQL, inline /
// appended / helper-returned / guarded batches (resolved); shadowed params, unkeyed
// composites, and recursive helpers (unresolved, fail closed); a runtime-built statement
// (dynamic); and an unrelated Execute method (ignored, not flagged). It also proves the
// recursion guard terminates.
func TestScanPkg_Fixtures(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./testdata/fixtures")
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("fixture package has load/type errors")
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 fixture package, got %d", len(pkgs))
	}

	var resolved, dynamic, unresolved, parseErr int
	byLineOK := map[int]bool{} // line -> classified (any)
	for _, f := range scanPkg(pkgs[0]) {
		byLineOK[f.pos.Line] = true
		switch {
		case f.unresolvedBatch:
			unresolved++
		case f.dynamic:
			dynamic++
		case f.parseErr != "":
			parseErr++
		default:
			resolved++
		}
	}

	if parseErr != 0 {
		t.Errorf("parseErr = %d, want 0", parseErr)
	}
	if dynamic != 1 {
		t.Errorf("dynamic = %d, want 1 (DynamicBuilder)", dynamic)
	}
	if unresolved != 3 {
		t.Errorf("unresolved = %d, want 3 (Shadowed, UnkeyedComposite, RecursiveBatch)", unresolved)
	}
	// Direct, ConstBuilder, InlineBatch(×2), AppendedBatch(≥2), HelperReturnBatch, Guarded.
	if resolved < 8 {
		t.Errorf("resolved = %d, want >= 8", resolved)
	}

	// The unrelated text/template Execute must not be flagged: total findings equal the sum
	// of the corrosion-only classifications, so any stray would show up as an extra dynamic
	// (the template SQL arg is a string literal, so it would fingerprint if wrongly matched).
	// Assert by checking the fixture's UnrelatedExecute line produced no finding.
	unrelatedLine := findWantLine(t, "UnrelatedExecute uses text/template")
	if byLineOK[unrelatedLine+1] { // the Execute call is on the next line
		t.Errorf("text/template.Execute at ~line %d was flagged; must be ignored", unrelatedLine+1)
	}
}

// findWantLine returns the 1-based line of the fixture source containing marker.
func findWantLine(t *testing.T, marker string) int {
	t.Helper()
	data, err := os.ReadFile("testdata/fixtures/fix.go")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, marker) {
			return i + 1
		}
	}
	t.Fatalf("marker %q not found in fixture", marker)
	return 0
}
