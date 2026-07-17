package main

import (
	"testing"

	"golang.org/x/tools/go/packages"
)

// classCount is a per-builder tally of finding classes.
type classCount struct{ resolved, dynamic, unresolved, parseErr int }

// TestScanPkg_Fixtures loads the testdata fixture package with type info and asserts the
// EXACT classification and multiplicity the guard produces for each builder function, so a
// dropped case can't be masked by a duplicated one (review finding 3). Covers direct/const
// calls, inline/appended/helper/guarded batches, shadowing, assignment-after-call,
// non-dominating parameter reassignment, the same helper twice, unkeyed composites,
// in-place field/index mutation + slice escape to an opaque helper, recursion (no hang),
// a runtime-built statement, and an unrelated Execute method.
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

	got := map[string]*classCount{}
	for _, f := range scanPkg(pkgs[0]) {
		cc := got[f.fn]
		if cc == nil {
			cc = &classCount{}
			got[f.fn] = cc
		}
		switch {
		case f.unresolvedBatch:
			cc.unresolved++
		case f.dynamic:
			cc.dynamic++
		case f.parseErr != "":
			cc.parseErr++
		default:
			cc.resolved++
		}
	}

	want := map[string]classCount{
		"Direct":             {resolved: 1},
		"ConstBuilder":       {resolved: 1},
		"InlineBatch":        {resolved: 2},
		"AppendedBatch":      {resolved: 2},
		"HelperReturnBatch":  {resolved: 1},
		"Guarded":            {resolved: 1},
		"SameHelperTwice":    {resolved: 2}, // finding 4: visited set popped, both calls resolve
		"Shadowed":           {unresolved: 1},
		"AssignAfterCall":    {unresolved: 1}, // finding 1: post-call assignment ignored
		"CondParam":          {unresolved: 1}, // finding 1: non-dominating param def rejected
		"UnkeyedComposite":   {unresolved: 1}, // finding 3: non-empty keyless Statement fails closed
		"RecursiveBatch":     {unresolved: 1},
		"FieldMutation":      {unresolved: 1}, // escape: stmt.SQL rewritten before the call
		"IndexedReplacement": {unresolved: 1}, // escape: stmts[i] replaced before the call
		"HelperMutation":     {unresolved: 1}, // escape: slice passed to opaque helper
		"DynamicBuilder":     {dynamic: 1},
	}
	for fn, exp := range want {
		cc := got[fn]
		if cc == nil {
			t.Errorf("%s: no findings, want %+v", fn, exp)
			continue
		}
		if *cc != exp {
			t.Errorf("%s: got %+v, want %+v", fn, *cc, exp)
		}
	}
	// UnrelatedExecute (text/template.Execute) and pure helpers must produce nothing.
	for fn := range got {
		if _, expected := want[fn]; !expected {
			t.Errorf("unexpected findings attributed to %q: %+v", fn, *got[fn])
		}
	}
}

// TestCheckPolicy covers the policy-acceptance logic (review findings 1/2): an unknown,
// empty, or missing-ledger-expansion policy must be rejected; only a registered, nonempty
// policy whose every expansion is in the ledger is accepted.
func TestCheckPolicy(t *testing.T) {
	inLedger := func(present ...string) func(string) bool {
		set := map[string]bool{}
		for _, p := range present {
			set[p] = true
		}
		return func(fp string) bool { return set[fp] }
	}
	cases := []struct {
		name       string
		fps        []string
		registered bool
		ledger     func(string) bool
		want       bool
	}{
		{"unknown policy", nil, false, inLedger(), false},
		{"empty policy", []string{}, true, inLedger(), false},
		{"expansion missing from ledger", []string{"fpA"}, true, inLedger(), false},
		{"partially missing", []string{"fpA", "fpB"}, true, inLedger("fpA"), false},
		{"all expansions in ledger", []string{"fpA", "fpB"}, true, inLedger("fpA", "fpB"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := checkPolicy(c.fps, c.registered, c.ledger); got != c.want {
				t.Fatalf("checkPolicy = %v, want %v", got, c.want)
			}
		})
	}
}
