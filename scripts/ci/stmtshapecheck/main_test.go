package main

import (
	"go/token"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestComputeGaps_UnregisteredStaticBuilderFails (review 5e): the COMPLETE guard decision must FAIL a
// static, parseable replicated builder whose fingerprint is absent from the ledger — not merely
// classify it as resolved. Uses a synthetic INSERT with an extra column no builder emits, so it
// parses to a fingerprint that is not registered.
func TestComputeGaps_UnregisteredStaticBuilderFails(t *testing.T) {
	const sql = `INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at, bogus_extra) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	fp, err := corrosion.FingerprintSQL(sql)
	if err != nil {
		t.Fatalf("synthetic fixture must parse to a fingerprint: %v", err)
	}
	if _, ok := corrosion.LedgerLookup(fp); ok {
		t.Fatal("fixture precondition failed: the synthetic shape must NOT be in the ledger")
	}
	// A correctly-classified resolved finding (has fp, no parse/dynamic error) must still gap.
	f := finding{pos: token.Position{Filename: "synthetic.go", Line: 1}, sql: sql, fp: fp}
	gaps := computeGaps([]finding{f})
	if len(gaps) != 1 {
		t.Fatalf("an unregistered static builder must produce exactly one gap, got %d: %v", len(gaps), gaps)
	}
	// A registered statement produces no gap (control).
	reg := `INSERT OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	regFP, err := corrosion.FingerprintSQL(reg)
	if err != nil {
		t.Fatalf("control statement must parse: %v", err)
	}
	if _, ok := corrosion.LedgerLookup(regFP); !ok {
		t.Fatal("precondition: the control statement (a real images builder) must be registered — ledger drift must not silently weaken this test")
	}
	if g := computeGaps([]finding{{pos: token.Position{Filename: "x.go", Line: 1}, sql: reg, fp: regFP}}); len(g) != 0 {
		t.Fatalf("a registered static builder must produce no gap, got %v", g)
	}
}

// TestGuardE2E_UnregisteredStaticBuilderGaps (review 4): the true end-to-end path — SCAN a synthetic
// static builder from the fixture package, locate its finding, and feed it through computeGaps. The
// finding is correctly classified as resolved (it parses to a fingerprint), yet the complete guard
// decision must FAIL it because that fingerprint is not in the ledger.
func TestGuardE2E_UnregisteredStaticBuilderGaps(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./testdata/fixtures")
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 || len(pkgs) != 1 {
		t.Fatalf("fixture package load error (pkgs=%d)", len(pkgs))
	}

	var target *finding
	for _, f := range scanPkg(pkgs[0]) {
		if f.fn == "UnregisteredStatic" {
			ff := f
			target = &ff
			break
		}
	}
	if target == nil {
		t.Fatal("scanPkg did not find the UnregisteredStatic builder")
	}
	// It must be a RESOLVED finding (parsed to a fingerprint), not dynamic/unresolved/parse-error.
	if target.dynamic || target.unresolvedBatch || target.parseErr != "" || target.fp == "" {
		t.Fatalf("UnregisteredStatic should classify as a resolved finding, got %+v", *target)
	}
	// And its shape must genuinely be absent from the ledger.
	if _, ok := corrosion.LedgerLookup(target.fp); ok {
		t.Fatal("precondition: the fixture shape must NOT be registered")
	}
	if gaps := computeGaps([]finding{*target}); len(gaps) != 1 {
		t.Fatalf("the complete guard must FAIL an unregistered static builder, got %d gaps: %v", len(gaps), gaps)
	}
}

// TestRenderLedgerEntry_AllFields verifies the generator renders EVERY LedgerEntry field it is
// given, so regeneration can't silently drop an activation/provenance field once H1/H2 begins
// populating them (finding 3).
func TestRenderLedgerEntry_AllFields(t *testing.T) {
	e := corrosion.LedgerEntry{
		Fingerprint:        "fp",
		Kind:               "update",
		Table:              "t",
		Disposition:        corrosion.DispBulkUpdate,
		Category:           corrosion.CatPerRowLWW,
		MonotoneColumn:     "last_used_at",
		MinSchema:          42,
		MaxSchema:          43,
		RequiresCapability: "canonical_identity_v1",
		DispositionAfter:   corrosion.DispFullPKUpdate,
		TransformerID:      "legacy_x",
		FirstEmitter:       "v1.3.0",
		LastEmitter:        "v1.4.0",
		RemovalHorizon:     "v1.5.0",
	}
	got, err := renderLedgerEntry(e)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		`Fingerprint: "fp"`, `Kind: "update"`, `Table: "t"`,
		"Disposition: DispBulkUpdate", "Category: CatPerRowLWW",
		`MonotoneColumn: "last_used_at"`, "MinSchema: 42", "MaxSchema: 43",
		`RequiresCapability: "canonical_identity_v1"`, "DispositionAfter: DispFullPKUpdate",
		`TransformerID: "legacy_x"`, `FirstEmitter: "v1.3.0"`, `LastEmitter: "v1.4.0"`,
		`RemovalHorizon: "v1.5.0"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered entry missing %q\n got: %s", want, got)
		}
	}
}

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
		"UnregisteredStatic": {resolved: 1}, // parses to a fp, but the shape isn't in the ledger
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
