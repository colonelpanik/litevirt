package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanSrc runs the checker over one in-memory file.
func scanSrc(t *testing.T, src string) []violation {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x.go")
	if err := os.WriteFile(path, []byte("package p\n"+src), 0o644); err != nil {
		t.Fatal(err)
	}
	vs, err := scanFile(path)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	return vs
}

func wantNone(t *testing.T, src, why string) {
	t.Helper()
	if vs := scanSrc(t, src); len(vs) != 0 {
		t.Errorf("%s: got %d violation(s), want 0:\n  %s", why, len(vs), vs[0].msg)
	}
}

func wantOne(t *testing.T, src, substr, why string) {
	t.Helper()
	vs := scanSrc(t, src)
	if len(vs) != 1 {
		t.Fatalf("%s: got %d violation(s), want 1", why, len(vs))
	}
	if !strings.Contains(vs[0].msg, substr) {
		t.Errorf("%s: message = %q, want it to mention %q", why, vs[0].msg, substr)
	}
}

// TestUnroutedRunningWriteIsFlagged is the rule the guard exists for.
func TestUnroutedRunningWriteIsFlagged(t *testing.T) {
	wantOne(t, `
func f() {
	corrosion.UpdateVMState(ctx, db, "vm1", "running", "detail")
}`, "not routed", "a bare running write")
}

// TestRoutedRunningWriteIsAccepted: the shape the codebase actually uses.
func TestRoutedRunningWriteIsAccepted(t *testing.T) {
	wantNone(t, `
func f() {
	s.publishRunning(ctx, name, state, func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", "running", "detail")
	})
}`, "an inline routed closure")
}

// TestLiteralNonRunningStateIsExempt: a write that can only ever publish a
// stopped VM has no runtime to prove.
func TestLiteralNonRunningStateIsExempt(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.UpdateVMState(ctx, db, "vm1", "stopped", "operator-stop")
}`, "a literal stopped write")
}

// TestDynamicStateIsNotExempt: a state only known at runtime may be "running",
// so it must be routed. The helper's own state gate makes a uniform wrap correct.
func TestDynamicStateIsNotExempt(t *testing.T) {
	wantOne(t, `
func f() {
	corrosion.UpdateVMState(ctx, db, "vm1", live, "detail")
}`, "not routed", "a runtime-determined state")
}

// TestMintingThroughThePlainHelperIsAFamilyMismatch is the bypass an earlier
// guard rule allowed: routing IS present, so a rule that only asks "is this
// inside a routed closure" passes it — while the mark-then-commit ordering
// stamps the generation the transfer is about to leave.
func TestMintingThroughThePlainHelperIsAFamilyMismatch(t *testing.T) {
	wantOne(t, `
func f() {
	s.publishRunning(ctx, name, state, func(ctx context.Context) error {
		return corrosion.TransferVMOwner(ctx, db, "vm1", "host-a", "running", 3)
	})
}`, "MINTING write routed through", "a minting write in a plain helper")
}

// TestMintingThroughTheMintedHelperIsAccepted.
func TestMintingThroughTheMintedHelperIsAccepted(t *testing.T) {
	wantNone(t, `
func f() {
	s.publishRunningMinted(ctx, name, func(ctx context.Context) error {
		return corrosion.TransferVMOwner(ctx, db, "vm1", "host-a", "running", 3)
	})
}`, "a minting write in the minted helper")
}

// TestMintingHandoffOfAStoppedVMIsExempt: a transfer that hands over a stopped
// VM publishes no runtime, so there is nothing to mark.
func TestMintingHandoffOfAStoppedVMIsExempt(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.TransferVMOwnerFresh(ctx, db, "vm1", "host-b", "stopped")
}`, "a stopped handoff")
}

// TestDirectClosureInvocationIsFlagged is the second bypass an earlier rule
// allowed: the closure IS passed to a helper, so a lexical "is it routed" test
// passes — while the unconditional direct call publishes unmarked anyway.
func TestDirectClosureInvocationIsFlagged(t *testing.T) {
	wantOne(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	commit(ctx)
	return s.publishRunning(ctx, name, state, commit)
}`, "invoked directly", "an unconditional direct invocation")
}

// TestDirectClosureInvocationUnderAProvenBranchIsAccepted: the shape a router
// legitimately uses to skip the row read for a non-running write.
func TestDirectClosureInvocationUnderAProvenBranchIsAccepted(t *testing.T) {
	wantNone(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	if state != "running" {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "a direct invocation under a proven branch")
}

// TestBornRunningInsertNeedsGraduation is the third bypass: an earlier rule
// matched only a literal State: "running", so a dynamic state — which is what
// the clone path actually writes — sailed past it.
func TestBornRunningInsertNeedsGraduation(t *testing.T) {
	wantOne(t, `
func f() {
	corrosion.InsertVMWithHardware(ctx, db, corrosion.VMRecord{
		Name: "vm1", State: state,
	}, nil, nil, nil, nil, false)
}`, "born at", "a dynamic born-running insert")
}

// TestBornRunningInsertWithGraduationIsAccepted.
func TestBornRunningInsertWithGraduationIsAccepted(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.InsertVMWithHardware(ctx, db, corrosion.VMRecord{
		Name: "vm1", State: "running",
	}, nil, nil, nil, nil, false)
	s.assignOwnerEpochAtCreate(ctx, "vm1")
}`, "a graduated born-running insert")
}

// TestStoppedInsertNeedsNoGraduation: a stopped row has no runtime to prove,
// and stamping a generation it did not earn would make the row and the marker
// disagree the moment whatever starts it mints one.
func TestStoppedInsertNeedsNoGraduation(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", State: "stopped",
	}, nil, nil)
}`, "a stopped insert")
}

// TestAllowDirectiveSuppresses, in both placements: trailing on the statement,
// and as a reason block directly above it.
func TestAllowDirectiveSuppresses(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.UpdateVMState(ctx, db, "vm1", "running", "d") //runningcheck:allow handoff
}`, "a trailing directive")

	wantNone(t, `
func f() {
	//runningcheck:allow ownership handoff — the publishing host is not the running host,
	// and its domain has already been undefined by the migration.
	corrosion.UpdateVMState(ctx, db, "vm1", "running", "d")
}`, "a directive block above the statement")
}

// TestUpdateVMHostRunningIsFlagged: UpdateVMHost(ctx, c, name, host, state)
// takes its state at index 4 and writes `UPDATE vms SET host_name = ?, state = ?`.
// It was registered with index -1 under a comment claiming the state travelled
// inside a VMRecord, which made it unconditionally exempt — a hole in the guard
// exactly where a same-host re-point would publish running unmarked.
func TestUpdateVMHostRunningIsFlagged(t *testing.T) {
	wantOne(t, `
func f() {
	corrosion.UpdateVMHost(ctx, db, "vm1", "host-a", "running")
}`, "not routed", "a bare UpdateVMHost running write")
}

// TestUpdateVMHostStoppedIsExempt: the literal exemption does the work now that
// the index is real.
func TestUpdateVMHostStoppedIsExempt(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.UpdateVMHost(ctx, db, "vm1", "host-a", "stopped")
}`, "a stopped UpdateVMHost")
}

// TestClientMethodWriterIsSeen: a writer reached as a METHOD on the corrosion
// client is invisible to a selector test keyed on the package identifier.
// CommitVMCreateOperation's statement is a literal UPDATE vms SET state='running'.
func TestClientMethodWriterIsSeen(t *testing.T) {
	wantOne(t, `
func f() {
	s.db.CommitVMCreateOperation(ctx, "op1", 1, corrosion.VMRecord{
		Name: "vm1", State: "running",
	}, nil, nil, nil, nil)
}`, "born at", "a client-method born-running commit")
}

// TestDisjunctiveConditionDoesNotProveNonRunning is the bypass an OR-as-AND
// reading let through: `state != "running" || force` is entered with state ==
// "running" whenever force is true.
func TestDisjunctiveConditionDoesNotProveNonRunning(t *testing.T) {
	wantOne(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	if state != "running" || force {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "invoked directly", "a disjunctive guard")
}

// TestConjunctiveConditionStillProvesNonRunning: either conjunct proving it is
// enough, because both must hold to enter the branch.
func TestConjunctiveConditionStillProvesNonRunning(t *testing.T) {
	wantNone(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	if state != "running" && ready {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "a conjunctive guard")
}

// TestStaleAllowDirectiveIsFlagged: a directive whose statement was deleted or
// moved silently exempts whatever code next occupies those lines. That is the
// self-defeating allowlist this guard exists to rule out, in the other
// direction.
func TestStaleAllowDirectiveIsFlagged(t *testing.T) {
	wantOne(t, `
func f() {
	//runningcheck:allow ownership handoff — but the call it covered is gone
	x := 1
	_ = x
}`, "suppressed nothing", "an orphaned directive")
}

// TestSecondBornRunningInsertNeedsItsOwnGraduation: the graduation evidence is
// block-scoped, because the routed code already depends on branch placement —
// promote.go graduates inside `if renamed`, templates.go inside
// `if state == "running"`. A function-wide check let a second insert on another
// branch ride on the first branch's call.
func TestSecondBornRunningInsertNeedsItsOwnGraduation(t *testing.T) {
	wantOne(t, `
func f() {
	if renamed {
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "a", State: "running"}, nil, nil)
		s.assignOwnerEpochAtCreate(ctx, "a")
	} else {
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "b", State: "running"}, nil, nil)
	}
}`, "same block", "a second born-running insert with no graduation of its own")
}

// TestPerBranchGraduationIsAccepted: both branches graduating is the shape the
// routed code actually has.
func TestPerBranchGraduationIsAccepted(t *testing.T) {
	wantNone(t, `
func f() {
	if renamed {
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "a", State: "running"}, nil, nil)
		s.assignOwnerEpochAtCreate(ctx, "a")
	} else {
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "b", State: "running"}, nil, nil)
		s.assignOwnerEpochAtCreate(ctx, "b")
	}
}`, "per-branch graduation")
}

// TestHelperArgumentsAreNotTreatedAsClosures: registering every identifier
// argument put ctx, name and state into the routed-variable set, so an
// unrelated local of one of those names was reported as the routed closure
// invoked directly.
func TestHelperArgumentsAreNotTreatedAsClosures(t *testing.T) {
	wantNone(t, `
func f() error {
	if err := s.publishRunning(ctx, name, state, func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}); err != nil {
		return err
	}
	return name(ctx)
}`, "an unrelated call sharing an argument name")
}

// TestProofAboutAnotherStringIsNotAProof: the condition has to be about the
// value the closure will WRITE. Accepting any expression compared against
// "running" made this bypass — a proof about the detail string, of all things —
// read as a proof about the state.
func TestProofAboutAnotherStringIsNotAProof(t *testing.T) {
	wantOne(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, detail)
	}
	if detail != "running" {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "invoked directly", "a proof about an unrelated string")
}

// TestPositiveStateComparisonProvesNonRunning: `state == "stopped"` is as good
// a proof as `state != "running"`, and it is how classifyStop's callers read.
// Rejecting it would have pushed a future site toward a directive instead.
func TestPositiveStateComparisonProvesNonRunning(t *testing.T) {
	wantNone(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	if state == "stopped" {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "a positive comparison against a non-running literal")
}

// TestPositiveRunningComparisonIsNotAProof: the same shape with the literal
// "running" proves the OPPOSITE, and must not be read as a proof.
func TestPositiveRunningComparisonIsNotAProof(t *testing.T) {
	wantOne(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	if state == "running" {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "invoked directly", "a positive comparison against \"running\"")
}

// TestSelectorStateExpressionIsMatched: the state at real call sites is
// `vm.State`, not a bare identifier. The proof must match it through the
// selector, or every routed site in the codebase would need a directive.
func TestSelectorStateExpressionIsMatched(t *testing.T) {
	wantNone(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", vm.State, "d")
	}
	if vm.State != "running" {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, vm.State, commit)
}`, "a proof through the same selector expression")
}

// TestMintedClosureIsNeverProvenNonRunning: a minted helper takes no state
// argument because it ALWAYS publishes running. No branch can disprove that, so
// a direct invocation of its closure is unroutable by construction.
func TestMintedClosureIsNeverProvenNonRunning(t *testing.T) {
	wantOne(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.CompleteVMStartProof(ctx, db, id, "vm1", host)
	}
	if state != "running" {
		return commit(ctx)
	}
	return s.publishRunningMinted(ctx, name, commit)
}`, "invoked directly", "a minted closure under a state proof")
}

// scanCorrosionSrc runs the checker over one in-memory file placed where rule 5
// applies — the rule is corrosion-only, and the package is identified by path.
func scanCorrosionSrc(t *testing.T, src string) []violation {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "corrosion")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "x.go")
	if err := os.WriteFile(path, []byte("package corrosion\n"+src), 0o644); err != nil {
		t.Fatal(err)
	}
	vs, err := scanFile(path)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	return vs
}

// TestUnregisteredStateStatementIsFlagged is rule 5's reason to exist: rules 1-4
// only police writers somebody remembered to name in a map.
func TestUnregisteredStateStatementIsFlagged(t *testing.T) {
	vs := scanCorrosionSrc(t, "const q = `UPDATE vms SET state = ?, updated_at = ? WHERE name = ?`\n")
	if len(vs) != 1 {
		t.Fatalf("got %d violation(s), want 1", len(vs))
	}
	if !strings.Contains(vs[0].msg, "stateWritingStatements") {
		t.Errorf("message = %q, want it to name the inventory", vs[0].msg)
	}
}

// TestRegisteredStateStatementIsAccepted, reflowed: the inventory is matched on
// normalized text, so re-wrapping a statement in corrosion must not fail CI.
func TestRegisteredStateStatementIsAccepted(t *testing.T) {
	vs := scanCorrosionSrc(t, "const q = `UPDATE vms\n"+
		"    SET state = ?, state_detail = ?, updated_at = ?\n"+
		"    WHERE name = ?`\n")
	if len(vs) != 0 {
		t.Errorf("a registered statement, reflowed, got %d violation(s), want 0:\n  %s", len(vs), vs[0].msg)
	}
}

// TestStateDetailIsNotAStateWrite: the near-misses a pattern match would trip
// over. Only the state column itself publishes a runtime.
func TestStateDetailIsNotAStateWrite(t *testing.T) {
	for _, sql := range []string{
		"UPDATE vms SET state_detail = ?, updated_at = ? WHERE name = ?",
		"UPDATE vms SET hardware_adoption_state = ?, updated_at = ? WHERE name = ?",
		"UPDATE vms SET updated_at = ? WHERE name = ? AND state = 'running'",
		"UPDATE vm_disks SET state = ?, updated_at = ? WHERE name = ?",
		"INSERT INTO vms (name, host_name, spec) VALUES (?, ?, ?)",
	} {
		if vs := scanCorrosionSrc(t, "const q = `"+sql+"`\n"); len(vs) != 0 {
			t.Errorf("%q was read as a vms.state write: %s", sql, vs[0].msg)
		}
	}
}

// TestStateStatementsOutsideCorrosionAreAlsoInventoried.
//
// Rule 5 was gated on internal/corrosion under a comment asserting no other
// package holds a vms.state statement — the unenforced assumption rule 5 exists
// to replace. A statement added in internal/health or internal/failover escaped
// the inventory entirely and nothing failed.
func TestStateStatementsOutsideCorrosionAreAlsoInventoried(t *testing.T) {
	wantOne(t, "const q = `UPDATE vms SET state = ?, updated_at = ? WHERE name = ?`\n",
		"stateWritingStatements", "an unregistered state statement outside internal/corrosion")
}

// TestEveryInventoryEntryIsStillPresent: an entry whose statement was deleted or
// edited is the inventory's own stale-directive case. Left in place it silently
// pre-approves whatever statement later normalizes to the same text.
func TestEveryInventoryEntryIsStillPresent(t *testing.T) {
	found := map[string]bool{}
	// _test.go is skipped, exactly as main()'s own walk skips it. internal/corrosion
	// has ~20 test files holding UPDATE vms / INSERT INTO vms literals, so counting
	// them let a fixture mirroring a production statement keep a DEAD entry alive —
	// the silent pre-approval this test exists to prevent.
	err := filepath.WalkDir("../../../internal/corrosion", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		for _, sql := range stateStatementsIn(t, path) {
			found[sql] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/corrosion: %v", err)
	}
	for _, st := range stateWritingStatements {
		if !found[normalizeSQL(st.sql)] {
			t.Errorf("inventory entry %q matches no statement in internal/corrosion any more — "+
				"remove it, or it pre-approves whatever next normalizes to the same text", st.note)
		}
	}
}

// stateStatementsIn returns the normalized vms.state statements a file holds.
func stateStatementsIn(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		bl, ok := n.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return true
		}
		if sql := normalizeSQL(strings.Trim(bl.Value, "`\"")); writesVMState(sql) {
			out = append(out, sql)
		}
		return true
	})
	return out
}

// TestBornRunningInsertInASwitchCaseNeedsItsOwnGraduation.
//
// Rule 4's scope search walked only *ast.BlockStmt, and a switch case is not
// one — so every case fell through to the enclosing function body, where ONE
// case's graduation covered all its siblings. That is the exact function-wide
// hole the block-scoped search was written to close, surviving in the construct
// branchy code reaches for most.
func TestBornRunningInsertInASwitchCaseNeedsItsOwnGraduation(t *testing.T) {
	wantOne(t, `
func f() {
	switch mode {
	case "clone":
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm1", State: "running"}, nil, nil)
		s.assignOwnerEpochAtCreate(ctx, "vm1")
	case "restore":
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm2", State: "running"}, nil, nil)
	}
}`, "assignOwnerEpochAtCreate", "a second switch case inserting without its own graduation")
}

// TestBornRunningInsertInASwitchCaseWithGraduationIsAccepted: the fix must
// narrow rule 4, not break the legitimate shape.
func TestBornRunningInsertInASwitchCaseWithGraduationIsAccepted(t *testing.T) {
	wantNone(t, `
func f() {
	switch mode {
	case "clone":
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm1", State: "running"}, nil, nil)
		s.assignOwnerEpochAtCreate(ctx, "vm1")
	case "restore":
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm2", State: "running"}, nil, nil)
		s.assignOwnerEpochAtCreate(ctx, "vm2")
	}
}`, "every switch case graduating its own insert")
}

// TestBornRunningInsertInASelectCaseNeedsItsOwnGraduation: *ast.CommClause has
// the same shape as CaseClause and the same hole.
func TestBornRunningInsertInASelectCaseNeedsItsOwnGraduation(t *testing.T) {
	wantOne(t, `
func f() {
	select {
	case <-a:
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm1", State: "running"}, nil, nil)
		s.assignOwnerEpochAtCreate(ctx, "vm1")
	case <-b:
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm2", State: "running"}, nil, nil)
	}
}`, "assignOwnerEpochAtCreate", "a second select case inserting without its own graduation")
}

// TestConcatenatedStateStatementIsInventoried.
//
// Rule 5 scanned one *ast.BasicLit at a time, so a statement split across lines
// with `+` — the ordinary way to keep long SQL readable — escaped the inventory:
// neither fragment carries the `update vms set` prefix the matcher needs.
func TestConcatenatedStateStatementIsInventoried(t *testing.T) {
	vs := scanCorrosionSrc(t, "const q = `UPDATE vms SET ` +\n"+
		"\t`state = ?, evil = ? WHERE name = ?`\n")
	if len(vs) != 1 {
		t.Fatalf("got %d violation(s), want 1 — a concatenated statement escaped rule 5", len(vs))
	}
	if !strings.Contains(vs[0].msg, "stateWritingStatements") {
		t.Errorf("message = %q, want it to name the inventory", vs[0].msg)
	}
}

// TestConcatenatedRegisteredStatementIsAccepted: folding must recognise a
// registered statement too, or reflowing one in corrosion breaks CI.
func TestConcatenatedRegisteredStatementIsAccepted(t *testing.T) {
	vs := scanCorrosionSrc(t, "const q = `UPDATE vms SET state = ?, ` +\n"+
		"\t`state_detail = ?, updated_at = ? WHERE name = ?`\n")
	if len(vs) != 0 {
		t.Errorf("got %d violation(s), want 0:\n  %s", len(vs), vs[0].msg)
	}
}

// TestInventoryDumpEmitsAPasteableEntry.
//
// Rule 5's doc and its violation message both tell a maintainer to run
// -inventory to get what to add. It printed map-literal syntax with a stray
// backslash for a SLICE inventory, so the thing they were told to paste was a
// syntax error — and it printed the lowercase normalized text, contradicting the
// inventory's own rule that entries carry the statement in source form.
func TestInventoryDumpEmitsAPasteableEntry(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "corrosion")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "x.go")
	src := "package corrosion\nconst q = `UPDATE vms SET state = ?, evil = ? WHERE name = ?`\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if _, err := scanFileOpts(path, true); err != nil {
			t.Fatalf("scanFileOpts: %v", err)
		}
	})

	// The printed entry must parse as the Go it claims to be: a slice element.
	wrapped := "package p\nvar _ = []stateStatement{\n" + out + "}\n"
	if _, err := parser.ParseFile(token.NewFileSet(), "x.go", wrapped, 0); err != nil {
		t.Errorf("the -inventory output does not compile as a stateWritingStatements entry: %v\n%s", err, out)
	}
	if !strings.Contains(out, "UPDATE vms SET state = ?, evil = ?") {
		t.Errorf("output = %q, want the statement in its SOURCE form, not normalized", out)
	}
}

// TestInventoryDumpDoesNotLeakIntoOtherScans: the dump flag is per-scan state.
// As a package global, one test exercising the dump path would have made every
// later rule-5 assertion pass vacuously.
func TestInventoryDumpDoesNotLeakIntoOtherScans(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "corrosion")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "x.go")
	src := "package corrosion\nconst q = `UPDATE vms SET state = ?, evil = ? WHERE name = ?`\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() {
		if _, err := scanFileOpts(path, true); err != nil {
			t.Fatalf("scanFileOpts: %v", err)
		}
	})
	vs, err := scanFile(path)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(vs) != 1 {
		t.Errorf("got %d violation(s) after a dump scan, want 1 — the flag leaked", len(vs))
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	os.Stdout = saved
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// TestEveryInventoriedWriterIsPoliced.
//
// The inventory used to record its owning writer as free prose, so it could
// claim an ordering for a function the call-site rules never looked at — the
// inventory describing a connection to nonMinting/minting/clientMethods that did
// not exist. Now every name it lists has to actually be in one of them.
func TestEveryInventoriedWriterIsPoliced(t *testing.T) {
	for _, st := range stateWritingStatements {
		for _, w := range st.writers {
			_, isNonMinting := nonMinting[w]
			_, isMinting := minting[w]
			_, isClient := clientMethods[w]
			if !isNonMinting && !isMinting && !isClient {
				t.Errorf("inventory names %q as a writer of a vms.state statement, but no call-site "+
					"rule polices it: add it to nonMinting, minting or clientMethods", w)
			}
		}
	}
}

// TestEveryPolicedWriterIsInventoried is the other direction: a name in the maps
// with no statement behind it is a rule guarding nothing, which is how
// UpdateVMHost sat exempt under a comment describing a different statement.
func TestEveryPolicedWriterIsInventoried(t *testing.T) {
	named := map[string]bool{}
	for _, st := range stateWritingStatements {
		for _, w := range st.writers {
			named[w] = true
		}
	}
	for _, m := range []map[string]int{nonMinting, minting, clientMethods} {
		for w := range m {
			if !named[w] {
				t.Errorf("%q is policed as a vms.state writer but the inventory lists no statement "+
					"for it — either it no longer writes state, or its statement is unregistered", w)
			}
		}
	}
}

// TestAHardcodedRunningStatementNamesAMintingWriter: a statement that writes
// state='running' as a literal cannot be exempted by a call site's argument, so
// something in the minting or client family has to own it.
func TestAHardcodedRunningStatementNamesAMintingWriter(t *testing.T) {
	for _, st := range stateWritingStatements {
		sql := normalizeSQL(st.sql)
		if !strings.Contains(sql, "state = 'running'") {
			continue
		}
		if len(st.writers) == 0 {
			// A frozen receive-only shape has no Go writer; note must say so.
			if !strings.Contains(st.note, "RECEIVE-ONLY") {
				t.Errorf("a statement hardcoding state='running' names no writer and is not marked "+
					"receive-only: %q", st.note)
			}
			continue
		}
		ok := false
		for _, w := range st.writers {
			if _, isMinting := minting[w]; isMinting {
				ok = true
			}
			if _, isClient := clientMethods[w]; isClient {
				ok = true
			}
		}
		if !ok {
			t.Errorf("a statement hardcoding state='running' is owned only by non-minting writers "+
				"%v — nothing can exempt it by argument: %q", st.writers, st.note)
		}
	}
}

// TestWorktreesAreNotScanned.
//
// .worktrees holds full checkouts of other branches: gitignored, not part of
// this tree, and full of .go files the walk happily read. On a machine with six
// worktrees `make ci-guards` reported 161 violations, all of them call sites on
// other branches. CI never caught it because Actions checks out a clean tree, so
// the guard was broken for precisely the local command developers are told to
// run.
func TestWorktreesAreNotScanned(t *testing.T) {
	root := t.TempDir()

	// An unrouted write in the real tree: must be reported.
	if err := os.WriteFile(filepath.Join(root, "real.go"), []byte(
		"package p\nfunc f() {\n\tcorrosion.UpdateVMState(ctx, db, \"vm1\", state, \"d\")\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The same write inside a worktree: must be ignored.
	wt := filepath.Join(root, ".worktrees", "other-branch", "internal", "health")
	if err := os.MkdirAll(wt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, "other.go"), []byte(
		"package p\nfunc g() {\n\tcorrosion.UpdateVMState(ctx, db, \"vm2\", state, \"d\")\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := scanTree(root, false)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d violation(s), want 1 — the worktree copy was scanned", len(got))
	}
	if strings.Contains(got[0].file, ".worktrees") {
		t.Errorf("the reported violation is inside .worktrees: %s", got[0].file)
	}
}
