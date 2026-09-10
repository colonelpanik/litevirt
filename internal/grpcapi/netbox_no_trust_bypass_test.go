package grpcapi

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// NO OPERATOR GRANT MAY SUPPLY A PREMISE, AND NO PATH MAY QUIETLY SKIP ONE.
//
// A prerelease build of this branch carried a permanent-loss recovery mechanism:
// an operator recorded a manifest about a destroyed machine, a narrow grant let
// that manifest stand in for the machine evidence a premise needed, an advisory
// surfaced the substitution, and a withdrawal took one back. It was removed
// before release so its authorization rules could be reviewed on their own terms
// (docs/reviews/2026-09-08-trust-lifecycle-followup-scope.md).
//
// REMOVING IT IS ONLY HALF THE JOB. The interesting failure is not the mechanism
// coming back under its old names — that is obvious in review. It is a path that
// LIFTS A SUSPENSION or HANDS OUT AN ALLOCATOR without going through the proof,
// which looks like ordinary plumbing and produces exactly the outcome the
// mechanism used to produce on purpose. The three guards here are aimed at that:
// nothing may name the removed surface, every path that makes a binding live must
// re-prove the inventory, and the allocator may only be built in the two places
// that have already been past the gate.

// removedTrustSurface is every identifier and table name the removed mechanism
// owned. Each is checked as a plain substring, so a rename that keeps the word
// still trips.
var removedTrustSurface = []string{
	// The three tables.
	"netbox_host_retirements",
	"netbox_recovery_manifests",
	"netbox_retirement_withdrawals",
	// The three RPCs.
	"RetireLostHost",
	"WithdrawHostRetirement",
	"ListLostHostRetirements",
	// The row types and premise vocabulary. These are the ones that matter most:
	// a premise a caller can NAME is a premise a caller can choose, which is how
	// the two premises leaked into each other's consumer before.
	"RetirementPremise",
	"PremiseMembership",
	"PremiseInventory",
	"HostRetirement{",
	"RecoveryManifest{",
	"membershipRetirements",
	"inventoryRetirements",
	"recoveredMembershipCandidates",
	"applicableRetirements",
	// The advisory's health codes.
	"netbox_premise_attested",
	"netbox_attestation_unvalidatable",
}

// allowedToNameTheRemovedSurface are the files that may mention it, and the
// reason each may.
//
// Every one of them is talking about the REMOVAL. The boundary has to name the
// tables and the removed evaluator's condition codes in order to detect them and
// refuse; the schema history has to record that they were here and went; the
// migration test asserts they are NOT created; this file lists them in order to
// forbid them.
var allowedToNameTheRemovedSurface = map[string]string{
	"internal/corrosion/netbox_prerelease_boundary.go":      "detects the prerelease trust schema and refuses to start on it",
	"internal/corrosion/schema.go":                          "records in the v51 history that they were removed",
	"internal/corrosion/schema_migration_test.go":           "asserts a migration does NOT create them",
	"internal/corrosion/netbox_prerelease_boundary_test.go": "exercises the refusal",
	"tests/fleet/netbox_prerelease_boundary_test.go":        "seeds a prerelease database to assert the refusal changes nothing cluster-wide",
	"internal/grpcapi/netbox_no_trust_bypass_test.go":       "this guard",
}

// TestTheRemovedTrustSurfaceIsGoneFromTheWholeTree is the flat scan.
//
// Deliberately repo-wide rather than package-local: the mechanism spanned the
// schema, the replication ledgers, the proto, the CLI and the health roll-up, so
// a package-scoped guard would pass while half of it lived on somewhere else.
// The generated protobuf files are included, which is what makes "the RPC is
// gone from the contract" — not merely unimplemented — a machine's job.
func TestTheRemovedTrustSurfaceIsGoneFromTheWholeTree(t *testing.T) {
	root := repoRootForTrustGuard(t)
	var problems []string
	for _, dir := range []string{"internal", "cmd", "proto", "gen", "scripts", "tests"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			switch filepath.Ext(path) {
			case ".go", ".proto":
			default:
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			if _, ok := allowedToNameTheRemovedSurface[filepath.ToSlash(rel)]; ok {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			src := string(body)
			for _, token := range removedTrustSurface {
				if strings.Contains(src, token) {
					problems = append(problems, filepath.ToSlash(rel)+": "+token)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("the removed permanent-loss trust surface is named in %d place(s):\n  %s\n\n"+
			"The recovery lifecycle is a follow-up against a frozen contract "+
			"(docs/reviews/2026-09-08-trust-lifecycle-followup-scope.md). Until it is "+
			"implemented, a premise may be satisfied ONLY by machine evidence — no grant, "+
			"manifest or attestation may supply one, and no table, RPC or command may exist "+
			"to record one.",
			len(problems), strings.Join(problems, "\n  "))
	}
}

// TestEveryPathThatMakesABindingLiveReProvesTheInventory is the half that catches
// a HALF-extraction.
//
// A binding that is suspended serves no claim; the moment its suspension is
// lifted, allocatorFor hands out a NetBox allocator across the whole prefix. So
// every path that lifts one is a door onto the same authority the removed grant
// used to hand over, and each has to pass the same proof. This asserts the call
// STRUCTURALLY, on the function that lifts the flag, because a behavioural test
// of one path says nothing about the next one somebody adds.
//
// FOUR DOORS ONTO ONE GATE. The doors are the four the extraction brief names,
// and each of them now reaches the proof through activateBinding:
//
//   - ResumeBinding      — `lv netbox resume`
//   - rekeyBinding       — `lv netbox rekey`, whose tail resumes
//   - resumeUnhydratedBinding — the AUTOMATIC one, lifted by the revalidation
//     pass with no operator involved, which is why it is the easiest to forget
//   - finishAdoptionAndResume — the bind's own repair, run from network create
//   - activateBinding    — the ONE gate, which adopts, re-validates AFTER the
//     adoption, and is the only place the flag comes off
//   - adoptExistingAddresses  — the adoption itself, which the gate goes through
//     and which owns the inventory proof
func TestEveryPathThatMakesABindingLiveReProvesTheInventory(t *testing.T) {
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	for _, f := range []string{"netbox_adopt.go", "netbox_revalidate.go", "netbox_bind.go"} {
		for name, fn := range parseFuncs(t, fset, f) {
			funcs[name] = fn
		}
	}
	for _, tc := range []struct{ fn, must string }{
		// The four doors reach the proof through the ONE final activation gate.
		// Asserted as the gate rather than as adoptExistingAddresses directly:
		// the gate is what also re-validates AFTER the adoption, and a door that
		// called the adoption on its own would be back to activating on a
		// premise the adoption's own NetBox requests could have outlived.
		{"ResumeBinding", "activateBinding"},
		{"rekeyBinding", "activateBinding"},
		{"resumeUnhydratedBinding", "activateBinding"},
		{"finishAdoptionAndResume", "activateBinding"},
		// And the chain the four of them rest on, so that a refactor cannot
		// leave them all calling something that no longer proves anything.
		{"activateBinding", "adoptExistingAddresses"},
		{"adoptExistingAddresses", "planAdoption"},
		{"planAdoption", "corroborateAdoptionInventory"},
		{"corroborateAdoptionInventory", "proveNoPeerHoldsInventoryRowsWeLack"},
		// The bind's own first pass reaches the proof by the same chain.
		{"validateAndBindPrefix", "planAdoption"},
	} {
		fn, ok := funcs[tc.fn]
		if !ok {
			t.Fatalf("%s is gone; if a door onto a live binding was renamed, this guard has "+
				"to follow it rather than being deleted", tc.fn)
		}
		if len(functionsCalledNamed(fn, tc.must)) == 0 {
			t.Errorf("%s no longer calls %s, so it can make a binding live without "+
				"re-proving that no peer holds address-bearing rows this node lacks. That is "+
				"the authority the removed permanent-loss grant used to hand over, reached by "+
				"a different door.", tc.fn, tc.must)
		}
	}
}

// TestNoActivationPathDiscardsTheUnknownDriftAnswer is the same guard aimed at
// the other way a door opens: not skipping the proof, but reading its FAILURE as
// a pass.
//
// bindingDrift has three answers — clean, drifted, and could-not-be-read — and
// the third is carried in an error precisely so no caller can mistake it for the
// first. That is a convention the compiler enforces only as far as forcing a
// second assignment target: `reason, _ :=` compiles, and it is the exact bug this
// signature replaced, reintroduced in one character.
//
// So every path that ends in a binding going LIVE must BIND the error, and the
// periodic pass is deliberately not on this list — it may only ever suspend, and
// its tolerance for an unreadable NetBox is the correct behaviour there.
func TestNoActivationPathDiscardsTheUnknownDriftAnswer(t *testing.T) {
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	for _, f := range []string{"netbox_revalidate.go", "netbox_adopt.go"} {
		for name, fn := range parseFuncs(t, fset, f) {
			funcs[name] = fn
		}
	}
	for _, name := range []string{
		"ResumeBinding",           // `lv netbox resume`
		"rekeyBinding",            // `lv netbox rekey`, whose tail resumes
		"resumeUnhydratedBinding", // the automatic completion, with no operator involved
		// The GATE, whose own re-check is the one the activation rests on. The
		// three above make a CHEAP pre-adoption refusal; this one makes the
		// premise, so discarding the unread answer here is the whole P1 back.
		"activateBinding",
	} {
		fn, ok := funcs[name]
		if !ok {
			t.Fatalf("%s is gone; if a door onto a live binding was renamed, this guard has "+
				"to follow it rather than being deleted", name)
		}
		calls := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 {
				return true
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "bindingDrift" {
				return true
			}
			calls++
			if len(as.Lhs) != 2 {
				t.Errorf("%s takes %d result(s) from bindingDrift: %s — the read-failure "+
					"answer is the second one, and a caller that does not take it cannot "+
					"refuse it", name, len(as.Lhs), renderNode(t, fset, as))
				return true
			}
			if id, ok := as.Lhs[1].(*ast.Ident); ok && id.Name == "_" {
				t.Errorf("%s DISCARDS bindingDrift's read-failure answer: %s — that is "+
					"\"I could not look\" read as \"nothing is wrong\", and this path ends "+
					"in a binding serving claims again", name, renderNode(t, fset, as))
			}
			return true
		})
		if calls == 0 {
			t.Errorf("%s no longer re-checks the binding for drift at all, so it can make one "+
				"live over a re-CIDRed prefix, a moved VRF or a VRF that stopped enforcing "+
				"uniqueness", name)
		}
	}
}

// activationGateName is the one function allowed to make a binding live.
const activationGateName = "activateBinding"

// TestOnlyTheActivationGateClearsASuspension pins the gate's UNIQUENESS.
//
// The four doors used to each carry their own `Suspended = false` and their own
// pre-adoption validation, and that is exactly how they came to share a bug: a
// premise read before the adoption, agreed on four times over. Unifying them
// fixes it once; nothing stops a fifth door appearing next to them and doing it
// again — which is why this is a structural guard and not four behavioural
// tests.
//
// So: across every non-test file in this package, there may be exactly ONE
// assignment that clears a binding's suspension, and it must be inside the gate.
// A door that wants to make a binding live has to call the gate, and the gate
// re-validates AFTER the adoption.
//
// Package-wide rather than scoped to the three netbox files, because the next
// door will not necessarily be written in them.
func TestOnlyTheActivationGateClearsASuspension(t *testing.T) {
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package files: %v", err)
	}
	var clears []string
	for _, path := range names {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		for fname, fn := range parseFuncs(t, fset, path) {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, lhs := range as.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Suspended" {
						continue
					}
					if i >= len(as.Rhs) {
						continue
					}
					id, ok := as.Rhs[i].(*ast.Ident)
					if !ok || id.Name != "false" {
						continue
					}
					clears = append(clears, fmt.Sprintf("%s:%s: %s",
						path, fname, renderNode(t, fset, as)))
				}
				return true
			})
		}
	}
	sort.Strings(clears)
	if len(clears) != 1 {
		t.Fatalf("%d place(s) clear a binding's suspension, want exactly 1 (inside %s):\n  %s\n\n"+
			"Every activation path must go through the ONE gate, because the gate is what "+
			"re-validates AFTER the adoption. A second place that lifts the flag is a door "+
			"that activates on a premise the adoption's own NetBox requests could have "+
			"outlived — which is the bug four agreeing call sites already produced once.",
			len(clears), activationGateName, strings.Join(clears, "\n  "))
	}
	if !strings.Contains(clears[0], ":"+activationGateName+":") {
		t.Fatalf("the suspension is cleared outside %s: %s", activationGateName, clears[0])
	}
}

// TestTheActivationGateRevalidatesAfterItAdopts pins the gate's ORDER, which is
// the whole content of the fix.
//
// A gate that called bindingDrift BEFORE adoptExistingAddresses would compile,
// pass every other guard here, and be precisely the bug: a validation that
// predates the adoption, which performs intervening NetBox requests. Nothing but
// source order distinguishes the two, so source order is what this asserts —
// drift AFTER the adoption, and the write that lifts the flag after both.
func TestTheActivationGateRevalidatesAfterItAdopts(t *testing.T) {
	fset := token.NewFileSet()
	funcs := parseFuncs(t, fset, "netbox_adopt.go")
	fn, ok := funcs[activationGateName]
	if !ok {
		t.Fatalf("%s is gone; if the activation gate was renamed, this guard has to follow it "+
			"rather than being deleted", activationGateName)
	}
	// The FIRST position of each call, because the order that matters is
	// "adoption finished, then re-read".
	pos := map[string]token.Pos{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if _, seen := pos[sel.Sel.Name]; !seen {
			pos[sel.Sel.Name] = call.Pos()
		}
		return true
	})
	for _, name := range []string{"adoptExistingAddresses", "bindingDrift", "UpsertBinding"} {
		if _, ok := pos[name]; !ok {
			t.Fatalf("%s no longer calls %s at all — it cannot be the activation gate without "+
				"all three of adopting, re-validating after the adoption, and lifting the flag",
				activationGateName, name)
		}
	}
	if pos["bindingDrift"] < pos["adoptExistingAddresses"] {
		t.Errorf("%s re-validates BEFORE it adopts, which is the stale premise the gate exists "+
			"to remove: the adoption performs intervening NetBox requests, so an answer read "+
			"ahead of it says nothing about the state the activation rests on",
			activationGateName)
	}
	if pos["UpsertBinding"] < pos["bindingDrift"] {
		t.Errorf("%s lifts the suspension BEFORE its post-adoption revalidation, so the "+
			"revalidation cannot refuse anything", activationGateName)
	}
}

// TestTheNetBoxAllocatorIsOnlyBuiltBehindTheGate pins the last door: the
// allocator itself.
//
// allocatorFor is the selector every ordinary caller uses, and it REFUSES a
// suspended binding. A direct construction bypasses that refusal, so there may be
// exactly one — inside the adoption pass, which runs while the binding is
// suspended by design and which has just been past the inventory proof.
//
// A third one appearing is how a suspended binding would start allocating again
// with nothing lifted and nothing logged.
func TestTheNetBoxAllocatorIsOnlyBuiltBehindTheGate(t *testing.T) {
	allowed := map[string]string{
		"allocatorFor":           "the selector itself, which refuses a suspended binding",
		"adoptExistingAddresses": "runs while the binding is suspended by design, after the proof",
	}
	fset := token.NewFileSet()
	var found []string
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		for fnName, fn := range parseFuncs(t, fset, name) {
			if len(functionsCalledNamed(fn, "NewNetBoxAllocator")) == 0 {
				continue
			}
			if _, ok := allowed[fnName]; ok {
				continue
			}
			found = append(found, name+": "+fnName)
		}
	}
	sort.Strings(found)
	if len(found) > 0 {
		t.Fatalf("NewNetBoxAllocator is constructed outside the two places allowed to:\n  %s\n\n"+
			"Every other caller must go through allocatorFor, which refuses a SUSPENDED "+
			"binding. A direct construction allocates across the prefix whatever the binding "+
			"row says, which is the refusal the permanent-loss grant used to buy an exception "+
			"from.", strings.Join(found, "\n  "))
	}
}

// repoRootForTrustGuard walks up from this package to the module root.
func repoRootForTrustGuard(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs cwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root from the grpcapi package")
	return ""
}
