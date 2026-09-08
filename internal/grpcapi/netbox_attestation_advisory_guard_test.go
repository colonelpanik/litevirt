package grpcapi

import (
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// STRUCTURAL GUARDS ON THE ATTESTATION ADVISORY.
//
// Three of its requirements are properties of the WIRING rather than of a
// behaviour, and each one is invisible in a passing behavioural test the moment
// somebody adds a new call site:
//
//   - IT GATES NOTHING. A behavioural test can only prove that the gates that
//     exist today do not consult it. The failure mode is a gate added tomorrow,
//     so the guard is on the code being absent from every list rather than on
//     each list's current behaviour. An earlier round on this branch found a
//     condition that gated nothing only by accident; here it is the requirement.
//   - IT IS A VIEW, NOT A CONTROL. Clearing it must neither revoke nor validate
//     the grant. The mechanism is that this file writes exactly one table and the
//     premise resolvers read none of it — one call in either direction breaks the
//     property, and a call is what these fail on.
//   - IT NEVER TOUCHES THE RUNTIME PREMISE. A retirement is not power-off
//     evidence and cannot become any, so the advisory must not be able to see the
//     runtime derivation or to word itself as though it spoke for it.

// advisorySourceFile carries the advisory. Tests run with the package directory
// as their working directory.
const advisorySourceFile = "netbox_attestation_advisory.go"

// advisoryCodes are the two condition codes the advisory writes, as they appear
// on the wire and in the rows.
var advisoryCodes = []string{"netbox_premise_attested", "netbox_attestation_unvalidatable"}

// advisoryCodeIdentifiers are the in-package names for the same two.
var advisoryCodeIdentifiers = []string{"condNetBoxPremiseAttested", "condNetBoxAttestationUnvalidatable"}

// advisoryCodeCallers are the ONLY files entitled to name either code: the
// advisory itself, its tests, and the fleet scenarios (which must use the wire
// string, being in another package). Anything else naming one is a second reader
// of the code, and the only reason to read a condition code is to act on it.
var advisoryCodeCallers = []string{
	filepath.Join("internal", "grpcapi", advisorySourceFile),
	filepath.Join("internal", "grpcapi", "netbox_attestation_advisory_test.go"),
	filepath.Join("internal", "grpcapi", "netbox_attestation_advisory_guard_test.go"),
	filepath.Join("tests", "fleet", "netbox_attestation_advisory_test.go"),
	// The withdrawal tests ASSERT on the advisory rather than gating on it: a
	// withdrawn grant supplies no premise, so it must stop being advertised as
	// in force. Reading the code to check that it went away is the opposite of
	// reading it to act on it.
	filepath.Join("internal", "grpcapi", "netbox_withdrawal_test.go"),
}

// TestTheAdvisoryIsInNoGatingList is the guard on "blocks nothing".
//
// TWO HALVES, because each catches what the other cannot. The map check is
// exact and immediate; the source scan is what survives somebody inventing a
// SECOND list — which is how a condition comes to gate something without anybody
// deciding that it should.
func TestTheAdvisoryIsInNoGatingList(t *testing.T) {
	// The list that exists today, by value rather than by reading the source.
	for _, code := range advisoryCodes {
		if ownershipConditionCodes[code] {
			t.Errorf("%s is in ownershipConditionCodes. That list blocks capacity-growing "+
				"admission to every involved host and every runtime-changing action on the "+
				"subject. This advisory reports a substitution an operator chose; it must "+
				"block no allocation, quorum or execution path", code)
		}
	}
	if len(ownershipConditionCodes) != 4 {
		t.Errorf("ownershipConditionCodes has %d entries, want 4: the check above is a "+
			"membership test, so a list that has grown deserves a look at what joined it",
			len(ownershipConditionCodes))
	}

	// And nothing outside the advisory and its tests may name either code.
	root := filepath.Join("..", "..")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "bin", "node_modules", "gen":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if slices.Contains(advisoryCodeCallers, rel) {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		src := string(b)
		for _, needle := range append(append([]string{}, advisoryCodes...), advisoryCodeIdentifiers...) {
			if strings.Contains(src, needle) {
				t.Errorf("%s names the advisory condition %q. The only reason to read a "+
					"condition code is to act on it, and this one must gate nothing — no "+
					"allocation, no quorum, no execution. If this is a legitimate new "+
					"surface, add it to advisoryCodeCallers and say in the commit why it "+
					"reads the code without gating on it", rel, needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the tree: %v", err)
	}
}

// TestTheAdvisoryWritesNothingButHealthConditions is the guard on "clearing it
// cannot revoke the grant".
//
// The advisory must not be able to touch the tables the grant lives in. A
// behavioural test proves that today's code does not; this fails on the CALL,
// which is the only way it could come to.
func TestTheAdvisoryWritesNothingButHealthConditions(t *testing.T) {
	fset := token.NewFileSet()
	funcs := parseFuncs(t, fset, advisorySourceFile)
	for _, name := range []string{"surveyAttestedPremises", "evaluateAttestedPremises"} {
		if _, ok := funcs[name]; !ok {
			t.Fatalf("%s is gone from %s — the advisory has been restructured, and these "+
				"guards are what keep it a view rather than a control", name, advisorySourceFile)
		}
	}

	// The writers of the recovery tables, named explicitly: a call to any of
	// them is the advisory acquiring the power to record or destroy a grant.
	// InsertRetirementWithdrawal is the one that would let a DISPLAY revoke:
	// withdrawal is the supported way to remove trust, and it must stay an
	// operator's deliberate act rather than something a recomputed surface can
	// do on its own.
	forbidden := []string{"InsertHostRetirement", "InsertRecoveryManifest",
		"InsertRetirementWithdrawal"}
	// And the shapes any other write would take.
	forbiddenPrefixes := []string{"Insert", "Update", "Delete", "Tombstone", "Execute",
		"Suspend", "Resume", "Claim", "Release", "Retire"}
	// UpsertHealthCondition is reached through applyNetBoxConditions*, which is
	// the one table the advisory may write.
	allowed := []string{"applyNetBoxConditions", "applyNetBoxConditionsWithSeverity"}

	for name, fn := range funcs {
		for _, called := range functionsCalled(fn) {
			if slices.Contains(allowed, called) {
				continue
			}
			if slices.Contains(forbidden, called) {
				t.Fatalf("%s calls %s: the advisory is a VIEW. If it could write the "+
					"retirement tables, clearing or recomputing a display could destroy an "+
					"exception an operator deliberately recorded — or record one nobody "+
					"attested", name, called)
			}
			for _, prefix := range forbiddenPrefixes {
				if strings.HasPrefix(called, prefix) {
					t.Fatalf("%s calls %s, which is a WRITE. The advisory writes exactly one "+
						"table (health_conditions, through applyNetBoxConditions*); a second "+
						"one is how a view becomes a control", name, called)
				}
			}
		}
	}
}

// TestNoPremiseResolverReadsTheAdvisory is the guard on the OTHER direction:
// clearing the advisory must not validate the grant.
//
// The premise resolvers decide whether a grant is in force. If any of them could
// read a health condition, dismissing a warning would become an input to that
// decision — an operator's annoyance laundered into evidence. So the resolvers
// must not be able to see the condition table at all, and the advisory's own
// names must not appear in their file.
func TestNoPremiseResolverReadsTheAdvisory(t *testing.T) {
	fset := token.NewFileSet()
	funcs := parseFuncs(t, fset, retirementSourceFile)
	for _, name := range []string{"applicableRetirements", "membershipRetirementsFor",
		"inventoryRetirementsFor", "recoveredMembershipCandidates"} {
		fn, ok := funcs[name]
		if !ok {
			t.Fatalf("%s is gone from %s", name, retirementSourceFile)
		}
		for _, called := range functionsCalled(fn) {
			if strings.Contains(called, "HealthCondition") ||
				strings.Contains(called, "AttestedPremises") {
				t.Fatalf("%s calls %s: whether a retirement is in force must be derived from "+
					"the cluster's own state — the fingerprint, the recorded incarnation, the "+
					"grant, and reachability — and NEVER from what an advisory row says. A "+
					"resolver that read the display would let clearing a warning validate the "+
					"attestation it was warning about", name, called)
			}
		}
	}
	src := readSourceFile(t, retirementSourceFile)
	for _, needle := range append(append([]string{}, advisoryCodes...), advisoryCodeIdentifiers...) {
		if strings.Contains(src, needle) {
			t.Fatalf("%s names %q: the premise resolvers must have no knowledge of the "+
				"advisory. The advisory is downstream of them and must stay there",
				retirementSourceFile, needle)
		}
	}
}

// TestTheAdvisoryCannotReachTheRuntimePremise is the guard on the one thing the
// advisory must never imply.
//
// A retirement excuses knowing what a machine KNEW, or what ROWS it held.
// Neither says anything about whether its libvirt is running a domain, and there
// is no retirement for that premise at all. So the advisory may not read the
// runtime derivation — an advisory that consulted power-off evidence would be one
// step from reporting a retirement as though it covered the runtime — and its
// text has to say what it is not.
func TestTheAdvisoryCannotReachTheRuntimePremise(t *testing.T) {
	fset := token.NewFileSet()
	funcs := parseFuncs(t, fset, advisorySourceFile)
	runtimeDerivation := []string{"hasFreshPowerOffProof", "snapshotPowerOffEvidence",
		"freshFenceConfirmation", "runtimeProofParticipants", "closedRuntimeProofSet"}
	for name, fn := range funcs {
		for _, called := range functionsCalled(fn) {
			if slices.Contains(runtimeDerivation, called) {
				t.Fatalf("%s calls %s: the advisory sits BESIDE the runtime premise, never "+
					"over it. Reading power-off evidence here is how a surface comes to group "+
					"the two, and a retirement can never supply the runtime premise", name, called)
			}
		}
	}

	// And it must state that, because a reader skimming `lv health` is exactly
	// who would otherwise assume a retired host is also known to be stopped.
	src := strings.ToLower(readSourceFile(t, advisorySourceFile))
	for _, needle := range []string{"not evidence that the machine is powered off", "fence-confirm"} {
		if !strings.Contains(src, needle) {
			t.Fatalf("%s no longer says %q. Runtime exclusion still requires fencing "+
				"evidence, and an advisory that left that to be inferred would be read as "+
				"covering it", advisorySourceFile, needle)
		}
	}
}
