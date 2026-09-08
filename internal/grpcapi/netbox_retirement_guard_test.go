package grpcapi

import (
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"
)

// readSourceFile reads a file this package's guards assert about. Tests run with
// the package directory as their working directory.
func readSourceFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// THE RECOVERY PATH ADDS A FOURTH WAY THE PERMISSIONS COULD COLLAPSE, and the
// guards here are structural for the same reason the participant-set guards are:
// every previous collapse was a locally reasonable reading, so what has to be
// unrepresentable is the mechanism and not the wording.
//
// A retirement excuses ONE premise. There are two retirable premises and they do
// not imply each other, and there is a third premise — power-off evidence — that
// is not retirable at all. The plausible-sounding mistakes are:
//
//   - one "the host is gone" flag standing in for all three. This is the
//     conflation this branch has now hit three times, and here it would undo
//     both previous rounds at once.
//   - a MEMBERSHIP retirement excusing the inventory digest, on the reading that
//     "we have recovered what the lost host knew" covers what it held. It does
//     not: its unique VM and NIC rows are precisely what the digest comparison
//     exists to notice, and excusing them returns the round-five collision
//     through the recovery path.
//   - either retirement excusing the RUNTIME scan, on the reading that a
//     retired host is obviously not running anything. Knowing what a machine
//     knew, and knowing what rows it held, say nothing about whether its libvirt
//     is running a domain. That still requires the fencing log.
//
// These parse source and fail on a signature, a selector, or an argument at a
// call site — never on a name that "sounds wrong".

// retirementSourceFile carries the premise resolvers and the trust-boundary
// documentation. Tests run with the package directory as their working directory.
const retirementSourceFile = "netbox_retirement.go"

// retirementBearingTypes are the types that carry a retirement. A parameter of
// any of them is the mechanism by which a retirement could reach a derivation
// that must not be excused by one.
var retirementBearingTypes = []string{"membershipRetirements", "inventoryRetirements",
	"HostRetirement", "RetirementPremise"}

// retirementResolvers are the functions that produce an applicable retirement.
// The runtime derivation must be downstream of none of them.
var retirementResolvers = []string{"membershipRetirementsFor", "inventoryRetirementsFor",
	"applicableRetirements", "recoveredMembershipCandidates"}

// TestTheRuntimePremiseIsNotRETIRABLE is the guard on the premise that has no
// retirement at all.
//
// The runtime derivation and its one evidence sampler must not be able to SEE a
// retirement: no retirement-bearing parameter, no call to a resolver, no read of
// a retirement selector. Teaching either of them to consult one means changing a
// signature, which this fails on.
//
// It is the strongest of the three guards because the runtime premise is the one
// whose collapse frees an address a running guest holds.
func TestTheRuntimePremiseIsNotRETIRABLE(t *testing.T) {
	fset := token.NewFileSet()
	funcs := parseFuncs(t, fset, sweeperSourceFile)

	for _, name := range []string{"runtimeProofParticipants", "snapshotPowerOffEvidence",
		"hasFreshPowerOffProof", "freshFenceConfirmation"} {
		fn, ok := funcs[name]
		if !ok {
			t.Fatalf("%s is gone from %s — the runtime premise's derivation has been "+
				"restructured, and this guard is what keeps it unretirable", name, sweeperSourceFile)
		}
		for _, param := range fn.Type.Params.List {
			rendered := renderNode(t, fset, param.Type)
			for _, bad := range retirementBearingTypes {
				if strings.Contains(rendered, bad) {
					t.Fatalf("%s takes a %s parameter (%s): NOTHING an operator attests "+
						"excuses a host from the runtime scan. Knowing what a machine knew, "+
						"and knowing what rows it held, say nothing about whether its libvirt "+
						"is running a domain — that still requires fencing evidence.",
						name, bad, rendered)
				}
			}
		}
		for _, called := range functionsCalled(fn) {
			if slices.Contains(retirementResolvers, called) {
				t.Fatalf("%s calls %s: the runtime premise is not retirable, so its "+
					"derivation must not be downstream of any retirement resolver", name, called)
			}
		}
		for _, sel := range selectorsRead(fn) {
			if sel == "retired" {
				t.Fatalf("%s reads .retired: a retirement excuses membership or inventory "+
					"accounting, never a runtime scan", name)
			}
		}
	}

	// There is no constant for a runtime premise, which is what makes the
	// premise unretirable in the DATA as well as in the code: no row can name
	// one, so no reader can find one. A constant appearing here would be the
	// first step to a row that excuses a scan.
	src := readSourceFile(t, "../corrosion/netbox_recovery.go")
	for _, bad := range []string{"PremiseRuntime", "PremisePowerOff", "PremiseFence"} {
		if strings.Contains(src, bad) {
			t.Fatalf("corrosion/netbox_recovery.go declares %s: the runtime premise must "+
				"stay unnameable, because a premise a row can name is a premise a reader "+
				"can honour. Power-off evidence comes from the fencing log and nowhere else.", bad)
		}
	}
}

// TestTheTwoRETIRABLEPremisesCannotLeakIntoEachOther pins each resolver to its
// own premise literal, and each consumer to its own resolver.
//
// The two maps have identical shape, so without distinct types a call site could
// hand either to either and the compiler would accept it. The types are the
// primary mechanism; this is the guard that the wiring behind them is right — a
// resolver that passed the other premise would produce a correctly-typed map
// full of the wrong grants.
func TestTheTwoRETIRABLEPremisesCannotLeakIntoEachOther(t *testing.T) {
	fset := token.NewFileSet()
	funcs := parseFuncs(t, fset, retirementSourceFile)

	for _, spec := range []struct {
		resolver  string
		wantArg   string
		rejectArg string
	}{
		{"membershipRetirementsFor", "corrosion.PremiseMembership", "corrosion.PremiseInventory"},
		{"inventoryRetirementsFor", "corrosion.PremiseInventory", "corrosion.PremiseMembership"},
	} {
		fn, ok := funcs[spec.resolver]
		if !ok {
			t.Fatalf("%s is gone from %s", spec.resolver, retirementSourceFile)
		}
		body := renderNode(t, fset, fn.Body)
		if !strings.Contains(body, spec.wantArg) {
			t.Fatalf("%s no longer names %s: the premise must be a LITERAL at this one site, "+
				"so what the function can return is fixed by the source rather than by a "+
				"caller's argument", spec.resolver, spec.wantArg)
		}
		if strings.Contains(body, spec.rejectArg) {
			t.Fatalf("%s names %s: the two premises are separate and neither is evidence for "+
				"the other. A resolver that reached for the other premise would return a "+
				"correctly-typed map of the wrong grants, which no type can catch.",
				spec.resolver, spec.rejectArg)
		}
	}

	// applicableRetirements is the shared revalidation, and it must take the
	// premise as a PARAMETER rather than choosing one: the validity rules have to
	// be identical for both premises, or the weaker one becomes the soft spot.
	shared, ok := funcs["applicableRetirements"]
	if !ok {
		t.Fatal("applicableRetirements is gone — it is the one place a retirement is revalidated")
	}
	var takesPremise bool
	for _, param := range shared.Type.Params.List {
		if strings.Contains(renderNode(t, fset, param.Type), "RetirementPremise") {
			takesPremise = true
		}
	}
	if !takesPremise {
		t.Fatal("applicableRetirements no longer takes the premise as a parameter: if it " +
			"chose one itself, one of the two premises would be revalidated by something else, " +
			"and a premise revalidated more weakly than the other is where everything migrates")
	}
	body := renderNode(t, fset, shared.Body)
	for _, bad := range []string{"corrosion.PremiseMembership", "corrosion.PremiseInventory"} {
		if strings.Contains(body, bad) {
			t.Fatalf("applicableRetirements names %s: it revalidates whichever premise it is "+
				"given, and a branch on a specific premise here is how the two would come to "+
				"be revalidated differently", bad)
		}
	}

	// Every one of the four read-side conditions must still be reachable from
	// the shared revalidation, because each is a separate way a retirement stops
	// applying and every one of them fails closed.
	for _, needed := range []string{"ClusterFingerprint", "HostIncarnationOf",
		"ListHostRetirements", "hostIsReachable"} {
		if !slices.Contains(functionsCalled(shared), needed) {
			t.Fatalf("applicableRetirements no longer calls %s. The four conditions are the "+
				"whole of what keeps a retirement narrow: the cluster must match, the host's "+
				"incarnation must be recorded and known, a grant must exist for THAT "+
				"incarnation and that premise, and the host must not be responding. Dropping "+
				"hostIsReachable is what lets a rejoin keep its exception; dropping "+
				"HostIncarnationOf is what lets a hostname reuse inherit one.", needed)
		}
	}
}

// TestEachConsumerReadsOnlyItsOwnPremise pins the two consumers to the resolver
// for the premise they are entitled to.
//
// The membership premise is consumed where a host is DIALLED for its membership
// view; the inventory premise is consumed where a peer is asked for a DIGEST.
// Crossing them is the round-five defect in recovery clothing.
func TestEachConsumerReadsOnlyItsOwnPremise(t *testing.T) {
	fset := token.NewFileSet()

	closure := parseFuncs(t, fset, sweeperSourceFile)["closedParticipantSets"]
	if closure == nil {
		t.Fatal("closedParticipantSets is gone")
	}
	called := functionsCalled(closure)
	if !slices.Contains(called, "membershipRetirementsFor") {
		t.Fatal("closedParticipantSets no longer resolves the MEMBERSHIP retirements. That " +
			"is the premise a closure can excuse — the obligation to ask a host what it knew " +
			"— and without it a permanent loss leaves the closure unclosable forever")
	}
	if slices.Contains(called, "inventoryRetirementsFor") {
		t.Fatal("closedParticipantSets resolves the INVENTORY retirements: the closure excuses " +
			"the obligation to ASK a host, and nothing about the rows it held. Reading the " +
			"inventory premise here would let one attestation stand in for two")
	}

	adopt := parseFuncs(t, fset, adoptSourceFile)
	digest := adopt["proveNoPeerHoldsInventoryRowsWeLack"]
	if digest == nil {
		t.Fatal("proveNoPeerHoldsInventoryRowsWeLack is gone — it is the bind's inventory premise")
	}
	called = functionsCalled(digest)
	if !slices.Contains(called, "inventoryRetirementsFor") {
		t.Fatal("proveNoPeerHoldsInventoryRowsWeLack no longer resolves the INVENTORY " +
			"retirements, so a permanently lost host leaves every bind suspended forever — " +
			"the dead end the recovery path exists to open")
	}
	if slices.Contains(called, "membershipRetirementsFor") {
		t.Fatal("proveNoPeerHoldsInventoryRowsWeLack resolves the MEMBERSHIP retirements: a " +
			"lost host's unique VM and NIC rows are exactly what this comparison exists to " +
			"notice, so 'we recovered the list of hosts it knew about' is not evidence about " +
			"them. This is the round-five collision reached through the recovery path")
	}
	// And no other function in the bind's file may reach either resolver: a
	// second route into the premises is how two proofs came to differ before.
	for name, fn := range adopt {
		if name == "proveNoPeerHoldsInventoryRowsWeLack" {
			continue
		}
		for _, c := range functionsCalled(fn) {
			if slices.Contains(retirementResolvers, c) {
				t.Fatalf("%s calls %s: the bind reaches a retirement through "+
					"proveNoPeerHoldsInventoryRowsWeLack alone, so the premise it withholds on "+
					"is the premise it checks", name, c)
			}
		}
	}
}

// TestTheTrustBoundaryIsWrittenDownWhereTheRowsAreProduced is not a mechanism
// guard; it is a guard on the one thing this feature cannot get from a
// mechanism.
//
// Every other premise here is machine-verified. This one is not, and the whole
// hazard is that the machinery AROUND a retirement — a confirmation prompt, an
// audit row, an immutable manifest, an exact identity — is the machinery of a
// verified premise and reads like evidence. So the code that produces these rows
// has to say plainly that auditing an assertion does not corroborate it, and the
// operator documentation has to say it too.
//
// A test on prose is unusual and deliberate: the sentence is load-bearing, and a
// refactor that moved these writes somewhere tidier would carry the mechanism
// and silently drop the warning.
func TestTheTrustBoundaryIsWrittenDownWhereTheRowsAreProduced(t *testing.T) {
	for _, tc := range []struct{ path, what string }{
		{retirementSourceFile, "the premise resolvers"},
		{"../corrosion/netbox_recovery.go", "the row writers"},
		{"../../docs/networking.md", "the operator documentation"},
		// And wherever the substitution is SURFACED. The advisory exists to make
		// an unverified premise visible, which is exactly the surface a reader
		// mistakes for evidence of the premise: a standing row in `lv health`,
		// with an identity, an attribution and a timestamp, reads like something
		// that was checked. So the sentence has to travel with it.
		{advisorySourceFile, "the standing advisory"},
		{"../../docs/diagnostics.md", "the advisory's operator documentation"},
	} {
		src := strings.ToLower(readSourceFile(t, tc.path))
		// It must say that litevirt does not verify the assertion...
		if !strings.Contains(src, "cannot check it") && !strings.Contains(src, "cannot check what you") &&
			!strings.Contains(src, "no machine verifies") && !strings.Contains(src, "cannot check") {
			t.Fatalf("%s (%s) no longer says that litevirt cannot check what an operator "+
				"attests. Every other premise in this subsystem is machine-verified; this one "+
				"is not, and that has to be stated where the rows are produced rather than "+
				"left for a reader to infer.", tc.path, tc.what)
		}
		// ...and that recording it is not the same as establishing it.
		if !strings.Contains(src, "does not make it true") && !strings.Contains(src, "make it correct") &&
			!strings.Contains(src, "not whether it was true") {
			t.Fatalf("%s (%s) no longer says that auditing an attestation does not make it "+
				"true. That is the specific misreading this feature invites: the audit row, "+
				"the immutable manifest and the exact identity are bookkeeping about an "+
				"assertion, not corroboration of it.", tc.path, tc.what)
		}
	}
}
