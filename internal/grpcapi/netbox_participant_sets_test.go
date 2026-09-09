package grpcapi

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The participant universe produces THREE sets, and no two of them are one set.
//
//   - membershipDiscoveryTargets — who is asked WHAT IT KNOWS. Everyone: no
//     role, no power state.
//   - inventoryCorroborationParticipants — whose REPLICATED ROWS must agree.
//     Everyone running the daemon, witnesses included.
//   - runtimeProofParticipants — who must produce a RUNTIME SCAN. Witnesses
//     excused on a role every row read agrees about, and machines an operator
//     has attested are powered off excused too.
//
// Collapsing a pair of them has now handed out or freed a held address three
// times:
//
//   - a stale local `role='witness'` kept a host that had since become a worker
//     out of the DISCOVERY fan-out, so the rule that a role counts only while
//     every row read agrees could never fire;
//   - a genuine witness — the only node that could name a third holder — was
//     never asked, for the same reason;
//   - the bind's DATABASE-DIGEST check was pointed at the runtime-proof set, so
//     a witness holding the only replicated copy of an incumbent's VM and NIC
//     rows was never asked for a digest, the remaining nodes' equally short
//     inventories agreed, and a newcomer took the incumbent's live address.
//
// Every one of those is a shape where an exclusion PREVENTED the query that
// would have refuted it, and the third one happened after a comment saying so
// was already in the file. So a comment is not the guard: the guards below are
// structural, and they are three rounds of evidence that they are needed.
//
// A NOTE ON WHAT MAY BE ADDED HERE. These guards fail on a signature, a
// selector, or an argument at a call site — never on a "sounds wrong" name. That
// is deliberate: the collapses were all locally reasonable readings, so what has
// to be unrepresentable is the mechanism, not the wording.

// sweeperSourceFile is the file most of the guards below parse. Tests run with
// the package directory as their working directory.
const sweeperSourceFile = "netbox_sweeper.go"

// adoptSourceFile carries the bind's inventory corroboration — the caller that
// read the wrong set.
const adoptSourceFile = "netbox_adopt.go"

// roleBearingTypes are the types that carry a role. A parameter of any of them
// is the mechanism by which a role could reach a set that must not filter on
// one.
var roleBearingTypes = []string{"participantCandidate", "candidateSet", "hostRoleRow"}

// powerOffBearingTypes are the types that carry power-off evidence. A parameter
// of any of them is the mechanism by which the runtime set's one excuse could
// reach a set it must never excuse anybody from.
var powerOffBearingTypes = []string{"powerOffSnapshot"}

// roleReadingSelectors are the ways code in this file reads a role.
var roleReadingSelectors = []string{"witness", "role", "Role"}

// powerOffReadingFuncs are the functions that sample or read power-off evidence.
// Only the runtime-proof derivation may be downstream of any of them.
var powerOffReadingFuncs = []string{"hasFreshPowerOffProof", "hostIsReachable",
	"freshFenceConfirmation", "snapshotPowerOffEvidence", "HealthyPeers"}

// unfilterableSets are the sets that must exclude NOBODY, plus the leg all three
// share. Each is pinned to a signature that cannot express an exclusion: NAMES
// in, no ctx (so there is no database to read a fencing_log from and no gate to
// sample), no role-bearing or power-off-bearing parameter.
var unfilterableSets = []string{"membershipDiscoveryTargets",
	"inventoryCorroborationParticipants", "participantsWithThisNode"}

// TestMembershipDiscoveryTargetsCannotFilterByRole is the structural guard over
// the two sets that must not filter, and over the leg all three share.
//
// Each takes NAMES and no ctx, and that is not a stylistic choice: with no role
// in scope the witness exclusion cannot be applied, and with no ctx there is no
// fencing_log to read and no gate to sample, so the power-off exclusion cannot be
// applied either. Teaching any of them to exclude a host means changing its
// signature — which this test then fails on.
func TestMembershipDiscoveryTargetsCannotFilterByRole(t *testing.T) {
	fset := token.NewFileSet()
	funcs := parseFuncs(t, fset, sweeperSourceFile)

	for _, name := range unfilterableSets {
		fn, ok := funcs[name]
		if !ok {
			t.Fatalf("%s is gone from %s — the three participant sets have been "+
				"restructured, and this guard is the reason they are three", name, sweeperSourceFile)
		}
		for _, param := range fn.Type.Params.List {
			rendered := renderNode(t, fset, param.Type)
			for _, bad := range roleBearingTypes {
				if strings.Contains(rendered, bad) {
					t.Fatalf("%s takes a %s parameter (%s): a set that must exclude nobody "+
						"must not be able to see a role. A host's role says what it may RUN, "+
						"never what it KNOWS or what rows it HOLDS, and excluding a host is "+
						"exactly what prevents learning the exclusion was wrong.", name, bad, rendered)
				}
			}
			for _, bad := range powerOffBearingTypes {
				if strings.Contains(rendered, bad) {
					t.Fatalf("%s takes a %s parameter (%s): power-off evidence excuses a host "+
						"from the RUNTIME-PROOF SET and from nothing else. A machine that is "+
						"off still knew which hosts existed and still holds replicated rows.",
						name, bad, rendered)
				}
			}
			if strings.Contains(rendered, "context.Context") {
				t.Fatalf("%s takes a %s parameter: with a ctx in scope it can read a "+
					"fencing_log and sample the healthy-peer gate, which is how the power-off "+
					"exclusion reaches a set that must excuse nobody", name, rendered)
			}
		}
		for _, sel := range selectorsRead(fn) {
			if slices.Contains(roleReadingSelectors, sel) {
				t.Fatalf("%s reads .%s: only runtimeProofParticipants may branch on a role", name, sel)
			}
		}
		for _, called := range functionsCalled(fn) {
			if called == "all" || called == "runtimeProofParticipants" {
				t.Fatalf("%s calls %s, which carries the role reading: a non-filtering set "+
					"must be built from candidateSet.names()", name, called)
			}
			if slices.Contains(powerOffReadingFuncs, called) {
				t.Fatalf("%s calls %s: power-off evidence must not reach a set that excuses "+
					"nobody — it excuses a RUNTIME, never a MEMORY", name, called)
			}
		}
	}

	// Exactly one function in this file may branch on a role, plus the accessors
	// that carry the reading to it.
	allowedRoleReaders := []string{"addRow", "all", "runtimeProofParticipants",
		"localHostRows", "localParticipantCandidates", "localMembershipView",
		"GetMembershipView", "membershipViewOf", "closedParticipantSets"}
	for name, fn := range funcs {
		if slices.Contains(allowedRoleReaders, name) {
			continue
		}
		for _, sel := range selectorsRead(fn) {
			if sel == "witness" {
				t.Fatalf("%s reads .witness: the witness exclusion belongs to "+
					"runtimeProofParticipants alone. Any other reader is a second place two "+
					"of the three sets can drift back into one.", name)
			}
		}
	}

	// And exactly one function may sample the power-off input, so that the
	// derivations read ONE snapshot instead of each taking a live sample of a
	// signal that changes when a host rejoins.
	for name, fn := range funcs {
		if name == "snapshotPowerOffEvidence" || name == "hasFreshPowerOffProof" {
			continue
		}
		for _, called := range functionsCalled(fn) {
			if called == "hasFreshPowerOffProof" || called == "freshFenceConfirmation" {
				t.Fatalf("%s calls %s: the power-off input is sampled ONCE per closure by "+
					"snapshotPowerOffEvidence. A second sampler is how a host that rejoined "+
					"between two evaluations was excluded from the set that decided who to "+
					"ask and returned by the set the caller acted on.", name, called)
			}
		}
	}

	// The one place the sets are built: the fan-out and the corroboration set get
	// names, the runtime set gets roles plus the snapshot, and the
	// answered-discovery gate runs before anything is returned.
	closure, ok := funcs["closedParticipantSets"]
	if !ok {
		t.Fatal("closedParticipantSets is gone — it is the only place any of the three sets is built")
	}
	for _, spec := range []struct {
		fn        string
		wantArg   string
		rejectArg string
		why       string
	}{
		{"membershipDiscoveryTargets", "names()", "all()",
			"no role may be in scope for the fan-out"},
		{"inventoryCorroborationParticipants", "names()", "all()",
			"a witness holds the replicated rows, so no role may be in scope here either"},
	} {
		args := callArguments(t, fset, closure, spec.fn)
		if len(args) == 0 {
			t.Fatalf("closedParticipantSets no longer derives %s", spec.fn)
		}
		for _, a := range args {
			joined := strings.Join(a, ", ")
			if !strings.Contains(joined, spec.wantArg) || strings.Contains(joined, spec.rejectArg) {
				t.Fatalf("%s is derived from %s: it must pass candidateSet.%s — %s",
					spec.fn, joined, spec.wantArg, spec.why)
			}
		}
	}
	proofArgs := callArguments(t, fset, closure, "runtimeProofParticipants")
	if len(proofArgs) == 0 {
		t.Fatal("closedParticipantSets no longer derives the runtime-proof set, so nothing " +
			"excuses a witness from a scan it cannot complete")
	}
	for _, args := range proofArgs {
		joined := strings.Join(args, ", ")
		if !strings.Contains(joined, "all()") {
			t.Fatalf("the runtime-proof set is derived from %v: it must read the accumulated "+
				"role from candidateSet.all()", args)
		}
		if !strings.Contains(joined, "off") {
			t.Fatalf("the runtime-proof set is derived from %v without the power-off "+
				"snapshot: it must read the ONE sample taken for this closure, not take its "+
				"own", args)
		}
	}
	if len(functionsCalledNamed(closure, "participantsThatNeverAnswered")) == 0 {
		t.Fatal("closedParticipantSets no longer runs the answered-discovery gate. It was " +
			"removed once as redundant with the closure's own loop; that argument is about " +
			"the exclusions being identical, not about the closure, and a reproduction shows " +
			"it catching a rejoined peer the loop returned unasked. See " +
			"participantsThatNeverAnswered.")
	}
}

// TestTheDigestPathCannotBePointedAtTheRuntimeProofSet is the ROUND-FIVE guard,
// and the one the other guard could not have caught.
//
// Round four made the fan-out and the runtime-proof set structurally distinct and
// then read the bind's DATABASE-DIGEST check out of the runtime-proof set,
// because "the hosts that must corroborate" and "the hosts that must answer"
// sounded like the same hosts. They are not: a witness has the rows and not the
// runtime, so the set that must produce a digest is not the set that must produce
// a scan.
//
// This pins the two accessors to their fields and each caller to its accessor.
// Neither is a naming preference: a generic accessor is what let the digest check
// read the scan set in the first place, and the two read identically at a call
// site.
func TestTheDigestPathCannotBePointedAtTheRuntimeProofSet(t *testing.T) {
	fset := token.NewFileSet()
	sweeper := parseFuncs(t, fset, sweeperSourceFile)
	adopt := parseFuncs(t, fset, adoptSourceFile)

	for _, spec := range []struct {
		file, fn, wantField, rejectField, why string
	}{
		{sweeperSourceFile, "closedInventoryCorroborationPeers", "corroborating", "runtime",
			"the bind needs the hosts that HOLD THE ROWS, witnesses included — a witness " +
				"holds every replicated row while hosting nothing, and its unique VM and NIC " +
				"rows are exactly the ones a short local inventory is missing"},
		{sweeperSourceFile, "closedRuntimeProofSet", "runtime", "corroborating",
			"the sweeper needs the hosts that can SCAN A DOMAIN, which is the one thing a " +
				"witness cannot do"},
	} {
		fn, ok := sweeper[spec.fn]
		if !ok {
			t.Fatalf("%s is gone from %s: each proof must reach the participant universe "+
				"through the accessor named for the set it needs", spec.fn, spec.file)
		}
		sels := selectorsRead(fn)
		if !slices.Contains(sels, spec.wantField) {
			t.Fatalf("%s no longer reads sets.%s — %s", spec.fn, spec.wantField, spec.why)
		}
		if slices.Contains(sels, spec.rejectField) {
			t.Fatalf("%s reads sets.%s: %s", spec.fn, spec.rejectField, spec.why)
		}
	}

	// The bind's digest fan-out: it must reach its peers through the
	// corroboration accessor and must not be able to name the runtime one.
	prove, ok := adopt["proveNoPeerHoldsInventoryRowsWeLack"]
	if !ok {
		t.Fatalf("proveNoPeerHoldsInventoryRowsWeLack is gone from %s", adoptSourceFile)
	}
	called := functionsCalled(prove)
	if !slices.Contains(called, "closedInventoryCorroborationPeers") {
		t.Fatal("the bind's inventory corroboration no longer asks " +
			"closedInventoryCorroborationPeers. Every other route into the participant " +
			"universe asks hosts chosen for a different property: the runtime set excuses a " +
			"witness, and a witness's rows are exactly the ones this check exists to find.")
	}
	for _, bad := range []string{"closedRuntimeProofSet", "runtimeProofParticipants"} {
		if slices.Contains(called, bad) {
			t.Fatalf("the bind's inventory corroboration calls %s: that set is chosen for "+
				"having a domain to SCAN, and this check needs the hosts that hold the ROWS",
				bad)
		}
	}

	// Nothing in the bind's file may reach the runtime field at all, so the
	// mis-pointing cannot come back one function further along.
	for name, fn := range adopt {
		for _, sel := range selectorsRead(fn) {
			if sel == "runtime" {
				t.Fatalf("%s in %s reads a .runtime field: the bind side has no business "+
					"with the runtime-proof set", name, adoptSourceFile)
			}
		}
	}

	// …and the sweeper's reclamation must keep asking for the scan set.
	reclaim, ok := sweeper["reclaimIfProven"]
	if !ok {
		t.Fatalf("reclaimIfProven is gone from %s", sweeperSourceFile)
	}
	rcalled := functionsCalled(reclaim)
	if !slices.Contains(rcalled, "closedRuntimeProofSet") {
		t.Fatal("reclaimIfProven no longer reads closedRuntimeProofSet: a witness cannot " +
			"produce a runtime scan, so asking the corroboration set for one wedges every " +
			"reclamation behind a proof that can never complete")
	}
	if slices.Contains(rcalled, "closedInventoryCorroborationPeers") {
		t.Fatal("reclaimIfProven reads the inventory-corroboration set, which includes " +
			"witnesses: they hold the rows and run no libvirt")
	}
}

// TestTheMirrorsRemovalProofIsTheBindsInventoryProof is the same discipline
// applied to the SECOND consumer of the inventory corroboration.
//
// The inventory mirror will not conclude that an incarnation stopped existing
// from its own mapping row — which identifies an incarnation and says nothing
// about whether it is gone — until the read that absence is measured against is
// corroborated as the cluster's. That is the property the bind already refuses
// to hand out addresses without, reached from the other side: a bind that
// adopted nothing because it could not see a holder, and a mirror that deleted a
// holder's inventory object because it could not see the holder, are one
// condition.
//
// So it must be ONE mechanism. Two notions of a whole read is how the sweeper's
// proof and the bind's came to differ over a witness, three rounds running, and
// a mirror comparing digests its own way would be the fourth. This pins the
// mirror's corroboration to the bind's proof, to the bind's table set, and away
// from the runtime-proof set that excuses a witness — whose rows are exactly the
// ones a short local inventory is missing.
func TestTheMirrorsRemovalProofIsTheBindsInventoryProof(t *testing.T) {
	fset := token.NewFileSet()
	adopt := parseFuncs(t, fset, adoptSourceFile)

	fn, ok := adopt["corroborateMirrorInventory"]
	if !ok {
		t.Fatalf("corroborateMirrorInventory is gone from %s: the mirror's removal-evidence "+
			"policy has one record it cannot conclude an absence from without the cluster, "+
			"and this is where it asks", adoptSourceFile)
	}
	called := functionsCalled(fn)
	for _, must := range []string{
		"localTableDigests", "proveNoPeerHoldsInventoryRowsWeLack", "adoptionInventoryTables",
		// …and the SHARED binding check. The mirror's conclusions are drawn from
		// a read taken before the pass did anything; without this the proof can
		// certify a later read and stamp the answer on that plan, which is how a
		// live VM's object came to be deleted on a successful proof.
		"inventoryMoved",
	} {
		if !slices.Contains(called, must) {
			t.Fatalf("corroborateMirrorInventory no longer calls %s: it must ask the BIND's "+
				"proof, over the bind's table set, with the bind's binding check, rather than "+
				"deciding for itself what a whole inventory read is", must)
		}
	}
	// The BOUND sample is what the peers are compared against, not a fresh read.
	// Asserted on the argument, because passing `now` there compiles, reads
	// almost identically, and is the entire defect.
	if arg := soleDigestArgOf(t, fn, "proveNoPeerHoldsInventoryRowsWeLack"); arg != "bound" {
		t.Fatalf("corroborateMirrorInventory proves %q against the peers, want the BOUND "+
			"sample: proving a freshly sampled read whole says nothing about the plan that "+
			"came out of the earlier one", arg)
	}
	for _, bad := range []string{
		// A comparison of its own, which is the shape a second mechanism takes.
		"TableDigestsAgree", "gatherTableDigests",
		// …and the wrong participant set, which is the mistake that has already
		// been made three times.
		"closedRuntimeProofSet", "runtimeProofParticipants", "closedInventoryCorroborationPeers",
	} {
		if slices.Contains(called, bad) {
			t.Fatalf("corroborateMirrorInventory calls %s: it must reach the peers and the "+
				"comparison only through proveNoPeerHoldsInventoryRowsWeLack, so the mirror "+
				"and the bind cannot come to disagree about what a whole read is", bad)
		}
	}

	// …and the mirror is actually wired to it. Without this the function could
	// be correct and unreached, which is a mirror deleting objects on
	// identification alone — the finding, reintroduced by omission.
	build, ok := parseFuncs(t, fset, "netbox_mirror.go")["netboxMirror"]
	if !ok {
		t.Fatal("netboxMirror is gone: it is the only place the mirror's options are built")
	}
	if !slices.Contains(selectorsRead(build), "netboxInventorySnapshot") {
		t.Fatal("netboxMirror no longer threads netboxInventorySnapshot into the reconciler. " +
			"netboxsync treats a missing inventory proof as 'not corroborated', so this does " +
			"not fail open — it withholds every removal whose only record is a mapping row, " +
			"permanently, which is a mirror that never converges")
	}
	// A SAMPLER, and the corroboration reached only through what it returns. A
	// predicate wired straight in would answer about the inventory at the moment
	// the question is asked, which is a different read from the one the pass's
	// conclusions came out of.
	mirror := parseFuncs(t, fset, "netbox_mirror.go")
	sampler, ok := mirror["netboxInventorySnapshot"]
	if !ok {
		t.Fatal("netboxInventorySnapshot is gone: the mirror's proof has to be BOUND to a " +
			"sample taken before the pass reads anything")
	}
	for _, must := range []string{"localTableDigests", "adoptionInventoryTables"} {
		if !slices.Contains(functionsCalled(sampler), must) {
			t.Fatalf("netboxInventorySnapshot no longer calls %s: the sample has to be the "+
				"bind's own table set, read the bind's own way", must)
		}
	}
	if slices.Contains(selectorsRead(sampler), "corroborateMirrorInventory") {
		t.Fatal("netboxInventorySnapshot answers the corroboration itself: sampling and " +
			"proving in one call is the defect — the pass has to read its state BETWEEN the " +
			"two, which is the whole of what the binding certifies")
	}
}

// soleDigestArgOf is the identifier `fn` passes to `callee` as its digest-map
// argument, or "" when it passes something that is not a plain identifier.
//
// Structural because the distinction is invisible behaviourally at that line:
// once the binding check has passed, the bound sample and a fresh read are
// equal, so a test can only tell them apart by what the code says.
func soleDigestArgOf(t *testing.T, fn *ast.FuncDecl, callee string) string {
	t.Helper()
	var got string
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != callee || len(call.Args) < 2 {
			return true
		}
		if id, ok := call.Args[len(call.Args)-1].(*ast.Ident); ok {
			got = id.Name
		}
		return true
	})
	if got == "" {
		t.Fatalf("could not read the digest argument %s passes to %s", fn.Name.Name, callee)
	}
	return got
}

// parseFuncs parses one file in this package and indexes its function
// declarations by name.
func parseFuncs(t *testing.T, fset *token.FileSet, path string) map[string]*ast.FuncDecl {
	t.Helper()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			funcs[fn.Name.Name] = fn
		}
	}
	return funcs
}

// functionsCalledNamed is every call to `name` inside fn.
func functionsCalledNamed(fn *ast.FuncDecl, name string) []string {
	var out []string
	for _, called := range functionsCalled(fn) {
		if called == name {
			out = append(out, called)
		}
	}
	return out
}

// renderNode prints one AST node back to source, for a legible failure.
func renderNode(t *testing.T, fset *token.FileSet, node ast.Node) string {
	t.Helper()
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, node); err != nil {
		t.Fatalf("render node: %v", err)
	}
	return sb.String()
}

// selectorsRead is every field or method name selected inside a function body.
func selectorsRead(fn *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			out = append(out, sel.Sel.Name)
		}
		return true
	})
	return out
}

// functionsCalled is every called name inside a function body, method calls
// reduced to the method name.
func functionsCalled(fn *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			out = append(out, f.Name)
		case *ast.SelectorExpr:
			out = append(out, f.Sel.Name)
		}
		return true
	})
	return out
}

// callArguments renders the arguments of every call to `name` inside fn.
func callArguments(t *testing.T, fset *token.FileSet, fn *ast.FuncDecl, name string) [][]string {
	t.Helper()
	var out [][]string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		called := ""
		switch f := call.Fun.(type) {
		case *ast.Ident:
			called = f.Name
		case *ast.SelectorExpr:
			called = f.Sel.Name
		}
		if called != name {
			return true
		}
		var args []string
		for _, a := range call.Args {
			args = append(args, renderNode(t, fset, a))
		}
		out = append(out, args)
		return true
	})
	return out
}

// TestTheThreeSetsDifferOnlyWhereTheEvidenceDiffers is the behavioural half of
// the guards above: one universe in, three sets out, differing in exactly the
// places the evidence differs.
//
// Every role reading a `hosts` row can carry — witness, worker, a role column
// nothing has written, and no row at all — produces the SAME discovery fan-out
// and the SAME inventory-corroboration set. Only the runtime-proof set differs,
// and it differs on the two grounds that mean "there is no domain here to scan":
// a corroborated witness, and a machine an operator has attested is off.
//
// A witness in the corroboration set is the round-five finding stated as a
// property: it holds the whole replicated database while hosting nothing, so its
// rows are evidence and its libvirt is not.
func TestTheThreeSetsDifferOnlyWhereTheEvidenceDiffers(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedSelfHost(t, s)

	roles := map[string]string{
		"a-witness":       "witness",
		"another-witness": "witness",
		"a-worker":        "worker",
		"no-role-at-all":  "",
		"attested-off":    "worker",
	}
	for name, role := range roles {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
			Name: name, Address: "203.0.113.9", GRPCPort: 7443, Role: role,
			SSHUser: "root", SSHPort: 22, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	// …and one host no row anywhere records, named by gossip alone.
	s.db.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: "gossip-only", Addr: "203.0.113.9:7946"}}
	})
	// The operator attests one worker is powered off. Nothing makes it
	// reachable, so the attestation stands — and it is deliberately written TEN
	// MINUTES OLD, which also pins netboxFenceWindow: the VIP release proof
	// expires an attestation after five minutes, right for a failover decided
	// seconds after a host drops and useless for a sweep that runs on a cadence
	// measured in minutes. Borrowing that window would expire every
	// confirmation before a pass could read it.
	if err := s.db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES ('fence-confirm-off', 'attested-off', 'manual', 'manual-confirmed', ?, 'attested')`,
		time.Now().UTC().Add(-10*time.Minute).Format(time.RFC3339)); err != nil {
		t.Fatalf("write fence confirmation: %v", err)
	}

	candidates, err := s.localParticipantCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	everyone := []string{"a-witness", "another-witness", "a-worker", "no-role-at-all",
		"attested-off", "gossip-only", s.hostName}

	targets := s.membershipDiscoveryTargets(candidates.names())
	for _, want := range everyone {
		if !slices.Contains(targets, want) {
			t.Fatalf("%s must be asked what it knows whatever its role says it may run and "+
				"whatever its power state — a machine that is off still knew who existed; got %v",
				want, targets)
		}
	}

	corroborating := s.inventoryCorroborationParticipants(candidates.names())
	for _, want := range everyone {
		if !slices.Contains(corroborating, want) {
			t.Fatalf("%s holds the replicated rows, so its inventory digest must be "+
				"consulted — a witness holds the whole database while hosting nothing, and a "+
				"machine that is off still holds its rows; got %v", want, corroborating)
		}
	}

	off, err := s.snapshotPowerOffEvidence(ctx, candidates.names())
	if err != nil {
		t.Fatal(err)
	}
	proof := s.runtimeProofParticipants(candidates.all(), off)
	for _, excused := range []string{"a-witness", "another-witness"} {
		if slices.Contains(proof, excused) {
			t.Fatalf("%s hosts no workload, so a scan of it is not evidence: it must not be "+
				"in the runtime-proof set, got %v", excused, proof)
		}
	}
	if slices.Contains(proof, "attested-off") {
		t.Fatalf("a machine attested powered off cannot be running a domain, so it owes no "+
			"scan, got %v", proof)
	}
	for _, want := range []string{"a-worker", "no-role-at-all", "gossip-only", s.hostName} {
		if !slices.Contains(proof, want) {
			t.Fatalf("%s must produce a runtime scan — an unknown role is not the statement "+
				"that a host is a witness; got %v", want, proof)
		}
	}
}

// TestAnUnreachableHostBlocksTheClosureWhateverItsFenceRecord is the liveness
// cost of the three sets, stated rather than discovered — and it is a cost that
// was deliberately accepted rather than mitigated.
//
// Every host is dialled for its membership view, so one that cannot answer
// leaves the set unclosed, whatever its role and WHATEVER THE FENCING LOG SAYS.
// An earlier round offered `lv host fence-confirm` as the escape from exactly
// this: excuse the attested-off host from being asked, and the closure completes.
// That trade was refused, and the refusal is the point of this test — confirming
// a machine is off proves its libvirt is not running a domain, and proves nothing
// about the hosts that machine alone knew existed. A witness attested off was the
// only node that could name a third host still holding the address, and excusing
// it from the question freed that address.
//
// So both sub-cases below stay blocked, before and after the attestation. What
// the attestation still buys is exactly one thing, pinned by
// TestTheThreeSetsDifferOnlyWhereTheEvidenceDiffers: the host owes no runtime
// scan. It never buys silence about what it knew.
func TestAnUnreachableHostBlocksTheClosureWhateverItsFenceRecord(t *testing.T) {
	for _, role := range []string{"witness", "worker"} {
		t.Run(role, func(t *testing.T) {
			s := newAdoptTestServer(t)
			ctx := context.Background()
			seedSelfHost(t, s)
			// No stub is installed and the address is a reserved documentation
			// address, so the dial fails at the transport.
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
				Name: "silent", Address: "203.0.113.9", GRPCPort: 7443, Role: role,
				SSHUser: "root", SSHPort: 22, State: "active", FenceStrategy: "best-effort",
			}); err != nil {
				t.Fatal(err)
			}

			closed, unclosed, err := s.closedRuntimeProofSet(ctx)
			if err != nil {
				t.Fatalf("a host that cannot answer is part of the answer, not an error: %v", err)
			}
			if unclosed == "" {
				t.Fatalf("a %s that cannot be asked what it knows leaves the set unclosed, got %v",
					role, closed)
			}
			if !strings.Contains(unclosed, "silent") {
				t.Fatalf("the reason must name the host so an operator can act: %q", unclosed)
			}

			// The operator attests the machine is off. It still knew which hosts
			// existed and still holds replicated rows, so it still blocks.
			if err := s.db.Execute(ctx,
				`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
				 VALUES ('fence-confirm-silent', 'silent', 'manual', 'manual-confirmed', ?, 'attested')`,
				s.db.NowWall()); err != nil {
				t.Fatalf("write fence confirmation: %v", err)
			}
			closed, unclosed, err = s.closedRuntimeProofSet(ctx)
			if err != nil {
				t.Fatalf("an unreadable answer is not this node's error: %v", err)
			}
			if unclosed == "" {
				t.Fatalf("power-off evidence excuses a SCAN, never the question of what a "+
					"host knew: an attested, unreachable %s must still leave the set "+
					"unclosed, got %v", role, closed)
			}
			if !strings.Contains(unclosed, "silent") {
				t.Fatalf("the reason must still name the host: %q", unclosed)
			}

			// The bind reaches its peers through the other accessor, and
			// withholds on the same unclosed set.
			peers, unclosed, err := s.closedInventoryCorroborationPeers(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if unclosed == "" {
				t.Fatalf("the bind must withhold on the same unclosed set, got peers %v", peers)
			}
		})
	}
}

// TestTheClosureRefusesToReturnAHostItNeverAsked pins THE ANSWERED-DISCOVERY
// GATE directly, because the gate is the one check whose value does not depend
// on the current exclusions being right.
//
// It was removed once as redundant: the closure returns only when every
// discovery target has answered, so a returned host must have been asked. That
// argument is about the three sets having identical membership — it is an
// argument about the exclusions, not about the loop — and the moment one set
// excludes a host another set returns, the loop's conclusion no longer covers
// what the caller acts on. Both reproductions above are that shape.
//
// Driving the gate directly is deliberate: it must refuse an unasked participant
// even when no current exclusion can produce one, since that is precisely the
// condition it exists to keep true.
func TestTheClosureRefusesToReturnAHostItNeverAsked(t *testing.T) {
	s := newAdoptTestServer(t)
	asked := map[string]bool{s.hostName: true, "answered": true}

	if why := s.participantsThatNeverAnswered(participantSets{
		corroborating: []string{s.hostName, "answered"},
		runtime:       []string{s.hostName, "answered"},
	}, asked); why != "" {
		t.Fatalf("every participant answered, so the gate must pass: %q", why)
	}

	// AN ANSWER IS THE ONLY THING THE GATE ACCEPTS. It takes the sets and the
	// asked-map and nothing else, so there is no third argument through which a
	// grant, manifest or attestation could account for a participant that never
	// spoke. A prerelease permanent-loss exception was exactly such an argument;
	// this loop is the refusal it had an exception for, with no exception left.
	for _, sets := range []participantSets{
		{corroborating: []string{s.hostName, "answered", "never-asked"},
			runtime: []string{s.hostName, "answered"}},
		{corroborating: []string{s.hostName, "answered"},
			runtime: []string{s.hostName, "answered", "never-asked"}},
	} {
		why := s.participantsThatNeverAnswered(sets, asked)
		if why == "" {
			t.Fatalf("a participant whose membership view was never read must leave the set "+
				"unclosed: %+v", sets)
		}
		if !strings.Contains(why, "never-asked") {
			t.Fatalf("the reason must name the host an operator has to look at: %q", why)
		}
	}
}

// TestOneClosureSamplesThePowerOffInputOnce pins the SNAPSHOT.
//
// The power-off input is live: it consults the healthy-peer gate, so two
// evaluations milliseconds apart can legitimately disagree when a host rejoins
// between them. While two derivations each took their own sample, that
// disagreement produced a set containing a host the other sample had excluded
// from being asked — a participant returned without its membership ever being
// read.
//
// The gate here answers differently on every read, so a second sample is
// observable: one closure must consult it exactly once per candidate.
func TestOneClosureSamplesThePowerOffInputOnce(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedSelfHost(t, s)
	seedPeerHost(t, s, "peer-b")
	// peer-b answers membership perfectly, so the closure reaches the
	// derivations — this is not about a dial failing.
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		return membershipNaming(host, workerRows(s.hostName, "peer-b"), nil)
	})
	// …and it is attested off while the gate reports it unreachable on the first
	// read and reachable on every read after that.
	if err := s.db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES ('fence-confirm-b', 'peer-b', 'manual', 'manual-confirmed', ?, 'attested')`,
		s.db.NowWall()); err != nil {
		t.Fatal(err)
	}
	g := &flippingReachabilityGate{}
	s.gate = g

	sets, unclosed, err := s.closedParticipantSets(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("every participant answered, so the set must close: %q (err %v)", unclosed, err)
	}
	if g.reads != 1 {
		t.Fatalf("the power-off input was sampled %d times in one closure: it must be "+
			"sampled ONCE per candidate and read from the snapshot, or two derivations "+
			"disagree about a host that rejoined mid-run", g.reads)
	}
	// The one sample said unreachable-and-attested, so the snapshot excuses
	// peer-b from the SCAN and from nothing else.
	if slices.Contains(sets.runtime, "peer-b") {
		t.Fatalf("the snapshot said peer-b is attested off, so it owes no scan: %v", sets.runtime)
	}
	if !slices.Contains(sets.corroborating, "peer-b") {
		t.Fatalf("peer-b still holds its replicated rows, so its inventory digest must be "+
			"consulted: %v", sets.corroborating)
	}
}

// flippingReachabilityGate answers "unreachable" once and "reachable" ever
// after, so any second sample of the power-off input reaches a different
// conclusion than the first — and counts the samples.
type flippingReachabilityGate struct {
	fakeServerGate
	reads int
}

func (g *flippingReachabilityGate) HealthyPeers(context.Context) []string {
	g.reads++
	if g.reads == 1 {
		return nil
	}
	return []string{"peer-b"}
}

// TestTheClosureRefusesAPeerThatRejoinedBetweenTwoReachabilitySamples is the
// reviewer's reproduction of the split evaluation, kept as a regression.
//
// The host is attested off and unreachable on the first sample, and reachable on
// the second. While the discovery fan-out and the derived set each took their own
// sample, the first excluded it — so nothing asked it what it knew — and the
// second put it straight back into the set the caller acted on. The closure
// returned success naming a peer whose membership had never been read.
//
// Two independent properties now stop it, and the test does not care which
// fires: the fan-out no longer applies power-off evidence at all (so the host is
// dialled, and the dial fails), and the answered-discovery gate refuses to return
// a host discovery never read.
func TestTheClosureRefusesAPeerThatRejoinedBetweenTwoReachabilitySamples(t *testing.T) {
	s := newAdoptTestServer(t)
	seedSelfHost(t, s)
	seedPeerHost(t, s, "peer-b")
	ctx := context.Background()
	if err := s.db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES ('review-fence', 'peer-b', 'manual', 'manual-confirmed', ?, 'attested')`,
		s.db.NowWall()); err != nil {
		t.Fatal(err)
	}
	// No RPC stub is installed, so peer-b cannot answer anything: success can
	// only mean it was never asked.
	g := &flippingReachabilityGate{}
	s.gate = g

	set, unclosed, err := s.closedRuntimeProofSet(ctx)
	if err != nil {
		t.Fatalf("a host that cannot answer is part of the answer, not an error: %v", err)
	}
	if unclosed == "" {
		t.Fatalf("closed with an unqueried peer after %d reachability samples: %v", g.reads, set)
	}
}

// TestBindRefusesAPeerItCouldNotEstablishTheMembershipOf is the reviewer's second
// reproduction, kept as a regression, and the evidence that the
// answered-discovery gate is not redundant.
//
// This peer answers GetStateDigest with digests that agree perfectly and cannot
// answer GetMembershipView at all — an older build, which returns Unimplemented.
// While power-off evidence excused it from the discovery fan-out, nothing ever
// called the RPC that would have failed, its rejoin put it into the set the bind
// asked for digests, the digests agreed, and the bind went live on an inventory
// no membership proof covered.
func TestBindRefusesAPeerItCouldNotEstablishTheMembershipOf(t *testing.T) {
	s := newAdoptTestServer(t)
	seedSelfHost(t, s)
	seedPeerHost(t, s, "peer-b")
	ctx := context.Background()
	if err := s.db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES ('review-fence', 'peer-b', 'manual', 'manual-confirmed', ?, 'attested')`,
		s.db.NowWall()); err != nil {
		t.Fatal(err)
	}
	local, err := s.localTableDigests(ctx, adoptionInventoryTables())
	if err != nil {
		t.Fatal(err)
	}
	tables := agreeingDigests(t, s)
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		// Digests that agree, and no membership view: GetMembershipView returns
		// Unimplemented, which must prevent corroboration.
		return &answeringPeer{tables: tables}, func() {}, nil
	}
	s.gate = &flippingReachabilityGate{}

	proven, why, err := s.proveNoPeerHoldsInventoryRowsWeLack(ctx, local)
	if err != nil {
		t.Fatalf("a peer that cannot answer is part of the answer, not an error: %v", err)
	}
	if proven {
		t.Fatalf("accepted a rejoined peer without establishing its membership: %q", why)
	}
	if !strings.Contains(why, "peer-b") {
		t.Fatalf("the reason must name the host: %q", why)
	}
}

// TestTheClosureBoundHoldsWithWitnessesInTheFanOut re-establishes termination.
//
// Widening the fan-out to every role widens what a pathological topology can
// feed it: a peer naming an endless chain of WITNESSES could not spin the
// closure before, because a witness never entered the fan-out at all. It can
// now, so the round bound has to be what stops it — and running out is a
// REFUSAL, not a truncated set.
func TestTheClosureBoundHoldsWithWitnessesInTheFanOut(t *testing.T) {
	s := newAdoptTestServer(t)
	seedPeerHost(t, s, "peer-b")

	var mu sync.Mutex
	dials := 0
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		mu.Lock()
		dials++
		n := dials
		mu.Unlock()
		// Every answer names one host nobody has seen, as a WITNESS.
		return membershipNaming(host, append(workerRows(host),
			&pb.MembershipHost{Name: fmt.Sprintf("witness-%d", n), Role: "witness"}), nil)
	})

	closed, unclosed, err := s.closedRuntimeProofSet(context.Background())
	if err != nil {
		t.Fatalf("a growing set is part of the answer, not an error: %v", err)
	}
	if unclosed == "" {
		t.Fatalf("a set that never stops growing must not be reported as closed, got %v", closed)
	}
	if closed != nil {
		t.Fatalf("an unclosed set must not be returned to a caller, got %v", closed)
	}
	if dials > hostSetClosureRounds {
		t.Fatalf("the fan-out dialled %d times, past the %d-round bound",
			dials, hostSetClosureRounds)
	}
}
