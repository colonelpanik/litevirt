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

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The participant universe produces TWO sets, and they must not be one set.
//
//   - membershipDiscoveryTargets — who is asked WHAT IT KNOWS. Everyone.
//   - runtimeProofParticipants — who must produce a RUNTIME SCAN. Witnesses
//     excused, on a role every row read agrees about.
//
// Collapsing them freed a held address twice: once because a stale local
// `role='witness'` kept a host that had since become a worker out of the
// fan-out, and once because a genuine witness — the only node that could name a
// third holder — was never asked. Both are shapes where the exclusion PREVENTED
// the query that would have refuted it, so a comment cannot be the guard.

// sweeperSourceFile is the file the guards below parse. Tests run with the
// package directory as their working directory.
const sweeperSourceFile = "netbox_sweeper.go"

// roleBearingTypes are the types that carry a role. A parameter of any of them
// is the mechanism by which a role could reach the discovery fan-out.
var roleBearingTypes = []string{"participantCandidate", "candidateSet", "hostRoleRow"}

// roleReadingSelectors are the ways code in this file reads a role.
var roleReadingSelectors = []string{"witness", "role", "Role"}

// TestMembershipDiscoveryTargetsCannotFilterByRole is the structural guard.
//
// The fan-out takes NAMES, and that is not a stylistic choice: with no role in
// scope, the filter that must never be applied cannot be applied without
// changing the signature — which this test then fails on. It also pins the
// SHARED leg (keepUnlessPoweredOff, which both sets go through) and the one call
// site, so a role cannot creep in one function further down either.
func TestMembershipDiscoveryTargetsCannotFilterByRole(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, sweeperSourceFile, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", sweeperSourceFile, err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			funcs[fn.Name.Name] = fn
		}
	}

	// The whole discovery path: the fan-out and the leg it shares with the proof
	// set. Neither may see a role.
	for _, name := range []string{"membershipDiscoveryTargets", "keepUnlessPoweredOff"} {
		fn, ok := funcs[name]
		if !ok {
			t.Fatalf("%s is gone from %s — the two participant sets have been "+
				"restructured, and this guard is the reason they are two", name, sweeperSourceFile)
		}
		for _, param := range fn.Type.Params.List {
			rendered := renderNode(t, fset, param.Type)
			for _, bad := range roleBearingTypes {
				if strings.Contains(rendered, bad) {
					t.Fatalf("%s takes a %s parameter (%s): the membership-discovery fan-out "+
						"must not be able to see a role. A host's role says what it may RUN, "+
						"never what it KNOWS, and excluding a host from the fan-out is exactly "+
						"what prevents learning the exclusion was wrong.", name, bad, rendered)
				}
			}
		}
		for _, sel := range selectorsRead(fn) {
			if slices.Contains(roleReadingSelectors, sel) {
				t.Fatalf("%s reads .%s: the membership-discovery fan-out must not filter by "+
					"role — see runtimeProofParticipants, which is where a role belongs", name, sel)
			}
		}
		for _, called := range functionsCalled(fn) {
			if called == "all" || called == "runtimeProofParticipants" {
				t.Fatalf("%s calls %s, which carries the role reading: the fan-out must be "+
					"built from candidateSet.names()", name, called)
			}
		}
	}

	// Exactly one function in this file may branch on a role, plus the two
	// candidateSet accessors that carry the reading to it.
	allowedRoleReaders := []string{"addRow", "all", "runtimeProofParticipants",
		"localHostRows", "localParticipantCandidates", "localMembershipView",
		"GetMembershipView", "membershipViewOf", "closedParticipantSet"}
	for name, fn := range funcs {
		if slices.Contains(allowedRoleReaders, name) {
			continue
		}
		for _, sel := range selectorsRead(fn) {
			if sel == "witness" {
				t.Fatalf("%s reads .witness: the witness exclusion belongs to "+
					"runtimeProofParticipants alone. Any other reader is a second place the "+
					"proof set and the discovery set can drift back into one.", name)
			}
		}
	}

	// The one call site: the fan-out gets names, the proof set gets roles.
	closure, ok := funcs["closedParticipantSet"]
	if !ok {
		t.Fatal("closedParticipantSet is gone — it is the only place either set is built")
	}
	discoveryArgs := callArguments(t, fset, closure, "membershipDiscoveryTargets")
	if len(discoveryArgs) == 0 {
		t.Fatal("closedParticipantSet no longer fans out over membershipDiscoveryTargets")
	}
	for _, args := range discoveryArgs {
		joined := strings.Join(args, ", ")
		if !strings.Contains(joined, "names()") || strings.Contains(joined, "all()") {
			t.Fatalf("the closure fans out over %s: it must pass candidateSet.names(), so no "+
				"role is in scope for the fan-out", joined)
		}
	}
	proofArgs := callArguments(t, fset, closure, "runtimeProofParticipants")
	if len(proofArgs) == 0 {
		t.Fatal("closedParticipantSet no longer derives the runtime-proof set, so nothing " +
			"excuses a witness from a scan it cannot complete")
	}
	for _, args := range proofArgs {
		if !strings.Contains(strings.Join(args, ", "), "all()") {
			t.Fatalf("the runtime-proof set is derived from %v: it must read the accumulated "+
				"role from candidateSet.all()", args)
		}
	}
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

// TestDiscoveryTargetsAreTheWHOLEUniverseWhateverTheRole is the behavioural half
// of the guard above.
//
// Every role reading a `hosts` row can carry — witness, worker, a role column
// nothing has written, and two rows that disagree — produces the SAME fan-out.
// The proof set built from the same candidates then differs, and that difference
// is the whole point: a witness is a first-class source of membership and a
// useless target for a runtime scan.
func TestDiscoveryTargetsAreTheWHOLEUniverseWhateverTheRole(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedSelfHost(t, s)

	roles := map[string]string{
		"a-witness":       "witness",
		"another-witness": "witness",
		"a-worker":        "worker",
		"no-role-at-all":  "",
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

	candidates, err := s.localParticipantCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := s.membershipDiscoveryTargets(ctx, candidates.names())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"a-witness", "another-witness", "a-worker",
		"no-role-at-all", "gossip-only", s.hostName} {
		if !slices.Contains(targets, want) {
			t.Fatalf("%s must be asked what it knows whatever its role says it may run, got %v",
				want, targets)
		}
	}

	proof, err := s.runtimeProofParticipants(ctx, candidates.all())
	if err != nil {
		t.Fatal(err)
	}
	for _, excused := range []string{"a-witness", "another-witness"} {
		if slices.Contains(proof, excused) {
			t.Fatalf("%s hosts no workload, so a scan of it is not evidence: it must not be "+
				"in the runtime-proof set, got %v", excused, proof)
		}
	}
	for _, want := range []string{"a-worker", "no-role-at-all", "gossip-only", s.hostName} {
		if !slices.Contains(proof, want) {
			t.Fatalf("%s must produce a runtime scan — an unknown role is not the statement "+
				"that a host is a witness; got %v", want, proof)
		}
	}
}

// TestAnUnreachableWitnessBlocksTheClosureLikeAnyWorker is the liveness cost of
// asking witnesses, stated rather than discovered.
//
// A witness is now dialled for its membership view, so one that cannot answer
// leaves the set unclosed — where a witness whose local row happened to say
// `witness` used to be dropped without a dial. That is the fail-closed
// direction, and it has to be: a host we cannot ask might be a worker whose role
// row here is stale, which is the first of the two reproductions this fixes.
//
// It cannot block forever, and it blocks for no longer than a worker would: the
// escape is the same operator attestation, with the same effect.
func TestAnUnreachableWitnessBlocksTheClosureLikeAnyWorker(t *testing.T) {
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

			closed, unclosed, err := s.closedParticipantSet(ctx)
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

			// The escape hatch, identical for both roles: an operator attests the
			// machine is off, and it leaves BOTH sets.
			if err := s.db.Execute(ctx,
				`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
				 VALUES ('fence-confirm-silent', 'silent', 'manual', 'manual-confirmed', ?, 'attested')`,
				s.db.NowWall()); err != nil {
				t.Fatalf("write fence confirmation: %v", err)
			}
			closed, unclosed, err = s.closedParticipantSet(ctx)
			if err != nil || unclosed != "" {
				t.Fatalf("an attested host is excluded from the fan-out too, so the set must "+
					"close: %q (err %v)", unclosed, err)
			}
			if slices.Contains(closed, "silent") {
				t.Fatalf("an attested host must be in neither set, got %v", closed)
			}
		})
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

	closed, unclosed, err := s.closedParticipantSet(context.Background())
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
