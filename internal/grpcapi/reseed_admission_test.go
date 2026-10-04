package grpcapi

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Admission must read the fence ONCE.
//
// It used to read twice — refuseLoginWhileReseedIncomplete read it, then
// stampReseedFence read it again — and a reseed starting between the two made
// the stamp capture the POST-reseed generation. The comparison at mintSession
// then found no change, and if the reseed had also finished, `incomplete` was
// clear again and an enrolled account got a password-only session. That is the
// very TOCTOU the generation was added to close, one layer in.
//
// This guard covers the ADMISSION layer only: that the gate makes one call.
// It cannot see inside that call, and for a while that mattered — ReseedFence
// itself then read twice, so this test passed against code with the very race
// its name denies. The read count at the layer that actually reads is pinned
// by corrosion.TestReseedFence_IsASingleRead; both are needed, because one
// call to a two-read function and two calls to a one-read function are
// different bugs with the same consequence.
func TestPreSessionAdmission_ReadsTheFenceExactlyOnce(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "reseed_login_gate.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The MINT-side read is legitimately separate: it is the far end of the
	// comparison, taken after the credentials have been checked. The invariant
	// here is about the ADMISSION side — everything between the request arriving
	// and its generation being stamped.
	mintSide := map[string]bool{"refuseIfReseedMovedSinceEntry": true}
	counts := map[string]int{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || mintSide[fn.Name.Name] {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// BOTH read methods. Counting only ReseedFence missed the bug
			// entirely: the refusal read through ReseedIncomplete and the stamp
			// through ReseedFence, so "one ReseedFence call" was satisfied by
			// code doing two reads.
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "ReseedFence", "ReseedIncomplete":
					counts[fn.Name.Name]++
				}
			}
			return true
		})
	}
	total := 0
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		t.Fatal("no admission-side ReseedFence call found at all; the matcher is broken, " +
			"or admission stopped reading the fence")
	}
	if total != 1 {
		t.Errorf("admission reads the reseed fence %d times across %v — a reseed landing "+
			"between two reads makes the stamped generation match the one the mint "+
			"compares against, which is exactly the race the generation exists to catch. "+
			"One read must drive both the refusal and the stamp.", total, counts)
	}
}

// A fence read that FAILS must refuse, not wave the request through unstamped.
//
// stampReseedFence swallowed the error and stamped nothing; the mint then could
// not tell "the stamp was dropped" from "this did not come through the gate"
// and skipped the comparison, falling back to the `incomplete` boolean the
// generation exists precisely because it is insufficient. A transient
// SQLITE_BUSY at the door was enough to reopen the whole hole.
func TestPreSessionAdmission_AFailedFenceReadRefuses(t *testing.T) {
	s := gateTestServer(t)
	s.db.Close() // every fence read now fails

	called := false
	_, err := s.UnaryAuthInterceptor(context.Background(), &pb.LoginRequest{Username: "alice"},
		&grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/Login"},
		func(context.Context, interface{}) (interface{}, error) { called = true; return nil, nil })

	if err == nil || called {
		t.Fatal("a login was admitted although the reseed fence could not be read — an " +
			"unreadable fence is not permission to serve, and the mint cannot recover the " +
			"comparison this dropped")
	}
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("code = %s, want Unavailable", got)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "reseed") {
		t.Errorf("error = %q; it must name what could not be confirmed", err)
	}
}

// Ping must stay reachable even when the fence cannot be read: it is how the
// condition is diagnosed and the reseed path itself calls it.
func TestPreSessionAdmission_PingSurvivesAnUnreadableFence(t *testing.T) {
	s := gateTestServer(t)
	s.db.Close()

	called := false
	if _, err := s.UnaryAuthInterceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/Ping"},
		func(context.Context, interface{}) (interface{}, error) { called = true; return nil, nil }); err != nil {
		t.Fatalf("Ping refused on an unreadable fence: %v", err)
	}
	if !called {
		t.Error("the Ping handler did not run")
	}
}
