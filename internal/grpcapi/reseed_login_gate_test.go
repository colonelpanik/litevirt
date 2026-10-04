package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func gateTestServer(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{db: db, hostName: "test-node"}
}

// The window this guards fails OPEN: a reseed restores password hashes in an
// earlier step than user_2fa, so a node that died in between authenticates every
// enrolled account with a password alone. While the marker is set, a pre-session
// credential exchange must be refused.
func TestLoginGate_RefusesLoginWhileAReseedIsIncomplete(t *testing.T) {
	ctx := context.Background()
	s := gateTestServer(t)
	if _, err := s.db.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("BeginReseed: %v", err)
	}

	called := false
	_, err := s.UnaryAuthInterceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/Login"},
		func(context.Context, interface{}) (interface{}, error) {
			called = true
			return nil, nil
		})

	if err == nil {
		t.Fatal("Login was allowed through while a reseed was incomplete — " +
			"every enrolled account on this node is reachable with a password alone")
	}
	if called {
		t.Error("the Login handler ran despite the refusal")
	}
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("code = %s, want %s", got, codes.Unavailable)
	}
	if !strings.Contains(err.Error(), "kvm001") {
		t.Errorf("error = %q; it must name the source so the operator knows which peer to repeat the reseed from", err)
	}
}

// Ping must stay reachable. It is how the condition is diagnosed and the reseed
// path itself calls it; gating it would hide the fault and break recovery.
func TestLoginGate_LeavesPingReachable(t *testing.T) {
	ctx := context.Background()
	s := gateTestServer(t)
	if _, err := s.db.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("BeginReseed: %v", err)
	}

	called := false
	if _, err := s.UnaryAuthInterceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/Ping"},
		func(context.Context, interface{}) (interface{}, error) {
			called = true
			return nil, nil
		}); err != nil {
		t.Fatalf("Ping refused while a reseed was incomplete: %v — the operator cannot see the fault", err)
	}
	if !called {
		t.Error("the Ping handler did not run")
	}
}

// The ordinary path: no reseed pending, login proceeds to the realm as before.
func TestLoginGate_AllowsLoginOnAHealthyNode(t *testing.T) {
	ctx := context.Background()
	s := gateTestServer(t)

	called := false
	if _, err := s.UnaryAuthInterceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/Login"},
		func(context.Context, interface{}) (interface{}, error) {
			called = true
			return nil, nil
		}); err != nil {
		t.Fatalf("Login refused on a node with no reseed pending: %v", err)
	}
	if !called {
		t.Error("the Login handler did not run on a healthy node")
	}
}

// WebAuthn login is a credential exchange too, and it bypasses the interceptor
// the same way. It must be gated alongside Login rather than left as a second
// door into the same window.
func TestLoginGate_RefusesWebAuthnLoginToo(t *testing.T) {
	ctx := context.Background()
	s := gateTestServer(t)
	if _, err := s.db.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("BeginReseed: %v", err)
	}

	for _, m := range []string{
		"/litevirt.v1.LiteVirt/BeginWebAuthnLogin",
		"/litevirt.v1.LiteVirt/FinishWebAuthnLogin",
	} {
		if _, err := s.UnaryAuthInterceptor(ctx, nil,
			&grpc.UnaryServerInfo{FullMethod: m},
			func(context.Context, interface{}) (interface{}, error) { return nil, nil }); err == nil {
			t.Errorf("%s was allowed through while a reseed was incomplete", m)
		}
	}
}

// Every skipAuth entry must be classified as either a diagnostic (reachable
// mid-reseed) or a credential exchange (refused). A new pre-session login RPC
// added to skipAuth and to neither set would silently reopen the window, and no
// behavioural test would catch it because the RPC would not exist yet.
func TestLoginGate_EverySkipAuthMethodIsClassified(t *testing.T) {
	diagnostic := map[string]bool{
		"/litevirt.v1.LiteVirt/Ping":       true,
		"/litevirt.v1.LiteVirt/ListRealms": true,
	}
	for m := range skipAuth {
		if diagnostic[m] == preSessionAuthMethods[m] {
			t.Errorf("skipAuth method %s is in %s — classify it as a diagnostic "+
				"(reachable while a reseed is incomplete) or as a pre-session credential "+
				"exchange (refused), because it bypasses authentication either way", m,
				map[bool]string{true: "BOTH sets", false: "NEITHER set"}[diagnostic[m]])
		}
	}
	for m := range preSessionAuthMethods {
		if !skipAuth[m] {
			t.Errorf("%s is gated as pre-session but is not in skipAuth; the gate is dead code for it", m)
		}
	}
}
