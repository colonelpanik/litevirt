package grpcapi

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeReconciler counts Reconcile calls and lets tests script the
// last-error/last-tick fields the handler reports.
type fakeReconciler struct {
	calls   int32
	err     error
	lastTS  time.Time
	failNow bool
}

func (f *fakeReconciler) Reconcile(_ context.Context) error {
	atomic.AddInt32(&f.calls, 1)
	if f.failNow {
		return errors.New("kernel said no")
	}
	f.lastTS = time.Now()
	return nil
}
func (f *fakeReconciler) LastError() error  { return f.err }
func (f *fakeReconciler) LastTick() time.Time { return f.lastTS }

// adminCtxWithEngine grants alice admin via a root binding so
// RequirePerm allows network.update.
func adminCtxWithEngine(t *testing.T, s *Server) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "alice", "admin", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "alice-root", Path: "/", Role: "Admin",
		Principal: "user:alice@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)
	out := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	out = context.WithValue(out, ctxKeyRole, "admin")
	return out
}

// TestReloadFirewall_DrivesReconcileSync confirms one RPC call → one
// Reconcile call. The push semantics are the entire point.
func TestReloadFirewall_DrivesReconcileSync(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)

	rec := &fakeReconciler{}
	s.SetFirewallReconciler(rec)

	resp, err := s.ReloadFirewall(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ReloadFirewall: %v", err)
	}
	if got := atomic.LoadInt32(&rec.calls); got != 1 {
		t.Errorf("Reconcile called %d times, want 1", got)
	}
	if resp.HostName != s.hostName {
		t.Errorf("HostName = %q, want %q", resp.HostName, s.hostName)
	}
}

// TestReloadFirewall_PropagatesReconcileError surfaces a kernel /
// nft binary failure as Internal so the operator sees it immediately.
func TestReloadFirewall_PropagatesReconcileError(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)

	s.SetFirewallReconciler(&fakeReconciler{failNow: true})
	_, err := s.ReloadFirewall(ctx, &emptypb.Empty{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
}

// TestReloadFirewall_NoReconciler_Unavailable matches the test-server
// path: tests that don't wire a reconciler get a clear error rather
// than a panic.
func TestReloadFirewall_NoReconciler_Unavailable(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)

	_, err := s.ReloadFirewall(ctx, &emptypb.Empty{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", err)
	}
}

// TestReloadFirewall_RBAC_RejectsNonAdmin verifies network.update is
// required.
func TestReloadFirewall_RBAC_RejectsNonAdmin(t *testing.T) {
	s := testServer(t)
	// No engine wired; the legacy fallback consults role on ctx.
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	ctx = context.WithValue(ctx, ctxKeyRole, "viewer")
	s.SetFirewallReconciler(&fakeReconciler{})
	_, err := s.ReloadFirewall(ctx, &emptypb.Empty{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for viewer, got %v", err)
	}
}
