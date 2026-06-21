package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUninstallHost_InsufficientRole(t *testing.T) {
	s := testServer(t)
	s.ReExecCh = make(chan struct{}, 1)
	s.ShutdownCh = make(chan struct{}, 1)

	// Viewer context — should be denied.
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "viewer-user")
	ctx = context.WithValue(ctx, ctxKeyRole, "viewer")

	req := &pb.UninstallHostRequest{KeepData: true}
	_, err := s.UninstallHost(ctx, req)
	if err == nil {
		t.Fatal("expected permission denied")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", st.Code())
	}
}

func TestUninstallHost_OperatorRole(t *testing.T) {
	s := testServer(t)
	s.ReExecCh = make(chan struct{}, 1)
	s.ShutdownCh = make(chan struct{}, 1)

	// Operator role — should also be denied (admin required).
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "op-user")
	ctx = context.WithValue(ctx, ctxKeyRole, "operator")

	req := &pb.UninstallHostRequest{KeepData: true}
	_, err := s.UninstallHost(ctx, req)
	if err == nil {
		t.Fatal("expected permission denied")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", st.Code())
	}
}

func TestUninstallHost_ForwardToPeer(t *testing.T) {
	s := testServer(t)
	s.ReExecCh = make(chan struct{}, 1)
	s.ShutdownCh = make(chan struct{}, 1)

	// Request targeting a different host should trigger forwarding.
	// It will fail because the peer doesn't exist, but we verify it goes
	// down the forwarding path.
	req := &pb.UninstallHostRequest{
		TargetHost: "other-host",
		KeepData:   true,
	}

	_, err := s.UninstallHost(adminCtx(), req)
	if err == nil {
		t.Fatal("expected error (peer not reachable)")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", st.Code())
	}
}

func TestUninstallHost_ShutdownSignal(t *testing.T) {
	s := testServer(t)
	s.ReExecCh = make(chan struct{}, 1)
	s.ShutdownCh = make(chan struct{}, 1)

	// Verify ShutdownCh is buffered and accepts a signal.
	select {
	case s.ShutdownCh <- struct{}{}:
	default:
		t.Error("ShutdownCh should accept a signal")
	}

	// Second send should not block (drops silently via select/default).
	select {
	case s.ShutdownCh <- struct{}{}:
		t.Error("ShutdownCh should be full after one signal")
	default:
		// expected
	}
}

func TestUninstallHost_RoutingLogic(t *testing.T) {
	// NOTE: We intentionally do NOT call UninstallHost with empty/self target_host
	// because that would execute real shell commands (systemctl, rm -rf, etc.)
	// on the test machine. Instead we verify only the routing/auth paths.

	s := testServer(t)
	s.ReExecCh = make(chan struct{}, 1)
	s.ShutdownCh = make(chan struct{}, 1)

	// Empty target goes to local execution — skip that path in tests.
	// Self-target also goes to local execution — skip.
	// Only test that a different target triggers forwarding (which fails safely).
	req := &pb.UninstallHostRequest{
		TargetHost: "nonexistent-peer",
		KeepData:   true,
	}

	_, err := s.UninstallHost(adminCtx(), req)
	if err == nil {
		t.Fatal("expected error for unreachable peer")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", st.Code())
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
