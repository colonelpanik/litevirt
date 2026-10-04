package ui

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

const fwAuditSessionToken = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// newUIOverRealDaemon wires the UI to a real grpcapi server through a real gRPC
// connection and the daemon's own auth interceptor — the production shape. The
// mock the other UI tests use cannot show who an audit row names, because the
// name is decided by the interceptor from the session's bearer token.
func newUIOverRealDaemon(t *testing.T, user, role string) (*Server, *corrosion.Client) {
	t.Helper()
	s, db, _ := newUIOverRealDaemonSvc(t, user, role)
	return s, db
}

// newUIOverRealDaemonSvc is newUIOverRealDaemon that also returns the daemon,
// for a test that has to wire an RBAC engine into it.
func newUIOverRealDaemonSvc(t *testing.T, user, role string) (*Server, *corrosion.Client, *grpcapi.Server) {
	t.Helper()
	ctx := context.Background()
	db := newCorrosionForUITest(t)
	hash, err := bcrypt.GenerateFromPassword([]byte(fwAuditSessionToken), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if err := corrosion.InsertUser(ctx, db, user, role, string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := corrosion.InsertToken(ctx, db, corrosion.TokenRecord{
		ID: "ui-session", Username: user, Name: "ui session", TokenHash: string(hash),
	}); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	service := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "test-host", DataDir: t.TempDir(), DB: db})
	listener := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer(grpc.UnaryInterceptor(service.UnaryAuthInterceptor))
	pb.RegisterLiteVirtServer(gs, service)
	go func() { _ = gs.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		gs.Stop()
		_ = listener.Close()
	})

	s, err := NewServer(pb.NewLiteVirtClient(conn), "test-cluster")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.SetCorrosionDB(db)
	return s, db, service
}

func uiSessionReq(t *testing.T, method, path string, form url.Values) *http.Request {
	t.Helper()
	r := authReq(t, method, path, form)
	r.Header.Del("Cookie")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fwAuditSessionToken})
	return r
}
