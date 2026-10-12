package ui

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// A notification target's config IS its credential: a webhook or Slack URL is a
// bearer secret. ListNotificationTargets redacts it below operator
// (internal/grpcapi/notification_secret_test.go), but the notifications page
// read the targets straight from the local DB and rendered {{.Config}} to any
// session with a role, a viewer included. The page now reads through the RPC,
// so the redaction rule lives in one place. Addresses colonelpanik/litevirt#200.

const uiNotifySecret = "https://hooks.slack.com/services/T000/B000/uiSeCrEtToKeN"

const uiRealDaemonSessionToken = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// newUIOverRealDaemonSvc wires the UI to a real grpcapi server through a real
// gRPC connection and the daemon's own auth interceptor — the production shape.
// The mock the other UI tests use cannot show what a given role receives,
// because the role is decided by the interceptor from the session's bearer.
func newUIOverRealDaemonSvc(t *testing.T, user, role string) (*Server, *corrosion.Client, *grpcapi.Server) {
	t.Helper()
	ctx := context.Background()
	db := newCorrosionForUITest(t)
	t.Cleanup(func() { db.Close() })
	hash, err := bcrypt.GenerateFromPassword([]byte(uiRealDaemonSessionToken), bcrypt.MinCost)
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

// uiSessionReq is authReq carrying the session token newUIOverRealDaemonSvc
// registered, so the daemon resolves the caller's real role.
func uiSessionReq(t *testing.T, method, path string, form url.Values) *http.Request {
	t.Helper()
	r := authReq(t, method, path, form)
	r.Header.Del("Cookie")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: uiRealDaemonSessionToken})
	return r
}

func renderNotificationsAs(t *testing.T, user, role string) string {
	t.Helper()
	s, db, _ := newUIOverRealDaemonSvc(t, user, role)
	if err := corrosion.InsertNotificationTarget(context.Background(), db, corrosion.NotificationTarget{
		ID: "t1", Name: "ops-slack", Type: "slack", Config: `{"url":"` + uiNotifySecret + `"}`, Enabled: true,
	}); err != nil {
		t.Fatalf("InsertNotificationTarget: %v", err)
	}
	w := serveRequest(s, uiSessionReq(t, "GET", "/notifications", nil))
	assertStatus(t, w, http.StatusOK)
	page := w.Body.String()
	// Knowing THAT a target exists stays viewer-visible.
	mustContain(t, page, "ops-slack", "/ui/notifications/targets/t1")
	return page
}

func TestNotificationsPage_ViewerDoesNotSeeTargetSecret(t *testing.T) {
	page := renderNotificationsAs(t, "val", "viewer")
	if strings.Contains(page, "uiSeCrEtToKeN") {
		t.Fatalf("viewer's notifications page renders the target's webhook secret")
	}
	if !strings.Contains(page, "redacted: requires operator") {
		t.Fatalf("viewer's page should show the redaction placeholder in place of the config")
	}
}

func TestNotificationsPage_OperatorSeesTargetConfig(t *testing.T) {
	for _, role := range []string{"operator", "admin"} {
		t.Run(role, func(t *testing.T) {
			page := renderNotificationsAs(t, "o-"+role, role)
			if !strings.Contains(page, uiNotifySecret) {
				t.Fatalf("%s's notifications page should show the target config", role)
			}
		})
	}
}
