package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const webhookSecret = `{"url":"https://hooks.example.com/services/T000/B000/sUp3rS3cr3t"}`

func seedNotificationTarget(t *testing.T, s *Server) {
	t.Helper()
	if err := corrosion.InsertNotificationTarget(adminCtx(), s.db, corrosion.NotificationTarget{
		ID: "tgt1", Name: "ops-webhook", Type: "webhook", Config: webhookSecret, Enabled: true,
	}); err != nil {
		t.Fatalf("InsertNotificationTarget: %v", err)
	}
}

// TestListNotificationTargets_ViewerDoesNotSeeTheSecret is the #200 regression.
//
// The RPC is gated at "viewer" and returned NotificationTarget.Config verbatim.
// That config IS the credential — a webhook/Slack URL is a bearer secret — and
// notification_targets sits in corrosion's sensitiveTableNames precisely
// because it "must never enter the operator-readable state dump". Handing it to
// every viewer over the API contradicted that.
func TestListNotificationTargets_ViewerDoesNotSeeTheSecret(t *testing.T) {
	s := testServer(t)
	seedNotificationTarget(t, s)

	resp, err := s.ListNotificationTargets(viewerCtx(), &pb.ListNotificationTargetsRequest{})
	if err != nil {
		t.Fatalf("a viewer should still be able to LIST targets: %v", err)
	}
	if len(resp.Targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(resp.Targets))
	}
	got := resp.Targets[0]
	if strings.Contains(got.Config, "sUp3rS3cr3t") {
		t.Errorf("viewer received the webhook secret: config = %q", got.Config)
	}
	// The rest of the row stays visible: a viewer may see THAT a target exists.
	if got.Name != "ops-webhook" || got.Type != "webhook" || !got.Enabled {
		t.Errorf("redaction ate the non-secret fields: %+v", got)
	}
}

// An operator is who the config is for, and must still get it — otherwise
// `lv notify target ls` stops being able to show what it is configured to call.
func TestListNotificationTargets_OperatorStillSeesTheConfig(t *testing.T) {
	s := testServer(t)
	seedNotificationTarget(t, s)

	for _, role := range []string{"operator", "admin"} {
		resp, err := s.ListNotificationTargets(userCtx("u", role), &pb.ListNotificationTargetsRequest{})
		if err != nil {
			t.Fatalf("%s list: %v", role, err)
		}
		if len(resp.Targets) != 1 {
			t.Fatalf("%s: got %d targets, want 1", role, len(resp.Targets))
		}
		if resp.Targets[0].Config != webhookSecret {
			t.Errorf("%s did not receive the real config: %q", role, resp.Targets[0].Config)
		}
	}
}
