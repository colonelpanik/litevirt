package ui

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The UI's mutating handlers write to the replicated DB in-process, bypassing
// gRPC entirely — so they inherited neither the role check nor the audit the
// equivalent RPC has (firewall_rules.go requires operator and audits).
//
// sessionValid, the only gate in front of them, checked that a cookie existed
// and that Whoami did not return Unauthenticated. It never looked at the role.
//
// So a VIEWER could flip the cluster default firewall policy, delete
// security-group rules for every VM, and repoint cluster notifications.
func TestUIMutation_ViewerCannotChangeClusterFirewallPolicy(t *testing.T) {
	mock := newDefaultMock()
	mock.whoamiRole = "viewer"
	s := newTestUIServer(t, mock)
	db := newCorrosionForUITest(t)
	s.SetCorrosionDB(db)

	w := serveRequest(s, authReq(t, "POST", "/ui/firewall/default-deny", url.Values{"deny": {"on"}}))

	if w.Code == http.StatusOK {
		t.Fatal("a viewer set the cluster-wide default firewall policy")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// An operator is the role the equivalent RPC requires, so it must still work —
// or the fix would simply break the page.
func TestUIMutation_OperatorStillAllowed(t *testing.T) {
	mock := newDefaultMock()
	mock.whoamiRole = "operator"
	s := newTestUIServer(t, mock)
	db := newCorrosionForUITest(t)
	s.SetCorrosionDB(db)

	w := serveRequest(s, authReq(t, "POST", "/ui/firewall/default-deny", url.Values{"deny": {"on"}}))
	if w.Code == http.StatusForbidden {
		t.Fatal("an operator was refused a mutation the equivalent RPC allows")
	}
}

// sessionValid failed OPEN on any non-Unauthenticated error:
// "ui: session validation hit a transient error; allowing through".
//
// For a read that is a deliberate trade — a brief daemon blip should not lock
// an operator out of the dashboard. For a WRITE it means the one component
// that knows the caller's role is unreachable and the write proceeds anyway,
// which is the opposite of what an unverifiable credential should buy.
func TestUIMutation_FailsClosedWhenTheRoleCannotBeChecked(t *testing.T) {
	mock := newDefaultMock()
	mock.whoamiErr = status.Error(codes.Unavailable, "daemon unreachable")
	s := newTestUIServer(t, mock)
	db := newCorrosionForUITest(t)
	s.SetCorrosionDB(db)

	w := serveRequest(s, authReq(t, "POST", "/ui/firewall/default-deny", url.Values{"deny": {"on"}}))
	if w.Code == http.StatusOK {
		t.Fatal("a mutation went through while the caller's role could not be checked")
	}
}

// ...and a READ must still survive that same blip, or the fix trades one
// outage for another.
func TestUIRead_StillSurvivesATransientError(t *testing.T) {
	mock := newDefaultMock()
	mock.whoamiErr = errors.New("transient")
	s := newTestUIServer(t, mock)
	db := newCorrosionForUITest(t)
	s.SetCorrosionDB(db)

	w := serveRequest(s, authReq(t, "GET", "/hosts", nil))
	if w.Code == http.StatusForbidden || w.Code == http.StatusServiceUnavailable {
		t.Errorf("a read was blocked by a transient auth error (status %d); "+
			"that locks operators out of the dashboard during a blip", w.Code)
	}
}
