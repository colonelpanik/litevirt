package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// authReq builds an authenticated request with an optional form body.
func authReq(t *testing.T, method, path string, form url.Values) *http.Request {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r, err := http.NewRequest(method, path, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return withAuth(r)
}

func TestSGCreate_PersistsAndRedirects(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	db := newCorrosionForUITest(t)
	s.SetCorrosionDB(db)

	w := serveRequest(s, authReq(t, "POST", "/ui/security-groups", url.Values{"name": {"web"}}))
	assertStatus(t, w, http.StatusOK)
	assertToast(t, w, "created")
	if w.Header().Get("HX-Redirect") != "/security-groups" {
		t.Errorf("HX-Redirect = %q", w.Header().Get("HX-Redirect"))
	}
	sgs, err := corrosion.ListSecurityGroups(context.Background(), db, "")
	if err != nil || len(sgs) != 1 || sgs[0].Name != "web" {
		t.Fatalf("expected one SG 'web', got %v (err %v)", sgs, err)
	}
}

func TestSGCreate_NameRequired(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	s.SetCorrosionDB(newCorrosionForUITest(t))
	w := serveRequest(s, authReq(t, "POST", "/ui/security-groups", url.Values{}))
	assertStatus(t, w, http.StatusBadRequest)
	assertToast(t, w, "required")
}

func TestSGRuleAddAndDelete(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	db := newCorrosionForUITest(t)
	s.SetCorrosionDB(db)
	ctx := context.Background()
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg1", Name: "web"}); err != nil {
		t.Fatalf("seed SG: %v", err)
	}

	w := serveRequest(s, authReq(t, "POST", "/ui/security-groups/sg1/rules", url.Values{
		"direction": {"ingress"}, "proto": {"tcp"}, "port_range": {"443"}, "action": {"accept"}, "priority": {"100"},
	}))
	assertStatus(t, w, http.StatusOK)
	rules, err := corrosion.ListSGRules(ctx, db, "sg1")
	if err != nil || len(rules) != 1 || rules[0].PortRange != "443" {
		t.Fatalf("expected one rule :443, got %v (err %v)", rules, err)
	}

	// Delete the rule.
	w = serveRequest(s, authReq(t, "DELETE", "/ui/security-groups/rules/"+rules[0].ID, nil))
	assertStatus(t, w, http.StatusOK)
	rules, _ = corrosion.ListSGRules(ctx, db, "sg1")
	if len(rules) != 0 {
		t.Fatalf("expected rule deleted, got %v", rules)
	}
}

func TestSGDelete_RemovesGroup(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	db := newCorrosionForUITest(t)
	s.SetCorrosionDB(db)
	ctx := context.Background()
	_ = corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg1", Name: "web"})

	w := serveRequest(s, authReq(t, "DELETE", "/ui/security-groups/sg1", nil))
	assertStatus(t, w, http.StatusOK)
	sgs, _ := corrosion.ListSecurityGroups(ctx, db, "")
	if len(sgs) != 0 {
		t.Fatalf("expected SG deleted, got %v", sgs)
	}
}

func TestRBACGrant_CallsRPC(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, authReq(t, "POST", "/ui/rbac/bindings", url.Values{
		"path": {"/projects/_default/vms"}, "role": {"operator"}, "principal": {"alice"}, "propagate": {"on"},
	}))
	assertStatus(t, w, http.StatusOK)
	assertToast(t, w, "Granted")
}

func TestRBACGrant_FieldsRequired(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, authReq(t, "POST", "/ui/rbac/bindings", url.Values{"role": {"operator"}}))
	assertStatus(t, w, http.StatusBadRequest)
	assertToast(t, w, "required")
}

func TestRBACRevoke_CallsRPC(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, authReq(t, "DELETE", "/ui/rbac/bindings/binding-123", nil))
	assertStatus(t, w, http.StatusOK)
	assertToast(t, w, "revoked")
}
