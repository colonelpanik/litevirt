package ui

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The web UI's security-group pages and the `lv sg` RPCs are two surfaces for
// one action, so they must authorize it identically (colonelpanik/litevirt#182).
// The pages used to ask the daemon for the generic "write" verb at "/", which
// only Admin's "*" grants; the RPCs ask for "sg.write", which NetworkAdmin holds
// too. A NetworkAdmin could therefore manage security groups from the CLI and
// was refused the same change in the browser.

// newUIBoundTo wires the UI to a real daemon whose RBAC engine binds user to
// the built-in role boundRole at "/". The user's legacy role is "viewer", the
// shape an external-realm user is shadowed as, so only the binding can grant
// anything.
func newUIBoundTo(t *testing.T, user, boundRole string) (*Server, *corrosion.Client) {
	t.Helper()
	s, db, svc := newUIOverRealDaemonSvc(t, user, "viewer")
	ctx := context.Background()
	if err := auth.SeedBuiltinRoles(ctx, db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, db, corrosion.RoleBindingRecord{
		ID: user + "-root", Path: "/", Role: boundRole, Principal: "user:" + user + "@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	svc.SetAuthEngine(engine)
	return s, db
}

type rpcAuditRow struct{ user, host, target, detail, result string }

func rpcAuditRows(t *testing.T, db *corrosion.Client, action string) []rpcAuditRow {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT username, host_name, target, detail, result FROM audit_log WHERE action = ?`, action)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	out := make([]rpcAuditRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, rpcAuditRow{r.String("username"), r.String("host_name"),
			r.String("target"), r.String("detail"), r.String("result")})
	}
	return out
}

// wantRPCAudit asserts exactly one row for action, and that it is the row the
// RPC writes: the session's user, the DAEMON's host name (not the UI's cluster
// name), and the group or rule before and after.
func wantRPCAudit(t *testing.T, db *corrosion.Client, action, user, target, detail string) {
	t.Helper()
	rows := rpcAuditRows(t, db, action)
	if len(rows) != 1 {
		t.Fatalf("%s: %d audit rows, want exactly 1: %+v", action, len(rows), rows)
	}
	want := rpcAuditRow{user: user, host: "test-host", target: target, detail: detail, result: "ok"}
	if rows[0] != want {
		t.Errorf("%s audit row = %+v\n                 want %+v", action, rows[0], want)
	}
}

func TestUISecurityGroups_NetworkAdminManagesThemLikeTheCLI(t *testing.T) {
	s, db := newUIBoundTo(t, "nadia", "NetworkAdmin")
	ctx := context.Background()

	w := serveRequest(s, uiSessionReq(t, "POST", "/ui/security-groups", url.Values{"name": {"isolate"}}))
	assertStatus(t, w, http.StatusOK)
	sgs, err := corrosion.ListSecurityGroups(ctx, db, "")
	if err != nil || len(sgs) != 1 || sgs[0].Name != "isolate" {
		t.Fatalf("security groups = %v (err %v), want the one just created", sgs, err)
	}
	sgID := sgs[0].ID
	wantRPCAudit(t, db, "sg.add", "nadia", "isolate", "before=none after={name=isolate rules=[]}")

	w = serveRequest(s, uiSessionReq(t, "POST", "/ui/security-groups/"+sgID+"/rules", url.Values{
		"direction": {"ingress"}, "port_range": {"22"}, "cidr": {"10.0.0.0/8"},
	}))
	assertStatus(t, w, http.StatusOK)
	rules, err := corrosion.ListSGRules(ctx, db, sgID)
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules = %v (err %v), want the one just added", rules, err)
	}
	rule := "{sg=" + sgID + " ingress all port=22 cidr=10.0.0.0/8 accept priority=100}"
	wantRPCAudit(t, db, "sg.rule.add", "nadia", sgID, "before=none after="+rule)

	w = serveRequest(s, uiSessionReq(t, "DELETE", "/ui/security-groups/rules/"+rules[0].ID, nil))
	assertStatus(t, w, http.StatusOK)
	if left, _ := corrosion.ListSGRules(ctx, db, sgID); len(left) != 0 {
		t.Fatalf("rule still present after removal: %v", left)
	}
	wantRPCAudit(t, db, "sg.rule.rm", "nadia", rules[0].ID, "before="+rule+" after=none")

	w = serveRequest(s, uiSessionReq(t, "DELETE", "/ui/security-groups/"+sgID, nil))
	assertStatus(t, w, http.StatusOK)
	if left, _ := corrosion.ListSecurityGroups(ctx, db, ""); len(left) != 0 {
		t.Fatalf("group still present after removal: %v", left)
	}
	wantRPCAudit(t, db, "sg.rm", "nadia", sgID, "before={name=isolate rules=[]} after=none")
}

func TestUISecurityGroups_ViewerRefused(t *testing.T) {
	cases := map[string]func(t *testing.T) (*Server, *corrosion.Client){
		// Bound to the built-in Viewer role: the RBAC engine decides.
		"bound Viewer": func(t *testing.T) (*Server, *corrosion.Client) { return newUIBoundTo(t, "vic", "Viewer") },
		// No role bindings at all: the legacy role fallback decides.
		"legacy viewer": func(t *testing.T) (*Server, *corrosion.Client) { return newUIOverRealDaemon(t, "vic", "viewer") },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			s, db := mk(t)
			ctx := context.Background()
			if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg-1", Name: "web"}); err != nil {
				t.Fatalf("InsertSecurityGroup: %v", err)
			}
			if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "r-1", SGID: "sg-1", Direction: "ingress"}); err != nil {
				t.Fatalf("InsertSGRule: %v", err)
			}
			reqs := map[string]*http.Request{
				"sg.add": uiSessionReq(t, "POST", "/ui/security-groups", url.Values{"name": {"sneaky"}}),
				"sg.rule.add": uiSessionReq(t, "POST", "/ui/security-groups/sg-1/rules", url.Values{
					"direction": {"egress"}, "action": {"accept"},
				}),
				"sg.rule.rm": uiSessionReq(t, "DELETE", "/ui/security-groups/rules/r-1", nil),
				"sg.rm":      uiSessionReq(t, "DELETE", "/ui/security-groups/sg-1", nil),
			}
			for action, r := range reqs {
				w := serveRequest(s, r)
				if w.Code != http.StatusForbidden {
					t.Errorf("%s: status = %d, want %d", action, w.Code, http.StatusForbidden)
				}
				if rows := rpcAuditRows(t, db, action); len(rows) != 0 {
					t.Errorf("%s: a refused change left audit rows %+v", action, rows)
				}
			}
			sgs, _ := corrosion.ListSecurityGroups(ctx, db, "")
			rules, _ := corrosion.ListSGRules(ctx, db, "sg-1")
			if len(sgs) != 1 || sgs[0].ID != "sg-1" || len(rules) != 1 || rules[0].ID != "r-1" {
				t.Errorf("a viewer changed security groups: groups=%v rules=%v", sgs, rules)
			}
		})
	}
}
