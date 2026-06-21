package auth

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func setupEngine(t *testing.T) (*Engine, *corrosion.Client) {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(t.Context(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := SeedBuiltinRoles(t.Context(), c); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	e := NewEngine(c)
	if err := e.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return e, c
}

func TestCanonicalPath(t *testing.T) {
	cases := map[string]string{
		"":         "/",
		"/":        "/",
		"/foo":     "/foo",
		"/foo/":    "/foo",
		"/foo//":   "/foo",
		"foo":      "/foo",
		"/foo/bar": "/foo/bar",
	}
	for in, want := range cases {
		if got := canonicalPath(in); got != want {
			t.Errorf("canonicalPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPathPrefixOf(t *testing.T) {
	cases := []struct {
		prefix, path string
		want         bool
	}{
		{"/", "/anything", true},
		{"/", "/", true},
		{"/foo", "/foo", true},
		{"/foo", "/foo/bar", true},
		{"/foo", "/foobar", false}, // not a path-prefix; only string-prefix
		{"/foo/bar", "/foo/bar/baz", true},
		{"/foo/bar", "/foo/baz", false},
		{"/projects/acme", "/projects/acme/vms/web-1", true},
		{"/projects/acme", "/projects/acmecorp", false},
	}
	for _, c := range cases {
		if got := pathPrefixOf(c.prefix, c.path); got != c.want {
			t.Errorf("pathPrefixOf(%q, %q) = %v, want %v",
				c.prefix, c.path, got, c.want)
		}
	}
}

func TestVerbMatches(t *testing.T) {
	cases := []struct {
		grants []string
		verb   string
		want   bool
	}{
		{[]string{"*"}, "vm.start", true},
		{[]string{"vm.*"}, "vm.start", true},
		{[]string{"vm.*"}, "vm.delete", true},
		{[]string{"vm.*"}, "lb.read", false},
		{[]string{"vm.start"}, "vm.start", true},
		{[]string{"vm.start"}, "vm.stop", false},
		{[]string{"vm.start", "vm.stop"}, "vm.stop", true},
		{[]string{}, "vm.start", false},
		{nil, "vm.start", false},
		// *.<verb> — read across all namespaces (Viewer / Auditor pattern).
		{[]string{"*.read"}, "vm.read", true},
		{[]string{"*.read"}, "lb.read", true},
		{[]string{"*.read"}, "audit.read", true},
		{[]string{"*.read"}, "vm.start", false},
	}
	for _, c := range cases {
		if got := verbMatches(c.grants, c.verb); got != c.want {
			t.Errorf("verbMatches(%v, %q) = %v, want %v",
				c.grants, c.verb, got, c.want)
		}
	}
}

// TestEngine_AdminBindingGrantsEverything verifies that a single root
// binding to the built-in Admin role gives the principal every verb on
// every path.
func TestEngine_AdminBindingGrantsEverything(t *testing.T) {
	e, db := setupEngine(t)
	if err := corrosion.InsertRoleBinding(t.Context(), db, corrosion.RoleBindingRecord{
		ID: "b1", Path: "/", Role: "Admin",
		Principal: "user:alice@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	if err := e.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	principals := []string{"user:alice@local"}
	for _, verb := range []string{"vm.start", "host.fence", "audit.read"} {
		for _, path := range []string{"/", "/hosts/host-a", "/projects/acme/vms/web-1"} {
			if !e.Allowed(principals, verb, path) {
				t.Errorf("Admin should allow %s on %s", verb, path)
			}
		}
	}
}

// TestEngine_PropagationOff_RestrictsToExactPath verifies propagate=false
// confines a binding to the exact path.
func TestEngine_PropagationOff_RestrictsToExactPath(t *testing.T) {
	e, db := setupEngine(t)
	if err := corrosion.InsertRoleBinding(t.Context(), db, corrosion.RoleBindingRecord{
		ID: "b1", Path: "/projects/acme", Role: "Operator",
		Principal: "user:alice@local", Propagate: false,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	if err := e.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	pp := []string{"user:alice@local"}
	if !e.Allowed(pp, "vm.start", "/projects/acme") {
		t.Error("propagate=false should grant on exact path")
	}
	if e.Allowed(pp, "vm.start", "/projects/acme/vms/web-1") {
		t.Error("propagate=false must NOT grant on descendant path")
	}
}

// TestEngine_PropagationOn_GrantsDescendants verifies propagate=true
// grants on the path and all descendants.
func TestEngine_PropagationOn_GrantsDescendants(t *testing.T) {
	e, db := setupEngine(t)
	if err := corrosion.InsertRoleBinding(t.Context(), db, corrosion.RoleBindingRecord{
		ID: "b1", Path: "/projects/acme", Role: "Operator",
		Principal: "group:platform@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	if err := e.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	pp := []string{"user:bob@local", "group:platform@local"}
	if !e.Allowed(pp, "vm.start", "/projects/acme/vms/web-1") {
		t.Error("group binding with propagate=true should grant on descendants")
	}
	if e.Allowed(pp, "vm.start", "/projects/other/vms/web-1") {
		t.Error("binding on /projects/acme must NOT grant on /projects/other")
	}
}

// TestEngine_NoBinding_DeniesByDefault verifies the absence of any
// binding means the verb is denied.
func TestEngine_NoBinding_DeniesByDefault(t *testing.T) {
	e, _ := setupEngine(t)
	if e.Allowed([]string{"user:nobody@local"}, "vm.start", "/projects/acme/vms/web-1") {
		t.Error("default policy should be deny-all")
	}
}

// TestEngine_ViewerCanReadButNotWrite verifies the built-in Viewer role
// matches `*.read` but rejects write verbs. Today Viewer's `*.read`
// includes audit.read; will tighten this when audit becomes
// hash-chained — the role list is forward-compatible because the engine
// re-reads SeedBuiltinRoles on every daemon start.
func TestEngine_ViewerCanReadButNotWrite(t *testing.T) {
	e, db := setupEngine(t)
	if err := corrosion.InsertRoleBinding(t.Context(), db, corrosion.RoleBindingRecord{
		ID: "b1", Path: "/", Role: "Viewer",
		Principal: "user:read-only@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	if err := e.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	pp := []string{"user:read-only@local"}
	if !e.Allowed(pp, "vm.read", "/projects/acme/vms/web-1") {
		t.Error("Viewer should allow vm.read")
	}
	if e.Allowed(pp, "vm.start", "/projects/acme/vms/web-1") {
		t.Error("Viewer must NOT allow vm.start")
	}
	if e.Allowed(pp, "vm.delete", "/projects/acme/vms/web-1") {
		t.Error("Viewer must NOT allow vm.delete")
	}
	// Auditor distinguishes itself by audit.export, not audit.read.
	if e.Allowed(pp, "audit.export", "/") {
		t.Error("Viewer must NOT allow audit.export (Auditor-only)")
	}
}

// TestEngine_HasAnyBinding is the bridge predicate used by RequirePerm
// to fall back to legacy roleLevel when no role-bindings exist for a user.
func TestEngine_HasAnyBinding(t *testing.T) {
	e, db := setupEngine(t)
	if e.HasAnyBinding([]string{"user:alice@local"}) {
		t.Error("expected false before any binding")
	}
	if err := corrosion.InsertRoleBinding(t.Context(), db, corrosion.RoleBindingRecord{
		ID: "b1", Path: "/", Role: "Operator",
		Principal: "user:alice@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	if err := e.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !e.HasAnyBinding([]string{"user:alice@local"}) {
		t.Error("expected true after binding")
	}
}

// TestEngine_BindingChange_RequiresReload verifies that inserts to
// role_bindings are not visible to Allowed() until Reload() is called.
// This is intentional — the engine snapshots state to keep checks O(1).
func TestEngine_BindingChange_RequiresReload(t *testing.T) {
	e, db := setupEngine(t)
	if err := corrosion.InsertRoleBinding(context.Background(), db, corrosion.RoleBindingRecord{
		ID: "b1", Path: "/", Role: "Admin",
		Principal: "user:late@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	pp := []string{"user:late@local"}
	if e.Allowed(pp, "vm.start", "/") {
		t.Error("binding should not be visible without Reload")
	}
	if err := e.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !e.Allowed(pp, "vm.start", "/") {
		t.Error("binding should be visible after Reload")
	}
}

// TestPrincipal_PrincipalID + GroupPrincipalIDs verifies the canonical
// "user:..." / "group:..." format used as role_bindings.principal value.
func TestPrincipal_PrincipalIDs(t *testing.T) {
	p := &Principal{Subject: "alice", Realm: "local", Groups: []string{"admins", "ops"}}
	if got := p.PrincipalID(); got != "user:alice@local" {
		t.Errorf("PrincipalID = %q, want user:alice@local", got)
	}
	groups := p.GroupPrincipalIDs()
	if len(groups) != 2 || groups[0] != "group:admins@local" || groups[1] != "group:ops@local" {
		t.Errorf("GroupPrincipalIDs = %v", groups)
	}
}
