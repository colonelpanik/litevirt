package auth

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// bind is a small helper that inserts a binding and reloads the engine.
func bind(t *testing.T, e *Engine, db *corrosion.Client, id, path, role, principal string) {
	t.Helper()
	if err := corrosion.InsertRoleBinding(t.Context(), db, corrosion.RoleBindingRecord{
		ID: id, Path: path, Role: role, Principal: principal, Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	if err := e.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
}

// TestEngine_RemoveBinding_ImmediateAndRetainsOthers verifies RemoveBinding
// drops exactly one binding from the live snapshot (recompute, don't
// blanket-drop) — the principal keeps perms other bindings still supply.
func TestEngine_RemoveBinding_ImmediateAndRetainsOthers(t *testing.T) {
	e, db := setupEngine(t)
	bind(t, e, db, "b1", "/projects/acme", "Operator", "user:alice@local")
	bind(t, e, db, "b2", "/projects/beta", "Operator", "user:alice@local")

	pp := []string{"user:alice@local"}
	e.RemoveBinding("b1")

	if e.Allowed(pp, "vm.start", "/projects/acme/vms/x") {
		t.Error("removed binding b1 should no longer grant")
	}
	if !e.Allowed(pp, "vm.start", "/projects/beta/vms/x") {
		t.Error("surviving binding b2 must still grant")
	}
}

// TestEngine_RemoveBinding_IndependentOfDBReload proves the in-memory delta
// takes effect even when a subsequent DB reload would fail — a revoke must
// not depend on a successful re-read of the store.
func TestEngine_RemoveBinding_IndependentOfDBReload(t *testing.T) {
	e, db := setupEngine(t)
	bind(t, e, db, "b1", "/", "Admin", "user:alice@local")
	pp := []string{"user:alice@local"}
	if !e.Allowed(pp, "vm.start", "/") {
		t.Fatal("precondition: binding should grant")
	}

	// Revoke in memory only (no DB delete, no reload).
	e.RemoveBinding("b1")
	if e.Allowed(pp, "vm.start", "/") {
		t.Fatal("RemoveBinding did not take effect")
	}

	// A failed reload must retain the current (revoked) snapshot.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_ = e.Reload(cancelled) // may or may not error depending on driver; must not resurrect
	if e.Allowed(pp, "vm.start", "/") {
		t.Fatal("reload resurrected a revoked binding")
	}
}

// TestEngine_Reload_DoesNotResurrectAfterDBDelete verifies that once the DB
// row is tombstoned and the in-memory delta applied, a normal successful
// reload keeps the binding gone (the DB no longer returns it).
func TestEngine_Reload_DoesNotResurrectAfterDBDelete(t *testing.T) {
	e, db := setupEngine(t)
	bind(t, e, db, "b1", "/", "Admin", "user:alice@local")
	pp := []string{"user:alice@local"}

	if err := corrosion.DeleteRoleBinding(t.Context(), db, "b1"); err != nil {
		t.Fatalf("DeleteRoleBinding: %v", err)
	}
	e.RemoveBinding("b1")
	if err := e.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if e.Allowed(pp, "vm.start", "/") {
		t.Fatal("binding resurrected after DB delete + reload")
	}
}

// TestEngine_RemovePrincipal drops every binding for a principal at once.
func TestEngine_RemovePrincipal(t *testing.T) {
	e, db := setupEngine(t)
	bind(t, e, db, "b1", "/projects/acme", "Operator", "user:alice@local")
	bind(t, e, db, "b2", "/projects/beta", "Operator", "user:alice@local")
	bind(t, e, db, "b3", "/projects/acme", "Operator", "user:bob@local")

	e.RemovePrincipal("user:alice@local")

	if e.HasAnyBinding([]string{"user:alice@local"}) {
		t.Error("alice should have no bindings after RemovePrincipal")
	}
	if !e.HasAnyBinding([]string{"user:bob@local"}) {
		t.Error("bob's binding must be untouched")
	}
}

// TestEngine_LastReload advances on a successful reload and is retained (not
// reset) when a reload fails.
func TestEngine_LastReload(t *testing.T) {
	e, _ := setupEngine(t)
	first := e.LastReloadUnix()
	if first == 0 {
		t.Fatal("expected a successful reload timestamp after setup")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_ = e.Reload(cancelled)
	if e.LastReloadUnix() < first {
		t.Fatal("last-successful-reload went backwards after a failed reload")
	}
}
