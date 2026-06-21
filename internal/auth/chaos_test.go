package auth

import (
	"context"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestEngine_ConcurrentReloadAndRead hammers the engine with concurrent
// readers (Allowed/HasAnyBinding) while a writer goroutine churns the
// role_bindings table and Reloads. With the atomic.Pointer snapshot
// design, no -race violation should fire and every read must see a
// self-consistent (roleVerbs, bindings) pair.
func TestEngine_ConcurrentReloadAndRead(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos test")
	}
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := SeedBuiltinRoles(ctx, db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, db, corrosion.RoleBindingRecord{
		ID: "alice-root-admin",
		Path: "/", Role: "Admin", Principal: "user:alice@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := NewEngine(db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("initial Reload: %v", err)
	}

	const readers = 16
	const ops = 500
	var readerWG sync.WaitGroup
	stop := make(chan struct{})

	// Writer: churn role bindings + Reload until the readers finish.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		bindingID := "chaos-churn"
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = corrosion.InsertRoleBinding(ctx, db, corrosion.RoleBindingRecord{
				ID:   bindingID,
				Path: "/projects/churn", Role: "Viewer",
				Principal: "user:bot@local", Propagate: true,
			})
			_ = engine.Reload(ctx)
			_ = corrosion.DeleteRoleBinding(ctx, db, bindingID)
			_ = engine.Reload(ctx)
			// Re-purge the soft-deleted row so the next INSERT can reuse the id.
			_ = db.Execute(ctx, `DELETE FROM role_bindings WHERE id = ? AND deleted_at IS NOT NULL`, bindingID)
		}
	}()

	for i := 0; i < readers; i++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			for j := 0; j < ops; j++ {
				if !engine.Allowed([]string{"user:alice@local"}, "vm.start", "/projects/acme/vms/web") {
					t.Errorf("alice's root admin binding disappeared mid-flight")
					return
				}
				_ = engine.HasAnyBinding([]string{"user:alice@local"})
			}
		}()
	}
	readerWG.Wait()
	close(stop)
	<-writerDone
}

// TestEngine_ReloadKeepsAlicePermissionsStable is the same race story
// without the writer goroutine — sanity check that a successful Reload
// preserves a previously-granted permission.
func TestEngine_ReloadKeepsAlicePermissionsStable(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := SeedBuiltinRoles(ctx, db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, db, corrosion.RoleBindingRecord{
		ID: "alice-root", Path: "/", Role: "Admin",
		Principal: "user:alice@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := NewEngine(db)
	for i := 0; i < 50; i++ {
		if err := engine.Reload(ctx); err != nil {
			t.Fatalf("Reload %d: %v", i, err)
		}
		if !engine.Allowed([]string{"user:alice@local"}, "vm.start", "/projects/x") {
			t.Fatalf("permission lost after Reload %d", i)
		}
	}
}
