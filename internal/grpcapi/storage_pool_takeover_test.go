package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// poolTenantCtx returns a caller who is Admin over project "acme" and holds
// nothing at the root — the shape of an ordinary tenant operator.
func poolTenantCtx(t *testing.T, s *Server) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "mallory", "admin", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "mallory-acme", Path: projectRBACBase("acme"), Role: "Admin",
		Principal: "user:mallory@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)
	out := context.WithValue(context.Background(), ctxKeyUsername, "mallory")
	return context.WithValue(out, ctxKeyRole, "admin")
}

// TestCreateStoragePool_CannotTakeOverAGlobalPool is the #207 regression.
//
// CreateStoragePool authorized poolRBACPathFor(req.Project, req.Name) — the
// project the REQUEST claims — and then INSERT OR REPLACE'd a row keyed on
// (host_name, name). A tenant who holds Admin only over their own project could
// therefore submit a create for an existing GLOBAL pool's name, pass the check
// against their own path, and repoint the global row at storage they control.
//
// DeleteStoragePool already authorizes against the STORED project and says so
// in a comment; this is the same rule on the write path.
func TestCreateStoragePool_CannotTakeOverAGlobalPool(t *testing.T) {
	s := testServer(t)
	mallory := poolTenantCtx(t, s)

	// An existing GLOBAL pool (Project "" — admin-managed, RBAC anchored at root).
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "shared-nfs", Driver: "local",
		Target: "/srv/shared", State: "active", Project: "",
	}); err != nil {
		t.Fatalf("seed global pool: %v", err)
	}

	_, err := s.CreateStoragePool(mallory, &pb.CreateStoragePoolRequest{
		Name: "shared-nfs", Driver: "local", Target: "/tmp/mallory", Project: "acme",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("taking over a global pool: got %v, want PermissionDenied", err)
	}

	// The stored row must be untouched — neither repointed nor re-owned.
	rec, ok, gErr := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, "shared-nfs")
	if gErr != nil || !ok {
		t.Fatalf("pool vanished: ok=%v err=%v", ok, gErr)
	}
	if rec.Project != "" {
		t.Errorf("pool was re-owned: project = %q, want \"\"", rec.Project)
	}
	if rec.Target != "/srv/shared" {
		t.Errorf("pool was repointed: target = %q, want /srv/shared", rec.Target)
	}
}

// The same rule between two tenants: acme may not repoint bravo's pool.
func TestCreateStoragePool_CannotTakeOverAnotherProjectsPool(t *testing.T) {
	s := testServer(t)
	mallory := poolTenantCtx(t, s)

	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "bravo-pool", Driver: "local",
		Target: "/srv/bravo", State: "active", Project: "bravo",
	}); err != nil {
		t.Fatalf("seed bravo pool: %v", err)
	}

	_, err := s.CreateStoragePool(mallory, &pb.CreateStoragePoolRequest{
		Name: "bravo-pool", Driver: "local", Target: "/tmp/mallory", Project: "acme",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("taking over another project's pool: got %v, want PermissionDenied", err)
	}
}

// A tenant creating a NEW pool in their own project is unaffected: there is no
// stored row to authorize against, so only the claimed path is checked.
func TestCreateStoragePool_OwnProjectNewPoolStillAllowed(t *testing.T) {
	s := testServer(t)
	mallory := poolTenantCtx(t, s)

	if _, err := s.CreateStoragePool(mallory, &pb.CreateStoragePoolRequest{
		Name: "acme-pool", Driver: "local", Target: t.TempDir(), Project: "acme",
	}); err != nil {
		t.Fatalf("creating a pool in one's own project: %v", err)
	}
}

// Re-applying the SAME pool in one's own project (the idempotent re-create the
// CLI does) must keep working — the stored project matches the claim.
func TestCreateStoragePool_OwnProjectRecreateStillAllowed(t *testing.T) {
	s := testServer(t)
	mallory := poolTenantCtx(t, s)
	dir := t.TempDir()

	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "acme-pool", Driver: "local",
		Target: dir, State: "active", Project: "acme",
	}); err != nil {
		t.Fatalf("seed acme pool: %v", err)
	}
	if _, err := s.CreateStoragePool(mallory, &pb.CreateStoragePoolRequest{
		Name: "acme-pool", Driver: "local", Target: dir, Project: "acme",
	}); err != nil {
		t.Fatalf("re-creating one's own pool: %v", err)
	}
}
