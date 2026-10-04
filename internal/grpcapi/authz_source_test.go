package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// boundAtCtx binds user as `role` on exactly `path` — NOT on "/" — and returns a
// caller context for them.
//
// Binding at a real path is what makes these tests load-bearing. A principal
// with no bindings makes HasAnyBinding false, and RequirePerm then falls back to
// its legacy RequireRole check, which every operator passes — so an unbound
// caller would sail through the very gate under test. The same trap is spelled
// out on boundCtx in lease_term_rpc_test.go.
func boundAtCtx(t *testing.T, s *Server, user, legacyRole, role, path string) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, user, legacyRole, "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID:        user + "-" + role,
		Path:      path,
		Role:      role,
		Principal: "user:" + user + "@local",
		Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)

	out := context.WithValue(context.Background(), ctxKeyUsername, user)
	return context.WithValue(out, ctxKeyRole, legacyRole)
}

func mustInsertVM(t *testing.T, s *Server, name, project string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name:     name,
		HostName: s.hostName,
		State:    "stopped",
		Project:  project,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}

// Cloning READS the source VM's disks and writes a full copy into the caller's
// own project. Authorizing only the destination therefore authorizes the write
// and not the read, which is the whole exposure: a tenant who may create VMs in
// their own project can lift another tenant's data into it.
//
// BuildImage already guards exactly this, and says so at imageops.go — "reads
// the source VM's root disk into a (global) image — a cross-project
// data-exposure surface". Clone is the same operation with a VM as the
// destination instead of an image.
func TestCloneVM_RefusesASourceInAnotherProject(t *testing.T) {
	s := testServer(t)
	mustInsertVM(t, s, "db-prod", "acme")
	ctx := boundAtCtx(t, s, "mallory", "operator", "Operator", "/projects/beta")

	_, err := s.CloneVM(ctx, &pb.CloneVMRequest{
		Source:  "db-prod",
		Target:  "stolen",
		Project: "beta",
		Mode:    "full",
	})

	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CloneVM from another project = %v (code %s), want PermissionDenied — "+
			"a beta-only operator just read an acme VM's disks", err, status.Code(err))
	}
}

// The guard must not break the ordinary case it is wrapped around: cloning
// inside the project you hold.
func TestCloneVM_AllowsASourceInTheCallersOwnProject(t *testing.T) {
	s := testServer(t)
	mustInsertVM(t, s, "db-prod", "beta")
	ctx := boundAtCtx(t, s, "owner", "operator", "Operator", "/projects/beta")

	_, err := s.CloneVM(ctx, &pb.CloneVMRequest{
		Source:  "db-prod",
		Target:  "copy",
		Project: "beta",
		Mode:    "full",
	})

	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("CloneVM within the caller's own project was denied: %v", err)
	}
}

// ImportVM forwards to the target host before authorizing anything, so an
// unauthorized caller's request is carried to the second node — where the peer
// leg authenticates as admin unless forwarded identity is both configured and
// latched, neither of which is on by default. Every other forwarding handler in
// the package (MigrateVM, MoveVolume, CreateSnapshot) authorizes first.
//
// The assertion distinguishes the two outcomes precisely: denied at the door is
// PermissionDenied; forwarded is anything else — in this harness Unavailable,
// because the peer does not exist. It must never be Unavailable.
func TestImportVM_AuthorizesBeforeForwarding(t *testing.T) {
	s := testServer(t)
	ctx := boundAtCtx(t, s, "mallory", "viewer", "Auditor", "/projects/beta")

	stream := &fakeImportStream{
		ctx: ctx,
		frames: []*pb.ImportVMRequest{{
			Name:       "pwned",
			Project:    "beta",
			TargetHost: "some-other-host",
		}},
	}

	err := s.ImportVM(stream)

	if status.Code(err) == codes.Unavailable {
		t.Fatalf("ImportVM forwarded an unauthorized request to the peer (err = %v); "+
			"authorization must happen before the forward", err)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ImportVM = %v (code %s), want PermissionDenied", err, status.Code(err))
	}
}

// The container twin of TestCloneVM_RefusesASourceInAnotherProject. A container
// clone copies the source rootfs, so authorizing only the destination leaves the
// read of another tenant's filesystem unguarded.
func TestCloneContainer_RefusesASourceInAnotherProject(t *testing.T) {
	s := testServer(t)
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: s.hostName,
		Name:     "ct-prod",
		State:    "stopped",
		Project:  "acme",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	ctx := boundAtCtx(t, s, "mallory-ct", "operator", "Operator", "/projects/beta")

	_, err := s.CloneContainer(ctx, &pb.CloneContainerRequest{
		Source:  "ct-prod",
		Target:  "stolen-ct",
		Project: "beta",
	})

	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CloneContainer from another project = %v (code %s), want PermissionDenied — "+
			"a beta-only operator just read an acme container's rootfs", err, status.Code(err))
	}
}
