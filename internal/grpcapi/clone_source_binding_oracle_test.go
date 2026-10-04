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

// A clone's source must not be an existence oracle for a caller who HOLDS
// bindings — just not on the source's project.
//
// requirePermPrecheck lets every binding-holder through, deferring to the
// per-path check once the source is fetched. CloneVM and CloneContainer then
// answered NotFound for a free name and PermissionDenied for another tenant's
// VM or container, so a tenant with an operator grant on their own project
// could enumerate every other tenant's resource names — the exact leak the
// precheck's comment says it prevents. The no-binding caller was covered; the
// tenant was not.
//
// Same shape as TestResolvedAuthz_AnOutOfScopeCallerCannotTellWhetherANameExists:
// one node holds the source (in a project the caller cannot reach), one does
// not, and the answers must match in code AND message.
func TestClone_ABindingHolderCannotTellWhetherAForeignSourceExists(t *testing.T) {
	ops := map[string]func(s *Server, ctx context.Context) error{
		"vm": func(s *Server, ctx context.Context) error {
			_, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "probe", Target: "mine", Project: "acme"})
			return err
		},
		"container": func(s *Server, ctx context.Context) error {
			_, err := s.CloneContainer(ctx, &pb.CloneContainerRequest{Source: "probe", Target: "mine", Project: "acme"})
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			holder := testServer(t)
			holder.SetContainerRuntime(&fakeCTRuntime{})
			if err := corrosion.InsertVM(context.Background(), holder.db, corrosion.VMRecord{
				Name: "probe", HostName: holder.hostName, Spec: "{}", State: "stopped", Project: "beta",
			}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			if err := corrosion.UpsertContainer(context.Background(), holder.db, corrosion.ContainerRecord{
				HostName: holder.hostName, Name: "probe", State: "stopped", Project: "beta",
			}); err != nil {
				t.Fatalf("UpsertContainer: %v", err)
			}
			lacker := testServer(t)
			lacker.SetContainerRuntime(&fakeCTRuntime{})

			present := op(holder, grantUser(t, holder, "carol", "/projects/acme", "Operator"))
			absent := op(lacker, grantUser(t, lacker, "carol", "/projects/acme", "Operator"))

			if status.Code(present) != codes.PermissionDenied {
				t.Errorf("source present in another project: %v, want PermissionDenied", present)
			}
			if status.Code(absent) != status.Code(present) || status.Convert(absent).Message() != status.Convert(present).Message() {
				t.Errorf("a tenant with no rights on the source can tell whether it exists:\n  present: %v\n  absent:  %v",
					present, absent)
			}
		})
	}
}

// The legitimate paths stay open: the source's own project clones it, and a
// cluster-root grant still gets a plain NotFound for a source that is absent.
func TestClone_OwnProjectAndRootStillResolveTheSource(t *testing.T) {
	s := testServer(t)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "probe", HostName: s.hostName, Spec: "{}", State: "running", Project: "acme",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	alice := grantUser(t, s, "alice", "/projects/acme", "Operator")
	// Past authorization, the running source is refused on its state — proof the
	// own-project caller got through to the source rather than a denial.
	if _, err := s.CloneVM(alice, &pb.CloneVMRequest{Source: "probe", Target: "mine"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("own-project clone of a running source: %v, want FailedPrecondition", err)
	}
	root := grantUser(t, s, "root-op", "/", "Admin")
	if _, err := s.CloneVM(root, &pb.CloneVMRequest{Source: "nope", Target: "mine"}); status.Code(err) != codes.NotFound {
		t.Errorf("root clone of an absent source: %v, want NotFound", err)
	}
	if _, err := s.CloneContainer(root, &pb.CloneContainerRequest{Source: "nope", Target: "mine"}); status.Code(err) != codes.NotFound {
		t.Errorf("root clone of an absent container: %v, want NotFound", err)
	}
}

// grantUser gives user role on path and reloads a real RBAC engine over every
// binding seeded so far.
func grantUser(t *testing.T, s *Server, user, path, role string) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, user, "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: user + "@" + path, Path: path, Role: role,
		Principal: "user:" + user + "@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)
	return userCtx(user, "operator")
}
