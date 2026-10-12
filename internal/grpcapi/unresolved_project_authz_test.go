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

// These pin one rule across every RPC that authorizes against a resource's
// project: when this node cannot name that project — the row has not reached
// it, or does not exist — the caller is NOT judged against _default. Only a
// cluster-root grant authorizes (so an admin's idempotent re-issue of a delete
// still works). A caller the old _default guess would have admitted gets a
// retryable NotFound and nothing happens; anyone else gets PermissionDenied,
// with one message whether or not the name exists here.
//
// The hazard each test reaches: a caller whose only grant is on _default names
// a resource in another project through a node that lacks its row. The old
// fallback judged them against _default, they passed, and the action then ran
// on the owner (a forward, which carries admin identity unless forwarded
// identity is enforced) or relayed a write every node that holds the row
// applied.

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

func unresolvedPeer(s *Server) *fakeCTDeletePeer {
	fake := &fakeCTDeletePeer{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return fake, func() {}, nil
	}
	return fake
}

func (f *fakeCTDeletePeer) forwards() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls) + len(f.startCalls) + len(f.stopCalls)
}

// Start, stop and delete name the owner explicitly and forward there. With no
// local row, a _default-only caller must be refused before any forward.
func TestContainerLifecycle_AnUnresolvedProjectIsNotAuthorizedAsDefault(t *testing.T) {
	s := testServer(t)
	s.SetContainerRuntime(&fakeCTRuntime{})
	fake := unresolvedPeer(s)
	bob := grantUser(t, s, "bob", "/projects/_default", "Operator")

	for name, call := range map[string]func() error{
		"start": func() error {
			_, err := s.StartContainer(bob, &pb.StartContainerRequest{Name: "victim", HostName: "host-b"})
			return err
		},
		"stop": func() error {
			_, err := s.StopContainer(bob, &pb.StopContainerRequest{Name: "victim", HostName: "host-b"})
			return err
		},
		"delete": func() error {
			_, err := s.DeleteContainer(bob, &pb.DeleteContainerRequest{Name: "victim", HostName: "host-b"})
			return err
		},
	} {
		if c := status.Code(call()); c != codes.NotFound {
			t.Errorf("%s of a container this node cannot place in a project: code %v, want NotFound", name, c)
		}
	}
	if n := fake.forwards(); n != 0 {
		t.Errorf("%d lifecycle call(s) were forwarded to the owner on the strength of a _default grant", n)
	}
}

// The legitimate path: the row is here, and its own project's grant forwards.
func TestContainerLifecycle_TheOwningProjectStillForwards(t *testing.T) {
	s := testServer(t)
	s.SetContainerRuntime(&fakeCTRuntime{})
	fake := unresolvedPeer(s)
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-b", Name: "web", State: "stopped", Project: "acme",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	alice := grantUser(t, s, "alice", "/projects/acme", "Operator")
	if _, err := s.StartContainer(alice, &pb.StartContainerRequest{Name: "web", HostName: "host-b"}); err != nil {
		t.Fatalf("own-project start: %v", err)
	}
	if n := fake.forwards(); n != 1 {
		t.Errorf("forwards = %d, want 1", n)
	}
	// And a _default grant does not reach it now that its project is known.
	bob := grantUser(t, s, "bob", "/projects/_default", "Operator")
	if _, err := s.StopContainer(bob, &pb.StopContainerRequest{Name: "web", HostName: "host-b"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("cross-project stop: %v, want PermissionDenied", err)
	}
}

// A cluster-root grant still reaches an unresolved container, so an admin's
// explicit-host delete keeps the retry idempotency failover relies on.
func TestContainerDelete_ARootGrantStillReachesAnUnresolvedContainer(t *testing.T) {
	s := testServer(t)
	s.SetContainerRuntime(&fakeCTRuntime{})
	fake := unresolvedPeer(s)
	root := grantUser(t, s, "root-op", "/", "Admin")
	if _, err := s.DeleteContainer(root, &pb.DeleteContainerRequest{Name: "gone", HostName: "host-b"}); err != nil {
		t.Fatalf("root explicit-host delete: %v", err)
	}
	if n := fake.forwards(); n != 1 {
		t.Errorf("forwards = %d, want 1", n)
	}
}

// Deleting a VM-scoped backup or replication schedule is a relayed tombstone
// keyed by VM name. With no VM row here the old fallback judged the caller
// against _default and shipped the tombstone to every node holding the
// schedule of a VM in another project.
func TestScheduleDelete_AnUnresolvedVMIsNotAuthorizedAsDefault(t *testing.T) {
	s := testServer(t)
	bob := grantUser(t, s, "bob", "/projects/_default", "Operator")

	before := sgMutationLogCount(t, s)
	if _, err := s.DeleteBackupSchedule(bob, &pb.DeleteBackupScheduleRequest{
		VmName: "victim", Repo: "/repo",
	}); status.Code(err) != codes.NotFound {
		t.Errorf("backup schedule delete: %v, want NotFound", err)
	}
	if _, err := s.DeleteReplicationSchedule(bob, &pb.DeleteReplicationScheduleRequest{
		VmName: "victim", TargetPool: "pool-b",
	}); status.Code(err) != codes.NotFound {
		t.Errorf("replication schedule delete: %v, want NotFound", err)
	}
	if after := sgMutationLogCount(t, s); after != before {
		t.Errorf("refused schedule deletes queued %d statement(s) for replication", after-before)
	}
}

// The legitimate paths: the VM's own project deletes its schedule, and a root
// grant can still clear an orphan schedule whose VM is gone.
func TestScheduleDelete_OwnerAndRootStillDelete(t *testing.T) {
	s := testServer(t)
	seedSGVM(t, s, "web", "acme")
	alice := grantUser(t, s, "alice", "/projects/acme", "Operator")
	if _, err := s.DeleteBackupSchedule(alice, &pb.DeleteBackupScheduleRequest{
		VmName: "web", Repo: "/repo",
	}); err != nil {
		t.Errorf("own-project schedule delete: %v", err)
	}
	bob := grantUser(t, s, "bob", "/projects/_default", "Operator")
	if _, err := s.DeleteBackupSchedule(bob, &pb.DeleteBackupScheduleRequest{
		VmName: "web", Repo: "/repo",
	}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("cross-project schedule delete: %v, want PermissionDenied", err)
	}
	root := grantUser(t, s, "root-op", "/", "Admin")
	if _, err := s.DeleteBackupSchedule(root, &pb.DeleteBackupScheduleRequest{
		VmName: "orphan", Repo: "/repo",
	}); err != nil {
		t.Errorf("root delete of an orphan schedule: %v", err)
	}
}

// A caller with no rights on a name must not learn whether it exists on this
// node. The same request, against a node that holds the resource (in a project
// the caller cannot reach) and one that does not, must fail identically — code
// AND message. RequirePerm's own denial names the resolved path, so without the
// uniform message a denial would reveal the resource's project, and a NotFound
// on the absent side would reveal its absence.
//
// Two callers: a grant confined to another project, and a root grant used
// through a token scoped to another project.
func TestResolvedAuthz_AnOutOfScopeCallerCannotTellWhetherANameExists(t *testing.T) {
	type principal struct {
		name  string
		setup func(t *testing.T, s *Server) context.Context
	}
	principals := []principal{
		{"project-confined grant", func(t *testing.T, s *Server) context.Context {
			return grantUser(t, s, "carol", "/projects/acme", "Admin")
		}},
		{"root grant through an acme-scoped token", func(t *testing.T, s *Server) context.Context {
			ctx := grantUser(t, s, "dave", "/", "Admin")
			return context.WithValue(ctx, ctxKeyScopePaths, []string{"/projects/acme"})
		}},
	}
	ops := map[string]func(s *Server, ctx context.Context) error{
		"sg bind": func(s *Server, ctx context.Context) error {
			_, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
				VmName: "probe", NetworkName: "lan", SecurityGroups: []string{"x"},
			})
			return err
		},
		"backup schedule delete": func(s *Server, ctx context.Context) error {
			_, err := s.DeleteBackupSchedule(ctx, &pb.DeleteBackupScheduleRequest{VmName: "probe", Repo: "/repo"})
			return err
		},
		"container stop": func(s *Server, ctx context.Context) error {
			_, err := s.StopContainer(ctx, &pb.StopContainerRequest{Name: "probe", HostName: "host-b"})
			return err
		},
	}
	for _, p := range principals {
		for opName, op := range ops {
			t.Run(p.name+"/"+opName, func(t *testing.T) {
				holder := testServer(t)
				holder.SetContainerRuntime(&fakeCTRuntime{})
				unresolvedPeer(holder)
				seedSGVM(t, holder, "probe", "beta")
				if err := corrosion.UpsertContainer(context.Background(), holder.db, corrosion.ContainerRecord{
					HostName: "host-b", Name: "probe", State: "running", Project: "beta",
				}); err != nil {
					t.Fatalf("UpsertContainer: %v", err)
				}
				lacker := testServer(t)
				lacker.SetContainerRuntime(&fakeCTRuntime{})
				fake := unresolvedPeer(lacker)

				present := op(holder, p.setup(t, holder))
				absent := op(lacker, p.setup(t, lacker))
				if status.Code(present) != codes.PermissionDenied {
					t.Errorf("name present: %v, want PermissionDenied", present)
				}
				if status.Code(absent) != status.Code(present) || status.Convert(absent).Message() != status.Convert(present).Message() {
					t.Errorf("the response tells a caller with no rights whether the name exists:\n  present: %v\n  absent:  %v",
						present, absent)
				}
				if n := fake.forwards(); n != 0 {
					t.Errorf("%d call(s) forwarded for a caller with no rights", n)
				}
			})
		}
	}
}
