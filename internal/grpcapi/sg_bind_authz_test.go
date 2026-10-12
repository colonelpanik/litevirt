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

// sgBindUser seeds a user whose ONLY grant is NetworkAdmin (it carries
// network.update) on /projects/<project>,
// wires a real RBAC engine, and returns that user's context.
func sgBindUser(t *testing.T, s *Server, user, project string) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, user, "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: user + "-" + project, Path: "/projects/" + project, Role: "NetworkAdmin",
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

func sgMutationLogCount(t *testing.T, s *Server) int64 {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil {
		t.Fatal(err)
	}
	return rows[0].Int64("n")
}

func seedSGVM(t *testing.T, s *Server, name, project string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: name, HostName: s.hostName, Spec: "{}", State: "running", Project: project,
	}, []corrosion.InterfaceRecord{{VMName: name, NetworkName: "lan", MAC: "52:54:00:00:00:01"}}, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

// The authorization gap: a node that does not hold the VM's row authorized the
// bind against the DEFAULT project's path, because that is what vmRBACPathFor
// ("", name) builds. A caller whose only grant is on _default therefore passed
// the check for a VM that lives in another project — and the zero-row UPDATE
// that followed was relayed, so every node that DOES hold the row applied it.
// Incident-response isolation SGs are exactly what this RPC is for, so the
// write that escaped could have pulled a victim VM out of its isolation group.
func TestBindSecurityGroups_AVMThisNodeLacksIsNotAuthorizedAsDefault(t *testing.T) {
	s := testServer(t)
	ctx := sgBindUser(t, s, "bob", "_default")

	before := sgMutationLogCount(t, s)
	_, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
		VmName: "victim", NetworkName: "lan", SecurityGroups: []string{"open"},
	})
	if err == nil {
		t.Fatal("a _default-only caller bound SGs to a VM this node cannot place in a project; " +
			"the relayed write lands on every node that holds the row")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound (retryable: the row may still be replicating)", c)
	}
	if after := sgMutationLogCount(t, s); after != before {
		t.Errorf("the refused bind queued %d statement(s) for replication", after-before)
	}
}

// With the row here, the VM's REAL project decides: _default does not reach P.
func TestBindSecurityGroups_AVMInAnotherProjectIsDenied(t *testing.T) {
	s := testServer(t)
	seedSGVM(t, s, "victim", "acme")
	ctx := sgBindUser(t, s, "bob", "_default")

	_, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
		VmName: "victim", NetworkName: "lan", SecurityGroups: []string{"open"},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-project bind: got %v, want PermissionDenied", err)
	}
}

// The legitimate path: a caller with rights on the VM's own project binds.
func TestBindSecurityGroups_TheOwningProjectStillBinds(t *testing.T) {
	s := testServer(t)
	seedSGVM(t, s, "web", "acme")
	ctx := sgBindUser(t, s, "alice", "acme")

	if _, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
		VmName: "web", NetworkName: "lan", SecurityGroups: []string{"isolate"},
	}); err != nil {
		t.Fatalf("own-project bind: %v", err)
	}
	ifaces, err := corrosion.GetVMInterfaces(context.Background(), s.db, "web")
	if err != nil || len(ifaces) != 1 {
		t.Fatalf("GetVMInterfaces: %+v %v", ifaces, err)
	}
	if got := ifaces[0].SecurityGroups; len(got) != 1 || got[0] != "isolate" {
		t.Errorf("security groups = %v, want [isolate]", got)
	}
}

// And a _default VM is still bindable by a _default caller — the fix must not
// have turned "default" into "never".
func TestBindSecurityGroups_ADefaultProjectVMStillBinds(t *testing.T) {
	s := testServer(t)
	seedSGVM(t, s, "plain", "")
	ctx := sgBindUser(t, s, "bob", "_default")

	if _, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
		VmName: "plain", NetworkName: "lan", SecurityGroups: []string{"web"},
	}); err != nil {
		t.Fatalf("default-project bind: %v", err)
	}
}
