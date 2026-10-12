package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func seedCT(t *testing.T, s *Server, host, name, project string) {
	t.Helper()
	if err := corrosion.UpsertContainer(adminCtx(), s.db, corrosion.ContainerRecord{
		Name: name, HostName: host, State: "running", Project: project,
	}); err != nil {
		t.Fatalf("UpsertContainer(%s/%s): %v", host, name, err)
	}
}

// TestExecContainer_AmbiguousNameIsRefused is the #184 regression.
//
// ExecContainer resolved the project with containerProject(ctx, "", name),
// which scans the cluster and returns the FIRST name match, then executed
// LOCALLY because it only forwards when host_name is non-empty. Authorization
// therefore used one host's row while execution used a different host's
// container: an attacker who owns a same-named container on a host that sorts
// earlier gets ct.exec inside the victim's container.
//
// Every other container lifecycle RPC routes through resolveContainerHost,
// which refuses an ambiguous name. ExecContainer was the one that skipped it.
func TestExecContainer_AmbiguousNameIsRefused(t *testing.T) {
	s := testServer(t)
	rt := &fakeCTRuntime{}
	s.containerRuntime = rt

	// "web" exists twice: the attacker's on the lexicographically FIRST host,
	// the victim's on this node. The scan would return "attacker".
	seedCT(t, s, "host-a", "web", "attacker")
	seedCT(t, s, s.hostName, "web", "victim")

	_, err := s.ExecContainer(adminCtx(), &pb.ExecContainerRequest{
		Name: "web", Argv: []string{"id"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ambiguous container name: got %v, want FailedPrecondition", err)
	}
	if len(rt.execCalls) != 0 {
		t.Errorf("the exec RAN despite the refusal: %+v", rt.execCalls)
	}
}

// The second variant the old scan exposed: with NO matching row at all,
// containerProject fell back to "_default", so anyone holding ct.exec on
// _default passed the check and the exec ran against whatever local container
// happened to carry that name.
func TestExecContainer_UnknownNameIsNotFound(t *testing.T) {
	s := testServer(t)
	rt := &fakeCTRuntime{}
	s.containerRuntime = rt

	_, err := s.ExecContainer(adminCtx(), &pb.ExecContainerRequest{
		Name: "ghost", Argv: []string{"id"},
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown container: got %v, want NotFound", err)
	}
	if len(rt.execCalls) != 0 {
		t.Errorf("the exec RAN for a container with no row: %+v", rt.execCalls)
	}
}

// An unambiguous local container still execs, with the project taken from the
// row that was actually resolved.
func TestExecContainer_UnambiguousLocalStillWorks(t *testing.T) {
	s := testServer(t)
	rt := &fakeCTRuntime{}
	s.containerRuntime = rt
	seedCT(t, s, s.hostName, "solo", "acme")

	resp, err := s.ExecContainer(adminCtx(), &pb.ExecContainerRequest{
		Name: "solo", Argv: []string{"id"},
	})
	if err != nil {
		t.Fatalf("unambiguous local exec: %v", err)
	}
	if string(resp.Stdout) != "ok" {
		t.Errorf("stdout = %q, want ok", resp.Stdout)
	}
	if len(rt.execCalls) != 1 || rt.execCalls[0].Name != "solo" {
		t.Errorf("exec calls = %+v, want one for solo", rt.execCalls)
	}
}

// Naming the host explicitly keeps working and still resolves the project from
// THAT host's row.
func TestExecContainer_ExplicitHostStillWorks(t *testing.T) {
	s := testServer(t)
	rt := &fakeCTRuntime{}
	s.containerRuntime = rt
	seedCT(t, s, "host-a", "web", "attacker")
	seedCT(t, s, s.hostName, "web", "victim")

	resp, err := s.ExecContainer(adminCtx(), &pb.ExecContainerRequest{
		Name: "web", HostName: s.hostName, Argv: []string{"id"},
	})
	if err != nil {
		t.Fatalf("explicit-host exec: %v", err)
	}
	if string(resp.Stdout) != "ok" {
		t.Errorf("stdout = %q, want ok", resp.Stdout)
	}
	if len(rt.execCalls) != 1 {
		t.Errorf("exec calls = %+v, want exactly one", rt.execCalls)
	}
}
