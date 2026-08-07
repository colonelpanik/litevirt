package main

import (
	"context"
	"io"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// `lv run` could not put a VM in a project.
//
// Every VM tenancy feature — project quota, per-project RBAC paths, per-project
// network and pool isolation — keys off spec.Project, and the only ways to set it
// were `lv ct create --project` (containers) and `lv clone --project` (which needs
// something to clone). So a VM created the ordinary way always landed in _default,
// and a project's vCPU/memory quota was unreachable for VMs from the CLI: the
// enforcement worked, nothing could route a VM into it.
//
// The interesting failure is not "the flag is missing" — it is a flag that parses
// fine and never reaches the request, which looks identical from the outside and
// silently puts the VM in the wrong project. So these drive the real command
// through cobra and assert on the CreateVMRequest the daemon would receive.

// captureCreateVM runs cmd with args against a client that records the
// CreateVMRequest and returns a stub VM, so nothing needs a daemon.
type captureCreateVM struct {
	pb.LiteVirtClient
	req *pb.CreateVMRequest
}

func (c *captureCreateVM) CreateVM(_ context.Context, in *pb.CreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	c.req = in
	return &pb.VM{Name: in.Spec.GetName(), HostName: "test-host", State: pb.VMState_VM_RUNNING}, nil
}

// runCLI executes the real `lv run` command with args, returning the request it
// built. Substituting withClient is what lets the assertion be about the wire
// request rather than about the flag set.
func runCLI(t *testing.T, args ...string) *pb.CreateVMRequest {
	t.Helper()
	spy := &captureCreateVM{}
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })

	cmd := newRunCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("lv run %v: %v", args, err)
	}
	if spy.req == nil {
		t.Fatalf("lv run %v never issued a CreateVM", args)
	}
	return spy.req
}

// TestRun_ProjectFlagReachesTheRequest is the whole point of the flag.
func TestRun_ProjectFlagReachesTheRequest(t *testing.T) {
	req := runCLI(t, "--name", "web-01", "--project", "/acme")
	if got := req.Spec.GetProject(); got != "/acme" {
		t.Fatalf("CreateVM spec.Project = %q, want %q — the VM would be created in the wrong "+
			"project, where a different quota (and different RBAC) applies", got, "/acme")
	}
}

// TestRun_ProjectDefaultsToUnset pins that omitting the flag changes nothing: the
// server normalizes an empty project to _default, so sending anything else here
// would silently relocate every existing scripted `lv run`.
func TestRun_ProjectDefaultsToUnset(t *testing.T) {
	req := runCLI(t, "--name", "web-02")
	if got := req.Spec.GetProject(); got != "" {
		t.Fatalf("CreateVM spec.Project = %q with no --project, want empty (server-side _default)", got)
	}
}
