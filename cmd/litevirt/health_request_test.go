package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// captureGetClusterHealth runs `lv health` against a client that records the
// request it received and returns a canned response, so the assertion is about
// the wire request — does --resolved actually reach GetClusterHealth? — rather
// than about flag parsing alone.
type captureGetClusterHealth struct {
	pb.LiteVirtClient
	req  *pb.GetClusterHealthRequest
	resp *pb.ClusterHealth
}

func (c *captureGetClusterHealth) GetClusterHealth(_ context.Context, in *pb.GetClusterHealthRequest, _ ...grpc.CallOption) (*pb.ClusterHealth, error) {
	c.req = in
	if c.resp != nil {
		return c.resp, nil
	}
	return &pb.ClusterHealth{Overall: "HEALTHY"}, nil
}

// runHealthCLI executes the health command against spy, returning its stdout.
// A non-zero health state is reported as a silentExitError, which is the
// command's success path for a degraded cluster — only an error that carries no
// exit code is a genuine failure.
func runHealthCLI(t *testing.T, spy *captureGetClusterHealth, args ...string) string {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })

	cmd := newHealthCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			if _, silent := exitCodeOf(err); !silent {
				t.Fatalf("lv health %v: %v", args, err)
			}
		}
	})
}

// TestHealth_ResolvedFlagReachesTheRequest is the whole point of the flag: a
// parsed-but-unwired flag looks identical in the CLI's output and silently
// always queries active-only conditions.
func TestHealth_ResolvedFlagReachesTheRequest(t *testing.T) {
	spy := &captureGetClusterHealth{}
	runHealthCLI(t, spy, "--resolved")
	if spy.req == nil || !spy.req.GetIncludeResolved() {
		t.Fatalf("GetClusterHealth request IncludeResolved = %v, want true", spy.req.GetIncludeResolved())
	}
}

// TestHealth_DefaultOmitsResolved pins that omitting the flag does not silently
// request the 30-day resolved history as well.
func TestHealth_DefaultOmitsResolved(t *testing.T) {
	spy := &captureGetClusterHealth{}
	runHealthCLI(t, spy)
	if spy.req == nil || spy.req.GetIncludeResolved() {
		t.Fatalf("GetClusterHealth request IncludeResolved = %v, want false", spy.req.GetIncludeResolved())
	}
}

// TestHealth_PrintsEverySection proves the command renders conditions,
// evaluator coverage, connectivity and capacity — not just the overall state.
// Each section is printed by its own block, so one of them can be dropped or
// left unwired without the others noticing.
func TestHealth_PrintsEverySection(t *testing.T) {
	spy := &captureGetClusterHealth{resp: &pb.ClusterHealth{
		Overall: "DEGRADED",
		Conditions: []*pb.HealthCondition{
			{Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectId: "vm1",
				Lifecycle: "confirmed", Severity: "critical"},
		},
		Evaluators: []*pb.HealthEvaluatorStatus{
			{Evaluator: "dual_run", Coverage: "complete", Reporter: "host-a"},
		},
		Connectivity: []*pb.ConnectivityEdge{
			{Observer: "host-a", Target: "host-b", Status: "healthy"},
		},
		Capacity: []*pb.HostCapacityAssessment{
			{HostName: "host-c", EffectiveCpu: 8, EffectiveMemMib: 16384, Complete: false,
				Detail: "runtime probe unreachable"},
		},
	}}

	out := runHealthCLI(t, spy)

	for _, want := range []string{
		"DEGRADED",
		"vm_dual_run", "vm/vm1", "confirmed", "critical", // conditions
		"complete",         // evaluators
		"host-a", "host-b", // connectivity
		"host-c", "8c/16384MiB", // capacity
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}
