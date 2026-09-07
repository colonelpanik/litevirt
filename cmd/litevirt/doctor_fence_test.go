package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type fenceReadinessClient struct {
	pb.LiteVirtClient
	resp *pb.FenceReadiness
}

func (c *fenceReadinessClient) GetFenceReadiness(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.FenceReadiness, error) {
	return c.resp, nil
}

// runDoctorFence executes the command against a canned response, returning its
// stdout and the exit code it signalled (0 when it returned no error).
func runDoctorFence(t *testing.T, resp *pb.FenceReadiness) (string, int) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, &fenceReadinessClient{resp: resp})
	}
	t.Cleanup(func() { withClient = orig })

	cmd := newDoctorFenceCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	code := 0
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			c, silent := exitCodeOf(err)
			if !silent {
				t.Fatalf("lv doctor fence: %v", err)
			}
			code = c
		}
	})
	return out, code
}

func enforcingHost(name string) *pb.FenceHostPosture {
	return &pb.FenceHostPosture{Host: name, Reachable: true, PostureKnown: true, Enforcing: true}
}

// TestDoctorFence_ExitCodeTracksExposure pins the scriptable contract. This is
// what makes the check usable from a pre-upgrade gate or a monitoring cron, and
// the two directions are asymmetric in cost: a false 0 tells an operator a
// corruption hazard is closed when it is open.
func TestDoctorFence_ExitCodeTracksExposure(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp *pb.FenceReadiness
		want int
	}{
		{"covered", &pb.FenceReadiness{
			CapabilityLatched: true, EnforcedEverywhere: true, VmsWithSharedDisk: 3,
			Hosts: []*pb.FenceHostPosture{enforcingHost("h1")}}, 0},
		{"no shared-disk VMs is not a hazard", &pb.FenceReadiness{
			CapabilityLatched: false, EnforcedEverywhere: false, VmsWithSharedDisk: 0}, 0},
		{"kill-switch off with VMs exposed", &pb.FenceReadiness{
			CapabilityLatched: true, EnforcedEverywhere: false, VmsWithSharedDisk: 1,
			Hosts: []*pb.FenceHostPosture{{Host: "h2", Reachable: true, PostureKnown: true}}}, 1},
		{"not latched with VMs exposed", &pb.FenceReadiness{
			CapabilityLatched: false, EnforcedEverywhere: true, VmsWithSharedDisk: 1,
			Hosts: []*pb.FenceHostPosture{enforcingHost("h1")}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, code := runDoctorFence(t, tc.resp)
			if code != tc.want {
				t.Errorf("exit code = %d, want %d", code, tc.want)
			}
		})
	}
}

// TestDoctorFence_NamesTheHostToFix pins that the warning is actionable. A
// warning that says the cluster is exposed without naming which host to change
// leaves the operator to guess, and guessing wrong on a fleet means the hazard
// stays open after they believe they closed it.
func TestDoctorFence_NamesTheHostToFix(t *testing.T) {
	out, code := runDoctorFence(t, &pb.FenceReadiness{
		CapabilityLatched: true, EnforcedEverywhere: false, VmsWithSharedDisk: 2,
		SampleVms: []string{"db-1", "db-2"},
		Hosts: []*pb.FenceHostPosture{
			enforcingHost("kvm001"),
			{Host: "kvm002", Reachable: true, PostureKnown: true,
				Detail: "enforcement.shared_storage_fence is false on this host"},
		},
	})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	for _, want := range []string{
		"WARNING",
		"kvm002",                           // the host at fault
		"enforcement.shared_storage_fence", // the setting to change
		"db-1",                             // what is exposed
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "true on kvm002") {
		t.Errorf("the remedy line does not name the host to change; got:\n%s", out)
	}
	if strings.Contains(out, "true on kvm001") {
		t.Error("the remedy names a host that is already enforcing")
	}
}

// TestDoctorFence_UnknownPostureIsNotReportedAsEnforcing pins the wording of the
// three-state posture. Collapsing "we could not ask" into "no" or "yes" both
// mislead: the operator either chases a host that is fine, or believes a host is
// covered when nothing checked it.
func TestDoctorFence_UnknownPostureIsNotReportedAsEnforcing(t *testing.T) {
	out, code := runDoctorFence(t, &pb.FenceReadiness{
		CapabilityLatched: true, EnforcedEverywhere: false, VmsWithSharedDisk: 1,
		Hosts: []*pb.FenceHostPosture{
			{Host: "gone", Reachable: false, Detail: "ping: connection refused"},
			{Host: "old", Reachable: true, PostureKnown: false,
				Detail: "host runs a binary that does not report enforcement posture"},
		},
	})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(out, "unknown (unreachable)") {
		t.Errorf("an unreachable host is not marked unknown; got:\n%s", out)
	}
	if !strings.Contains(out, "did not answer") {
		t.Errorf("the remedy does not say the host never answered; got:\n%s", out)
	}
	if !strings.Contains(out, "cannot report its posture") {
		t.Errorf("an old binary is not distinguished from one that answered; got:\n%s", out)
	}
}

// TestDoctorFence_CoveredClusterSaysSo guards the quiet path: a cluster with
// shared-disk VMs and both switches on must state that they are covered, not
// print an empty report an operator has to interpret.
func TestDoctorFence_CoveredClusterSaysSo(t *testing.T) {
	out, code := runDoctorFence(t, &pb.FenceReadiness{
		CapabilityLatched: true, EnforcedEverywhere: true, VmsWithSharedDisk: 4,
		SampleVms: []string{"db-1"},
		Hosts:     []*pb.FenceHostPosture{enforcingHost("kvm001")},
	})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "will be fenced") {
		t.Errorf("a covered cluster does not say so; got:\n%s", out)
	}
	if strings.Contains(out, "WARNING") {
		t.Errorf("a covered cluster warns anyway; got:\n%s", out)
	}
}
