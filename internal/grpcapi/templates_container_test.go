package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestConvertContainerToTemplate covers convert (requires stopped), the
// can't-start-a-template guard, and revert.
func TestConvertContainerToTemplate(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	ctx := context.Background()
	_ = corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "base", State: "running", Project: "acme",
	})

	// Convert while running → FailedPrecondition.
	if _, err := s.ConvertContainerToTemplate(adminCtx(), &pb.ConvertContainerToTemplateRequest{Name: "base", HostName: "host-a"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("convert-running want FailedPrecondition, got %v", err)
	}
	// Stop, then convert.
	_ = corrosion.SetContainerState(ctx, s.db, "host-a", "base", "stopped")
	ct, err := s.ConvertContainerToTemplate(adminCtx(), &pb.ConvertContainerToTemplateRequest{Name: "base", HostName: "host-a"})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	row, _ := corrosion.GetContainer(ctx, s.db, "host-a", "base")
	if !row.IsTemplate {
		t.Errorf("container not marked template: %+v / pb=%+v", row, ct)
	}

	// Can't start a template.
	if _, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "base", HostName: "host-a"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("starting a template want FailedPrecondition, got %v", err)
	}
	if len(rt.startCalls) != 0 {
		t.Errorf("template start reached the runtime: %v", rt.startCalls)
	}

	// Revert.
	if _, err := s.ConvertContainerToTemplate(adminCtx(), &pb.ConvertContainerToTemplateRequest{Name: "base", HostName: "host-a", Revert: true}); err != nil {
		t.Fatalf("revert: %v", err)
	}
	row, _ = corrosion.GetContainer(ctx, s.db, "host-a", "base")
	if row.IsTemplate {
		t.Error("revert did not clear is_template")
	}
}

// TestCloneContainer clones a stopped source: runtime clone invoked, row
// persisted with a fresh identity (not a template), source unchanged.
func TestCloneContainer(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	ctx := context.Background()
	_ = corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "base", State: "stopped", Image: "alpine:3.19",
		CPULimit: 1, MemMiB: 128, Project: "acme", IsTemplate: true,
	})

	ct, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "base", Target: "web1", HostName: "host-a"})
	if err != nil {
		t.Fatalf("CloneContainer: %v", err)
	}
	if ct.Name != "web1" || ct.State != "stopped" {
		t.Errorf("clone pb = %+v", ct)
	}
	if len(rt.cloneCalls) != 1 || rt.cloneCalls[0].Src != "base" || rt.cloneCalls[0].Dst != "web1" {
		t.Errorf("runtime clone calls = %v, want [base→web1]", rt.cloneCalls)
	}
	row, _ := corrosion.GetContainer(ctx, s.db, "host-a", "web1")
	if row == nil || row.IsTemplate || row.Image != "alpine:3.19" || row.CPULimit != 1 || row.Project != "acme" {
		t.Errorf("clone row = %+v, want non-template alpine 1cpu acme", row)
	}
}

// TestCloneContainer_RunningSourceRefused — a running, non-template source
// isn't crash-consistent to clone.
func TestCloneContainer_RunningSourceRefused(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.SetContainerRuntime(&fakeCTRuntime{})
	_ = corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "base", State: "running", Project: "acme",
	})
	_, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "base", Target: "web1", HostName: "host-a"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("clone-running want FailedPrecondition, got %v", err)
	}
}
