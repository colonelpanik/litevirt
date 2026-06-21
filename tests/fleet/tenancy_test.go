// Fleet scenario 7: tenancy admission end-to-end.
//
// Creates a project + quota over real gRPC, then drives a CreateVM
// at and over the quota limit. Asserts the under-limit case passes,
// the over-limit case is rejected with ResourceExhausted, and
// GetProjectUsage reports the live consumption accurately.

package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestFleet_TenancyQuotaAdmission(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx := context.Background()
	node := c.Nodes[0]
	client := c.SelfClient(node)

	// Seed the image so CreateVM doesn't fail on missing-image.
	if err := node.DB.Execute(ctx,
		`INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES ('test', 'qcow2', 'file:///dev/null', 'deadbeef', 1024, datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	if err := writeEmptyImageFile(node.Server.ImagePathForTests("test")); err != nil {
		t.Fatalf("stage image file: %v", err)
	}

	// Create a project with a tight quota: 4 vCPU, 4 GiB RAM.
	if _, err := client.CreateProject(ctx, &pb.CreateProjectRequest{
		Name: "/acme", Display: "Acme Co",
	}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if _, err := client.SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
		Quota: &pb.ProjectQuota{
			ProjectName: "/acme", VcpuLimit: 4, MemMibLimit: 4096,
		},
	}); err != nil {
		t.Fatalf("SetProjectQuota: %v", err)
	}

	// Under quota: 2 vCPU / 2 GiB. Must succeed.
	if _, err := client.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "small", Image: "test",
			Cpu: 2, MemoryMib: 2048,
			Project:   "/acme",
			Placement: &pb.PlacementSpec{Host: node.Name},
		},
	}); err != nil {
		t.Fatalf("under-quota CreateVM: %v", err)
	}

	// Over quota: another 4 vCPU would push us to 6 > 4.
	_, err := client.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "big", Image: "test",
			Cpu: 4, MemoryMib: 4096,
			Project:   "/acme",
			Placement: &pb.PlacementSpec{Host: node.Name},
		},
	})
	if err == nil {
		t.Fatal("over-quota CreateVM should be rejected")
	}
	if !strings.Contains(err.Error(), "ResourceExhausted") &&
		!strings.Contains(err.Error(), "quota exceeded") {
		t.Errorf("expected ResourceExhausted/quota-exceeded, got %v", err)
	}

	// Usage report should show the under-quota VM.
	usage, err := client.GetProjectUsage(ctx, &pb.GetProjectUsageRequest{
		ProjectName: "/acme",
	})
	if err != nil {
		t.Fatalf("GetProjectUsage: %v", err)
	}
	if usage.VmCount != 1 {
		t.Errorf("expected 1 VM in /acme, got %d", usage.VmCount)
	}
	if usage.VcpuUsed != 2 {
		t.Errorf("expected vcpu_used=2, got %d", usage.VcpuUsed)
	}

	// Project deletion should refuse while VMs still belong.
	_, err = client.DeleteProject(ctx, &pb.DeleteProjectRequest{Name: "/acme"})
	if err == nil {
		t.Fatal("DeleteProject should refuse while project owns VMs")
	}
}

// TestFleet_TenancyDefaultProjectUnbounded confirms VMs without a
// project label land in _default and aren't gated by quota — single-
// tenant clusters keep working unchanged.
func TestFleet_TenancyDefaultProjectUnbounded(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx := context.Background()
	node := c.Nodes[0]
	client := c.SelfClient(node)

	if err := node.DB.Execute(ctx,
		`INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES ('test', 'qcow2', 'file:///dev/null', 'deadbeef', 1024, datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	if err := writeEmptyImageFile(node.Server.ImagePathForTests("test")); err != nil {
		t.Fatalf("stage image file: %v", err)
	}

	// No project field — should default to _default and skip the quota check.
	if _, err := client.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "untenanted", Image: "test",
			Cpu: 1024, MemoryMib: 999999, // absurd values, should still pass
			Placement: &pb.PlacementSpec{Host: node.Name},
		},
	}); err != nil {
		t.Fatalf("default-project CreateVM: %v", err)
	}

	vm, _ := corrosion.GetVM(ctx, node.DB, "untenanted")
	if vm == nil {
		t.Fatal("VM should exist after default-project create")
	}
	// Verify the project column landed as _default.
	rows, _ := node.DB.Query(ctx, "SELECT project FROM vms WHERE name = 'untenanted'")
	if len(rows) == 0 || rows[0].String("project") != corrosion.DefaultProject {
		t.Errorf("expected project=_default, got %+v", rows)
	}
}
