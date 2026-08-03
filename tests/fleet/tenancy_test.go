// Fleet scenario 7: tenancy admission end-to-end.
//
// Creates a project + quota over real gRPC, then drives a CreateVM
// at and over the quota limit. Asserts the under-limit case passes,
// the over-limit case is rejected with ResourceExhausted, and
// GetProjectUsage reports the live consumption accurately.

package fleet

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedQuotaProject is the single-node preamble shared by the tenancy-quota
// tests: a usable image named "test" plus project "/acme" capped at the given
// quota. Returns the node and its client.
func seedQuotaProject(t *testing.T, c *Cluster, vcpuLimit, memMiBLimit int32) (*Node, pb.LiteVirtClient) {
	t.Helper()
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
	if _, err := client.CreateProject(ctx, &pb.CreateProjectRequest{
		Name: "/acme", Display: "Acme Co",
	}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if _, err := client.SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
		Quota: &pb.ProjectQuota{
			ProjectName: "/acme", VcpuLimit: vcpuLimit, MemMibLimit: memMiBLimit,
		},
	}); err != nil {
		t.Fatalf("SetProjectQuota: %v", err)
	}
	return node, client
}

func TestFleet_TenancyQuotaAdmission(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx := context.Background()
	// Tight quota: 4 vCPU, 4 GiB RAM.
	node, client := seedQuotaProject(t, c, 4, 4096)

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

	// No project field — should default to _default and skip the QUOTA check.
	//
	// Large enough that any real project quota would reject it, but still within
	// the host's allocatable capacity: host admission is a separate check that now
	// runs on create too, and truly absurd values (1024 vCPU / 999999 MiB) would
	// be refused for capacity — proving nothing about quotas.
	if _, err := client.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "untenanted", Image: "test",
			Cpu: 200, MemoryMib: 200000,
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

// A stopped workload is still counted in project-quota usage ("an allocation
// counts whether running or stopped"), so restarting it must NOT admit its
// full size against the quota a second time — start-time admission is about
// HOST capacity only. Regression: stop→start of a VM sized above ~50% of its
// project quota was refused with "quota exceeded".
func TestFleet_TenancyQuota_StopStartStaysWithinQuota(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx := context.Background()
	node, client := seedQuotaProject(t, c, 4, 4096)

	// 3000 MiB fits the 4096 quota at create — but is over half of it, so a
	// double-counting start-time check would compute 3000+3000 > 4096.
	if _, err := client.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "big-half", Image: "test", Cpu: 2, MemoryMib: 3000,
			Project:   "/acme",
			Placement: &pb.PlacementSpec{Host: node.Name},
		},
	}); err != nil {
		t.Fatalf("under-quota CreateVM: %v", err)
	}
	if _, err := client.StopVM(ctx, &pb.StopVMRequest{Name: "big-half"}); err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	if _, err := client.StartVM(ctx, &pb.StartVMRequest{Name: "big-half"}); err != nil {
		t.Fatalf("StartVM of a stopped VM within quota: %v — start must not count the allocation against its own quota again", err)
	}
}

// --allow-overcommit bypasses the HOST capacity check only. Project quota is a
// tenancy limit, not a physical one — the flag must not sidestep it (the code
// comment and proto doc both promise "project quota still applies").
func TestFleet_TenancyQuota_AllowOvercommitStillEnforcesQuota(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx := context.Background()
	node, client := seedQuotaProject(t, c, 4, 4096)

	if _, err := client.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "first", Image: "test", Cpu: 2, MemoryMib: 3000,
			Project:   "/acme",
			Placement: &pb.PlacementSpec{Host: node.Name},
		},
	}); err != nil {
		t.Fatalf("under-quota CreateVM: %v", err)
	}

	// Second VM pushes memory to 6000 > 4096. --allow-overcommit may skip the
	// host check, never the quota.
	_, err := client.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "second", Image: "test", Cpu: 1, MemoryMib: 3000,
			Project:   "/acme",
			Placement: &pb.PlacementSpec{Host: node.Name},
		},
		AllowOvercommit: true,
	})
	if err == nil {
		t.Fatal("over-quota CreateVM with --allow-overcommit must still be refused by project quota")
	}
	if !strings.Contains(err.Error(), "quota exceeded") {
		t.Errorf("want quota-exceeded error, got %v", err)
	}
}

// UpdateVM growth under --allow-overcommit: the flag skips only the HOST
// capacity check. Project quota must still refuse a grow past the limit
// (proto doc: "project quota still applies").
func TestFleet_TenancyQuota_UpdateAllowOvercommitStillEnforcesQuota(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx := context.Background()
	node, client := seedQuotaProject(t, c, 8, 4096)
	if _, err := client.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "grower", Image: "test", Cpu: 1, MemoryMib: 2048,
			Project:   "/acme",
			Placement: &pb.PlacementSpec{Host: node.Name},
		},
	}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	allowRestart := true
	_, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name: "grower", MemoryMib: 6000, // grow to 6000 > 4096 quota
		AllowRestart:    &allowRestart,
		AllowOvercommit: true,
	})
	if err == nil {
		t.Fatal("over-quota UpdateVM grow with --allow-overcommit must still be refused by project quota")
	}
	if !strings.Contains(err.Error(), "quota exceeded") {
		t.Errorf("want quota-exceeded error, got %v", err)
	}
}

// TestFleet_ProjectQuota_ConcurrentCreatesAcrossNodes is the cross-daemon half of
// the admission race, and the reason project quota needed routing rather than just
// a lock.
//
// Host capacity is owner-local, so a per-host lock on the owning daemon serializes
// it. Project quota is not: two creates in one project can target DIFFERENT hosts,
// so they are admitted by two different daemons, each reading its own CRDT
// snapshot. Neither sees the other's in-flight grow and both pass — no per-node
// lock can fix that. Routing every admission for a project to its single authority
// holder is what makes the holder's mutex + ledger cluster-wide.
//
// Here two VMs, each 4 vCPU / 2048 MiB, are created concurrently through two
// different entry nodes against a quota of 4 vCPU / 4096 MiB. Only one fits on
// vCPU. Without routing, both are admitted and /acme ends up at 8 vCPU against a
// 4 vCPU limit.
func TestFleet_ProjectQuota_ConcurrentCreatesAcrossNodes(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	node, _ := seedQuotaProject(t, c, 4, 4096)
	_ = node

	// Opt every node into routing and drive the real cluster latch, using the same
	// production wiring the hardware_v2 latch scenario uses (a real health.Checker
	// gate pinging peers over the harness's loopback mTLS). Without an ACTIVE token
	// admission stays on the legacy local path and this test would silently assert
	// nothing.
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		n.Server.SetProjectQuotaAuthority(true)
	}
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.ProjectQuotaAuthorityV1) {
			t.Fatalf("%s: project_quota_authority_v1 failed to latch with the flag on everywhere", n.Name)
		}
	}

	clients := make([]pb.LiteVirtClient, len(c.Nodes))
	for i, n := range c.Nodes {
		clients[i] = c.SelfClient(n) // dial on the test goroutine
	}
	// The image and project were seeded on node 0's DB; with SharedCRDT every node
	// sees them, but the image FILE is per-node, so pin creates to node 0's host.
	target := c.Nodes[0].Name

	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(clients))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, cl := range clients {
		wg.Add(1)
		go func(i int, cl pb.LiteVirtClient) {
			defer wg.Done()
			name := fmt.Sprintf("q-racer-%d", i)
			<-start
			_, err := cl.CreateVM(context.Background(), &pb.CreateVMRequest{
				Spec: &pb.VMSpec{
					Name: name, Project: "/acme", Image: "test",
					Cpu: 4, MemoryMib: 2048,
					Placement: &pb.PlacementSpec{Host: target},
				},
			})
			results <- result{name: name, err: err}
		}(i, cl)
	}
	close(start)
	wg.Wait()
	close(results)

	var admitted int
	for r := range results {
		if r.err == nil {
			admitted++
			continue
		}
		if rec, _ := corrosion.GetVM(ctx, c.Nodes[0].DB, r.name); rec != nil {
			admitted++
		}
	}

	// The quota allows 4 vCPU; each VM wants 4. Admitting both would put /acme at
	// double its limit.
	if admitted > 1 {
		t.Errorf("admitted %d concurrent 4-vCPU creates against a 4-vCPU project quota — "+
			"quota admission is not serialized across daemons", admitted)
	}

	usage, err := corrosion.SumProjectUsage(ctx, c.Nodes[0].DB, "/acme")
	if err != nil {
		t.Fatalf("SumProjectUsage: %v", err)
	}
	if usage.VCPUUsed > 4 {
		t.Errorf("/acme committed usage = %d vCPU against a limit of 4 — the project is over quota",
			usage.VCPUUsed)
	}
}
