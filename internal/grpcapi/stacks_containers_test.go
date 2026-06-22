package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// buildContainerRequest maps a compose container workload to a
// CreateContainerRequest: download templates, rootfs paths, restart, networks;
// and rejects an un-pullable OCI registry ref.
func TestBuildContainerRequest(t *testing.T) {
	s := testServerR2(t)
	ctx := context.Background()
	f := &compose.File{Name: "ct-stack"}

	// kind=lxc download template "distro:release".
	req, err := s.buildContainerRequest(ctx, "ct-stack-web-0", &compose.VMDef{
		Kind:    compose.WorkloadKindLXC,
		Image:   "alpine:3.21",
		CPU:     2,
		Memory:  512,
		Restart: &compose.RestartDef{Condition: "on-failure"},
		Network: []compose.NetworkAttachment{{Name: "lan", IP: "10.0.1.5"}},
	}, f, "test-host")
	if err != nil {
		t.Fatalf("lxc download: %v", err)
	}
	if req.HostName != "test-host" || req.Template != "download" || req.Distro != "alpine" || req.Release != "3.21" || req.Arch != "amd64" {
		t.Errorf("download mapping wrong: %+v", req)
	}
	if req.Cpu != 2 || req.MemoryMib != 512 {
		t.Errorf("cpu/mem = %d/%d, want 2/512", req.Cpu, req.MemoryMib)
	}
	if req.Restart == nil || req.Restart.Condition != "on-failure" {
		t.Errorf("restart not mapped: %+v", req.Restart)
	}
	if len(req.Networks) != 1 || req.Networks[0].Name != "lan" || req.Networks[0].Ip != "10.0.1.5" {
		t.Errorf("network mapping wrong: %+v", req.Networks)
	}

	// "alpine" (no release).
	req, err = s.buildContainerRequest(ctx, "c", &compose.VMDef{Kind: compose.WorkloadKindLXC, Image: "alpine"}, f, "h")
	if err != nil || req.Distro != "alpine" || req.Release != "" {
		t.Errorf("no-release mapping: req=%+v err=%v", req, err)
	}

	// rootfs path → used verbatim as Template (works for lxc and oci).
	for _, kind := range []compose.WorkloadKind{compose.WorkloadKindLXC, compose.WorkloadKindOCI} {
		req, err = s.buildContainerRequest(ctx, "c", &compose.VMDef{Kind: kind, Image: "/srv/rootfs"}, f, "h")
		if err != nil || req.Template != "/srv/rootfs" || req.Distro != "" {
			t.Errorf("rootfs path (kind=%s): req=%+v err=%v", kind, req, err)
		}
	}

	// kind=oci with a registry ref is not auto-pulled yet → error.
	if _, err := s.buildContainerRequest(ctx, "c", &compose.VMDef{Kind: compose.WorkloadKindOCI, Image: "nginx:latest"}, f, "h"); err == nil {
		t.Error("oci registry ref should error (no auto-pull yet)")
	}
}

// DeployStack routes a kind=lxc workload through CreateContainer + StartContainer
// (not CreateVM) and persists a container row.
func TestDeployStack_RoutesLXCContainer(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	insertTestHostR2(t, ctx, s.db, "test-host", "active")
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)

	yaml := `name: ct-stack
workloads:
  web:
    kind: lxc
    image: alpine:3.21
    cpu: 1
    memory: 256
`
	stream := &mockDeployStream{ctx: ctx}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, stream); err != nil {
		t.Fatalf("DeployStack: %v", err)
	}

	if len(rt.createCalls) != 1 {
		t.Fatalf("CreateContainer calls = %d, want 1", len(rt.createCalls))
	}
	if c := rt.createCalls[0]; c.Template != "download" || c.Distro != "alpine" || c.Release != "3.21" {
		t.Errorf("create opts = %+v, want download/alpine/3.21", c)
	}
	if len(rt.startCalls) != 1 {
		t.Errorf("StartContainer calls = %d, want 1 (compose up should start it)", len(rt.startCalls))
	}
	cts, err := corrosion.ListContainers(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(cts) != 1 {
		t.Fatalf("container rows = %d, want 1", len(cts))
	}
}
