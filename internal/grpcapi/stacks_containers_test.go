package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// A container NIC on a stack's isolated network must resolve to the real host
// bridge (br-iso-<hash> derived from the SCOPED network name) and carry a CIDR
// address — not the bare logical name / bare IP, which made lxc-start abort
// ("bridge interface doesn't exist") in the live test.
func TestBuildContainerRequest_ScopedBridgeAndCIDR(t *testing.T) {
	s := testServerR2(t)
	ctx := context.Background()
	f := &compose.File{Name: "lbmix"}

	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "lbmix_lbnet", Type: "isolated", Config: `{"subnet":"10.77.0.0/24"}`,
	}); err != nil {
		t.Fatal(err)
	}

	req, err := s.buildContainerRequest(ctx, "web", &compose.VMDef{
		Kind: compose.WorkloadKindLXC, Image: "alpine:3.21",
		Network: []compose.NetworkAttachment{{Name: "lbnet", IP: "10.77.0.20"}},
	}, f, "h")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	wantBridge := network.IsolatedBridgeName("lbmix_lbnet")
	if req.Networks[0].Bridge != wantBridge {
		t.Errorf("bridge = %q, want %q (scoped isolated bridge, not the logical name)", req.Networks[0].Bridge, wantBridge)
	}
	if req.Networks[0].Ip != "10.77.0.20/24" {
		t.Errorf("nic IP = %q, want 10.77.0.20/24 (CIDR from subnet prefix)", req.Networks[0].Ip)
	}
	// The LB-backend label keeps the bare address (HAProxy needs host:port).
	if req.Labels[corrosion.LabelIP] != "10.77.0.20" {
		t.Errorf("LabelIP = %q, want bare 10.77.0.20", req.Labels[corrosion.LabelIP])
	}
}

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
	// A static NIC address is recorded as the reserved IP label so the container
	// can be discovered as an LB backend cluster-wide.
	if req.Labels[corrosion.LabelIP] != "10.0.1.5" {
		t.Errorf("LabelIP = %q, want 10.0.1.5 (from static NIC)", req.Labels[corrosion.LabelIP])
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

	// The reserved stack label is set so the planner/down can find the container.
	req2, err := s.buildContainerRequest(ctx, "c", &compose.VMDef{Kind: compose.WorkloadKindLXC, Image: "alpine:3.21"}, f, "h")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if req2.Labels[corrosion.LabelStack] != "ct-stack" {
		t.Errorf("stack label = %q, want ct-stack", req2.Labels[corrosion.LabelStack])
	}
}

// compose down (DeleteStack) deletes the stack's containers (found via the
// reserved stack label), not just its VMs — the live-test teardown gap.
func TestDeleteStack_RemovesContainers(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)

	// Store the stack with a compose YAML that declares the container, so
	// DeleteStack's "merge compose-YAML workloads into the VM delete list" path
	// runs — it must SKIP the container (not DeleteVM it), or the stack would be
	// left "deleting" (hadFailures) instead of tombstoned.
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{
		Name:  "ct-stack",
		State: "active",
		ComposeYAML: "name: ct-stack\nworkloads:\n  web:\n    kind: lxc\n" +
			"    image: alpine:3.21\n    cpu: 1\n    memory: 256\n",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "test-host", Name: "web", State: "running",
		Image: "alpine:3.21", CPULimit: 1, MemMiB: 256,
		Labels: map[string]string{corrosion.LabelStack: "ct-stack"},
	}); err != nil {
		t.Fatal(err)
	}

	stream := &mockDeleteStreamR2{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "ct-stack"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}

	found := false
	for _, n := range rt.deleteCalls {
		if n == "web" {
			found = true
		}
	}
	if !found {
		t.Errorf("DeleteContainer not called for web; deleteCalls=%v", rt.deleteCalls)
	}
	cts, err := corrosion.ListContainersByStack(ctx, s.db, "ct-stack")
	if err != nil {
		t.Fatal(err)
	}
	if len(cts) != 0 {
		t.Errorf("container still present after down: %d", len(cts))
	}
	// Tombstoned cleanly — proves the container wasn't mis-handled as a failed
	// VM delete (which would leave the stack in "deleting").
	if st, _ := corrosion.GetStack(ctx, s.db, "ct-stack"); st != nil {
		t.Errorf("stack not tombstoned after down (state=%q) — container likely mis-counted as a VM", st.State)
	}
}

// DeployStack routes a kind=lxc workload through CreateContainer + StartContainer
// (not CreateVM) and persists a container row.
func TestDeployStack_RoutesLXCContainer(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	insertTestHostR2(t, ctx, s.db, "test-host", "active")
	// Containers are placed only on LXC-capable hosts (daemon-advertised label).
	if err := corrosion.SetHostLabel(ctx, s.db, "test-host", corrosion.LabelLXCCapable, "true"); err != nil {
		t.Fatal(err)
	}
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
