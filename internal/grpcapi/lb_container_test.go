package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestMapHAProxyStatus(t *testing.T) {
	cases := map[string]string{
		"UP 2/3":          "active",
		"UP":              "active",
		"DOWN (agent)":    "down",
		"DOWN":            "down",
		"MAINT (via a/b)": "maint",
		"MAINT":           "maint",
		"DRAIN":           "draining",
		"NOLB":            "nolb",
		"something-weird": "run-state", // unexpected → fallback
		"":                "run-state", // empty → fallback
	}
	for raw, want := range cases {
		if got := mapHAProxyStatus(raw, "run-state"); got != want {
			t.Errorf("mapHAProxyStatus(%q) = %q, want %q", raw, got, want)
		}
	}
}

// InspectLoadBalancer overlays REAL HAProxy health onto the run-state status:
// a backend whose workload is running but whose HAProxy check is DOWN must show
// "down", not "active". On a stats-fetch failure it keeps run-state + flags it.
func TestInspectLB_HealthOverlay(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "app-lb", StackName: "app", VIP: "10.0.0.9/24", Algorithm: "roundrobin", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web-1", StackName: "app", HostName: "other-host", Spec: "{}", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "web-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:00:00:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatal(err)
	}

	// HAProxy says the running VM's backend is DOWN → inspect must reflect it.
	s.lbHealthOverride = func(context.Context, string) (map[string]string, error) {
		return map[string]string{"web-1": "DOWN (L4 timeout)"}, nil
	}
	lbResp, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "app-lb"})
	if err != nil {
		t.Fatalf("InspectLoadBalancer: %v", err)
	}
	if len(lbResp.Backends) != 1 || lbResp.Backends[0].Status != "down" {
		t.Fatalf("backend status = %+v, want real health 'down' (not run-state 'active')", lbResp.Backends)
	}

	// Stats unavailable → keep run-state 'active' but flag it.
	s.lbHealthOverride = func(context.Context, string) (map[string]string, error) {
		return nil, errStatsUnavailableForTest
	}
	lbResp, _ = s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "app-lb"})
	if lbResp.Backends[0].Status != "active" || lbResp.Backends[0].LastError == "" {
		t.Errorf("fallback wrong: status=%q lastErr=%q, want active + a 'health unavailable' note",
			lbResp.Backends[0].Status, lbResp.Backends[0].LastError)
	}
}

// An enabled LB whose keepalived isn't running on the host that should run it is
// reported "degraded" — its VIP isn't actually assigned even though HAProxy
// binds it non-locally and would otherwise look "active".
func TestInspectLB_DegradedWhenKeepalivedDown(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	ctx := adminCtx()
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "app-lb", StackName: "app", VIP: "10.0.0.9/24", Algorithm: "roundrobin",
		Hosts: `["test-host"]`, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Health reachable (so degraded comes only from the VIP/keepalived check).
	s.lbHealthOverride = func(context.Context, string) (map[string]string, error) {
		return map[string]string{}, nil
	}

	s.lbKeepalivedOverride = func(string) bool { return false } // VIP not assigned
	lbResp, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "app-lb"})
	if err != nil {
		t.Fatalf("InspectLoadBalancer: %v", err)
	}
	if lbResp.State != "degraded" {
		t.Errorf("state = %q, want degraded (keepalived down → VIP unassigned)", lbResp.State)
	}

	s.lbKeepalivedOverride = func(string) bool { return true } // VIP assigned
	lbResp, _ = s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "app-lb"})
	if lbResp.State != "active" {
		t.Errorf("state = %q, want active when keepalived is up", lbResp.State)
	}
}

var errStatsUnavailableForTest = &lbTestErr{"haproxy not running"}

type lbTestErr struct{ s string }

func (e *lbTestErr) Error() string { return e.s }

// resolveStackBackends is the single resolver behind both the status and render
// paths: it returns every VM (running or not, with its stored/discovered IP) and
// every stack container. The list path (allowRemote=false) must not attempt a
// peer RPC for a remote VM, and a non-running VM keeps its stored interface IP.
func TestResolveStackBackends_UnifiesVMsAndContainers(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "api-1", StackName: "app", HostName: "other-host", Spec: "{}", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "api-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "api-2", StackName: "app", HostName: "other-host", Spec: "{}", State: "stopped",
	}, []corrosion.InterfaceRecord{
		{VMName: "api-2", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:02", IP: "10.0.0.11"},
	}, nil); err != nil {
		t.Fatal(err)
	}
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "running", "10.0.0.20")

	// List path: read-only, no remote RPC.
	got := map[string]resolvedBackend{}
	for _, rb := range s.resolveStackBackends(ctx, "app", false, false) {
		got[rb.Name] = rb
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 backends, got %d: %+v", len(got), got)
	}
	if b := got["api-1"]; b.IP != "10.0.0.10" || !b.Running {
		t.Errorf("api-1 = %+v, want 10.0.0.10/running", b)
	}
	// A stopped VM keeps its stored IP and is marked not-running (so the status
	// view shows it [down] with its last address).
	if b := got["api-2"]; b.IP != "10.0.0.11" || b.Running {
		t.Errorf("api-2 = %+v, want 10.0.0.11/stopped", b)
	}
	if b := got["web"]; b.IP != "10.0.0.20" || !b.Running {
		t.Errorf("web = %+v, want 10.0.0.20/running", b)
	}
}

// upsertStackContainer inserts a container tagged with its stack (and optionally
// a recorded static IP), the way buildContainerRequest does at deploy time.
func upsertStackContainer(t *testing.T, ctx context.Context, s *Server, name, stack, host, state, ip string) {
	t.Helper()
	labels := map[string]string{corrosion.LabelStack: stack}
	if ip != "" {
		labels[corrosion.LabelIP] = ip
	}
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: host, Name: name, State: state, Image: "alpine:3.21",
		CPULimit: 1, MemMiB: 256, Labels: labels,
	}); err != nil {
		t.Fatalf("UpsertContainer(%s): %v", name, err)
	}
}

// A running stack container with a recorded static IP shows up as an active LB
// backend in the status view — cluster-wide, no local runtime needed.
func TestLBBackends_IncludesContainerStaticIP(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "running", "10.0.0.20")

	backends := s.lbBackends(ctx, "app-lb")
	if len(backends) != 1 {
		t.Fatalf("expected 1 container backend, got %d", len(backends))
	}
	if backends[0].VmName != "web" || backends[0].Address != "10.0.0.20" || backends[0].Status != "active" {
		t.Errorf("container backend = %+v, want web/10.0.0.20/active", backends[0])
	}
}

// A stopped container is still listed but marked down.
func TestLBBackends_StoppedContainerIsDown(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "stopped", "10.0.0.20")

	backends := s.lbBackends(ctx, "app-lb")
	if len(backends) != 1 || backends[0].Status != "down" {
		t.Fatalf("expected 1 down backend, got %+v", backends)
	}
}

// A single stack LB fronts a mix of VMs and containers — the headline case.
func TestLBBackends_MixedVMAndContainer(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "api-1", StackName: "app", HostName: "other-host", Spec: "{}", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "api-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "running", "10.0.0.20")

	backends := s.lbBackends(ctx, "app-lb")
	got := map[string]string{} // name -> address
	for _, b := range backends {
		got[b.VmName] = b.Address
	}
	if len(got) != 2 || got["api-1"] != "10.0.0.10" || got["web"] != "10.0.0.20" {
		t.Fatalf("mixed backends = %+v, want api-1=10.0.0.10 + web=10.0.0.20", got)
	}
}

// The HAProxy render path (collectLBBackends) includes a running container with
// the LB's target port, and skips stopped / IP-less containers.
func TestCollectLBBackends_IncludesContainer(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "running", "10.0.0.20")
	upsertStackContainer(t, ctx, s, "stopped-ct", "app", "other-host", "stopped", "10.0.0.21")
	upsertStackContainer(t, ctx, s, "noip-ct", "app", "other-host", "running", "") // no IP, not local → skipped

	lbSpec := &pb.LBSpec{
		Enabled: true,
		Vip:     "10.0.0.50/24",
		Ports:   []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	backends := s.collectLBBackends(ctx, "app", lbSpec)
	if len(backends) != 1 {
		t.Fatalf("expected 1 rendered backend (running+IP only), got %d: %+v", len(backends), backends)
	}
	if backends[0].Name != "web" || backends[0].IP != "10.0.0.20" || backends[0].Port != 8080 {
		t.Errorf("rendered backend = %+v, want web/10.0.0.20/8080", backends[0])
	}
}

// Render path: a stack LB renders both the VM and the container as server lines.
func TestCollectLBBackends_MixedVMAndContainer(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "api-1", StackName: "app", HostName: "other-host", Spec: "{}", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "api-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "running", "10.0.0.20")

	lbSpec := &pb.LBSpec{
		Enabled: true,
		Vip:     "10.0.0.50/24",
		Ports:   []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	backends := s.collectLBBackends(ctx, "app", lbSpec)
	got := map[string]string{}
	for _, b := range backends {
		got[b.Name] = b.IP
	}
	if len(got) != 2 || got["api-1"] != "10.0.0.10" || got["web"] != "10.0.0.20" {
		t.Fatalf("rendered mixed backends = %+v, want api-1 + web", got)
	}
}

// containerBackendIP prefers the recorded static label, then falls back to a
// local lxc-info lookup for a container on this host (DHCP NICs); a remote
// container with no recorded IP is left unresolved.
func TestContainerBackendIP_StaticThenLocalFallback(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{ipByName: map[string]string{"local-ct": "10.0.0.30"}})

	// Static label wins, no runtime call needed (even on a remote host).
	if ip := s.containerBackendIP(ctx, corrosion.ContainerRecord{
		Name: "web", HostName: "other-host", Labels: map[string]string{corrosion.LabelIP: "10.0.0.20"},
	}); ip != "10.0.0.20" {
		t.Errorf("static label IP = %q, want 10.0.0.20", ip)
	}

	// No label, but container is local → lxc-info fallback resolves it.
	if ip := s.containerBackendIP(ctx, corrosion.ContainerRecord{
		Name: "local-ct", HostName: "test-host",
	}); ip != "10.0.0.30" {
		t.Errorf("local fallback IP = %q, want 10.0.0.30", ip)
	}

	// No label and remote → unresolved (cross-host DHCP discovery is a follow-up).
	if ip := s.containerBackendIP(ctx, corrosion.ContainerRecord{
		Name: "remote-ct", HostName: "other-host",
	}); ip != "" {
		t.Errorf("remote no-label IP = %q, want empty", ip)
	}
}
