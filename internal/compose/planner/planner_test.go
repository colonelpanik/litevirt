package planner

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

func makeHost(name string, cpu, memMiB int) corrosion.HostRecord {
	return corrosion.HostRecord{
		Name:     name,
		State:    "active",
		CPUTotal: cpu,
		MemTotal: memMiB,
	}
}

func makeState(hosts []corrosion.HostRecord, vms []corrosion.VMRecord, nets []corrosion.NetworkRecord) *ClusterState {
	return &ClusterState{
		Hosts:      hosts,
		VMs:        vms,
		Networks:   nets,
		Devices:    map[string][]corrosion.PCIDeviceRecord{},
		ImageHosts: map[string][]string{},
	}
}

func makeFile(name string, vms map[string]compose.VMDef) *compose.File {
	return &compose.File{
		Name: name,
		VMs:  vms,
	}
}

func intPtr(n int) *int { return &n }

// ── Resolve integration tests ────────────────────────────────────────────────

func TestResolve_CreateAllNewVMs(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512},
		"db":  {Image: "ubuntu", CPU: 2, Memory: 1024},
	})
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil, nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	creates := 0
	for _, vm := range plan.VMs {
		if vm.Kind == OpCreate {
			creates++
		}
	}
	if creates != 2 {
		t.Errorf("expected 2 creates, got %d", creates)
	}
}

func TestResolve_NoChanges(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512},
	})
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		[]corrosion.VMRecord{{
			Name:      "web",
			StackName: "mystack",
			HostName:  "h1",
			Spec:      `{"image":"ubuntu"}`,
			State:     "running",
			CPUActual: 1,
			MemActual: 512,
		}},
		nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, vm := range plan.VMs {
		if vm.Kind == OpCreate || vm.Kind == OpDelete {
			t.Errorf("unexpected op %s for %s", vm.Kind, vm.VMName)
		}
	}
}

func TestResolve_DeleteRemovedVM(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512},
	})
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		[]corrosion.VMRecord{
			{Name: "web", StackName: "mystack", HostName: "h1", Spec: `{"image":"ubuntu"}`, State: "running", CPUActual: 1, MemActual: 512},
			{Name: "old-vm", StackName: "mystack", HostName: "h1", Spec: `{}`, State: "running", CPUActual: 1, MemActual: 256},
		},
		nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	foundDelete := false
	for _, vm := range plan.VMs {
		if vm.Kind == OpDelete && vm.VMName == "old-vm" {
			foundDelete = true
		}
	}
	if !foundDelete {
		t.Error("expected OpDelete for old-vm")
	}
}

func TestResolve_Replicas(t *testing.T) {
	replicas := 3
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512, Replicas: &replicas},
	})
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 32, 65536)},
		nil, nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	creates := 0
	for _, vm := range plan.VMs {
		if vm.Kind == OpCreate {
			creates++
		}
	}
	if creates != 3 {
		t.Errorf("expected 3 creates for replicas=3, got %d", creates)
	}
}

func TestResolve_NetworkCreate(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512, Network: []compose.NetworkAttachment{{Name: "mynet"}}},
	})
	f.Networks = map[string]compose.NetworkDef{
		"mynet": {Type: "bridge"},
	}
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil, nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	foundCreate := false
	for _, na := range plan.Networks {
		if na.Kind == OpCreate {
			foundCreate = true
		}
	}
	if !foundCreate {
		t.Error("expected network create action")
	}
}

func TestResolve_NetworkNoChange(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512},
	})
	f.Networks = map[string]compose.NetworkDef{
		"mynet": {Type: "bridge"},
	}
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil,
		[]corrosion.NetworkRecord{{Name: "mystack_mynet", StackName: "mystack", Type: "bridge"}},
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, na := range plan.Networks {
		if na.Name == "mystack_mynet" && na.Kind != OpNoChange {
			t.Errorf("expected no-change for existing network, got %s", na.Kind)
		}
	}
}

func TestResolve_NetworkDelete(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512},
	})
	// No networks in compose — but one exists in state.
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil,
		[]corrosion.NetworkRecord{{Name: "mystack_oldnet", StackName: "mystack", Type: "bridge"}},
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	foundDelete := false
	for _, na := range plan.Networks {
		if na.Kind == OpDelete && na.Name == "mystack_oldnet" {
			foundDelete = true
		}
	}
	if !foundDelete {
		t.Error("expected delete for mystack-oldnet")
	}
}

func TestResolve_ExternalNetwork(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512},
	})
	f.Networks = map[string]compose.NetworkDef{
		"ext": {Type: "bridge", External: true},
	}
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil, nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, na := range plan.Networks {
		if na.Name == "ext" {
			if na.Kind != OpNoChange {
				t.Errorf("external network should be no-change, got %s", na.Kind)
			}
			return
		}
	}
	t.Error("expected external network in plan")
}

func TestResolve_VXLANNetworkTargets(t *testing.T) {
	replicas := 2
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512, Replicas: &replicas, Network: []compose.NetworkAttachment{{Name: "vx"}}},
	})
	f.Networks = map[string]compose.NetworkDef{
		"vx": {Type: "vxlan", Subnet: "10.100.0.0/24"},
	}
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768), makeHost("h2", 16, 32768)},
		nil, nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, na := range plan.Networks {
		if na.Type == "vxlan" {
			if len(na.VTEPHosts) == 0 {
				t.Error("expected VTEPHosts to be populated for vxlan network")
			}
			if na.DHCPGateway == "" {
				t.Error("expected DHCPGateway to be set for vxlan with subnet")
			}
			return
		}
	}
	t.Error("expected vxlan network in plan")
}

func TestResolve_ImagePullWarning(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512},
	})
	// No images cached on any host.
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil, nil,
	)
	state.ImageHosts = map[string][]string{} // empty

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	foundPullWarning := false
	for _, w := range plan.Warnings {
		if containsSubstr(w, "will be pulled") {
			foundPullWarning = true
		}
	}
	if !foundPullWarning {
		t.Errorf("expected image pull warning, got warnings: %v", plan.Warnings)
	}
}

func TestResolve_DependencyOrdering(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512, DependsOn: compose.DependsOn{"db": {Condition: "vm_started"}}},
		"db":  {Image: "ubuntu", CPU: 1, Memory: 512},
	})
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil, nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// db should appear before web in the plan.
	dbIdx, webIdx := -1, -1
	for i, vm := range plan.VMs {
		if vm.VMName == "db" {
			dbIdx = i
		}
		if vm.VMName == "web" {
			webIdx = i
		}
	}
	if dbIdx < 0 || webIdx < 0 {
		t.Fatal("expected both db and web in plan")
	}
	if dbIdx >= webIdx {
		t.Errorf("db (idx=%d) should come before web (idx=%d) in dependency order", dbIdx, webIdx)
	}
}

func TestResolve_DNS_StaticIP(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512, Network: []compose.NetworkAttachment{{Name: "br0", IP: "10.0.0.5"}}},
	})
	f.DNS = &compose.DNSDef{Domain: "example.com"}
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil, nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(plan.DNS) == 0 {
		t.Fatal("expected DNS actions")
	}
	for _, dns := range plan.DNS {
		if dns.VMName == "web" {
			if dns.IP != "10.0.0.5" {
				t.Errorf("DNS IP = %q, want 10.0.0.5", dns.IP)
			}
			if dns.Deferred {
				t.Error("DNS should not be deferred with static IP")
			}
			return
		}
	}
	t.Error("expected DNS action for web")
}

func TestResolve_DNS_Deferred(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 1, Memory: 512},
	})
	f.DNS = &compose.DNSDef{Domain: "example.com"}
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil, nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(plan.DNS) == 0 {
		t.Fatal("expected DNS actions")
	}
	for _, dns := range plan.DNS {
		if dns.VMName == "web" {
			if !dns.Deferred {
				t.Error("DNS should be deferred without static IP")
			}
			return
		}
	}
	t.Error("expected DNS action for web")
}

func TestResolve_LBCreation(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {
			Image: "ubuntu", CPU: 1, Memory: 512,
			LoadBalancer: &compose.LBDef{
				Enabled:   true,
				VIP:       "10.0.0.100",
				Algorithm: "roundrobin",
				Ports:     []compose.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
			},
		},
	})
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil, nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(plan.LBs) == 0 {
		t.Fatal("expected LB actions")
	}
	lb := plan.LBs[0]
	if lb.Kind != OpCreate {
		t.Errorf("LB kind = %s, want create", lb.Kind)
	}
	if lb.VIP != "10.0.0.100" {
		t.Errorf("LB VIP = %q, want 10.0.0.100", lb.VIP)
	}
	if len(lb.BackendVMs) != 1 || lb.BackendVMs[0] != "web" {
		t.Errorf("LB backends = %v, want [web]", lb.BackendVMs)
	}
}

func TestResolve_WarningLocalDiskRestartAny(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"db": {
			Image: "ubuntu", CPU: 1, Memory: 512,
			Disks: map[string]compose.DiskDef{"data": {Size: "10G"}},
			Migrate: &compose.MigrateDef{OnHostFailure: "restart-any"},
		},
	})
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		nil, nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	foundWarning := false
	for _, w := range plan.Warnings {
		if containsSubstr(w, "local disk") && containsSubstr(w, "restart-any") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("expected local disk + restart-any warning, got: %v", plan.Warnings)
	}
}

// ── Pure helper function tests ───────────────────────────────────────────────

func TestVmBaseName(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"web-1", "web"},
		{"web-10", "web"},
		{"web", "web"},
		{"my-vm-3", "my-vm"},
		{"web-abc", "web-abc"},
	}
	for _, tt := range tests {
		got := vmBaseName(tt.input)
		if got != tt.want {
			t.Errorf("vmBaseName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSpecField(t *testing.T) {
	tests := []struct {
		spec, field, want string
	}{
		{`{"image":"ubuntu","cpu":2}`, "image", "ubuntu"},
		{`{"image":"ubuntu","cpu":2}`, "missing", ""},
		{`{}`, "image", ""},
		{`{"cloud_init_hash":"abc123"}`, "cloud_init_hash", "abc123"},
	}
	for _, tt := range tests {
		got := specField(tt.spec, tt.field)
		if got != tt.want {
			t.Errorf("specField(%q, %q) = %q, want %q", tt.spec, tt.field, got, tt.want)
		}
	}
}

func TestExpandAntiAffinity(t *testing.T) {
	composeInstances := map[string][]string{
		"web": {"web-1", "web-2", "web-3"},
		"db":  {"db"},
	}

	// Expanding a compose key gives all instances.
	got := expandAntiAffinity([]string{"web"}, "web-1", composeInstances)
	if len(got) != 2 { // web-2, web-3 (self excluded)
		t.Errorf("expected 2 expanded, got %d: %v", len(got), got)
	}

	// Self is always excluded.
	for _, name := range got {
		if name == "web-1" {
			t.Error("self (web-1) should be excluded from anti-affinity")
		}
	}

	// Literal names kept as-is.
	got = expandAntiAffinity([]string{"external-vm"}, "web-1", composeInstances)
	if len(got) != 1 || got[0] != "external-vm" {
		t.Errorf("expected [external-vm], got %v", got)
	}

	// Empty input.
	got = expandAntiAffinity(nil, "web-1", composeInstances)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestHighestWaitCondition(t *testing.T) {
	ops := []compose.Op{
		{Kind: "create", VMName: "web-1", DependsOn: compose.DependsOn{"db": {Condition: "vm_started"}}},
		{Kind: "create", VMName: "web-2", DependsOn: compose.DependsOn{"db": {Condition: "vm_healthy"}}},
	}

	got := highestWaitCondition("db", ops)
	if got != "vm_healthy" {
		t.Errorf("highestWaitCondition = %q, want vm_healthy", got)
	}

	// No dependencies.
	got = highestWaitCondition("unknown", ops)
	if got != "" {
		t.Errorf("expected empty for no deps, got %q", got)
	}
}

func TestHostHasImage(t *testing.T) {
	imageHosts := map[string][]string{
		"ubuntu": {"h1", "h2"},
	}
	if !hostHasImage(imageHosts, "ubuntu", "h1") {
		t.Error("expected h1 to have ubuntu")
	}
	if hostHasImage(imageHosts, "ubuntu", "h3") {
		t.Error("h3 should not have ubuntu")
	}
	if hostHasImage(imageHosts, "missing", "h1") {
		t.Error("h1 should not have missing image")
	}
}

func TestBuildComposeInstanceMap(t *testing.T) {
	replicas := 3
	f := &compose.File{VMs: map[string]compose.VMDef{
		"web": {Replicas: &replicas},
		"db":  {},
	}}
	m := buildComposeInstanceMap(f)
	if len(m["web"]) != 3 {
		t.Errorf("expected 3 web instances, got %d", len(m["web"]))
	}
	if len(m["db"]) != 1 || m["db"][0] != "db" {
		t.Errorf("expected db instances [db], got %v", m["db"])
	}
}

func TestSortedKeys(t *testing.T) {
	m := map[string]bool{"c": true, "a": true, "b": true}
	got := sortedKeys(m)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("sortedKeys = %v, want [a b c]", got)
	}
}

// ── Test utility ─────────────────────────────────────────────────────────────

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestResolve_UpdatePinsToCurrentHost: a VM UPDATE stays on its current host even
// when another host has far more free capacity — re-running placement must not move it.
func TestResolve_UpdatePinsToCurrentHost(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 2, Memory: 1024}, // cpu 1->2 vs current → OpUpdate
	})
	state := makeState(
		// h2 is far roomier; naive placement would pick it.
		[]corrosion.HostRecord{makeHost("h1", 8, 8192), makeHost("h2", 128, 262144)},
		[]corrosion.VMRecord{{
			Name: "web", StackName: "mystack", HostName: "h1",
			Spec: `{"image":"ubuntu","cpu":1}`, State: "running", CPUActual: 1, MemActual: 1024,
		}},
		nil,
	)

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	found := false
	for _, vm := range plan.VMs {
		if vm.VMName == "web" && vm.Kind == OpUpdate {
			found = true
			if vm.TargetHost != "h1" {
				t.Errorf("update moved the VM: TargetHost=%q, want h1 (its current host)", vm.TargetHost)
			}
		}
	}
	if !found {
		t.Fatal("expected an OpUpdate for web")
	}
}
