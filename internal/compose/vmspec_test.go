package compose

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func mustBuildVMSpec(t *testing.T, instanceName, baseName string, vm *VMDef, f *File) *pb.VMSpec {
	t.Helper()
	spec, err := BuildVMSpec(instanceName, baseName, vm, f)
	if err != nil {
		t.Fatalf("BuildVMSpec(%q): %v", instanceName, err)
	}
	return spec
}

func boolPtr(b bool) *bool { return &b }

func baseFile(name string, networks map[string]NetworkDef) *File {
	f := &File{Name: name, Networks: networks, VMs: map[string]VMDef{}}
	if f.Networks == nil {
		f.Networks = map[string]NetworkDef{}
	}
	return f
}

func TestBuildVMSpec_Basic(t *testing.T) {
	f := baseFile("mystack", nil)
	vm := &VMDef{
		Image:  "ubuntu-24.04",
		CPU:    2,
		Memory: 1024,
	}

	spec := mustBuildVMSpec(t,"web", "web", vm, f)

	if spec.Name != "web" {
		t.Errorf("Name = %q, want %q", spec.Name, "web")
	}
	if spec.StackName != "mystack" {
		t.Errorf("StackName = %q, want %q", spec.StackName, "mystack")
	}
	if spec.Image != "ubuntu-24.04" {
		t.Errorf("Image = %q, want %q", spec.Image, "ubuntu-24.04")
	}
	if spec.Cpu != 2 {
		t.Errorf("Cpu = %d, want 2", spec.Cpu)
	}
	if spec.MemoryMib != 1024 {
		t.Errorf("MemoryMib = %d, want 1024", spec.MemoryMib)
	}
	if spec.Boot != "disk" {
		t.Errorf("Boot = %q, want %q", spec.Boot, "disk")
	}
	if !spec.GuestAgent {
		t.Error("GuestAgent should default to true for non-ISO")
	}
}

func TestBuildVMSpec_WithDisks(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Disks: map[string]DiskDef{
			"root": {Size: "20G", Bus: "virtio", Cache: "writeback"},
			"data": {Size: "100G", Storage: "nfs-pool"},
		},
	}

	spec := mustBuildVMSpec(t,"db", "db", vm, f)

	if len(spec.Disks) != 2 {
		t.Fatalf("expected 2 disks, got %d", len(spec.Disks))
	}

	disksByName := map[string]bool{}
	for _, d := range spec.Disks {
		disksByName[d.Name] = true
		switch d.Name {
		case "root":
			if d.Size != "20G" {
				t.Errorf("root disk size = %q", d.Size)
			}
			if d.Bus != "virtio" {
				t.Errorf("root disk bus = %q", d.Bus)
			}
			if d.Cache != "writeback" {
				t.Errorf("root disk cache = %q", d.Cache)
			}
		case "data":
			if d.Size != "100G" {
				t.Errorf("data disk size = %q", d.Size)
			}
			if d.Storage != "nfs-pool" {
				t.Errorf("data disk storage = %q", d.Storage)
			}
		}
	}
	if !disksByName["root"] || !disksByName["data"] {
		t.Errorf("missing disk(s): %v", disksByName)
	}
}

func TestBuildVMSpec_WithNetwork(t *testing.T) {
	f := baseFile("stack", map[string]NetworkDef{
		"mgmt": {Interface: "br-mgmt", VLAN: 100},
		"data": {Interface: ""},
	})
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Network: []NetworkAttachment{
			{Name: "mgmt", Model: "virtio", IP: "10.0.1.5", Gateway: "10.0.1.1", MAC: "52:54:00:00:00:01"},
			{Name: "data", Model: "e1000", Trunk: []int{200, 201}},
		},
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if len(spec.Network) != 2 {
		t.Fatalf("expected 2 network attachments, got %d", len(spec.Network))
	}

	// First network: mgmt with interface override and VLAN auto-trunk
	// Network names are scoped by stack: "stack_mgmt"
	n0 := spec.Network[0]
	if n0.Name != "stack_mgmt" {
		t.Errorf("net[0] Name = %q, want stack_mgmt", n0.Name)
	}
	if n0.Model != "virtio" {
		t.Errorf("net[0] Model = %q", n0.Model)
	}
	if n0.Ip != "10.0.1.5" {
		t.Errorf("net[0] IP = %q", n0.Ip)
	}
	if n0.Gateway != "10.0.1.1" {
		t.Errorf("net[0] Gateway = %q", n0.Gateway)
	}
	if n0.Mac != "52:54:00:00:00:01" {
		t.Errorf("net[0] MAC = %q", n0.Mac)
	}
	// VLAN 100 should be auto-added as trunk since no explicit trunk
	if len(n0.Trunk) != 1 || n0.Trunk[0] != 100 {
		t.Errorf("net[0] Trunk = %v, want [100]", n0.Trunk)
	}

	// Second network: data with explicit trunk, scoped as stack_data
	n1 := spec.Network[1]
	if n1.Name != "stack_data" {
		t.Errorf("net[1] Name = %q, want stack_data", n1.Name)
	}
	if len(n1.Trunk) != 2 || n1.Trunk[0] != 200 || n1.Trunk[1] != 201 {
		t.Errorf("net[1] Trunk = %v, want [200 201]", n1.Trunk)
	}
}

func TestBuildVMSpec_WithCloudInit(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		CloudInit: &CloudInitDef{
			UserData:      "#cloud-config\npackages: [htop]",
			NetworkConfig: "version: 2\nethernets: {}",
		},
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.CloudInit == nil {
		t.Fatal("CloudInit should not be nil")
	}
	if spec.CloudInit.Userdata != "#cloud-config\npackages: [htop]" {
		t.Errorf("Userdata = %q", spec.CloudInit.Userdata)
	}
	if spec.CloudInit.Networkconfig != "version: 2\nethernets: {}" {
		t.Errorf("Networkconfig = %q", spec.CloudInit.Networkconfig)
	}
}

func TestBuildVMSpec_WithPlacement(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Placement: &PlacementDef{
			Host:         "node-1",
			AntiAffinity: []string{"db"},
			Affinity:     []string{"cache"},
			Require:      map[string]string{"zone": "us-east"},
			Prefer:       map[string]string{"rack": "r1"},
			Spread:       true,
		},
	}

	spec := mustBuildVMSpec(t,"web", "web", vm, f)

	if spec.Placement == nil {
		t.Fatal("Placement should not be nil")
	}
	p := spec.Placement
	if p.Host != "node-1" {
		t.Errorf("Host = %q", p.Host)
	}
	if len(p.AntiAffinity) != 1 || p.AntiAffinity[0] != "db" {
		t.Errorf("AntiAffinity = %v", p.AntiAffinity)
	}
	if len(p.Affinity) != 1 || p.Affinity[0] != "cache" {
		t.Errorf("Affinity = %v", p.Affinity)
	}
	if p.Require["zone"] != "us-east" {
		t.Errorf("Require = %v", p.Require)
	}
	if p.Prefer["rack"] != "r1" {
		t.Errorf("Prefer = %v", p.Prefer)
	}
	if !p.Spread {
		t.Error("Spread should be true")
	}
}

func TestBuildVMSpec_WithLoadBalancer(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		LoadBalancer: &LBDef{
			Enabled:   true,
			VIP:       "10.0.100.100",
			Algorithm: "leastconn",
			Sticky:    true,
			Hosts:     []string{"node-1", "node-2"},
			Ports: []LBPort{
				{Listen: 80, Target: 8080, Protocol: "http", RedirectHTTPS: true},
				{Listen: 443, Target: 8080, Protocol: "tcp"},
			},
		},
	}

	spec := mustBuildVMSpec(t,"app", "app", vm, f)

	if spec.Loadbalancer == nil {
		t.Fatal("Loadbalancer should not be nil")
	}
	lb := spec.Loadbalancer
	if !lb.Enabled {
		t.Error("LB should be enabled")
	}
	if lb.Vip != "10.0.100.100" {
		t.Errorf("VIP = %q", lb.Vip)
	}
	if lb.Algorithm != "leastconn" {
		t.Errorf("Algorithm = %q", lb.Algorithm)
	}
	if !lb.StickySessions {
		t.Error("StickySessions should be true")
	}
	if len(lb.Hosts) != 2 {
		t.Errorf("Hosts = %v", lb.Hosts)
	}
	if len(lb.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(lb.Ports))
	}
	if lb.Ports[0].Listen != 80 || lb.Ports[0].Target != 8080 || lb.Ports[0].Protocol != "http" || !lb.Ports[0].RedirectHttps {
		t.Errorf("port[0] = %+v", lb.Ports[0])
	}
	if lb.Ports[1].Listen != 443 || lb.Ports[1].Target != 8080 {
		t.Errorf("port[1] = %+v", lb.Ports[1])
	}
}

func TestBuildVMSpec_WithLoadBalancer_Disabled(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		LoadBalancer: &LBDef{
			Enabled: false,
			VIP:     "10.0.100.100",
		},
	}

	spec := mustBuildVMSpec(t,"app", "app", vm, f)

	if spec.Loadbalancer != nil {
		t.Error("Loadbalancer should be nil when disabled")
	}
}

func TestBuildVMSpec_WithHealthCheck(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		HealthCheck: &HealthCheckDef{
			Type:     "http",
			Target:   "http://localhost:8080/health",
			Interval: "10s",
			Timeout:  "5s",
			Retries:  3,
			Action:   "restart",
		},
	}

	spec := mustBuildVMSpec(t,"app", "app", vm, f)

	if spec.Healthcheck == nil {
		t.Fatal("Healthcheck should not be nil")
	}
	hc := spec.Healthcheck
	if hc.Type != "http" {
		t.Errorf("Type = %q", hc.Type)
	}
	if hc.Target != "http://localhost:8080/health" {
		t.Errorf("Target = %q", hc.Target)
	}
	if hc.Interval != "10s" {
		t.Errorf("Interval = %q", hc.Interval)
	}
	if hc.Timeout != "5s" {
		t.Errorf("Timeout = %q", hc.Timeout)
	}
	if hc.Retries != 3 {
		t.Errorf("Retries = %d", hc.Retries)
	}
	if hc.Action != "restart" {
		t.Errorf("Action = %q", hc.Action)
	}
}

func TestBuildVMSpec_WithHooks(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Hooks: &HooksDef{
			PreStart:    "/opt/hooks/pre-start.sh",
			PostStart:   "/opt/hooks/post-start.sh",
			PreStop:     "/opt/hooks/pre-stop.sh",
			PostStop:    "/opt/hooks/post-stop.sh",
			PreMigrate:  "/opt/hooks/pre-migrate.sh",
			PostMigrate: "/opt/hooks/post-migrate.sh",
		},
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.Hooks == nil {
		t.Fatal("Hooks should not be nil")
	}
	h := spec.Hooks
	if h.PreStart != "/opt/hooks/pre-start.sh" {
		t.Errorf("PreStart = %q", h.PreStart)
	}
	if h.PostStart != "/opt/hooks/post-start.sh" {
		t.Errorf("PostStart = %q", h.PostStart)
	}
	if h.PreStop != "/opt/hooks/pre-stop.sh" {
		t.Errorf("PreStop = %q", h.PreStop)
	}
	if h.PostStop != "/opt/hooks/post-stop.sh" {
		t.Errorf("PostStop = %q", h.PostStop)
	}
	if h.PreMigrate != "/opt/hooks/pre-migrate.sh" {
		t.Errorf("PreMigrate = %q", h.PreMigrate)
	}
	if h.PostMigrate != "/opt/hooks/post-migrate.sh" {
		t.Errorf("PostMigrate = %q", h.PostMigrate)
	}
}

func TestBuildVMSpec_WithResources(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    4,
		Memory: 8192,
		Resources: &ResourcesDef{
			HugePages:    true,
			CPUPinning:   []int{0, 1, 2, 3},
			NUMATopology: "strict",
			IOThreads:    2,
		},
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.Resources == nil {
		t.Fatal("Resources should not be nil")
	}
	r := spec.Resources
	if !r.Hugepages {
		t.Error("Hugepages should be true")
	}
	if len(r.CpuPinning) != 4 {
		t.Fatalf("CpuPinning len = %d, want 4", len(r.CpuPinning))
	}
	for i, want := range []int32{0, 1, 2, 3} {
		if r.CpuPinning[i] != want {
			t.Errorf("CpuPinning[%d] = %d, want %d", i, r.CpuPinning[i], want)
		}
	}
	if r.NumaTopology != "strict" {
		t.Errorf("NumaTopology = %q", r.NumaTopology)
	}
	if r.IoThreads != 2 {
		t.Errorf("IoThreads = %d", r.IoThreads)
	}
}

func TestBuildVMSpec_WithDevices(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    4,
		Memory: 8192,
		Devices: []DeviceDef{
			{Type: "gpu", Vendor: "10de", Model: "A100", Count: 2, Address: "0000:41:00.0"},
			{Type: "network", SRIOV: true, Parent: "enp3s0f0"},
			{Type: "nvme"}, // count defaults to 1
		},
	}

	spec := mustBuildVMSpec(t,"gpu-vm", "gpu-vm", vm, f)

	if len(spec.Devices) != 3 {
		t.Fatalf("expected 3 devices, got %d", len(spec.Devices))
	}

	d0 := spec.Devices[0]
	if d0.Type != "gpu" || d0.Vendor != "10de" || d0.Model != "A100" || d0.Count != 2 || d0.Address != "0000:41:00.0" {
		t.Errorf("device[0] = %+v", d0)
	}

	d1 := spec.Devices[1]
	if d1.Type != "network" || !d1.Sriov || d1.Parent != "enp3s0f0" {
		t.Errorf("device[1] = %+v", d1)
	}

	d2 := spec.Devices[2]
	if d2.Type != "nvme" || d2.Count != 1 {
		t.Errorf("device[2] = %+v (count should default to 1)", d2)
	}
}

func TestBuildVMSpec_ISO(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		ISO:    "windows-server-2022.iso",
		CPU:    4,
		Memory: 4096,
	}

	spec := mustBuildVMSpec(t,"win", "win", vm, f)

	if spec.Image != "windows-server-2022.iso" {
		t.Errorf("Image = %q, want ISO path", spec.Image)
	}
	if spec.Boot != "cdrom" {
		t.Errorf("Boot = %q, want cdrom", spec.Boot)
	}
	if spec.GuestAgent {
		t.Error("GuestAgent should default to false for ISO installs")
	}
}

func TestBuildVMSpec_NilOptionalFields(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 256,
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.CloudInit != nil {
		t.Error("CloudInit should be nil")
	}
	if spec.Placement != nil {
		t.Error("Placement should be nil")
	}
	if spec.Loadbalancer != nil {
		t.Error("Loadbalancer should be nil")
	}
	if spec.Healthcheck != nil {
		t.Error("Healthcheck should be nil")
	}
	if spec.Hooks != nil {
		t.Error("Hooks should be nil")
	}
	if spec.Resources != nil {
		t.Error("Resources should be nil")
	}
	if len(spec.Disks) != 0 {
		t.Errorf("Disks should be empty, got %d", len(spec.Disks))
	}
	if len(spec.Devices) != 0 {
		t.Errorf("Devices should be empty, got %d", len(spec.Devices))
	}
}

func TestBuildVMSpec_Labels(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 256,
		Labels: map[string]string{"env": "prod", "team": "platform"},
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if len(spec.Labels) != 2 {
		t.Fatalf("Labels len = %d", len(spec.Labels))
	}
	if spec.Labels["env"] != "prod" || spec.Labels["team"] != "platform" {
		t.Errorf("Labels = %v", spec.Labels)
	}
}

func TestBuildVMSpec_MachineAndFirmware(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:    "ubuntu",
		CPU:      1,
		Memory:   512,
		Machine:  "q35",
		Firmware: "uefi",
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.Machine != "q35" {
		t.Errorf("Machine = %q", spec.Machine)
	}
	if spec.Firmware != "uefi" {
		t.Errorf("Firmware = %q", spec.Firmware)
	}
}

// --- parseDurationSeconds tests ---

func TestParseDurationSeconds(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"30s", 30},
		{"2m", 120},
		{"1h", 3600},
		{"45", 45},
		{"", 0},
		{"  10s  ", 10}, // whitespace trimmed
		{"0s", 0},
		{"90m", 5400},
	}
	for _, tt := range tests {
		got, err := parseDurationSeconds(tt.input)
		if err != nil {
			t.Errorf("parseDurationSeconds(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseDurationSeconds(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParseDurationSeconds_Invalid(t *testing.T) {
	invalids := []string{"abc", "1.5s", "xm"}
	for _, s := range invalids {
		_, err := parseDurationSeconds(s)
		if err == nil {
			t.Errorf("parseDurationSeconds(%q) should return error", s)
		}
	}
}

// --- BuildVMSpec StopGracePeriod / Restart / Placement.MaxPerNode tests ---

func TestBuildVMSpec_StopGracePeriod(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:           "ubuntu",
		CPU:             1,
		Memory:          512,
		StopGracePeriod: "2m",
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.StopTimeoutSec != 120 {
		t.Errorf("StopTimeoutSec = %d, want 120 (2m)", spec.StopTimeoutSec)
	}
}

func TestBuildVMSpec_StopGracePeriod_Seconds(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:           "ubuntu",
		CPU:             1,
		Memory:          512,
		StopGracePeriod: "30s",
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.StopTimeoutSec != 30 {
		t.Errorf("StopTimeoutSec = %d, want 30", spec.StopTimeoutSec)
	}
}

func TestBuildVMSpec_StopGracePeriod_Empty(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.StopTimeoutSec != 0 {
		t.Errorf("StopTimeoutSec = %d, want 0 (unset)", spec.StopTimeoutSec)
	}
}

func TestBuildVMSpec_Restart(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Restart: &RestartDef{
			Condition:   "on-failure",
			Delay:       "5s",
			MaxAttempts: 3,
			Window:      "1h",
		},
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.Restart == nil {
		t.Fatal("Restart should not be nil")
	}
	r := spec.Restart
	if r.Condition != "on-failure" {
		t.Errorf("Condition = %q, want on-failure", r.Condition)
	}
	if r.Delay != "5s" {
		t.Errorf("Delay = %q, want 5s", r.Delay)
	}
	if r.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", r.MaxAttempts)
	}
	if r.Window != "1h" {
		t.Errorf("Window = %q, want 1h", r.Window)
	}
}

func TestBuildVMSpec_Restart_Nil(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.Restart != nil {
		t.Error("Restart should be nil when not set")
	}
}

func TestBuildVMSpec_Placement_MaxPerNode(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Placement: &PlacementDef{
			MaxPerNode: 2,
		},
	}

	spec := mustBuildVMSpec(t,"web-1", "web", vm, f)

	if spec.Placement == nil {
		t.Fatal("Placement should not be nil")
	}
	if spec.Placement.MaxPerNode != 2 {
		t.Errorf("MaxPerNode = %d, want 2", spec.Placement.MaxPerNode)
	}
}

func TestBuildVMSpec_Placement_MaxPerNode_Zero(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Placement: &PlacementDef{
			Host:       "node-1",
			MaxPerNode: 0, // unlimited
		},
	}

	spec := mustBuildVMSpec(t,"vm1", "vm1", vm, f)

	if spec.Placement == nil {
		t.Fatal("Placement should not be nil")
	}
	if spec.Placement.MaxPerNode != 0 {
		t.Errorf("MaxPerNode = %d, want 0 (unlimited)", spec.Placement.MaxPerNode)
	}
}

// --- FindVMDef tests ---

func TestFindVMDef_ExactMatch(t *testing.T) {
	f := &File{
		VMs: map[string]VMDef{
			"web": {Image: "nginx", CPU: 1, Memory: 256},
			"db":  {Image: "postgres", CPU: 2, Memory: 1024},
		},
	}

	def, baseName := FindVMDef(f, "web")
	if def == nil {
		t.Fatal("expected to find 'web'")
	}
	if baseName != "web" {
		t.Errorf("baseName = %q, want 'web'", baseName)
	}
	if def.Image != "nginx" {
		t.Errorf("Image = %q", def.Image)
	}
}

func TestFindVMDef_ReplicaSuffix(t *testing.T) {
	replicas := 3
	f := &File{
		VMs: map[string]VMDef{
			"worker": {Image: "worker:v1", CPU: 2, Memory: 512, Replicas: &replicas},
		},
	}

	// Replica instances are named "worker-1", "worker-2", "worker-3"
	for _, name := range []string{"worker-1", "worker-2", "worker-3"} {
		def, baseName := FindVMDef(f, name)
		if def == nil {
			t.Errorf("expected to find %q", name)
			continue
		}
		if baseName != "worker" {
			t.Errorf("baseName for %q = %q, want 'worker'", name, baseName)
		}
		if def.Image != "worker:v1" {
			t.Errorf("Image = %q for %q", def.Image, name)
		}
	}
}

func TestFindVMDef_NotFound(t *testing.T) {
	f := &File{
		VMs: map[string]VMDef{
			"web": {Image: "nginx", CPU: 1, Memory: 256},
		},
	}

	def, baseName := FindVMDef(f, "nonexistent")
	if def != nil {
		t.Error("expected nil for non-existent VM")
	}
	if baseName != "" {
		t.Errorf("baseName = %q, want empty", baseName)
	}
}

func TestFindVMDef_SingleReplicaExact(t *testing.T) {
	// Single replica (nil Replicas) should match by exact name, not "name-1"
	f := &File{
		VMs: map[string]VMDef{
			"api": {Image: "api:v1", CPU: 1, Memory: 256},
		},
	}

	def, baseName := FindVMDef(f, "api")
	if def == nil {
		t.Fatal("expected to find 'api'")
	}
	if baseName != "api" {
		t.Errorf("baseName = %q", baseName)
	}

	// "api-1" should NOT match a single-replica VM
	def2, _ := FindVMDef(f, "api-1")
	if def2 != nil {
		t.Error("api-1 should not match single-replica 'api'")
	}
}

func TestBuildVMSpec_MigratePolicy(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Migrate: &MigrateDef{
			Strategy:      "cold",
			MaxDowntime:   "200ms",
			AutoConverge:  true,
			WithStorage:   true,
			OnHostFailure: "restart-same",
			Priority:      5,
			FenceStrategy: "ipmi",
			BandwidthMiB:  100,
			TimeoutSec:    300,
		},
	}

	spec := mustBuildVMSpec(t, "vm1", "vm1", vm, f)

	if spec.Migrate == nil {
		t.Fatal("Migrate should not be nil")
	}
	m := spec.Migrate
	if m.Strategy != pb.MigrateStrategy_MIGRATE_COLD {
		t.Errorf("Strategy = %v, want MIGRATE_COLD", m.Strategy)
	}
	if m.MaxDowntime != "200ms" {
		t.Errorf("MaxDowntime = %q, want %q", m.MaxDowntime, "200ms")
	}
	if !m.AutoConverge {
		t.Errorf("AutoConverge = false, want true")
	}
	if !m.WithStorage {
		t.Errorf("WithStorage = false, want true")
	}
	if m.OnHostFailure != pb.HostFailurePolicy_RESTART_SAME {
		t.Errorf("OnHostFailure = %v, want RESTART_SAME", m.OnHostFailure)
	}
	if m.Priority != 5 {
		t.Errorf("Priority = %d, want 5", m.Priority)
	}
	if m.FenceStrategy != "ipmi" {
		t.Errorf("FenceStrategy = %q, want %q", m.FenceStrategy, "ipmi")
	}
	if m.BandwidthMibSec != 100 {
		t.Errorf("BandwidthMibSec = %d, want 100", m.BandwidthMibSec)
	}
	if m.TimeoutSec != 300 {
		t.Errorf("TimeoutSec = %d, want 300", m.TimeoutSec)
	}
}

func TestBuildVMSpec_MigratePolicy_Live(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Migrate: &MigrateDef{
			Strategy: "",
		},
	}

	spec := mustBuildVMSpec(t, "vm1", "vm1", vm, f)

	if spec.Migrate == nil {
		t.Fatal("Migrate should not be nil")
	}
	if spec.Migrate.Strategy != pb.MigrateStrategy_MIGRATE_LIVE {
		t.Errorf("Strategy = %v, want MIGRATE_LIVE", spec.Migrate.Strategy)
	}
}

func TestBuildVMSpec_MigratePolicy_None(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Migrate: &MigrateDef{
			Strategy:      "none",
			OnHostFailure: "none",
		},
	}

	spec := mustBuildVMSpec(t, "vm1", "vm1", vm, f)

	if spec.Migrate == nil {
		t.Fatal("Migrate should not be nil")
	}
	if spec.Migrate.Strategy != pb.MigrateStrategy_MIGRATE_NONE {
		t.Errorf("Strategy = %v, want MIGRATE_NONE", spec.Migrate.Strategy)
	}
	if spec.Migrate.OnHostFailure != pb.HostFailurePolicy_FAILURE_NONE {
		t.Errorf("OnHostFailure = %v, want FAILURE_NONE", spec.Migrate.OnHostFailure)
	}
}

func TestBuildVMSpec_MigratePolicy_Nil(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
	}

	spec := mustBuildVMSpec(t, "vm1", "vm1", vm, f)

	if spec.Migrate != nil {
		t.Error("Migrate should be nil when not set")
	}
}

func TestBuildVMSpec_UpdatePolicy(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		Update: &UpdateDef{
			Strategy:          "rolling",
			MaxUnavailable:    1,
			MaxSurge:          2,
			Order:             "start-first",
			HealthWait:        "30s",
			RollbackOnFailure: true,
			PauseBetween:      "10s",
		},
	}

	spec := mustBuildVMSpec(t, "vm1", "vm1", vm, f)

	if spec.Update == nil {
		t.Fatal("Update should not be nil")
	}
	u := spec.Update
	if u.Strategy != "rolling" {
		t.Errorf("Strategy = %q, want %q", u.Strategy, "rolling")
	}
	if u.MaxUnavailable != 1 {
		t.Errorf("MaxUnavailable = %d, want 1", u.MaxUnavailable)
	}
	if u.MaxSurge != 2 {
		t.Errorf("MaxSurge = %d, want 2", u.MaxSurge)
	}
	if u.Order != "start-first" {
		t.Errorf("Order = %q, want %q", u.Order, "start-first")
	}
	if u.HealthWait != "30s" {
		t.Errorf("HealthWait = %q, want %q", u.HealthWait, "30s")
	}
	if !u.RollbackOnFailure {
		t.Errorf("RollbackOnFailure = false, want true")
	}
	if u.PauseBetween != "10s" {
		t.Errorf("PauseBetween = %q, want %q", u.PauseBetween, "10s")
	}
}

func TestBuildVMSpec_UpdatePolicy_Nil(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
	}

	spec := mustBuildVMSpec(t, "vm1", "vm1", vm, f)

	if spec.Update != nil {
		t.Error("Update should be nil when not set")
	}
}

func TestBuildVMSpec_LBWithTLS(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		LoadBalancer: &LBDef{
			Enabled: true,
			VIP:     "10.0.100.100",
			Ports: []LBPort{
				{
					Listen:   443,
					Target:   8080,
					Protocol: "tcp",
					TLS: &LBTLSDef{
						Cert: "/etc/ssl/certs/app.pem",
						Key:  "/etc/ssl/private/app.key",
					},
				},
			},
		},
	}

	spec := mustBuildVMSpec(t, "app", "app", vm, f)

	if spec.Loadbalancer == nil {
		t.Fatal("Loadbalancer should not be nil")
	}
	lb := spec.Loadbalancer
	if len(lb.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(lb.Ports))
	}
	if lb.Ports[0].Tls == nil {
		t.Fatal("Tls should not be nil")
	}
	if lb.Ports[0].Tls.Cert != "/etc/ssl/certs/app.pem" {
		t.Errorf("Tls.Cert = %q, want %q", lb.Ports[0].Tls.Cert, "/etc/ssl/certs/app.pem")
	}
	if lb.Ports[0].Tls.Key != "/etc/ssl/private/app.key" {
		t.Errorf("Tls.Key = %q, want %q", lb.Ports[0].Tls.Key, "/etc/ssl/private/app.key")
	}
}

func TestBuildVMSpec_LBWithHealth(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		LoadBalancer: &LBDef{
			Enabled: true,
			VIP:     "10.0.100.100",
			Health: &LBHealth{
				UseVMHealthcheck: true,
				Type:             "http",
				Path:             "/health",
				IntervalMS:       500,
			},
		},
	}

	spec := mustBuildVMSpec(t, "app", "app", vm, f)

	if spec.Loadbalancer == nil {
		t.Fatal("Loadbalancer should not be nil")
	}
	lb := spec.Loadbalancer
	if lb.Health == nil {
		t.Fatal("Health should not be nil")
	}
	if !lb.Health.UseVmHealthcheck {
		t.Errorf("UseVmHealthcheck = false, want true")
	}
	if lb.Health.Type != "http" {
		t.Errorf("Type = %q, want %q", lb.Health.Type, "http")
	}
	if lb.Health.Path != "/health" {
		t.Errorf("Path = %q, want %q", lb.Health.Path, "/health")
	}
	if lb.Health.Interval != "500ms" {
		t.Errorf("Interval = %q, want %q", lb.Health.Interval, "500ms")
	}
}

func TestBuildVMSpec_LBWithSNAT(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		LoadBalancer: &LBDef{
			Enabled: true,
			VIP:     "10.0.100.100",
			SNAT:    true,
		},
	}

	spec := mustBuildVMSpec(t, "app", "app", vm, f)

	if spec.Loadbalancer == nil {
		t.Fatal("Loadbalancer should not be nil")
	}
	if !spec.Loadbalancer.Snat {
		t.Errorf("Snat = false, want true")
	}
}

func TestBuildVMSpec_LBWithoutSNAT(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 512,
		LoadBalancer: &LBDef{
			Enabled: true,
			VIP:     "10.0.100.100",
			SNAT:    false,
		},
	}

	spec := mustBuildVMSpec(t, "app", "app", vm, f)

	if spec.Loadbalancer == nil {
		t.Fatal("Loadbalancer should not be nil")
	}
	if spec.Loadbalancer.Snat {
		t.Errorf("Snat = true, want false")
	}
}

func TestBuildVMSpec_NilOptionalFields_Extended(t *testing.T) {
	f := baseFile("stack", nil)
	vm := &VMDef{
		Image:  "ubuntu",
		CPU:    1,
		Memory: 256,
	}

	spec := mustBuildVMSpec(t, "vm1", "vm1", vm, f)

	if spec.Migrate != nil {
		t.Error("Migrate should be nil when not set")
	}
	if spec.Update != nil {
		t.Error("Update should be nil when not set")
	}
}

func TestBuildVMSpec_DiskOrdering_RootFirst(t *testing.T) {
	f := baseFile("ceph", nil)
	vm := &VMDef{
		Image:  "ubuntu-24.04",
		CPU:    4,
		Memory: 8192,
		Disks: map[string]DiskDef{
			"osd1": {Size: "250G"},
			"root": {Size: "50G"},
			"osd0": {Size: "250G"},
			"data": {Size: "100G"},
		},
	}

	// Run multiple times to catch non-determinism from map iteration.
	for i := 0; i < 50; i++ {
		spec := mustBuildVMSpec(t, "ceph-0", "ceph", vm, f)
		if len(spec.Disks) != 4 {
			t.Fatalf("iteration %d: expected 4 disks, got %d", i, len(spec.Disks))
		}
		want := []string{"root", "data", "osd0", "osd1"}
		for j, d := range spec.Disks {
			if d.Name != want[j] {
				t.Fatalf("iteration %d: disk[%d] = %q, want %q (full order: %v)",
					i, j, d.Name, want[j], diskNames(spec))
			}
		}
	}
}

func TestBuildVMSpec_DiskOrdering_NoRoot(t *testing.T) {
	f := baseFile("test", nil)
	vm := &VMDef{
		Image:  "ubuntu-24.04",
		CPU:    2,
		Memory: 4096,
		Disks: map[string]DiskDef{
			"data":  {Size: "100G"},
			"cache": {Size: "50G"},
		},
	}

	for i := 0; i < 50; i++ {
		spec := mustBuildVMSpec(t, "vm-0", "vm", vm, f)
		want := []string{"cache", "data"}
		for j, d := range spec.Disks {
			if d.Name != want[j] {
				t.Fatalf("iteration %d: disk[%d] = %q, want %q", i, j, d.Name, want[j])
			}
		}
	}
}

func diskNames(spec *pb.VMSpec) []string {
	names := make([]string, len(spec.Disks))
	for i, d := range spec.Disks {
		names[i] = d.Name
	}
	return names
}
