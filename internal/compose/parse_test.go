package compose

import (
	"strings"
	"testing"
)

func TestEffectiveReplicas_Nil(t *testing.T) {
	vm := VMDef{}
	if got := vm.EffectiveReplicas(); got != 1 {
		t.Errorf("nil Replicas: got %d, want 1", got)
	}
}

func TestEffectiveReplicas_Zero(t *testing.T) {
	zero := 0
	vm := VMDef{Replicas: &zero}
	if got := vm.EffectiveReplicas(); got != 0 {
		t.Errorf("explicit 0: got %d, want 0", got)
	}
}

func TestEffectiveReplicas_Positive(t *testing.T) {
	n := 5
	vm := VMDef{Replicas: &n}
	if got := vm.EffectiveReplicas(); got != 5 {
		t.Errorf("explicit 5: got %d, want 5", got)
	}
}

func TestInstanceName_SingleReplica(t *testing.T) {
	vm := VMDef{} // nil Replicas → 1
	if got := vm.InstanceName("web", 0); got != "web" {
		t.Errorf("single replica: got %q, want %q", got, "web")
	}
}

func TestInstanceName_MultiReplica(t *testing.T) {
	n := 3
	vm := VMDef{Replicas: &n}
	tests := []struct {
		idx  int
		want string
	}{
		{0, "web-1"},
		{1, "web-2"},
		{2, "web-3"},
	}
	for _, tt := range tests {
		if got := vm.InstanceName("web", tt.idx); got != tt.want {
			t.Errorf("replica %d: got %q, want %q", tt.idx, got, tt.want)
		}
	}
}

func TestEffectiveGuestAgent_Default(t *testing.T) {
	vm := VMDef{Image: "ubuntu-24"}
	if !vm.EffectiveGuestAgent() {
		t.Error("cloud image should default to guest agent enabled")
	}
}

func TestEffectiveGuestAgent_ISO(t *testing.T) {
	vm := VMDef{ISO: "installer.iso"}
	if vm.EffectiveGuestAgent() {
		t.Error("ISO install should default to guest agent disabled")
	}
}

func TestEffectiveGuestAgent_Explicit(t *testing.T) {
	f := false
	vm := VMDef{Image: "ubuntu-24", GuestAgent: &f}
	if vm.EffectiveGuestAgent() {
		t.Error("explicit false should disable guest agent")
	}
}

func TestParseMemoryString(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"8G", 8192},
		{"512M", 512},
		{"1024", 1024},
		{"2g", 2048},
	}
	for _, tt := range tests {
		got, err := parseMemoryString(tt.input)
		if err != nil {
			t.Errorf("parseMemoryString(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseMemoryString(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParseMemoryString_Invalid(t *testing.T) {
	invalids := []string{"8X", "abc", "", "1.5G"}
	for _, s := range invalids {
		_, err := parseMemoryString(s)
		if err == nil {
			t.Errorf("parseMemoryString(%q) should return error", s)
		}
	}
}

func TestValidateAffinityRules_NoConflict(t *testing.T) {
	f := &File{
		VMs: map[string]VMDef{
			"web":   {Image: "nginx", Placement: &PlacementDef{Affinity: []string{"cache"}}},
			"cache": {Image: "redis"},
			"db":    {Image: "postgres", Placement: &PlacementDef{AntiAffinity: []string{"web"}}},
		},
	}
	if err := validateAffinityRules(f); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateAffinityRules_TransitiveConflict(t *testing.T) {
	// A has affinity with B, B has affinity with C, but C has anti-affinity with A.
	// This is contradictory: A-B-C must be co-located, but C can't be with A.
	f := &File{
		VMs: map[string]VMDef{
			"a": {Image: "img", Placement: &PlacementDef{Affinity: []string{"b"}}},
			"b": {Image: "img", Placement: &PlacementDef{Affinity: []string{"c"}}},
			"c": {Image: "img", Placement: &PlacementDef{AntiAffinity: []string{"a"}}},
		},
	}
	err := validateAffinityRules(f)
	if err == nil {
		t.Fatal("expected contradictory affinity error")
	}
	if !strings.Contains(err.Error(), "contradictory") {
		t.Errorf("error should mention 'contradictory', got: %v", err)
	}
}

func TestValidateAffinityRules_DirectConflict(t *testing.T) {
	// A has both affinity and anti-affinity with B — direct contradiction.
	f := &File{
		VMs: map[string]VMDef{
			"a": {Image: "img", Placement: &PlacementDef{
				Affinity:     []string{"b"},
				AntiAffinity: []string{"b"},
			}},
			"b": {Image: "img"},
		},
	}
	err := validateAffinityRules(f)
	if err == nil {
		t.Fatal("expected contradictory affinity error for direct conflict")
	}
}

func TestValidateAffinityRules_NoPlacement(t *testing.T) {
	f := &File{
		VMs: map[string]VMDef{
			"web": {Image: "nginx"},
			"db":  {Image: "postgres"},
		},
	}
	if err := validateAffinityRules(f); err != nil {
		t.Errorf("no placement should be valid, got: %v", err)
	}
}

func TestValidate_TempNameCollision(t *testing.T) {
	// VM "web-next" collides with the rolling update temp name for "web".
	n := 2
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web":        {Image: "nginx", Replicas: &n},
			"web-1-next": {Image: "nginx"},
		},
	}
	err := validate(f)
	if err == nil {
		t.Fatal("expected validation error for temp name collision")
	}
	if !strings.Contains(err.Error(), "rolling update temporary name") {
		t.Errorf("error should mention rolling update temp name, got: %v", err)
	}
}

func TestValidate_InstanceNameCollision(t *testing.T) {
	// VM "web" with two replicas generates "web-1", colliding with an
	// explicitly named workload. This must fail before deploy planning.
	n := 2
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web":   {Image: "nginx", Replicas: &n},
			"web-1": {Image: "nginx"},
		},
	}
	err := validate(f)
	if err == nil {
		t.Fatal("expected validation error for duplicate instance name")
	}
	if !strings.Contains(err.Error(), "instance name") || !strings.Contains(err.Error(), "web-1") {
		t.Errorf("error should mention duplicate instance name web-1, got: %v", err)
	}
}

func TestValidate_NegativeReplicas(t *testing.T) {
	neg := -1
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web": {Image: "nginx", Replicas: &neg},
		},
	}
	err := validate(f)
	if err == nil {
		t.Fatal("expected validation error for negative replicas")
	}
	if !strings.Contains(err.Error(), "replicas must be >= 0") {
		t.Errorf("error should mention replicas >= 0, got: %v", err)
	}
}

func TestValidate_ZeroReplicas_Valid(t *testing.T) {
	zero := 0
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web": {Image: "nginx", Replicas: &zero},
		},
	}
	if err := validate(f); err != nil {
		t.Errorf("replicas: 0 (scale-to-zero) should be valid, got: %v", err)
	}
}

func TestValidate_MissingImage(t *testing.T) {
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web": {CPU: 2, Memory: 512},
		},
	}
	err := validate(f)
	if err == nil {
		t.Fatal("expected error for missing image")
	}
	if !strings.Contains(err.Error(), "image or iso required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_LB_MissingVIP(t *testing.T) {
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web": {
				Image: "nginx",
				LoadBalancer: &LBDef{
					Enabled: true,
					Ports:   []LBPort{{Listen: 80, Target: 80}},
				},
			},
		},
	}
	err := validate(f)
	if err == nil {
		t.Fatal("expected error for LB missing VIP")
	}
	if !strings.Contains(err.Error(), "vip required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_LB_InvalidVIPCIDR(t *testing.T) {
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web": {
				Image: "nginx",
				LoadBalancer: &LBDef{
					Enabled: true,
					VIP:     "10.0.0.50", // missing CIDR
					Ports:   []LBPort{{Listen: 80, Target: 80}},
				},
			},
		},
	}
	err := validate(f)
	if err == nil {
		t.Fatal("expected error for LB with invalid CIDR VIP")
	}
	if !strings.Contains(err.Error(), "valid CIDR") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_LB_InvalidPort(t *testing.T) {
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web": {
				Image: "nginx",
				LoadBalancer: &LBDef{
					Enabled: true,
					VIP:     "10.0.0.50/24",
					Ports:   []LBPort{{Listen: 0, Target: 80}},
				},
			},
		},
	}
	err := validate(f)
	if err == nil {
		t.Fatal("expected error for LB port listen=0")
	}
	if !strings.Contains(err.Error(), "listen must be > 0") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_LB_MissingPorts(t *testing.T) {
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web": {
				Image: "nginx",
				LoadBalancer: &LBDef{
					Enabled: true,
					VIP:     "10.0.0.50/24",
					Ports:   []LBPort{},
				},
			},
		},
	}
	err := validate(f)
	if err == nil {
		t.Fatal("expected error for LB with no ports")
	}
	if !strings.Contains(err.Error(), "at least one port required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_LB_ImplicitEnable(t *testing.T) {
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web": {
				Image: "nginx",
				LoadBalancer: &LBDef{
					VIP:   "10.0.0.50/24",
					Ports: []LBPort{{Listen: 80, Target: 8080}},
				},
			},
		},
	}
	err := validate(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.VMs["web"].LoadBalancer.Enabled {
		t.Error("LB should be implicitly enabled when VIP is set")
	}
}

func TestValidate_LB_Valid(t *testing.T) {
	f := &File{
		Name: "test",
		VMs: map[string]VMDef{
			"web": {
				Image: "nginx",
				LoadBalancer: &LBDef{
					Enabled:   true,
					VIP:       "10.0.100.50/24",
					Algorithm: "roundrobin",
					Ports:     []LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
					Hosts:     []string{"node1", "node2"},
				},
			},
		},
	}
	if err := validate(f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseBytes_ValidYAML(t *testing.T) {
	yaml := `
name: mystack
vms:
  web:
    image: nginx
    cpu: 2
    memory: 1024
`
	f, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if f.Name != "mystack" {
		t.Errorf("Name = %q, want mystack", f.Name)
	}
	if _, ok := f.VMs["web"]; !ok {
		t.Error("expected VM 'web'")
	}
}

func TestParseBytes_InvalidYAML(t *testing.T) {
	_, err := ParseBytes([]byte("{{invalid"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestValidate_ExternalNetworkNoConfig(t *testing.T) {
	yml := `
name: test
vms:
  web:
    image: nginx
    network:
      - name: ext-net
networks:
  ext-net:
    external: true
`
	// Should parse fine — external with no extra config.
	_, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidate_ExternalNetworkWithSubnet(t *testing.T) {
	yml := `
name: test
vms:
  web:
    image: nginx
networks:
  ext-net:
    external: true
    subnet: "10.0.0.0/24"
`
	_, err := ParseBytes([]byte(yml))
	if err == nil {
		t.Fatal("expected error for external network with subnet")
	}
	if !strings.Contains(err.Error(), "external network must not set") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_ExternalNetworkWithType(t *testing.T) {
	yml := `
name: test
vms:
  web:
    image: nginx
networks:
  ext-net:
    external: true
    type: vxlan
`
	_, err := ParseBytes([]byte(yml))
	if err == nil {
		t.Fatal("expected error for external network with type")
	}
	if !strings.Contains(err.Error(), "external network must not set") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtends_BasicInheritance(t *testing.T) {
	yml := `
name: test
vms:
  base:
    image: ubuntu
    cpu: 2
    memory: 4096
  web:
    extends: base
    cpu: 4
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	web := f.VMs["web"]
	if web.Image != "ubuntu" {
		t.Errorf("web.Image = %q, want ubuntu (inherited)", web.Image)
	}
	if web.CPU != 4 {
		t.Errorf("web.CPU = %d, want 4 (overridden)", web.CPU)
	}
	if int(web.Memory) != 4096 {
		t.Errorf("web.Memory = %d, want 4096 (inherited)", web.Memory)
	}
	if web.Extends != "" {
		t.Errorf("web.Extends should be cleared after resolution, got %q", web.Extends)
	}
}

func TestExtends_Override(t *testing.T) {
	yml := `
name: test
vms:
  base:
    image: ubuntu
    cpu: 2
    memory: 4096
    firmware: bios
  child:
    extends: base
    image: debian
    memory: 8192
    firmware: uefi
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	c := f.VMs["child"]
	if c.Image != "debian" {
		t.Errorf("child.Image = %q, want debian", c.Image)
	}
	if int(c.Memory) != 8192 {
		t.Errorf("child.Memory = %d, want 8192", c.Memory)
	}
	if c.Firmware != "uefi" {
		t.Errorf("child.Firmware = %q, want uefi", c.Firmware)
	}
	if c.CPU != 2 {
		t.Errorf("child.CPU = %d, want 2 (inherited)", c.CPU)
	}
}

func TestExtends_CycleDetection(t *testing.T) {
	yml := `
name: test
vms:
  a:
    image: img
    extends: b
  b:
    image: img
    extends: a
`
	_, err := ParseBytes([]byte(yml))
	if err == nil {
		t.Fatal("expected error for extends cycle")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error should mention cycle, got: %v", err)
	}
}

func TestExtends_UnknownRef(t *testing.T) {
	yml := `
name: test
vms:
  web:
    image: nginx
    extends: nonexistent
`
	_, err := ParseBytes([]byte(yml))
	if err == nil {
		t.Fatal("expected error for unknown extends ref")
	}
	if !strings.Contains(err.Error(), "unknown vm") {
		t.Errorf("error should mention unknown vm, got: %v", err)
	}
}

func TestExtends_LabelMerge(t *testing.T) {
	yml := `
name: test
vms:
  base:
    image: ubuntu
    labels:
      env: prod
      team: infra
  web:
    extends: base
    labels:
      team: web
      tier: frontend
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	labels := f.VMs["web"].Labels
	if labels["env"] != "prod" {
		t.Errorf("env label = %q, want prod (inherited)", labels["env"])
	}
	if labels["team"] != "web" {
		t.Errorf("team label = %q, want web (child wins)", labels["team"])
	}
	if labels["tier"] != "frontend" {
		t.Errorf("tier label = %q, want frontend", labels["tier"])
	}
}

func TestExtends_NetworkSliceReplacesParent(t *testing.T) {
	yml := `
name: test
vms:
  base:
    image: ubuntu
    network:
      - name: backend
        ip: 10.0.1.10
      - name: metrics
  web:
    extends: base
    network:
      - name: frontend
        ip: 10.0.2.10
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	nics := f.VMs["web"].Network
	if len(nics) != 1 {
		t.Fatalf("child network slice should replace parent, got %+v", nics)
	}
	if nics[0].Name != "frontend" || nics[0].IP != "10.0.2.10" {
		t.Fatalf("child network not preserved after replacement: %+v", nics[0])
	}
}

func TestExtends_ReplicasZeroBase(t *testing.T) {
	yml := `
name: test
vms:
  base:
    image: ubuntu
    cpu: 2
    replicas: 0
  web:
    extends: base
    replicas: 3
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	base := f.VMs["base"]
	if base.EffectiveReplicas() != 0 {
		t.Errorf("base replicas = %d, want 0", base.EffectiveReplicas())
	}
	web := f.VMs["web"]
	if web.EffectiveReplicas() != 3 {
		t.Errorf("web replicas = %d, want 3", web.EffectiveReplicas())
	}
	if web.CPU != 2 {
		t.Errorf("web.CPU = %d, want 2 (inherited)", web.CPU)
	}
}

func TestExtends_ChainedInheritance(t *testing.T) {
	yml := `
name: test
vms:
  base:
    image: ubuntu
    cpu: 1
  mid:
    extends: base
    cpu: 2
    memory: 4096
  top:
    extends: mid
    memory: 8192
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	top := f.VMs["top"]
	if top.Image != "ubuntu" {
		t.Errorf("top.Image = %q, want ubuntu (inherited from base)", top.Image)
	}
	if top.CPU != 2 {
		t.Errorf("top.CPU = %d, want 2 (inherited from mid)", top.CPU)
	}
	if int(top.Memory) != 8192 {
		t.Errorf("top.Memory = %d, want 8192 (overridden)", top.Memory)
	}
}

func TestExtends_SelfReference(t *testing.T) {
	yml := `
name: test
vms:
  web:
    image: nginx
    extends: web
`
	_, err := ParseBytes([]byte(yml))
	if err == nil {
		t.Fatal("expected error for self-reference")
	}
	if !strings.Contains(err.Error(), "extends itself") {
		t.Errorf("error should mention self-reference, got: %v", err)
	}
}

func TestDependsOn_ListForm(t *testing.T) {
	yml := `
name: test
vms:
  db:
    image: postgres
  redis:
    image: redis
  app:
    image: myapp
    depends-on: [db, redis]
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	app := f.VMs["app"]
	if len(app.DependsOn) != 2 {
		t.Fatalf("app.DependsOn len = %d, want 2", len(app.DependsOn))
	}
	if app.DependsOn["db"].Condition != "vm_started" {
		t.Errorf("db condition = %q, want vm_started", app.DependsOn["db"].Condition)
	}
	if app.DependsOn["redis"].Condition != "vm_started" {
		t.Errorf("redis condition = %q, want vm_started", app.DependsOn["redis"].Condition)
	}
}

func TestDependsOn_MapForm(t *testing.T) {
	yml := `
name: test
vms:
  db:
    image: postgres
  app:
    image: myapp
    depends-on:
      db:
        condition: vm_healthy
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if f.VMs["app"].DependsOn["db"].Condition != "vm_healthy" {
		t.Errorf("condition = %q, want vm_healthy", f.VMs["app"].DependsOn["db"].Condition)
	}
}

func TestDependsOn_CycleDetection(t *testing.T) {
	yml := `
name: test
vms:
  a:
    image: img
    depends-on: [b]
  b:
    image: img
    depends-on: [a]
`
	_, err := ParseBytes([]byte(yml))
	if err == nil {
		t.Fatal("expected error for depends-on cycle")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error should mention cycle, got: %v", err)
	}
}

func TestDependsOn_UnknownTarget(t *testing.T) {
	yml := `
name: test
vms:
  app:
    image: myapp
    depends-on: [nonexistent]
`
	_, err := ParseBytes([]byte(yml))
	if err == nil {
		t.Fatal("expected error for unknown depends-on target")
	}
	if !strings.Contains(err.Error(), "unknown vm") {
		t.Errorf("error should mention unknown vm, got: %v", err)
	}
}

func TestDependsOn_TopologicalSort(t *testing.T) {
	yml := `
name: test
vms:
  app:
    image: myapp
    depends-on: [db]
  db:
    image: postgres
  cache:
    image: redis
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	plan, err := Build(f, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	sorted := TopologicalSortOps(plan.Ops)
	// db must come before app
	dbIdx, appIdx := -1, -1
	for i, op := range sorted {
		if op.VMName == "db" {
			dbIdx = i
		}
		if op.VMName == "app" {
			appIdx = i
		}
	}
	if dbIdx == -1 || appIdx == -1 {
		t.Fatal("expected both db and app in sorted ops")
	}
	if dbIdx > appIdx {
		t.Errorf("db (idx %d) should come before app (idx %d)", dbIdx, appIdx)
	}
}

func TestParseBytes_StopGracePeriod(t *testing.T) {
	yml := `
name: test
vms:
  web:
    image: nginx
    cpu: 1
    memory: 512
    stop-grace-period: "45s"
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	web := f.VMs["web"]
	if web.StopGracePeriod != "45s" {
		t.Errorf("StopGracePeriod = %q, want 45s", web.StopGracePeriod)
	}
}

func TestParseBytes_StopGracePeriod_Minutes(t *testing.T) {
	yml := `
name: test
vms:
  db:
    image: postgres
    cpu: 2
    memory: 2048
    stop-grace-period: "2m"
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	db := f.VMs["db"]
	if db.StopGracePeriod != "2m" {
		t.Errorf("StopGracePeriod = %q, want 2m", db.StopGracePeriod)
	}
}

func TestParseBytes_Restart(t *testing.T) {
	yml := `
name: test
vms:
  worker:
    image: worker:v1
    cpu: 1
    memory: 512
    restart:
      condition: on-failure
      delay: 5s
      max-attempts: 3
      window: 1h
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	worker := f.VMs["worker"]
	if worker.Restart == nil {
		t.Fatal("Restart should not be nil")
	}
	r := worker.Restart
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

func TestParseBytes_Restart_Always(t *testing.T) {
	yml := `
name: test
vms:
  app:
    image: myapp
    cpu: 2
    memory: 1024
    restart:
      condition: always
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	app := f.VMs["app"]
	if app.Restart == nil {
		t.Fatal("Restart should not be nil")
	}
	if app.Restart.Condition != "always" {
		t.Errorf("Condition = %q, want always", app.Restart.Condition)
	}
}

func TestParseBytes_Restart_Absent(t *testing.T) {
	yml := `
name: test
vms:
  app:
    image: myapp
    cpu: 1
    memory: 512
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if f.VMs["app"].Restart != nil {
		t.Error("Restart should be nil when not set")
	}
}

func TestExtends_PointerStructInheritance(t *testing.T) {
	yml := `
name: test
vms:
  base:
    image: ubuntu
    placement:
      host: node-1
      spread: true
    healthcheck:
      type: tcp
      target: "80"
      interval: 30s
  web:
    extends: base
    placement:
      host: node-2
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	web := f.VMs["web"]
	// Child placement replaces entirely
	if web.Placement.Host != "node-2" {
		t.Errorf("web.Placement.Host = %q, want node-2", web.Placement.Host)
	}
	if web.Placement.Spread {
		t.Error("web.Placement.Spread should be false (child replaces entire struct)")
	}
	// Healthcheck inherited from base
	if web.HealthCheck == nil || web.HealthCheck.Type != "tcp" {
		t.Error("web.HealthCheck should be inherited from base")
	}
}

func TestParseBytes_HostIsolation(t *testing.T) {
	yml := `
name: test
networks:
  overlay:
    type: vxlan
    vni: 1000
    subnet: "10.100.0.0/24"
    host-isolation: true
    dns:
      - "1.1.1.1"
      - "8.8.8.8"
vms:
  web:
    image: nginx
    cpu: 1
    memory: 512
    network:
      - name: overlay
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	net := f.Networks["overlay"]
	if !net.HostIsolation {
		t.Error("HostIsolation should be true")
	}
	if len(net.DNS) != 2 {
		t.Fatalf("DNS should have 2 entries, got %d", len(net.DNS))
	}
	if net.DNS[0] != "1.1.1.1" || net.DNS[1] != "8.8.8.8" {
		t.Errorf("DNS = %v, want [1.1.1.1, 8.8.8.8]", net.DNS)
	}
}

func TestParseBytes_HostIsolation_DefaultFalse(t *testing.T) {
	yml := `
name: test
networks:
  plain:
    type: bridge
    interface: br0
vms:
  web:
    image: nginx
    cpu: 1
    memory: 512
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	net := f.Networks["plain"]
	if net.HostIsolation {
		t.Error("HostIsolation should default to false")
	}
	if len(net.DNS) != 0 {
		t.Errorf("DNS should be empty by default, got %v", net.DNS)
	}
}

func TestParseBytes_LBSNAT(t *testing.T) {
	yml := `
name: test
vms:
  web:
    image: nginx
    cpu: 1
    memory: 512
    replicas: 2
    loadbalancer:
      vip: "10.0.0.50/24"
      snat: true
      ports:
        - listen: 80
          target: 8080
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	web := f.VMs["web"]
	if web.LoadBalancer == nil {
		t.Fatal("LoadBalancer should not be nil")
	}
	if !web.LoadBalancer.SNAT {
		t.Error("SNAT should be true")
	}
}

func TestParseBytes_LBSNAT_DefaultFalse(t *testing.T) {
	yml := `
name: test
vms:
  web:
    image: nginx
    cpu: 1
    memory: 512
    loadbalancer:
      vip: "10.0.0.50/24"
      ports:
        - listen: 80
          target: 8080
`
	f, err := ParseBytes([]byte(yml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	web := f.VMs["web"]
	if web.LoadBalancer == nil {
		t.Fatal("LoadBalancer should not be nil")
	}
	if web.LoadBalancer.SNAT {
		t.Error("SNAT should default to false")
	}
}
