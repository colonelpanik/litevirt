package compose

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// baseSpec is a minimal running-VM spec used as the "stored" side of a diff.
func baseSpec() *pb.VMSpec {
	return &pb.VMSpec{
		Name:         "vm",
		Image:        "ubuntu-24.04",
		Cpu:          2,
		MaxCpu:       8,
		MemoryMib:    2048,
		MinMemoryMib: 1024,
		MaxMemoryMib: 4096,
		Disks:        []*pb.DiskSpec{{Name: "root", Bus: "virtio"}},
		Network:      []*pb.NetworkAttachment{{Name: "default"}},
	}
}

func TestClassify_NoChange(t *testing.T) {
	p := Classify(baseSpec(), baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionNoChange {
		t.Fatalf("identical specs: Max()=%v, want NoChange", got)
	}
}

func TestClassify_CPUGrowWithinCeiling_Live(t *testing.T) {
	d := baseSpec()
	d.Cpu = 4 // within MaxCpu=8
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionLive {
		t.Fatalf("cpu grow within ceiling: Max()=%v, want Live", got)
	}
	if len(p.ResourceChanges) != 1 || p.ResourceChanges[0].Field != "cpu" {
		t.Fatalf("expected one cpu resource change, got %+v", p.ResourceChanges)
	}
}

func TestClassify_CPUShrink_Restart(t *testing.T) {
	d := baseSpec()
	d.Cpu = 1
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionRestart {
		t.Fatalf("cpu shrink: Max()=%v, want Restart", got)
	}
	if len(p.RestartReasons) == 0 {
		t.Fatalf("cpu shrink should record a restart reason")
	}
	// The delta is still retained even though it downgrades to restart-class.
	if len(p.ResourceChanges) != 0 {
		t.Fatalf("cpu shrink must not be a live resource change, got %+v", p.ResourceChanges)
	}
}

func TestClassify_CPUGrowBeyondCeiling_Restart(t *testing.T) {
	d := baseSpec()
	d.Cpu = 10 // beyond MaxCpu=8
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionRestart {
		t.Fatalf("cpu grow beyond ceiling: Max()=%v, want Restart", got)
	}
}

func TestClassify_CPUGrowNoCeiling_Restart(t *testing.T) {
	st := baseSpec()
	st.MaxCpu = 0 // no declared hotplug headroom → any grow needs a redefine
	d := baseSpec()
	d.MaxCpu = 0
	d.Cpu = 4
	p := Classify(d, st, StoredDisksFromSpec(st))
	if got := p.Max(); got != ActionRestart {
		t.Fatalf("cpu grow with no ceiling: Max()=%v, want Restart", got)
	}
}

func TestClassify_MemoryWithinBand_Live(t *testing.T) {
	d := baseSpec()
	d.MemoryMib = 3072 // within [1024, 4096]
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionLive {
		t.Fatalf("memory within band: Max()=%v, want Live", got)
	}
	if len(p.ResourceChanges) != 1 || p.ResourceChanges[0].Field != "memory" {
		t.Fatalf("expected one memory resource change, got %+v", p.ResourceChanges)
	}
}

func TestClassify_MemoryBalloonDownNoCeiling_Live(t *testing.T) {
	st := baseSpec()
	st.MaxMemoryMib = 0 // ceiling defaults to current memory; a decrease still balloons live
	d := baseSpec()
	d.MaxMemoryMib = 0
	d.MemoryMib = 1024 // below current 2048, above min 1024
	p := Classify(d, st, StoredDisksFromSpec(st))
	if got := p.Max(); got != ActionLive {
		t.Fatalf("balloon-down within band: Max()=%v, want Live", got)
	}
}

func TestClassify_MemoryOutOfBand_Restart(t *testing.T) {
	d := baseSpec()
	d.MemoryMib = 8192 // beyond MaxMemoryMib=4096
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionRestart {
		t.Fatalf("memory beyond ceiling: Max()=%v, want Restart", got)
	}
}

func TestClassify_MaxCPUChange_Restart(t *testing.T) {
	d := baseSpec()
	d.MaxCpu = 16
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionRestart {
		t.Fatalf("max_cpu change: Max()=%v, want Restart", got)
	}
}

func TestClassify_DevicesChange_Restart(t *testing.T) {
	d := baseSpec()
	d.Devices = []*pb.DeviceSpec{{Type: "gpu", Vendor: "10de"}}
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionRestart {
		t.Fatalf("device change: Max()=%v, want Restart", got)
	}
}

func TestClassify_ImageChange_Recreate(t *testing.T) {
	d := baseSpec()
	d.Image = "debian-12"
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionRecreate {
		t.Fatalf("image change: Max()=%v, want Recreate", got)
	}
}

func TestClassify_DiskTopologyChange_Recreate(t *testing.T) {
	d := baseSpec()
	d.Disks = append(d.Disks, &pb.DiskSpec{Name: "data", Bus: "virtio"})
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionRecreate {
		t.Fatalf("disk topology change: Max()=%v, want Recreate", got)
	}
}

func TestClassify_NetworkTopologyChange_Recreate(t *testing.T) {
	d := baseSpec()
	d.Network = append(d.Network, &pb.NetworkAttachment{Name: "backend"})
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionRecreate {
		t.Fatalf("network topology change: Max()=%v, want Recreate", got)
	}
}

func TestClassify_CloudInitChange_Recreate(t *testing.T) {
	st := baseSpec()
	st.CloudInit = &pb.CloudInitSpec{Userdata: "#cloud-config\nold"}
	d := baseSpec()
	d.CloudInit = &pb.CloudInitSpec{Userdata: "#cloud-config\nnew"}
	p := Classify(d, st, StoredDisksFromSpec(st))
	if got := p.Max(); got != ActionRecreate {
		t.Fatalf("cloud-init change: Max()=%v, want Recreate", got)
	}
}

func TestClassify_LabelsChange_Live(t *testing.T) {
	d := baseSpec()
	d.Labels = map[string]string{"tier": "web"}
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionLive {
		t.Fatalf("label change: Max()=%v, want Live", got)
	}
	if len(p.MetadataChanges) == 0 {
		t.Fatalf("label change should record a metadata change")
	}
}

func TestClassify_RestartPolicyChange_Live(t *testing.T) {
	d := baseSpec()
	d.Onboot = true
	d.StartupOrder = 5
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionLive {
		t.Fatalf("onboot/ordering change: Max()=%v, want Live", got)
	}
}

func TestClassify_PlacementChange_LiveMetadata(t *testing.T) {
	d := baseSpec()
	d.Placement = &pb.PlacementSpec{Host: "node-2"}
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionLive {
		t.Fatalf("placement change: Max()=%v, want Live (metadata)", got)
	}
}

// MIXED: a recreate reason plus a live resource change → Recreate wins, but every
// delta is retained so a non-in-place path can still see the resource delta.
func TestClassify_Mixed_CPUAndImage_RecreateWins_DeltasRetained(t *testing.T) {
	d := baseSpec()
	d.Cpu = 4
	d.Image = "debian-12"
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionRecreate {
		t.Fatalf("cpu+image: Max()=%v, want Recreate", got)
	}
	if len(p.ResourceChanges) != 1 {
		t.Fatalf("cpu delta must still be retained under a recreate, got %+v", p.ResourceChanges)
	}
	if len(p.RecreateReasons) == 0 {
		t.Fatalf("image change must record a recreate reason")
	}
}

// MIXED: cpu grow within ceiling plus a max_cpu change → Restart wins.
func TestClassify_Mixed_CPUAndCeiling_RestartWins(t *testing.T) {
	d := baseSpec()
	d.Cpu = 4
	d.MaxCpu = 16
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionRestart {
		t.Fatalf("cpu+max_cpu: Max()=%v, want Restart", got)
	}
}

// Regression: the STORED spec carries create-time defaults + server-assigned fields
// (machine, firmware, boot, resolved placement, uuid) that the compose-built DESIRED
// spec leaves unset. A cpu-only bump must classify as Live — the unset machine/firmware
// must NOT read as a redefine and block the in-place update. (Found via e2e on real
// hardware: an in-place cpu grow was refused with "machine-type change needs a redefine".)
func TestClassify_ServerDefaultedFields_DoNotFalsePositive(t *testing.T) {
	// Stored: what CreateVM persisted (compose cpu=1,max-cpu=2,mem=256,max-mem=512 +
	// server defaults).
	stored := &pb.VMSpec{
		Name: "app", Image: "cirros", Cpu: 1, MaxCpu: 2, MemoryMib: 256, MaxMemoryMib: 512,
		Machine: "q35", Firmware: "uefi", Boot: "disk", GuestAgent: true,
		Uuid:      "aad2e0bb-3311-42a9-92f9-4062205a4dc1",
		Placement: &pb.PlacementSpec{Host: "node-1"},
		Update:    &pb.UpdatePolicy{Strategy: "in-place"},
	}
	// Desired: what BuildVMSpec produces from the same compose with cpu bumped 1→2 —
	// machine/firmware/placement/uuid all UNSET.
	desired := &pb.VMSpec{
		Name: "app", Image: "cirros", Cpu: 2, MaxCpu: 2, MemoryMib: 256, MaxMemoryMib: 512,
		Boot: "disk", GuestAgent: true,
		Update: &pb.UpdatePolicy{Strategy: "in-place"},
	}
	p := Classify(desired, stored, StoredDisksFromSpec(stored))
	if got := p.Max(); got != ActionLive {
		t.Fatalf("cpu bump against a server-defaulted stored spec: Max()=%v (reasons restart=%v recreate=%v), want Live",
			got, p.RestartReasons, p.RecreateReasons)
	}
	if len(p.ResourceChanges) != 1 || p.ResourceChanges[0].Field != "cpu" {
		t.Fatalf("expected exactly the cpu resource change, got %+v", p.ResourceChanges)
	}
}

func TestClassify_Delegated_NotAnUpdateAction(t *testing.T) {
	d := baseSpec()
	d.Loadbalancer = &pb.LBSpec{Vip: "10.0.0.1"}
	p := Classify(d, baseSpec(), StoredDisksFromSpec(baseSpec()))
	if got := p.Max(); got != ActionNoChange {
		t.Fatalf("a load-balancer-only change is delegated, not a VM action: Max()=%v, want NoChange", got)
	}
	if len(p.Delegated) == 0 {
		t.Fatalf("load-balancer change should be recorded as delegated")
	}
}

// A compose definition leaves disk bus, NIC model, placement host and SR-IOV
// address unset and the create path fills them in (bus/model defaults, the
// planner's chosen host, the reserved VF address). An unchanged file re-applied
// to the VM it created must classify as no-change, or the default update
// strategy would delete and recreate the VM.
func TestClassify_ServerFilledTopologyFieldsInherit(t *testing.T) {
	stored := &pb.VMSpec{
		Name: "app", Image: "ubuntu", Cpu: 2, MemoryMib: 2048, Machine: "q35", Uuid: "u-1",
		Disks:     []*pb.DiskSpec{{Name: "root", Size: "20G", Bus: "virtio"}},
		Network:   []*pb.NetworkAttachment{{Name: "lan", Model: "virtio", Mac: "52:54:00:00:00:01"}},
		Placement: &pb.PlacementSpec{Host: "h1", AntiAffinity: []string{"db"}},
		Devices:   []*pb.DeviceSpec{{Type: "nic", Sriov: true, Address: "0000:01:00.1"}},
	}
	desired := &pb.VMSpec{
		Name: "app", Image: "ubuntu", Cpu: 2, MemoryMib: 2048,
		Disks:     []*pb.DiskSpec{{Name: "root", Size: "20G"}},
		Network:   []*pb.NetworkAttachment{{Name: "lan"}},
		Placement: &pb.PlacementSpec{AntiAffinity: []string{"db"}},
		Devices:   []*pb.DeviceSpec{{Type: "nic", Sriov: true}},
	}
	p := Classify(desired, stored, StoredDisksFromSpec(stored))
	if got := p.Max(); got != ActionNoChange {
		t.Fatalf("unchanged compose vs server-filled stored spec: Max()=%v (restart=%v recreate=%v meta=%+v), want NoChange",
			got, p.RestartReasons, p.RecreateReasons, p.MetadataChanges)
	}

	// The same fields SET to a different value are still changes.
	d := &pb.VMSpec{Name: "app", Image: "ubuntu",
		Disks:   []*pb.DiskSpec{{Name: "root", Bus: "scsi"}},
		Network: []*pb.NetworkAttachment{{Name: "lan", Model: "e1000"}}}
	if got := Classify(d, stored, StoredDisksFromSpec(stored)).Max(); got != ActionRecreate {
		t.Fatalf("explicit bus/model change: Max()=%v, want Recreate", got)
	}
	d = &pb.VMSpec{Name: "app", Image: "ubuntu", Placement: &pb.PlacementSpec{Host: "h2", AntiAffinity: []string{"db"}}}
	if got := Classify(d, stored, StoredDisksFromSpec(stored)).Max(); got != ActionLive {
		t.Fatalf("explicit placement host change: Max()=%v, want Live (metadata)", got)
	}
}

// Compose names a machine ALIAS ("q35", "pc"); the create path stores the
// concrete type libvirt resolved it to ("pc-q35-9.0") so the guest ABI travels
// with the VM. The same alias re-applied is therefore not a change — treating it
// as one recreated the VM under the default strategy. A different family, or an
// explicit pinned version that differs, still is.
func TestClassify_MachineAliasMatchesPinnedType(t *testing.T) {
	cases := []struct {
		desired, stored string
		want            Action
	}{
		{"q35", "pc-q35-9.0", ActionNoChange},
		{"pc", "pc-i440fx-9.0", ActionNoChange},
		{"pc-q35-9.0", "pc-q35-9.0", ActionNoChange},
		{"", "pc-q35-9.0", ActionNoChange}, // unset inherits
		{"pc", "pc-q35-9.0", ActionRestart},
		{"q35", "pc-i440fx-9.0", ActionRestart},
		{"pc-q35-8.2", "pc-q35-9.0", ActionRestart}, // explicit pin differs
		{"q35", "q35", ActionNoChange},
	}
	for _, c := range cases {
		st := baseSpec()
		st.Machine = c.stored
		d := baseSpec()
		d.Machine = c.desired
		if got := Classify(d, st, StoredDisksFromSpec(st)).Max(); got != c.want {
			t.Errorf("machine desired=%q stored=%q: Max()=%v, want %v", c.desired, c.stored, got, c.want)
		}
	}
}
