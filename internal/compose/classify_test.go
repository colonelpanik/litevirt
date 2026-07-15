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
