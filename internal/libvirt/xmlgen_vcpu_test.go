package libvirt

import (
	"strings"
	"testing"
)

// TestGenerateDomainXML_CPUHeadroom: a hotplug ceiling above the boot count emits
// <vcpu current=CPU>MAX</vcpu>; a fixed-size domain emits a plain <vcpu>N</vcpu>.
func TestGenerateDomainXML_CPUHeadroom(t *testing.T) {
	hot, err := GenerateDomainXML(VMConfig{Name: "hp", CPU: 2, MaxCPU: 8, MemoryMiB: 2048})
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if !strings.Contains(hot, `<vcpu current="2">8</vcpu>`) {
		t.Errorf("hotplug headroom missing:\n%s", hot)
	}

	fixed, err := GenerateDomainXML(VMConfig{Name: "fx", CPU: 4, MemoryMiB: 2048})
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if !strings.Contains(fixed, `<vcpu>4</vcpu>`) {
		t.Errorf("fixed vcpu missing:\n%s", fixed)
	}
	if strings.Contains(fixed, "current=") {
		t.Errorf("fixed-size domain should not emit a vcpu current attr:\n%s", fixed)
	}

	// MaxCPU <= CPU is treated as fixed (no headroom).
	eq, _ := GenerateDomainXML(VMConfig{Name: "eq", CPU: 4, MaxCPU: 4, MemoryMiB: 2048})
	if !strings.Contains(eq, `<vcpu>4</vcpu>`) {
		t.Errorf("MaxCPU==CPU should be fixed:\n%s", eq)
	}
}
