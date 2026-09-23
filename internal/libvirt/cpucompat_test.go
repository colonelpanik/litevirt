package libvirt

import (
	"strings"
	"testing"
)

const capsXML = `<capabilities>
  <host>
    <uuid>abc</uuid>
    <cpu>
      <arch>x86_64</arch>
      <model>Skylake-Server-IBRS</model>
      <vendor>Intel</vendor>
      <feature name='avx512f'/>
    </cpu>
  </host>
</capabilities>`

func TestHostCPUFromCapabilities(t *testing.T) {
	got, err := hostCPUFromCapabilities(capsXML)
	if err != nil {
		t.Fatalf("hostCPUFromCapabilities: %v", err)
	}
	// The host form must come through verbatim — <arch> included. CompareCPU
	// parses this native shape; a hand-rebuilt hybrid is neither host nor guest
	// form and libvirt rejects it.
	if !strings.HasPrefix(got, "<cpu>") || !strings.HasSuffix(got, "</cpu>") {
		t.Errorf("not a standalone host cpu element: %s", got)
	}
	if !strings.Contains(got, "<arch>x86_64</arch>") {
		t.Errorf("host form lost its <arch>: %s", got)
	}
	if !strings.Contains(got, "<model>Skylake-Server-IBRS</model>") {
		t.Errorf("host model lost: %s", got)
	}
	if !strings.Contains(got, "avx512f") {
		t.Errorf("host features lost — a compare would accept a poorer destination: %s", got)
	}
}

// The host CPU must come from <host>, never from anywhere else in the document.
// A <guest> section describes what the hypervisor can EMULATE, which is a far
// richer set than the silicon — comparing against that would wave through a
// migration to a host whose CPU cannot actually run the guest.
func TestHostCPUFromCapabilitiesIgnoresNonHostCPUs(t *testing.T) {
	caps := `<capabilities>
	  <host><uuid>abc</uuid></host>
	  <guest>
	    <arch name='x86_64'>
	      <cpu><model>emulated-everything</model></cpu>
	    </arch>
	  </guest>
	</capabilities>`
	got, err := hostCPUFromCapabilities(caps)
	if err == nil {
		t.Fatalf("want an error when <host> carries no <cpu>, got %q", got)
	}
	if strings.Contains(got, "emulated-everything") {
		t.Fatalf("picked up a non-host <cpu>: %s", got)
	}
}

// A running host-model domain has its CPU already expanded by libvirt, so the
// live XML is the exact requirement a destination must satisfy.
func TestDomainCPURequirementExpandedHostModel(t *testing.T) {
	dom := `<domain type='kvm'><name>vm1</name>
	  <cpu mode='custom' match='exact' check='full'>
	    <model fallback='forbid'>Skylake-Server-IBRS</model>
	    <feature policy='require' name='avx2'/>
	  </cpu>
	</domain>`
	got, ok := DomainCPURequirement(dom)
	if !ok {
		t.Fatal("DomainCPURequirement found no requirement in an expanded host-model domain")
	}
	if !strings.Contains(got, "Skylake-Server-IBRS") || !strings.Contains(got, "avx2") {
		t.Errorf("requirement dropped the model or its features: %s", got)
	}
	// The expanded guest form is passed through verbatim, mode/match and all.
	if !strings.Contains(got, "mode='custom'") || !strings.Contains(got, "match='exact'") {
		t.Errorf("expanded guest form was not passed through verbatim: %s", got)
	}
}

// No <cpu> element at all (the qemu64 case) is not a requirement: it is
// identical on every host, so a preflight on it would be pure cost.
func TestDomainCPURequirementNoCPUElement(t *testing.T) {
	if _, ok := DomainCPURequirement(`<domain type='kvm'><name>vm1</name></domain>`); ok {
		t.Fatal("a domain with no <cpu> element must yield no requirement")
	}
}

// An unexpanded host-passthrough element names no model, so there is nothing to
// compare; the caller resolves it from the source HOST's CPU instead.
func TestDomainCPURequirementUnexpandedPassthrough(t *testing.T) {
	dom := `<domain type='kvm'><name>vm1</name><cpu mode='host-passthrough' check='none'/></domain>`
	if _, ok := DomainCPURequirement(dom); ok {
		t.Fatal("an unexpanded host-passthrough element must yield no comparable requirement")
	}
	if got := DomainCPUMode(dom); got != CPUModeHostPassthrough {
		t.Errorf("DomainCPUMode = %q, want %q", got, CPUModeHostPassthrough)
	}
}

func TestCPUCompareRunnable(t *testing.T) {
	for verdict, want := range map[CPUCompare]bool{
		CPUCompareIdentical:    true,
		CPUCompareSuperset:     true,
		CPUCompareIncompatible: false,
	} {
		if got := verdict.Runnable(); got != want {
			t.Errorf("CPUCompare(%v).Runnable() = %v, want %v", verdict, got, want)
		}
	}
}
