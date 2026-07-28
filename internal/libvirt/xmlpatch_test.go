package libvirt

import (
	"strings"
	"testing"
)

// a representative libvirt-serialized inactive domain (single quotes, extra attrs,
// a stable PCI slot address that a full regeneration would reshuffle).
const sampleInactiveXML = `<domain type='kvm'>
  <name>vm1</name>
  <memory unit='KiB'>4194304</memory>
  <currentMemory unit='KiB'>2097152</currentMemory>
  <vcpu placement='static'>2</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-9.0'>hvm</type>
  </os>
  <devices>
    <interface type='bridge'>
      <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
    </interface>
  </devices>
</domain>`

func TestPatchInactiveResources_PreservesEverythingElse(t *testing.T) {
	out, err := PatchInactiveResources(sampleInactiveXML, 8, 8192, 16384)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if !strings.Contains(out, "<vcpu placement='static'>8</vcpu>") {
		t.Errorf("vcpu not patched to 8:\n%s", out)
	}
	if !strings.Contains(out, "<memory unit='KiB'>16777216</memory>") { // 16384 MiB ceiling
		t.Errorf("memory not patched to the 16384 MiB ceiling:\n%s", out)
	}
	if !strings.Contains(out, "<currentMemory unit='KiB'>8388608</currentMemory>") { // 8192 MiB
		t.Errorf("currentMemory not patched to 8192 MiB:\n%s", out)
	}
	// The libvirt-assigned PCI slot address MUST survive unchanged.
	if !strings.Contains(out, "slot='0x00' function='0x0'") {
		t.Errorf("PCI address reshuffled by the patch:\n%s", out)
	}
	// The vcpu 'placement' attribute must be preserved.
	if strings.Contains(out, "<vcpu>8</vcpu>") {
		t.Errorf("patch dropped the vcpu attributes:\n%s", out)
	}
}

func TestPatchInactiveResources_RemovesCurrentMemoryWhenNoBalloon(t *testing.T) {
	// maxMem <= mem ⇒ no ballooning ⇒ <currentMemory> must be dropped.
	out, err := PatchInactiveResources(sampleInactiveXML, 4, 8192, 0)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if strings.Contains(out, "currentMemory") {
		t.Errorf("currentMemory should be removed when there is no balloon ceiling:\n%s", out)
	}
	if !strings.Contains(out, "<memory unit='KiB'>8388608</memory>") {
		t.Errorf("memory not set to 8192 MiB:\n%s", out)
	}
}

func TestPatchInactiveResources_InsertsCurrentMemoryWhenAbsent(t *testing.T) {
	noBalloon := `<domain type='kvm'>
  <name>vm1</name>
  <memory unit='KiB'>4194304</memory>
  <vcpu placement='static'>2</vcpu>
</domain>`
	out, err := PatchInactiveResources(noBalloon, 2, 2048, 4096)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if !strings.Contains(out, "<memory unit='KiB'>4194304</memory>") { // 4096 ceiling
		t.Errorf("memory ceiling wrong:\n%s", out)
	}
	if !strings.Contains(out, "<currentMemory unit='KiB'>2097152</currentMemory>") { // 2048 boot
		t.Errorf("currentMemory not inserted:\n%s", out)
	}
	// It must sit right after </memory>.
	mi := strings.Index(out, "</memory>")
	ci := strings.Index(out, "<currentMemory")
	if mi < 0 || ci < 0 || ci < mi {
		t.Errorf("currentMemory not placed after </memory>:\n%s", out)
	}
}

func TestPatchInactiveResources_Errors(t *testing.T) {
	if _, err := PatchInactiveResources("<domain><name>x</name></domain>", 2, 2048, 0); err == nil {
		t.Error("want error when <vcpu> is missing")
	}
	if _, err := PatchInactiveResources(sampleInactiveXML, 0, 2048, 0); err == nil {
		t.Error("want error for non-positive cpu")
	}
}
