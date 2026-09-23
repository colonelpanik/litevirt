package libvirt

import (
	"strings"
	"testing"
)

// inactiveQ35XML is the shape libvirt serializes: single-quoted attributes and,
// crucially, the guest-side <address> elements it assigned. Those are what the
// in-place patch exists to preserve.
const inactiveQ35XML = `<domain type='kvm'>
  <name>vm1</name>
  <uuid>11111111-2222-3333-4444-555555555555</uuid>
  <memory unit='KiB'>4194304</memory>
  <vcpu placement='static'>2</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-9.0'>hvm</type>
  </os>
  <devices>
    <disk type='file' device='disk'>
      <source file='/data/vm1/root.qcow2'/>
      <target dev='vda' bus='virtio'/>
      <address type='pci' domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>
    </disk>
    <interface type='bridge'>
      <mac address='52:54:00:ab:cd:ef'/>
      <source bridge='br0'/>
      <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
    </interface>
  </devices>
</domain>`

// assertAddressesPreserved is the whole reason this path exists.
func assertAddressesPreserved(t *testing.T, out string) {
	t.Helper()
	for _, want := range []string{
		`<address type='pci' domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>`,
		`<address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>`,
		`<mac address='52:54:00:ab:cd:ef'/>`,
		`<source file='/data/vm1/root.qcow2'/>`,
		`machine='pc-q35-9.0'`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("patch did not preserve %s:\n%s", want, out)
		}
	}
}

// Retrofitting a mode onto a VM that has no <cpu> element inserts one, and
// leaves every libvirt-assigned address alone.
func TestPatchInactiveCPUMode_InsertsWhenAbsent(t *testing.T) {
	out, err := PatchInactiveCPUMode(inactiveQ35XML, CPUModeHostModel, "")
	if err != nil {
		t.Fatalf("PatchInactiveCPUMode: %v", err)
	}
	if !strings.Contains(out, `<cpu mode="host-model">`) {
		t.Errorf("no host-model cpu element inserted:\n%s", out)
	}
	assertAddressesPreserved(t, out)
}

// An existing element is REPLACED, not duplicated — two <cpu> elements would be
// invalid and libvirt would refuse the define.
func TestPatchInactiveCPUMode_ReplacesExisting(t *testing.T) {
	withCPU := strings.Replace(inactiveQ35XML,
		"  <os>", "  <cpu mode='host-passthrough' check='none'/>\n  <os>", 1)

	out, err := PatchInactiveCPUMode(withCPU, CPUModeCustom, "x86-64-v3")
	if err != nil {
		t.Fatalf("PatchInactiveCPUMode: %v", err)
	}
	if strings.Count(out, "<cpu ") != 1 {
		t.Fatalf("want exactly one <cpu> element, got %d:\n%s", strings.Count(out, "<cpu "), out)
	}
	if strings.Contains(out, "host-passthrough") {
		t.Errorf("old mode survived the replacement:\n%s", out)
	}
	if !strings.Contains(out, `<model fallback="allow">x86-64-v3</model>`) {
		t.Errorf("custom mode carries no model:\n%s", out)
	}
	assertAddressesPreserved(t, out)
}

// An empty mode is a no-op. This is the safety property: a cpu-count or memory
// edit on a VM that never named a CPU mode must not gain a <cpu> element as a
// side effect, which would change the guest's CPU without anyone asking.
func TestPatchInactiveCPUMode_EmptyModeIsAByteForByteNoOp(t *testing.T) {
	out, err := PatchInactiveCPUMode(inactiveQ35XML, "", "")
	if err != nil {
		t.Fatalf("PatchInactiveCPUMode: %v", err)
	}
	if out != inactiveQ35XML {
		t.Errorf("empty mode changed the document:\n%s", out)
	}
	if strings.Contains(out, "<cpu") {
		t.Error("empty mode inserted a <cpu> element")
	}
}

// An empty mode must not DELETE an existing element either — same reasoning in
// the other direction.
func TestPatchInactiveCPUMode_EmptyModeKeepsAnExistingElement(t *testing.T) {
	withCPU := strings.Replace(inactiveQ35XML,
		"  <os>", "  <cpu mode='host-model'/>\n  <os>", 1)
	out, err := PatchInactiveCPUMode(withCPU, "", "")
	if err != nil {
		t.Fatalf("PatchInactiveCPUMode: %v", err)
	}
	if !strings.Contains(out, "<cpu mode='host-model'/>") {
		t.Errorf("empty mode removed an existing cpu element:\n%s", out)
	}
}

// An invalid pair never reaches the document; the caller falls back to full
// regeneration rather than defining XML libvirt would reject.
func TestPatchInactiveCPUMode_RejectsInvalidPairs(t *testing.T) {
	for _, tc := range []struct{ name, mode, model string }{
		{"custom without model", CPUModeCustom, ""},
		{"model without custom", CPUModeHostModel, "x86-64-v3"},
		{"unknown mode", "host-passthru", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PatchInactiveCPUMode(inactiveQ35XML, tc.mode, tc.model); err == nil {
				t.Fatal("want an error, got nil")
			}
		})
	}
}

// With no <cpu> to replace and no </vcpu> to insert after, the patch refuses
// rather than placing the element somewhere it guessed.
func TestPatchInactiveCPUMode_RefusesWithNoInsertionPoint(t *testing.T) {
	if _, err := PatchInactiveCPUMode(`<domain type='kvm'><name>vm1</name></domain>`, CPUModeHostModel, ""); err == nil {
		t.Fatal("want an error when there is no safe insertion point, got nil")
	}
}

// Only the TOP-LEVEL <cpu> is patched. A nested element that happens to share
// the name is not the guest's CPU, and rewriting it would corrupt whatever it
// belongs to while leaving the real CPU untouched.
func TestPatchInactiveCPUMode_IgnoresNestedCPUElements(t *testing.T) {
	nested := strings.Replace(inactiveQ35XML,
		"  <os>",
		"  <metadata><vendor:cpu xmlns:vendor='http://example.invalid/'>bookkeeping</vendor:cpu></metadata>\n  <os>", 1)

	out, err := PatchInactiveCPUMode(nested, CPUModeHostModel, "")
	if err != nil {
		t.Fatalf("PatchInactiveCPUMode: %v", err)
	}
	if !strings.Contains(out, "bookkeeping") {
		t.Errorf("patch rewrote a nested cpu element:\n%s", out)
	}
	if !strings.Contains(out, `<cpu mode="host-model">`) {
		t.Errorf("patch did not add the real guest cpu element:\n%s", out)
	}
}

// The patch composes with the resource patch: that is how the redefine path
// applies a cpu-count and a cpu-mode change in one pass.
func TestPatchInactiveCPUMode_ComposesWithResourcePatch(t *testing.T) {
	resourced, err := PatchInactiveResources(inactiveQ35XML, 8, 8192, 0)
	if err != nil {
		t.Fatalf("PatchInactiveResources: %v", err)
	}
	out, err := PatchInactiveCPUMode(resourced, CPUModeHostModel, "")
	if err != nil {
		t.Fatalf("PatchInactiveCPUMode: %v", err)
	}
	if !strings.Contains(out, ">8</vcpu>") {
		t.Errorf("vcpu patch lost:\n%s", out)
	}
	if !strings.Contains(out, "8388608</memory>") {
		t.Errorf("memory patch lost:\n%s", out)
	}
	if !strings.Contains(out, `<cpu mode="host-model">`) {
		t.Errorf("cpu patch lost:\n%s", out)
	}
	assertAddressesPreserved(t, out)
}
