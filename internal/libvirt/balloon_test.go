package libvirt

import (
	"strings"
	"testing"
)

func TestGenerateDomainXML_Ballooning(t *testing.T) {
	// max > boot → <memory> is the ceiling, <currentMemory> the boot allocation.
	xml, err := GenerateDomainXML(VMConfig{
		Name: "balloon-vm", CPU: 2, MemoryMiB: 2048, MaxMemoryMiB: 8192, Firmware: "uefi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(xml, `<memory unit="KiB">8388608</memory>`) { // 8192 MiB ceiling
		t.Errorf("expected <memory> ceiling of 8192 MiB, got:\n%s", xml)
	}
	if !strings.Contains(xml, `<currentMemory unit="KiB">2097152</currentMemory>`) { // 2048 MiB boot
		t.Errorf("expected <currentMemory> boot allocation of 2048 MiB, got:\n%s", xml)
	}
	if !strings.Contains(xml, `<memballoon model="virtio">`) {
		t.Errorf("expected a virtio memballoon device")
	}
}

func TestGenerateDomainXML_FixedMemoryNoCurrentMemory(t *testing.T) {
	// No max set → fixed memory, no <currentMemory>, but still a balloon device.
	xml, err := GenerateDomainXML(VMConfig{Name: "fixed-vm", CPU: 1, MemoryMiB: 1024, Firmware: "uefi"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(xml, "<currentMemory") {
		t.Errorf("fixed-memory VM must not emit <currentMemory>, got:\n%s", xml)
	}
	if !strings.Contains(xml, `<memory unit="KiB">1048576</memory>`) {
		t.Errorf("expected <memory> of 1024 MiB")
	}
	if !strings.Contains(xml, `<memballoon model="virtio">`) {
		t.Errorf("expected a virtio memballoon device even for fixed memory")
	}
}
