package libvirt

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestParsePCIAddress(t *testing.T) {
	tests := []struct {
		input string
		want  ParsedPCIAddr
	}{
		{
			"0000:41:00.0",
			ParsedPCIAddr{Domain: "0x0000", Bus: "0x41", Slot: "0x00", Function: "0x0"},
		},
		{
			"0000:03:00.1",
			ParsedPCIAddr{Domain: "0x0000", Bus: "0x03", Slot: "0x00", Function: "0x1"},
		},
		{
			"0000:b4:02.3",
			ParsedPCIAddr{Domain: "0x0000", Bus: "0xb4", Slot: "0x02", Function: "0x3"},
		},
		{
			// Short input with no function
			"0000:41:00",
			ParsedPCIAddr{Domain: "0x0000", Bus: "0x41", Slot: "0x00", Function: "0x0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParsePCIAddress(tt.input)
			if got != tt.want {
				t.Errorf("ParsePCIAddress(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParsePCIAddress_Invalid(t *testing.T) {
	// Too few colons — should return zero defaults
	got := ParsePCIAddress("41:00.0")
	if got.Domain != "0x0000" {
		t.Errorf("invalid address: Domain = %q, want 0x0000", got.Domain)
	}
}

func TestGenerateDomainXML_Hostdev(t *testing.T) {
	cfg := VMConfig{
		Name:      "gpu-vm",
		CPU:       4,
		MemoryMiB: 8192,
		Firmware:  "uefi",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio"},
		},
		Hostdevs: []HostdevConfig{
			{Address: "0000:41:00.0"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	checks := []string{
		`mode="subsystem"`,
		`type="pci"`,
		`managed="yes"`,
		`domain="0x0000"`,
		`bus="0x41"`,
		`slot="0x00"`,
		`function="0x0"`,
	}
	for _, check := range checks {
		if !strings.Contains(xmlOut, check) {
			t.Errorf("hostdev XML missing %q", check)
		}
	}
}

func TestGenerateDomainXML_MultipleHostdevs(t *testing.T) {
	cfg := VMConfig{
		Name:      "multi-gpu-vm",
		CPU:       8,
		MemoryMiB: 16384,
		Firmware:  "uefi",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio"},
		},
		Hostdevs: []HostdevConfig{
			{Address: "0000:41:00.0"},
			{Address: "0000:42:00.0"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// Should have two hostdev entries
	count := strings.Count(xmlOut, `<hostdev`)
	if count != 2 {
		t.Errorf("expected 2 hostdev entries, got %d", count)
	}

	if !strings.Contains(xmlOut, `bus="0x41"`) {
		t.Error("missing bus 0x41")
	}
	if !strings.Contains(xmlOut, `bus="0x42"`) {
		t.Error("missing bus 0x42")
	}
}

func TestGenerateDomainXML_NoHostdevs(t *testing.T) {
	cfg := VMConfig{
		Name:      "no-gpu-vm",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if strings.Contains(xmlOut, `<hostdev`) {
		t.Error("should have no hostdev entries when Hostdevs is empty")
	}
}

func TestGenerateDomainXML_HostdevValidXML(t *testing.T) {
	cfg := VMConfig{
		Name:       "valid-hostdev-vm",
		CPU:        2,
		MemoryMiB:  4096,
		Firmware:   "uefi",
		GuestAgent: true,
		Disks: []DiskConfig{
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio"},
		},
		Networks: []NetworkConfig{
			{Bridge: "br0", MAC: "52:54:00:aa:bb:cc"},
		},
		Hostdevs: []HostdevConfig{
			{Address: "0000:41:00.0"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// Verify the complete XML is well-formed
	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("hostdev XML is not valid: %v", err)
	}

	if len(dom.Devices.Hostdevs) != 1 {
		t.Fatalf("expected 1 hostdev, got %d", len(dom.Devices.Hostdevs))
	}
	hd := dom.Devices.Hostdevs[0]
	if hd.Mode != "subsystem" {
		t.Errorf("Mode = %q, want subsystem", hd.Mode)
	}
	if hd.Type != "pci" {
		t.Errorf("Type = %q, want pci", hd.Type)
	}
	if hd.Managed != "yes" {
		t.Errorf("Managed = %q, want yes", hd.Managed)
	}
}

func TestGenerateDomainXML_HugePages(t *testing.T) {
	cfg := VMConfig{
		Name:      "huge-vm",
		CPU:       4,
		MemoryMiB: 8192,
		Firmware:  "bios",
		HugePages: true,
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.Contains(xmlOut, "<hugepages") {
		t.Error("hugepages should be present in memoryBacking")
	}
}

func TestGenerateDomainXML_CPUPinning(t *testing.T) {
	cfg := VMConfig{
		Name:       "pinned-vm",
		CPU:        2,
		MemoryMiB:  4096,
		Firmware:   "bios",
		CPUPinning: []int{4, 5},
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.Contains(xmlOut, `vcpu="0"`) {
		t.Error("missing vcpu 0 pin")
	}
	if !strings.Contains(xmlOut, `cpuset="4"`) {
		t.Error("missing cpuset 4")
	}
	if !strings.Contains(xmlOut, `cpuset="5"`) {
		t.Error("missing cpuset 5")
	}
}

func TestGenerateDomainXML_IOThreads(t *testing.T) {
	cfg := VMConfig{
		Name:      "io-vm",
		CPU:       2,
		MemoryMiB: 4096,
		Firmware:  "bios",
		IOThreads: 4,
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.Contains(xmlOut, "<iothreads>4</iothreads>") {
		t.Error("missing iothreads element")
	}
}

func TestGenerateDomainXML_NUMATune(t *testing.T) {
	cfg := VMConfig{
		Name:      "numa-vm",
		CPU:       4,
		MemoryMiB: 8192,
		Firmware:  "bios",
		NUMAPolicy: &NUMAPolicy{
			PreferredNode: 1,
			Strict:        true,
		},
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.Contains(xmlOut, `<numatune>`) {
		t.Error("missing numatune element")
	}
	if !strings.Contains(xmlOut, `mode="strict"`) {
		t.Error("expected strict mode")
	}
	if !strings.Contains(xmlOut, `nodeset="1"`) {
		t.Error("expected nodeset 1")
	}
}

func TestGenerateDomainXML_NUMATune_Preferred(t *testing.T) {
	cfg := VMConfig{
		Name:      "numa-preferred-vm",
		CPU:       2,
		MemoryMiB: 4096,
		Firmware:  "bios",
		NUMAPolicy: &NUMAPolicy{
			PreferredNode: 0,
			Strict:        false,
		},
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.Contains(xmlOut, `mode="preferred"`) {
		t.Error("expected preferred mode")
	}
}

func TestGenerateDomainXML_NUMATune_Auto(t *testing.T) {
	cfg := VMConfig{
		Name:      "numa-auto-vm",
		CPU:       2,
		MemoryMiB: 4096,
		Firmware:  "bios",
		NUMAPolicy: &NUMAPolicy{
			PreferredNode: -1, // auto = no numatune
		},
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if strings.Contains(xmlOut, `<numatune>`) {
		t.Error("numatune should not be present when PreferredNode is -1")
	}
}
