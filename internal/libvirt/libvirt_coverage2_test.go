package libvirt

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"testing"
)

// ── readTapVLANs edge cases ──

func TestReadTapVLANs_PortHeaderLines(t *testing.T) {
	orig := execVLAN
	defer func() { execVLAN = orig }()

	execVLAN = func(name string, args ...string) ([]byte, error) {
		// "port" prefix lines should be skipped entirely.
		out := "port vnet0 state forwarding\n  100\nport vnet1 state disabled\n  200\n"
		return []byte(out), nil
	}

	vlans, err := readTapVLANs("vnet0")
	if err != nil {
		t.Fatalf("readTapVLANs: %v", err)
	}
	if len(vlans) != 2 {
		t.Fatalf("expected 2 VLANs, got %d: %v", len(vlans), vlans)
	}
}

func TestReadTapVLANs_OutOfRangeIgnored(t *testing.T) {
	orig := execVLAN
	defer func() { execVLAN = orig }()

	// VIDs outside 1-4094 should be ignored.
	execVLAN = func(name string, args ...string) ([]byte, error) {
		out := "  0\n  100\n  5000\n  4094\n"
		return []byte(out), nil
	}

	vlans, err := readTapVLANs("vnet0")
	if err != nil {
		t.Fatalf("readTapVLANs: %v", err)
	}
	expected := map[int]bool{100: true, 4094: true}
	if len(vlans) != len(expected) {
		t.Fatalf("expected %d VLANs, got %d: %v", len(expected), len(vlans), vlans)
	}
	for _, v := range vlans {
		if !expected[v] {
			t.Errorf("unexpected VLAN %d", v)
		}
	}
}

func TestReadTapVLANs_Error(t *testing.T) {
	orig := execVLAN
	defer func() { execVLAN = orig }()

	execVLAN = func(name string, args ...string) ([]byte, error) {
		return []byte("nope"), fmt.Errorf("command failed")
	}

	_, err := readTapVLANs("vnet0")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "command failed") {
		t.Errorf("error should contain 'command failed', got: %v", err)
	}
}

func TestReadTapVLANs_NonNumericFields(t *testing.T) {
	orig := execVLAN
	defer func() { execVLAN = orig }()

	execVLAN = func(name string, args ...string) ([]byte, error) {
		// Lines with only non-numeric content should be skipped.
		out := "  PVID Egress Untagged\n  abc\n  42 PVID\n"
		return []byte(out), nil
	}

	vlans, err := readTapVLANs("vnet0")
	if err != nil {
		t.Fatalf("readTapVLANs: %v", err)
	}
	if len(vlans) != 1 || vlans[0] != 42 {
		t.Errorf("expected [42], got %v", vlans)
	}
}

// ── configureAccessBridgeVLAN / configureTrunkBridgeVLANs error handling ──

func TestConfigureAccessBridgeVLAN_Error(t *testing.T) {
	orig := execVLAN
	defer func() { execVLAN = orig }()

	execVLAN = func(name string, args ...string) ([]byte, error) {
		return []byte("RTNETLINK error"), fmt.Errorf("exit status 2")
	}

	err := configureAccessBridgeVLAN("vnet0", 100)
	if err == nil {
		t.Fatal("expected error from configureAccessBridgeVLAN")
	}
	if !strings.Contains(err.Error(), "RTNETLINK") {
		t.Errorf("error message should include command output, got: %v", err)
	}
}

func TestConfigureTrunkBridgeVLANs_PartialFailure(t *testing.T) {
	orig := execVLAN
	defer func() { execVLAN = orig }()

	callCount := 0
	execVLAN = func(name string, args ...string) ([]byte, error) {
		callCount++
		if callCount == 2 {
			return []byte("fail"), fmt.Errorf("mid-failure")
		}
		return nil, nil
	}

	err := configureTrunkBridgeVLANs("vnet0", []int{10, 20, 30})
	if err == nil {
		t.Fatal("expected error on second VLAN")
	}
	if !strings.Contains(err.Error(), "vid 20") {
		t.Errorf("error should reference vid 20, got: %v", err)
	}
	// Should have stopped at 2 calls (first succeeded, second failed).
	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

// ── replaceBootDev edge cases ──

func TestReplaceBootDev_SingleQuoteMultipleAttributes(t *testing.T) {
	// Ensure it handles XML with surrounding attributes correctly.
	input := `<type>hvm</type><boot dev='disk'/><bootmenu enable='yes'/>`
	got := replaceBootDev(input, "network")
	if !strings.Contains(got, `dev='network'`) {
		t.Errorf("expected dev='network', got: %s", got)
	}
	// Bootmenu should be unchanged.
	if !strings.Contains(got, `bootmenu`) {
		t.Errorf("bootmenu should be preserved, got: %s", got)
	}
}

func TestReplaceBootDev_EmptyValue(t *testing.T) {
	input := `<boot dev=''/>`
	got := replaceBootDev(input, "cdrom")
	if got != `<boot dev='cdrom'/>` {
		t.Errorf("got: %s", got)
	}
}

// ── patchBootDev edge cases ──

func TestPatchBootDev_NoBootElement(t *testing.T) {
	// os section exists but has no boot element.
	input := `<domain><os><type>hvm</type></os></domain>`
	got := patchBootDev(input, "cdrom")
	// No boot element to patch, os section is preserved.
	if !strings.Contains(got, "<os>") || !strings.Contains(got, "</os>") {
		t.Errorf("os section should be preserved, got: %s", got)
	}
}

func TestPatchBootDev_MissingCloseOS(t *testing.T) {
	// Malformed: has <os> but no </os>.
	input := `<domain><os><boot dev='disk'/></domain>`
	got := patchBootDev(input, "cdrom")
	// Should return unchanged since osEnd == -1.
	if got != input {
		t.Errorf("should return unchanged for malformed XML, got: %s", got)
	}
}

// ── ParsePCIAddress additional edge cases ──

func TestParsePCIAddress_EmptyString(t *testing.T) {
	got := ParsePCIAddress("")
	want := ParsedPCIAddr{Domain: "0x0000", Bus: "0x00", Slot: "0x00", Function: "0x0"}
	if got != want {
		t.Errorf("ParsePCIAddress(\"\") = %+v, want %+v", got, want)
	}
}

func TestParsePCIAddress_SingleColon(t *testing.T) {
	got := ParsePCIAddress("0000:41")
	want := ParsedPCIAddr{Domain: "0x0000", Bus: "0x00", Slot: "0x00", Function: "0x0"}
	if got != want {
		t.Errorf("ParsePCIAddress(\"0000:41\") = %+v, want %+v", got, want)
	}
}

func TestParsePCIAddress_NoFunction(t *testing.T) {
	// Slot without dot-function suffix.
	got := ParsePCIAddress("0000:03:1a")
	want := ParsedPCIAddr{Domain: "0x0000", Bus: "0x03", Slot: "0x1a", Function: "0x0"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// ── CPUPinning truncation (more pins listed than vCPUs) ──

func TestGenerateDomainXML_CPUPinning_MorePinsThanCPUs(t *testing.T) {
	cfg := VMConfig{
		Name:       "pin-trunc",
		CPU:        2,
		MemoryMiB:  1024,
		Firmware:   "bios",
		CPUPinning: []int{10, 11, 12, 13}, // 4 pins but only 2 vCPUs
		Disks:      []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// Only 2 vcpupin entries should exist (min of CPU count and pin list length).
	// Each <vcpupin...></vcpupin> produces 2 occurrences of the string.
	if strings.Count(xmlOut, "<vcpupin") != 2 {
		t.Errorf("expected 2 vcpupin entries, got %d", strings.Count(xmlOut, "<vcpupin"))
	}
	if !strings.Contains(xmlOut, `cpuset="10"`) {
		t.Error("missing cpuset 10")
	}
	if !strings.Contains(xmlOut, `cpuset="11"`) {
		t.Error("missing cpuset 11")
	}
	// Pins 12, 13 should NOT appear.
	if strings.Contains(xmlOut, `cpuset="12"`) || strings.Contains(xmlOut, `cpuset="13"`) {
		t.Error("extra pins beyond CPU count should not be present")
	}
}

func TestGenerateDomainXML_CPUPinning_FewerPinsThanCPUs(t *testing.T) {
	cfg := VMConfig{
		Name:       "pin-fewer",
		CPU:        4,
		MemoryMiB:  1024,
		Firmware:   "bios",
		CPUPinning: []int{0, 1}, // 2 pins but 4 vCPUs
		Disks:      []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// Only 2 vcpupin entries (limited by pin list length).
	if strings.Count(xmlOut, "<vcpupin") != 2 {
		t.Errorf("expected 2 vcpupin entries, got %d", strings.Count(xmlOut, "<vcpupin"))
	}
}

// ── Full XML structural roundtrip ──

func TestGenerateDomainXML_FullRoundTrip(t *testing.T) {
	cfg := VMConfig{
		Name:         "roundtrip-vm",
		CPU:          8,
		MemoryMiB:    16384,
		Machine:      "q35",
		Firmware:     "uefi",
		GuestAgent:   true,
		EnableVNC:    true,
		HugePages:    true,
		IOThreads:    2,
		CPUPinning:   []int{0, 1, 2, 3, 4, 5, 6, 7},
		NUMAPolicy:   &NUMAPolicy{PreferredNode: 0, Strict: true},
		CloudInitISO: "/ci/roundtrip.iso",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio", Cache: "none"},
			{Name: "data", Path: "/disks/data.qcow2", Bus: "scsi", Cache: "writethrough"},
		},
		Networks: []NetworkConfig{
			{Bridge: "br0", Model: "virtio", MAC: "52:54:00:11:22:33"},
			{Bridge: "br1", Model: "e1000", MAC: "52:54:00:44:55:66"},
		},
		Hostdevs: []HostdevConfig{
			{Address: "0000:41:00.0"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// Parse back.
	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("round-trip unmarshal failed: %v", err)
	}

	// Top-level.
	if dom.Type != "kvm" {
		t.Errorf("Type = %q", dom.Type)
	}
	if dom.Name != "roundtrip-vm" {
		t.Errorf("Name = %q", dom.Name)
	}
	if dom.VCPU.Value != 8 {
		t.Errorf("VCPU = %d", dom.VCPU.Value)
	}
	if dom.Memory.Value != 16384*1024 {
		t.Errorf("Memory = %d KiB", dom.Memory.Value)
	}
	if dom.Memory.Unit != "KiB" {
		t.Errorf("Memory.Unit = %q", dom.Memory.Unit)
	}
	if dom.IOThreads != 2 {
		t.Errorf("IOThreads = %d", dom.IOThreads)
	}

	// OS section.
	if dom.OS.Type.Machine != "q35" {
		t.Errorf("OS.Type.Machine = %q", dom.OS.Type.Machine)
	}
	if dom.OS.Type.Arch != "x86_64" {
		t.Errorf("OS.Type.Arch = %q", dom.OS.Type.Arch)
	}
	if dom.OS.Type.Value != "hvm" {
		t.Errorf("OS.Type.Value = %q", dom.OS.Type.Value)
	}
	if dom.OS.Loader == nil {
		t.Fatal("Loader should not be nil for UEFI")
	}
	if dom.OS.Loader.Type != "pflash" {
		t.Errorf("Loader.Type = %q", dom.OS.Loader.Type)
	}
	if dom.OS.Nvram == nil {
		t.Fatal("Nvram should not be nil for UEFI")
	}
	// UEFI should not have <boot dev="..."> — boot order is on disk devices.
	if dom.OS.Boot != nil {
		t.Errorf("UEFI should not have OS.Boot, got dev=%q", dom.OS.Boot.Dev)
	}

	// Features.
	if dom.Features.ACPI == nil {
		t.Error("ACPI should be set")
	}
	if dom.Features.APIC == nil {
		t.Error("APIC should be set")
	}

	// Clock.
	if dom.Clock.Offset != "utc" {
		t.Errorf("Clock.Offset = %q", dom.Clock.Offset)
	}

	// Lifecycle.
	if dom.OnPoweroff != "destroy" {
		t.Errorf("OnPoweroff = %q", dom.OnPoweroff)
	}
	if dom.OnReboot != "restart" {
		t.Errorf("OnReboot = %q", dom.OnReboot)
	}
	if dom.OnCrash != "destroy" {
		t.Errorf("OnCrash = %q", dom.OnCrash)
	}

	// Memory backing.
	if dom.MemoryBacking == nil || dom.MemoryBacking.HugePages == nil {
		t.Error("HugePages should be enabled")
	}

	// CPU pinning.
	if dom.CPUTune == nil {
		t.Fatal("CPUTune should not be nil")
	}
	if len(dom.CPUTune.VCPUPin) != 8 {
		t.Errorf("expected 8 vcpupin entries, got %d", len(dom.CPUTune.VCPUPin))
	}
	for i, pin := range dom.CPUTune.VCPUPin {
		if pin.VCPU != i {
			t.Errorf("VCPUPin[%d].VCPU = %d", i, pin.VCPU)
		}
		if pin.CPUSet != fmt.Sprintf("%d", i) {
			t.Errorf("VCPUPin[%d].CPUSet = %q", i, pin.CPUSet)
		}
	}

	// NUMA tune.
	if dom.NUMATune == nil {
		t.Fatal("NUMATune should not be nil")
	}
	if dom.NUMATune.Memory.Mode != "strict" {
		t.Errorf("NUMATune.Mode = %q", dom.NUMATune.Memory.Mode)
	}
	if dom.NUMATune.Memory.Nodeset != "0" {
		t.Errorf("NUMATune.Nodeset = %q", dom.NUMATune.Memory.Nodeset)
	}

	// Devices.
	if dom.Devices == nil {
		t.Fatal("Devices should not be nil")
	}
	if dom.Devices.Emulator != "/usr/bin/qemu-system-x86_64" {
		t.Errorf("Emulator = %q", dom.Devices.Emulator)
	}

	// Disks: 2 VM disks + 1 cloud-init CDROM = 3.
	if len(dom.Devices.Disks) != 3 {
		t.Fatalf("expected 3 disks, got %d", len(dom.Devices.Disks))
	}
	// First disk: virtio, cache=none.
	d0 := dom.Devices.Disks[0]
	if d0.Device != "disk" {
		t.Errorf("Disk[0].Device = %q", d0.Device)
	}
	if d0.Driver.Cache != "none" {
		t.Errorf("Disk[0].Cache = %q", d0.Driver.Cache)
	}
	if d0.Target.Dev != "vda" {
		t.Errorf("Disk[0].Target.Dev = %q", d0.Target.Dev)
	}
	if d0.Target.Bus != "virtio" {
		t.Errorf("Disk[0].Target.Bus = %q", d0.Target.Bus)
	}
	// Second disk: scsi, cache=writethrough.
	d1 := dom.Devices.Disks[1]
	if d1.Driver.Cache != "writethrough" {
		t.Errorf("Disk[1].Cache = %q", d1.Driver.Cache)
	}
	if d1.Target.Dev != "sdb" {
		t.Errorf("Disk[1].Target.Dev = %q", d1.Target.Dev)
	}
	// Third disk: cloud-init CDROM.
	d2 := dom.Devices.Disks[2]
	if d2.Device != "cdrom" {
		t.Errorf("Disk[2].Device = %q", d2.Device)
	}
	if d2.Readonly == nil {
		t.Error("cloud-init CDROM should be readonly")
	}
	if d2.Source.File != "/ci/roundtrip.iso" {
		t.Errorf("Disk[2].Source.File = %q", d2.Source.File)
	}

	// Interfaces: 2.
	if len(dom.Devices.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(dom.Devices.Interfaces))
	}
	if dom.Devices.Interfaces[0].MAC.Address != "52:54:00:11:22:33" {
		t.Errorf("Interface[0].MAC = %q", dom.Devices.Interfaces[0].MAC.Address)
	}
	if dom.Devices.Interfaces[0].Source.Bridge != "br0" {
		t.Errorf("Interface[0].Bridge = %q", dom.Devices.Interfaces[0].Source.Bridge)
	}
	if dom.Devices.Interfaces[1].Model.Type != "e1000" {
		t.Errorf("Interface[1].Model = %q", dom.Devices.Interfaces[1].Model.Type)
	}

	// Hostdevs: 1.
	if len(dom.Devices.Hostdevs) != 1 {
		t.Fatalf("expected 1 hostdev, got %d", len(dom.Devices.Hostdevs))
	}

	// Serial / console.
	if len(dom.Devices.Serials) != 1 {
		t.Errorf("expected 1 serial, got %d", len(dom.Devices.Serials))
	}
	if len(dom.Devices.Consoles) != 1 {
		t.Errorf("expected 1 console, got %d", len(dom.Devices.Consoles))
	}

	// Channel (guest agent).
	if len(dom.Devices.Channels) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(dom.Devices.Channels))
	}
	if dom.Devices.Channels[0].Target.Name != "org.qemu.guest_agent.0" {
		t.Errorf("Channel.Target.Name = %q", dom.Devices.Channels[0].Target.Name)
	}

	// Graphics (VNC).
	if len(dom.Devices.Graphics) != 1 {
		t.Fatalf("expected 1 graphics, got %d", len(dom.Devices.Graphics))
	}
	if dom.Devices.Graphics[0].Type != "vnc" {
		t.Errorf("Graphics.Type = %q", dom.Devices.Graphics[0].Type)
	}
	if dom.Devices.Graphics[0].Autoport != "yes" {
		t.Errorf("Graphics.Autoport = %q", dom.Devices.Graphics[0].Autoport)
	}
	if dom.Devices.Graphics[0].Listen.Address != "127.0.0.1" {
		t.Errorf("Graphics.Listen.Address = %q", dom.Devices.Graphics[0].Listen.Address)
	}

	// Video.
	if len(dom.Devices.Videos) != 1 {
		t.Fatalf("expected 1 video, got %d", len(dom.Devices.Videos))
	}
	if dom.Devices.Videos[0].Model.Type != "virtio" {
		t.Errorf("Video.Model.Type = %q", dom.Devices.Videos[0].Model.Type)
	}
}

// ── ISO disk handling ──

func TestGenerateDomainXML_ISODisk_Properties(t *testing.T) {
	cfg := VMConfig{
		Name:      "iso-props",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "installer", Path: "/images/os.iso", Bus: "sata", IsISO: true},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(dom.Devices.Disks) != 1 {
		t.Fatalf("expected 1 disk, got %d", len(dom.Devices.Disks))
	}
	d := dom.Devices.Disks[0]
	if d.Device != "cdrom" {
		t.Errorf("ISO disk should be cdrom, got %q", d.Device)
	}
	if d.Driver.Type != "raw" {
		t.Errorf("ISO driver type should be raw, got %q", d.Driver.Type)
	}
	if d.Target.Bus != "sata" {
		t.Errorf("ISO target bus should be sata, got %q", d.Target.Bus)
	}
	if d.Readonly == nil {
		t.Error("ISO disk should be readonly")
	}
	// sda for index 0.
	if d.Target.Dev != "sda" {
		t.Errorf("ISO target dev should be sda, got %q", d.Target.Dev)
	}
}

// ── diskDevName for higher indices ──

func TestDiskDevName_HighIndex(t *testing.T) {
	// Index 25 -> 'z'.
	got := diskDevName("virtio", 25)
	if got != "vdz" {
		t.Errorf("diskDevName(virtio, 25) = %q, want vdz", got)
	}
}

// ── XML starts with declaration ──

func TestGenerateDomainXML_XMLDeclaration(t *testing.T) {
	cfg := VMConfig{
		Name:      "decl-vm",
		CPU:       1,
		MemoryMiB: 256,
		Firmware:  "bios",
		Disks:     []DiskConfig{{Name: "r", Path: "/d.qcow2", Bus: "virtio"}},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.HasPrefix(xmlOut, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Error("XML should start with XML declaration header")
	}
}

// ── CanHotModify boundary values ──

func TestCanHotModify_BothIncrease(t *testing.T) {
	ok, reason := CanHotModify(1, 512, 2, 1024)
	if !ok {
		t.Errorf("expected ok=true, reason=%q", reason)
	}
}

func TestCanHotModify_CPUReduceMemIncrease(t *testing.T) {
	ok, _ := CanHotModify(4, 1024, 2, 2048)
	if ok {
		t.Error("CPU reduction should fail even if memory increases")
	}
}

func TestCanHotModify_MemReduceCPUIncrease(t *testing.T) {
	ok, _ := CanHotModify(2, 4096, 4, 2048)
	if ok {
		t.Error("memory reduction should fail even if CPU increases")
	}
}

func TestCanHotModify_BothReduce(t *testing.T) {
	ok, reason := CanHotModify(4, 8192, 2, 4096)
	if ok {
		t.Error("both reduce should fail")
	}
	// CPU check comes first.
	if !strings.Contains(reason, "CPU") {
		t.Errorf("reason should mention CPU, got: %q", reason)
	}
}

// ── VLAN access mode: verify exact args ──

func TestConfigureAccessBridgeVLAN_ExactArgs(t *testing.T) {
	orig := execVLAN
	defer func() { execVLAN = orig }()

	var capturedArgs []string
	execVLAN = func(name string, args ...string) ([]byte, error) {
		capturedArgs = append([]string{name}, args...)
		return nil, nil
	}

	if err := configureAccessBridgeVLAN("vnet5", 42); err != nil {
		t.Fatal(err)
	}

	expected := []string{"bridge", "vlan", "add", "dev", "vnet5", "vid", "42", "pvid", "untagged"}
	if len(capturedArgs) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(capturedArgs), capturedArgs)
	}
	for i := range expected {
		if capturedArgs[i] != expected[i] {
			t.Errorf("arg[%d] = %q, want %q", i, capturedArgs[i], expected[i])
		}
	}
}

// ── Multiple ISO disks: second ISO gets correct device name ──

func TestGenerateDomainXML_MultipleISOs(t *testing.T) {
	cfg := VMConfig{
		Name:      "multi-iso",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		Boot:      "cdrom",
		Disks: []DiskConfig{
			{Name: "os", Path: "/images/os.iso", Bus: "sata", IsISO: true},
			{Name: "tools", Path: "/images/tools.iso", Bus: "sata", IsISO: true},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// Index 0 -> sda, index 1 -> sdb.
	if !strings.Contains(xmlOut, `dev="sda"`) {
		t.Error("first ISO should be sda")
	}
	if !strings.Contains(xmlOut, `dev="sdb"`) {
		t.Error("second ISO should be sdb")
	}
}

// ── No disks at all ──

func TestGenerateDomainXML_NoDisks(t *testing.T) {
	cfg := VMConfig{
		Name:      "diskless",
		CPU:       1,
		MemoryMiB: 256,
		Firmware:  "bios",
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if strings.Contains(xmlOut, `<disk`) {
		t.Error("should have no disk elements")
	}
}

// ── DHCP leases: malformed line (too few fields) ──

func TestGetIPFromDHCPLeases_MalformedLines(t *testing.T) {
	tmp := t.TempDir()
	leaseFile := tmp + "/test.leases"
	content := "short line\n\n1234567890 52:54:00:aa:bb:cc 10.0.0.8 host *\n"
	if err := writeTestFile(leaseFile, content); err != nil {
		t.Fatal(err)
	}

	ip := GetIPFromDHCPLeases(tmp, "52:54:00:aa:bb:cc")
	if ip != "10.0.0.8" {
		t.Errorf("expected 10.0.0.8, got %q", ip)
	}
}

func TestGetIPFromDHCPLeases_InvalidDir(t *testing.T) {
	ip := GetIPFromDHCPLeases("/nonexistent/path", "52:54:00:aa:bb:cc")
	if ip != "" {
		t.Errorf("expected empty for invalid dir, got %q", ip)
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
