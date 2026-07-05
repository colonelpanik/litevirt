package libvirt

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestMachineTypeFromXML(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		want string
	}{
		{"resolved q35", `<domain><os><type arch="x86_64" machine="pc-q35-9.0">hvm</type></os></domain>`, "pc-q35-9.0"},
		{"alias only", `<domain><os><type arch="x86_64" machine="q35">hvm</type></os></domain>`, "q35"},
		{"no machine attr", `<domain><os><type arch="x86_64">hvm</type></os></domain>`, ""},
		{"malformed", `not xml`, ""},
		{"empty", ``, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MachineTypeFromXML(tc.xml); got != tc.want {
				t.Errorf("MachineTypeFromXML = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsPinnedMachineType(t *testing.T) {
	pinned := []string{"pc-q35-9.0", "pc-q35-8.2", "pc-i440fx-7.1", "virt-9.0"}
	notPinned := []string{"", "q35", "pc", "pc-q35", "virt", "pc-q35-"}
	for _, m := range pinned {
		if !IsPinnedMachineType(m) {
			t.Errorf("IsPinnedMachineType(%q) = false, want true", m)
		}
	}
	for _, m := range notPinned {
		if IsPinnedMachineType(m) {
			t.Errorf("IsPinnedMachineType(%q) = true, want false", m)
		}
	}
}

func TestIsQ35Machine(t *testing.T) {
	q35 := []string{"", "q35", "pc-q35", "pc-q35-9.0", "pc-q35-8.2"}
	notQ35 := []string{"pc", "pc-i440fx-7.1", "pc-i440fx", "microvm", "virt-9.0"}
	for _, m := range q35 {
		if !isQ35Machine(m) {
			t.Errorf("isQ35Machine(%q) = false, want true", m)
		}
	}
	for _, m := range notQ35 {
		if isQ35Machine(m) {
			t.Errorf("isQ35Machine(%q) = true, want false", m)
		}
	}
}

// TestSecureBoot_RejectsPinnedI440fx: a pinned i440fx machine must be rejected for
// Secure Boot (the pre-fix check only caught the bare "pc" alias).
func TestSecureBoot_RejectsPinnedI440fx(t *testing.T) {
	cfg := VMConfig{
		Name: "sb", CPU: 2, MemoryMiB: 2048, Machine: "pc-i440fx-7.1",
		Firmware: "uefi", SecureBoot: true, LoaderPath: "/l", NvramTemplate: "/n",
	}
	if _, err := GenerateDomainXML(cfg); err == nil {
		t.Fatal("expected Secure Boot on pinned i440fx to be rejected")
	}
	// A pinned q35 must pass the machine-type gate.
	cfg.Machine = "pc-q35-9.0"
	if _, err := GenerateDomainXML(cfg); err != nil {
		t.Fatalf("Secure Boot on pinned q35 should pass the machine gate, got: %v", err)
	}
}

func TestGenerateDomainXML_Basic(t *testing.T) {
	cfg := VMConfig{
		Name:       "test-vm",
		CPU:        4,
		MemoryMiB:  8192,
		Machine:    "q35",
		Firmware:   "uefi",
		GuestAgent: true,
		EnableVNC:  true,
		Disks: []DiskConfig{
			{Name: "root", Path: "/var/lib/litevirt/disks/test-vm/root.qcow2", Bus: "virtio"},
		},
		Networks: []NetworkConfig{
			{Bridge: "br0", Model: "virtio", MAC: "52:54:00:aa:bb:cc"},
		},
		CloudInitISO: "/var/lib/litevirt/cloudinit/test-vm.iso",
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	checks := []string{
		`<name>test-vm</name>`,
		`<vcpu>4</vcpu>`,
		`<memory unit="KiB">8388608</memory>`,
		`type="kvm"`,
		`machine="q35"`,
		`org.qemu.guest_agent.0`,
		`52:54:00:aa:bb:cc`,
		`bridge="br0"`,
		`root.qcow2`,
		`test-vm.iso`,
		`OVMF`,
		`type="vnc"`,
	}

	for _, check := range checks {
		if !strings.Contains(xmlOut, check) {
			t.Errorf("XML missing %q", check)
		}
	}
}

func TestGenerateDomainXML_BIOS(t *testing.T) {
	cfg := VMConfig{
		Name:      "bios-vm",
		CPU:       2,
		MemoryMiB: 2048,
		Machine:   "pc",
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if strings.Contains(xmlOut, "OVMF") {
		t.Error("BIOS mode should not have OVMF loader")
	}
	if strings.Contains(xmlOut, "guest_agent") {
		t.Error("guest agent should not be present when GuestAgent=false")
	}
	// Regression: libvirt's <os><boot dev=...> accepts only fd|hd|cdrom|network,
	// never "disk". The default boot ("disk") must be emitted as "hd", or
	// DomainDefineXML rejects the VM with
	// "Invalid value for attribute 'dev' in element 'boot': 'disk'".
	if !strings.Contains(xmlOut, `<boot dev="hd">`) {
		t.Errorf("BIOS mode should emit <boot dev=\"hd\">; got:\n%s", xmlOut)
	}
	if strings.Contains(xmlOut, `<boot dev="disk"`) {
		t.Error(`BIOS mode must not emit <boot dev="disk"> (invalid libvirt value)`)
	}
}

func TestLibvirtBootDev(t *testing.T) {
	cases := map[string]string{
		"disk":    "hd",
		"":        "hd",
		"cdrom":   "cdrom",
		"network": "network",
		"weird":   "hd",
	}
	for in, want := range cases {
		if got := libvirtBootDev(in); got != want {
			t.Errorf("libvirtBootDev(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGenerateDomainXML_VideoModelByFirmware(t *testing.T) {
	// virtio-gpu has no VGA BIOS: a BIOS guest needs a legacy VGA video model or
	// VNC stays black through firmware/GRUB. UEFI (OVMF) drives virtio-gpu fine.
	base := func(fw string) VMConfig {
		return VMConfig{
			Name: "vid-" + fw, CPU: 1, MemoryMiB: 512, Firmware: fw, EnableVNC: true,
			Disks: []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
		}
	}

	bios, err := GenerateDomainXML(base("bios"))
	if err != nil {
		t.Fatalf("bios: %v", err)
	}
	if !strings.Contains(bios, `<video>`) || !strings.Contains(bios, `<model type="vga">`) {
		t.Errorf("BIOS+VNC should use legacy vga video model; got:\n%s", bios)
	}

	uefi, err := GenerateDomainXML(base("uefi"))
	if err != nil {
		t.Fatalf("uefi: %v", err)
	}
	if !strings.Contains(uefi, `<video>`) || !strings.Contains(uefi, `<model type="virtio">`) {
		t.Errorf("UEFI+VNC should keep virtio video model; got:\n%s", uefi)
	}
}

func TestGenerateDomainXML_ISOBoot(t *testing.T) {
	cfg := VMConfig{
		Name:      "iso-vm",
		CPU:       2,
		MemoryMiB: 4096,
		Firmware:  "uefi",
		Boot:      "cdrom",
		Disks: []DiskConfig{
			{Name: "installer", Path: "/images/opnsense.iso", Bus: "sata", IsISO: true},
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// UEFI: no <boot dev="cdrom">, but the ISO disk should be present as a cdrom device.
	if strings.Contains(xmlOut, `<boot dev=`) {
		t.Error("UEFI should not have <boot dev=...>")
	}
	if !strings.Contains(xmlOut, `device="cdrom"`) {
		t.Error("expected ISO disk as cdrom device")
	}
}

func TestGenerateDomainXML_Defaults(t *testing.T) {
	cfg := VMConfig{
		Name:      "default-vm",
		CPU:       1,
		MemoryMiB: 512,
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// Default machine should be q35
	if !strings.Contains(xmlOut, `machine="q35"`) {
		t.Error("default machine should be q35")
	}
	// Default firmware is UEFI — no <boot dev="..."> element, boot order on disk instead.
	if strings.Contains(xmlOut, `<boot dev=`) {
		t.Error("UEFI should not have <boot dev=...>")
	}
	if !strings.Contains(xmlOut, `<boot order="1"`) {
		t.Error("UEFI should set boot order on first disk")
	}
	if !strings.Contains(xmlOut, "OVMF") {
		t.Error("empty firmware should default to UEFI")
	}
}

func TestGenerateDomainXML_MultipleDiskBuses(t *testing.T) {
	cfg := VMConfig{
		Name:      "multi-bus-vm",
		CPU:       2,
		MemoryMiB: 2048,
		Firmware:  "uefi",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio"},
			{Name: "data", Path: "/disks/data.qcow2", Bus: "scsi"},
			{Name: "backup", Path: "/disks/backup.qcow2", Bus: "sata"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.Contains(xmlOut, `dev="vda"`) {
		t.Error("virtio disk should be vda")
	}
	if !strings.Contains(xmlOut, `dev="sdb"`) {
		t.Error("scsi disk should be sdb")
	}
	if !strings.Contains(xmlOut, `dev="sdc"`) {
		t.Error("sata disk should be sdc")
	}
}

func TestGenerateDomainXML_MultipleNetworks(t *testing.T) {
	cfg := VMConfig{
		Name:      "multi-net-vm",
		CPU:       1,
		MemoryMiB: 1024,
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
		Networks: []NetworkConfig{
			{Bridge: "br0", Model: "virtio", MAC: "52:54:00:aa:bb:01"},
			{Bridge: "br1", Model: "e1000", MAC: "52:54:00:aa:bb:02"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.Contains(xmlOut, `bridge="br0"`) {
		t.Error("missing br0 bridge")
	}
	if !strings.Contains(xmlOut, `bridge="br1"`) {
		t.Error("missing br1 bridge")
	}
	if !strings.Contains(xmlOut, `type="e1000"`) {
		t.Error("missing e1000 model")
	}
	if strings.Count(xmlOut, `type="bridge"`) != 2 {
		t.Errorf("expected 2 bridge interfaces, got %d", strings.Count(xmlOut, `type="bridge"`))
	}
}

func TestGenerateDomainXML_NoNetworks(t *testing.T) {
	cfg := VMConfig{
		Name:      "no-net-vm",
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

	if strings.Contains(xmlOut, `type="bridge"`) {
		t.Error("should have no network interfaces")
	}
}

func TestGenerateDomainXML_AutoMAC(t *testing.T) {
	cfg := VMConfig{
		Name:      "auto-mac-vm",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
		Networks: []NetworkConfig{
			{Bridge: "br0"}, // no MAC specified
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// Should auto-generate a MAC with QEMU OUI
	if !strings.Contains(xmlOut, `address="52:54:00:`) {
		t.Error("auto-generated MAC should start with QEMU OUI prefix")
	}
}

func TestGenerateDomainXML_DefaultNetworkModel(t *testing.T) {
	cfg := VMConfig{
		Name:      "default-model-vm",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
		Networks: []NetworkConfig{
			{Bridge: "br0", MAC: "52:54:00:aa:bb:cc"}, // no model
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// Default model should be virtio
	if !strings.Contains(xmlOut, `type="virtio"`) {
		t.Error("default network model should be virtio")
	}
}

func TestGenerateDomainXML_DiskCacheDefault(t *testing.T) {
	cfg := VMConfig{
		Name:      "cache-vm",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"}, // no cache specified
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.Contains(xmlOut, `cache="writeback"`) {
		t.Error("default disk cache should be writeback")
	}
}

func TestGenerateDomainXML_DiskCacheExplicit(t *testing.T) {
	cfg := VMConfig{
		Name:      "cache-explicit-vm",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio", Cache: "none"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.Contains(xmlOut, `cache="none"`) {
		t.Error("explicit disk cache should be none")
	}
	if strings.Contains(xmlOut, `cache="writeback"`) {
		t.Error("should not have writeback when none is set")
	}
}

func TestGenerateDomainXML_NoCloudInit(t *testing.T) {
	cfg := VMConfig{
		Name:      "no-ci-vm",
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

	// Should have exactly 1 disk (root), no cloud-init CDROM
	if strings.Count(xmlOut, `device="cdrom"`) != 0 {
		t.Error("should not have any CDROMs when cloud-init is not set")
	}
}

func TestGenerateDomainXML_SerialConsole(t *testing.T) {
	cfg := VMConfig{
		Name:      "serial-vm",
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

	if !strings.Contains(xmlOut, `<serial type="pty"`) {
		t.Error("should have pty serial device")
	}
	if !strings.Contains(xmlOut, `<console type="pty"`) {
		t.Error("should have pty console device")
	}
}

func TestGenerateDomainXML_ValidXML(t *testing.T) {
	cfg := VMConfig{
		Name:       "valid-xml-vm",
		CPU:        2,
		MemoryMiB:  4096,
		Machine:    "q35",
		Firmware:   "uefi",
		GuestAgent: true,
		Disks: []DiskConfig{
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio"},
		},
		Networks: []NetworkConfig{
			{Bridge: "br0", Model: "virtio", MAC: "52:54:00:aa:bb:cc"},
		},
		CloudInitISO: "/cloudinit/test.iso",
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// Verify it's well-formed XML
	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("generated XML is not valid: %v", err)
	}

	if dom.Name != "valid-xml-vm" {
		t.Errorf("parsed name = %s, want valid-xml-vm", dom.Name)
	}
	if dom.Type != "kvm" {
		t.Errorf("parsed type = %s, want kvm", dom.Type)
	}
	if dom.VCPU.Value != 2 {
		t.Errorf("parsed vcpu = %d, want 2", dom.VCPU.Value)
	}
	if dom.Memory.Value != 4096*1024 {
		t.Errorf("parsed memory = %d, want %d", dom.Memory.Value, 4096*1024)
	}
}

func TestGenerateMAC(t *testing.T) {
	mac := GenerateMAC()
	if !strings.HasPrefix(mac, "52:54:00:") {
		t.Errorf("MAC should start with QEMU OUI prefix, got %s", mac)
	}
	if len(mac) != 17 {
		t.Errorf("MAC should be 17 chars, got %d: %s", len(mac), mac)
	}

	// Ensure randomness
	mac2 := GenerateMAC()
	if mac == mac2 {
		t.Error("two generated MACs should not be identical")
	}
}

func TestDiskDevName(t *testing.T) {
	tests := []struct {
		bus   string
		index int
		want  string
	}{
		{"virtio", 0, "vda"},
		{"virtio", 1, "vdb"},
		{"scsi", 0, "sda"},
		{"scsi", 2, "sdc"},
		{"sata", 0, "sda"},
		{"sata", 1, "sdb"},
		{"ide", 0, "hda"},
		{"ide", 1, "hdb"},
		{"unknown", 0, "vda"}, // default to virtio naming
	}

	for _, tt := range tests {
		t.Run(tt.bus+"_"+tt.want, func(t *testing.T) {
			got := DiskDevName(tt.bus, tt.index)
			if got != tt.want {
				t.Errorf("DiskDevName(%s, %d) = %s, want %s", tt.bus, tt.index, got, tt.want)
			}
		})
	}
}

func TestDiskPath(t *testing.T) {
	path := DiskPath("/var/lib/litevirt", "myvm", "root")
	if path != "/var/lib/litevirt/disks/myvm-root.qcow2" {
		t.Errorf("unexpected disk path: %s", path)
	}
}

func TestCloudInitISOPath(t *testing.T) {
	path := CloudInitISOPath("/var/lib/litevirt", "myvm")
	if path != "/var/lib/litevirt/cloudinit/myvm.iso" {
		t.Errorf("unexpected cloud-init path: %s", path)
	}
}

func TestImagePath(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"ubuntu-24", "/data/images/ubuntu-24.qcow2"},
		{"opnsense.iso", "/data/images/opnsense.iso"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ImagePath("/data", tt.name)
			if got != tt.want {
				t.Errorf("ImagePath(%s) = %s, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestGenerateDomainXML_MemoryConversion(t *testing.T) {
	cfg := VMConfig{
		Name:      "mem-vm",
		CPU:       1,
		MemoryMiB: 1024, // 1 GiB
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	// 1024 MiB = 1048576 KiB
	if !strings.Contains(xmlOut, `<memory unit="KiB">1048576</memory>`) {
		t.Error("memory should be converted to KiB correctly (1024 MiB = 1048576 KiB)")
	}
}

func TestGenerateDomainXML_Features(t *testing.T) {
	cfg := VMConfig{
		Name:      "feat-vm",
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

	if !strings.Contains(xmlOut, "<acpi") {
		t.Error("should have ACPI feature")
	}
	if !strings.Contains(xmlOut, "<apic") {
		t.Error("should have APIC feature")
	}
}

func TestGenerateDomainXML_VNCEnabled(t *testing.T) {
	cfg := VMConfig{
		Name:      "vnc-vm",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		EnableVNC: true,
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if !strings.Contains(xmlOut, `type="vnc"`) {
		t.Error("EnableVNC=true should include VNC graphics device")
	}
	if !strings.Contains(xmlOut, `<video>`) {
		t.Error("EnableVNC=true should include video device")
	}
}

func TestGenerateDomainXML_VNCDisabled(t *testing.T) {
	cfg := VMConfig{
		Name:      "headless-vm",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		EnableVNC: false,
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	if strings.Contains(xmlOut, `type="vnc"`) {
		t.Error("EnableVNC=false should not include VNC graphics device")
	}
	if strings.Contains(xmlOut, `<video>`) {
		t.Error("EnableVNC=false should not include video device")
	}
	// Serial console should still be present
	if !strings.Contains(xmlOut, `<serial type="pty"`) {
		t.Error("headless VM should still have serial console")
	}
}

func TestGenerateDomainXML_DirectNetwork(t *testing.T) {
	cfg := VMConfig{
		Name:      "direct-vm",
		CPU:       2,
		MemoryMiB: 4096,
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
		Networks: []NetworkConfig{
			{Direct: "bond0.206", Model: "virtio", MAC: "52:54:00:dd:ee:ff"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	checks := []string{
		`type="direct"`,
		`dev="bond0.206"`,
		`mode="bridge"`,
		`52:54:00:dd:ee:ff`,
		`type="virtio"`,
	}
	for _, check := range checks {
		if !strings.Contains(xmlOut, check) {
			t.Errorf("XML missing %q", check)
		}
	}

	// Must NOT contain bridge= attribute (that's only for bridge type)
	if strings.Contains(xmlOut, `bridge=`) {
		t.Error("direct network should not have bridge= attribute")
	}
	// Must NOT contain type="bridge" (interface type should be "direct")
	if strings.Contains(xmlOut, `type="bridge"`) {
		t.Error("direct network should not have type=\"bridge\" interface")
	}

	// Verify valid XML and correct structure via unmarshal
	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("generated XML is not valid: %v", err)
	}
	if len(dom.Devices.Interfaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(dom.Devices.Interfaces))
	}
	iface := dom.Devices.Interfaces[0]
	if iface.Type != "direct" {
		t.Errorf("interface type = %s, want direct", iface.Type)
	}
	if iface.Source.Dev != "bond0.206" {
		t.Errorf("source dev = %s, want bond0.206", iface.Source.Dev)
	}
	if iface.Source.Mode != "bridge" {
		t.Errorf("source mode = %s, want bridge", iface.Source.Mode)
	}
	if iface.MAC.Address != "52:54:00:dd:ee:ff" {
		t.Errorf("mac = %s, want 52:54:00:dd:ee:ff", iface.MAC.Address)
	}
}

func TestGenerateDomainXML_DirectAndBridgeMixed(t *testing.T) {
	cfg := VMConfig{
		Name:      "mixed-net-vm",
		CPU:       1,
		MemoryMiB: 1024,
		Firmware:  "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disk.qcow2", Bus: "virtio"},
		},
		Networks: []NetworkConfig{
			{Bridge: "br0", Model: "virtio", MAC: "52:54:00:aa:bb:01"},
			{Direct: "eth0.100", Model: "virtio", MAC: "52:54:00:aa:bb:02"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("generated XML is not valid: %v", err)
	}
	if len(dom.Devices.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(dom.Devices.Interfaces))
	}

	// First interface: bridge
	if dom.Devices.Interfaces[0].Type != "bridge" {
		t.Errorf("first interface type = %s, want bridge", dom.Devices.Interfaces[0].Type)
	}
	if dom.Devices.Interfaces[0].Source.Bridge != "br0" {
		t.Errorf("first interface bridge = %s, want br0", dom.Devices.Interfaces[0].Source.Bridge)
	}

	// Second interface: direct
	if dom.Devices.Interfaces[1].Type != "direct" {
		t.Errorf("second interface type = %s, want direct", dom.Devices.Interfaces[1].Type)
	}
	if dom.Devices.Interfaces[1].Source.Dev != "eth0.100" {
		t.Errorf("second interface dev = %s, want eth0.100", dom.Devices.Interfaces[1].Source.Dev)
	}
	if dom.Devices.Interfaces[1].Source.Mode != "bridge" {
		t.Errorf("second interface mode = %s, want bridge", dom.Devices.Interfaces[1].Source.Mode)
	}
}

func TestGenerateDomainXML_Lifecycle(t *testing.T) {
	cfg := VMConfig{
		Name:      "lifecycle-vm",
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

	if !strings.Contains(xmlOut, "<on_poweroff>destroy</on_poweroff>") {
		t.Error("on_poweroff should be destroy")
	}
	if !strings.Contains(xmlOut, "<on_reboot>restart</on_reboot>") {
		t.Error("on_reboot should be restart")
	}
	if !strings.Contains(xmlOut, "<on_crash>destroy</on_crash>") {
		t.Error("on_crash should be destroy")
	}
}

// TestGenerateDomainXML_SPICE verifies that EnableSPICE produces a SPICE
// graphics device alongside (or instead of) VNC.
func TestGenerateDomainXML_SPICE(t *testing.T) {
	cfg := VMConfig{
		Name:        "spice-vm",
		CPU:         2,
		MemoryMiB:   2048,
		Machine:     "q35",
		Firmware:    "bios",
		EnableVNC:   true,
		EnableSPICE: true,
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if !strings.Contains(xmlOut, `type="vnc"`) {
		t.Errorf("expected VNC graphics; got:\n%s", xmlOut)
	}
	if !strings.Contains(xmlOut, `type="spice"`) {
		t.Errorf("expected SPICE graphics; got:\n%s", xmlOut)
	}
}

// TestGenerateDomainXML_SPICEOnly verifies a headless-VNC + SPICE combo.
func TestGenerateDomainXML_SPICEOnly(t *testing.T) {
	cfg := VMConfig{
		Name:        "spice-only",
		CPU:         2,
		MemoryMiB:   2048,
		Machine:     "q35",
		Firmware:    "bios",
		EnableVNC:   false,
		EnableSPICE: true,
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if strings.Contains(xmlOut, `type="vnc"`) {
		t.Errorf("VNC should be absent; got:\n%s", xmlOut)
	}
	if !strings.Contains(xmlOut, `type="spice"`) {
		t.Errorf("expected SPICE graphics; got:\n%s", xmlOut)
	}
	// A video device should still be present (SPICE needs one).
	if !strings.Contains(xmlOut, `<video>`) {
		t.Errorf("expected video device for SPICE-only VM; got:\n%s", xmlOut)
	}
}
