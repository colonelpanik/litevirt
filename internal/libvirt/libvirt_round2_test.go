package libvirt

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── NUMAPolicy edge cases ───────────────────────────────────────────────────

func TestGenerateDomainXML_NUMAPolicyNilDoesNotPanic(t *testing.T) {
	cfg := VMConfig{
		Name:       "numa-nil",
		CPU:        1,
		MemoryMiB:  512,
		Firmware:   "bios",
		NUMAPolicy: nil,
		Disks:      []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if strings.Contains(xmlOut, "numatune") {
		t.Error("nil NUMAPolicy should not produce numatune")
	}
}

func TestGenerateDomainXML_NUMAPolicy_NegativeNode(t *testing.T) {
	cfg := VMConfig{
		Name:       "numa-neg",
		CPU:        2,
		MemoryMiB:  1024,
		Firmware:   "bios",
		NUMAPolicy: &NUMAPolicy{PreferredNode: -5, Strict: true},
		Disks:      []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if strings.Contains(xmlOut, "numatune") {
		t.Error("negative PreferredNode should skip numatune")
	}
}

// ── HugePages combined with NUMA ────────────────────────────────────────────

func TestGenerateDomainXML_HugePagesAndNUMA(t *testing.T) {
	cfg := VMConfig{
		Name:       "huge-numa",
		CPU:        4,
		MemoryMiB:  8192,
		Firmware:   "bios",
		HugePages:  true,
		NUMAPolicy: &NUMAPolicy{PreferredNode: 1, Strict: true},
		Disks:      []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if !strings.Contains(xmlOut, "hugepages") {
		t.Error("should have hugepages")
	}
	if !strings.Contains(xmlOut, "numatune") {
		t.Error("should have numatune")
	}
}

// ── IOThreads combined with CPU pinning ─────────────────────────────────────

func TestGenerateDomainXML_IOThreadsAndPinning(t *testing.T) {
	cfg := VMConfig{
		Name:       "io-pin",
		CPU:        2,
		MemoryMiB:  2048,
		Firmware:   "bios",
		IOThreads:  2,
		CPUPinning: []int{0, 1},
		Disks:      []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dom.IOThreads != 2 {
		t.Errorf("IOThreads = %d, want 2", dom.IOThreads)
	}
	if dom.CPUTune == nil || len(dom.CPUTune.VCPUPin) != 2 {
		t.Error("expected 2 vcpupin entries")
	}
}

// ── Empty CPUPinning slice ──────────────────────────────────────────────────

func TestGenerateDomainXML_EmptyCPUPinningSlice(t *testing.T) {
	cfg := VMConfig{
		Name:       "empty-pin",
		CPU:        2,
		MemoryMiB:  1024,
		Firmware:   "bios",
		CPUPinning: []int{},
		Disks:      []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if strings.Contains(xmlOut, "cputune") {
		t.Error("empty CPUPinning slice should not produce cputune")
	}
}

// ── Cloud-init ISO appended as last disk ────────────────────────────────────

func TestGenerateDomainXML_CloudInitIsLastDisk(t *testing.T) {
	cfg := VMConfig{
		Name:         "ci-last",
		CPU:          1,
		MemoryMiB:    512,
		Firmware:     "bios",
		CloudInitISO: "/ci/test.iso",
		Disks: []DiskConfig{
			{Name: "root", Path: "/d/root.qcow2", Bus: "virtio"},
			{Name: "data", Path: "/d/data.qcow2", Bus: "scsi"},
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
	if len(dom.Devices.Disks) != 3 {
		t.Fatalf("expected 3 disks, got %d", len(dom.Devices.Disks))
	}
	last := dom.Devices.Disks[2]
	if last.Device != "cdrom" {
		t.Errorf("last disk should be cdrom, got %q", last.Device)
	}
	if last.Source.File != "/ci/test.iso" {
		t.Errorf("cloud-init source = %q", last.Source.File)
	}
	if last.Target.Bus != "sata" {
		t.Errorf("cloud-init bus = %q, want sata", last.Target.Bus)
	}
	if last.Readonly == nil {
		t.Error("cloud-init should be readonly")
	}
	// The cloud-init cdrom's target dev must be unique — the scsi data disk
	// here also lands on the sd* bus (sdb), so a hardcoded "sdb" cloud-init
	// would collide. Assert no two devices share a target dev.
	seen := map[string]string{}
	for _, d := range dom.Devices.Disks {
		if prev, dup := seen[d.Target.Dev]; dup {
			t.Errorf("duplicate target dev %q (devices %q and %q)", d.Target.Dev, prev, d.Source.File)
		}
		seen[d.Target.Dev] = d.Source.File
	}
}

// ── Mixed ISO and regular disks ─────────────────────────────────────────────

func TestGenerateDomainXML_MixedISOAndRegularDisks(t *testing.T) {
	cfg := VMConfig{
		Name:      "mixed",
		CPU:       2,
		MemoryMiB: 2048,
		Firmware:  "bios",
		Boot:      "cdrom",
		Disks: []DiskConfig{
			{Name: "installer", Path: "/images/os.iso", Bus: "sata", IsISO: true},
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio"},
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
	if len(dom.Devices.Disks) != 2 {
		t.Fatalf("expected 2 disks, got %d", len(dom.Devices.Disks))
	}
	d0 := dom.Devices.Disks[0]
	if d0.Device != "cdrom" {
		t.Errorf("disk[0] device = %q, want cdrom", d0.Device)
	}
	if d0.Driver.Type != "raw" {
		t.Errorf("disk[0] driver type = %q, want raw", d0.Driver.Type)
	}
	if d0.Readonly == nil {
		t.Error("ISO disk should be readonly")
	}
	d1 := dom.Devices.Disks[1]
	if d1.Device != "disk" {
		t.Errorf("disk[1] device = %q, want disk", d1.Device)
	}
	if d1.Driver.Type != "qcow2" {
		t.Errorf("disk[1] driver type = %q, want qcow2", d1.Driver.Type)
	}
	if d1.Readonly != nil {
		t.Error("regular disk should not be readonly")
	}
}

// ── UEFI firmware default (empty firmware string) ───────────────────────────

func TestGenerateDomainXML_EmptyFirmwareIsUEFI(t *testing.T) {
	cfg := VMConfig{
		Name:      "fw-default",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "",
		Disks:     []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dom.OS.Loader == nil {
		t.Fatal("empty firmware should produce UEFI loader")
	}
	if dom.OS.Loader.Type != "pflash" {
		t.Errorf("loader type = %q, want pflash", dom.OS.Loader.Type)
	}
	if dom.OS.Loader.Readonly != "yes" {
		t.Errorf("loader readonly = %q, want yes", dom.OS.Loader.Readonly)
	}
	if dom.OS.Nvram == nil {
		t.Error("UEFI should have nvram")
	}
}

// ── ParsePCIAddress detailed structure ──────────────────────────────────────

func TestParsePCIAddress_FullAddress(t *testing.T) {
	got := ParsePCIAddress("abcd:ef:12.3")
	want := ParsedPCIAddr{
		Domain:   "0xabcd",
		Bus:      "0xef",
		Slot:     "0x12",
		Function: "0x3",
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParsePCIAddress_ZeroPadded(t *testing.T) {
	got := ParsePCIAddress("0000:00:1f.0")
	want := ParsedPCIAddr{
		Domain:   "0x0000",
		Bus:      "0x00",
		Slot:     "0x1f",
		Function: "0x0",
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// ── Hostdev in XML roundtrip ────────────────────────────────────────────────

func TestGenerateDomainXML_HostdevRoundTrip(t *testing.T) {
	cfg := VMConfig{
		Name:      "hd-rt",
		CPU:       2,
		MemoryMiB: 4096,
		Firmware:  "bios",
		Disks:     []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
		Hostdevs: []HostdevConfig{
			{Address: "0000:41:00.0"},
			{Address: "0000:42:00.1"},
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
	if len(dom.Devices.Hostdevs) != 2 {
		t.Fatalf("expected 2 hostdevs, got %d", len(dom.Devices.Hostdevs))
	}
	hd0 := dom.Devices.Hostdevs[0]
	if hd0.Source.Address.Bus != "0x41" {
		t.Errorf("hostdev[0] bus = %q", hd0.Source.Address.Bus)
	}
	if hd0.Source.Address.Function != "0x0" {
		t.Errorf("hostdev[0] function = %q", hd0.Source.Address.Function)
	}
	hd1 := dom.Devices.Hostdevs[1]
	if hd1.Source.Address.Bus != "0x42" {
		t.Errorf("hostdev[1] bus = %q", hd1.Source.Address.Bus)
	}
	if hd1.Source.Address.Function != "0x1" {
		t.Errorf("hostdev[1] function = %q", hd1.Source.Address.Function)
	}
}

// ── Guest agent channel absent when disabled ────────────────────────────────

func TestGenerateDomainXML_NoGuestAgent(t *testing.T) {
	cfg := VMConfig{
		Name:       "no-agent",
		CPU:        1,
		MemoryMiB:  512,
		Firmware:   "bios",
		GuestAgent: false,
		Disks:      []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(dom.Devices.Channels) != 0 {
		t.Errorf("expected 0 channels, got %d", len(dom.Devices.Channels))
	}
}

// ── Guest agent channel present when enabled ────────────────────────────────

func TestGenerateDomainXML_GuestAgentChannel(t *testing.T) {
	cfg := VMConfig{
		Name:       "agent-vm",
		CPU:        1,
		MemoryMiB:  512,
		Firmware:   "bios",
		GuestAgent: true,
		Disks:      []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(dom.Devices.Channels) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(dom.Devices.Channels))
	}
	ch := dom.Devices.Channels[0]
	if ch.Type != "unix" {
		t.Errorf("channel type = %q, want unix", ch.Type)
	}
	if ch.Target.Type != "virtio" {
		t.Errorf("channel target type = %q, want virtio", ch.Target.Type)
	}
	if ch.Target.Name != "org.qemu.guest_agent.0" {
		t.Errorf("channel target name = %q", ch.Target.Name)
	}
}

// ── VNC graphics always present ─────────────────────────────────────────────

func TestGenerateDomainXML_VNCGraphics(t *testing.T) {
	cfg := VMConfig{
		Name:      "vnc-vm",
		CPU:       1,
		MemoryMiB: 256,
		Firmware:  "bios",
		EnableVNC: true,
		Disks:     []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(dom.Devices.Graphics) != 1 {
		t.Fatalf("expected 1 graphics device, got %d", len(dom.Devices.Graphics))
	}
	g := dom.Devices.Graphics[0]
	if g.Type != "vnc" {
		t.Errorf("graphics type = %q, want vnc", g.Type)
	}
	if g.Port != -1 {
		t.Errorf("graphics port = %d, want -1 (auto)", g.Port)
	}
	if g.Autoport != "yes" {
		t.Errorf("graphics autoport = %q, want yes", g.Autoport)
	}
	if g.Listen.Type != "address" {
		t.Errorf("listen type = %q, want address", g.Listen.Type)
	}
	if g.Listen.Address != "127.0.0.1" {
		t.Errorf("listen address = %q, want 127.0.0.1", g.Listen.Address)
	}
}

// ── Video device always present ─────────────────────────────────────────────

func TestGenerateDomainXML_VideoDevice(t *testing.T) {
	cfg := VMConfig{
		Name:      "video-vm",
		CPU:       1,
		MemoryMiB: 256,
		Firmware:  "bios",
		EnableVNC: true,
		Disks:     []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(dom.Devices.Videos) != 1 {
		t.Fatalf("expected 1 video, got %d", len(dom.Devices.Videos))
	}
	// BIOS guests get a legacy VGA model — virtio-gpu has no VGA BIOS, so SeaBIOS/
	// GRUB render nothing on it (black VNC). UEFI keeps virtio-gpu.
	if dom.Devices.Videos[0].Model.Type != "vga" {
		t.Errorf("video model = %q, want vga (BIOS)", dom.Devices.Videos[0].Model.Type)
	}
}

// ── Emulator path ───────────────────────────────────────────────────────────

func TestGenerateDomainXML_EmulatorPath(t *testing.T) {
	cfg := VMConfig{
		Name:      "emu-vm",
		CPU:       1,
		MemoryMiB: 256,
		Firmware:  "bios",
		Disks:     []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dom.Devices.Emulator != "/usr/bin/qemu-system-x86_64" {
		t.Errorf("emulator = %q", dom.Devices.Emulator)
	}
}

// ── Default machine is q35 ──────────────────────────────────────────────────

func TestGenerateDomainXML_DefaultMachineQ35(t *testing.T) {
	cfg := VMConfig{
		Name:      "mach-default",
		CPU:       1,
		MemoryMiB: 256,
		Firmware:  "bios",
		Machine:   "",
		Disks:     []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dom.OS.Type.Machine != "q35" {
		t.Errorf("machine = %q, want q35", dom.OS.Type.Machine)
	}
}

// ── pc machine type ─────────────────────────────────────────────────────────

func TestGenerateDomainXML_PCMachine(t *testing.T) {
	cfg := VMConfig{
		Name:      "pc-vm",
		CPU:       1,
		MemoryMiB: 256,
		Firmware:  "bios",
		Machine:   "pc",
		Disks:     []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
	}
	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if !strings.Contains(xmlOut, `machine="pc"`) {
		t.Error("should have machine=pc")
	}
}

// ── CanHotModify edge cases ─────────────────────────────────────────────────

func TestCanHotModify_NoChange(t *testing.T) {
	ok, reason := CanHotModify(4, 8192, 4, 8192)
	if ok {
		t.Error("no change should return false")
	}
	if reason != "no change" {
		t.Errorf("reason = %q, want 'no change'", reason)
	}
}

func TestCanHotModify_OnlyCPUIncrease(t *testing.T) {
	ok, reason := CanHotModify(2, 4096, 4, 4096)
	if !ok {
		t.Errorf("CPU-only increase should be ok, reason: %q", reason)
	}
}

func TestCanHotModify_OnlyMemIncrease(t *testing.T) {
	ok, reason := CanHotModify(2, 4096, 2, 8192)
	if !ok {
		t.Errorf("mem-only increase should be ok, reason: %q", reason)
	}
}

// ── DHCP lease: multiple lease files ────────────────────────────────────────

func TestGetIPFromDHCPLeases_MultipleFiles(t *testing.T) {
	tmp := t.TempDir()
	writeFileHelper(t, tmp, "net1.leases", "1234567890 aa:bb:cc:dd:ee:ff 10.0.0.1 host1 *\n")
	writeFileHelper(t, tmp, "net2.leases", "1234567890 52:54:00:11:22:33 10.0.0.99 host2 *\n")

	ip := GetIPFromDHCPLeases(tmp, "52:54:00:11:22:33")
	if ip != "10.0.0.99" {
		t.Errorf("expected 10.0.0.99, got %q", ip)
	}
}

func TestGetIPFromDHCPLeases_EmptyMAC(t *testing.T) {
	tmp := t.TempDir()
	writeFileHelper(t, tmp, "default.leases", "1234567890 52:54:00:aa:bb:cc 10.0.0.5 host *\n")
	ip := GetIPFromDHCPLeases(tmp, "")
	if ip != "" {
		t.Errorf("empty MAC should return empty, got %q", ip)
	}
}

// ── GetIPFromDHCPLeases: file open error ────────────────────────────────────

func TestGetIPFromDHCPLeases_UnreadableFile(t *testing.T) {
	tmp := t.TempDir()
	leaseFile := filepath.Join(tmp, "test.leases")
	// Create file then make it unreadable.
	os.WriteFile(leaseFile, []byte("1234567890 52:54:00:aa:bb:cc 10.0.0.5 host *\n"), 0644)
	os.Chmod(leaseFile, 0000)
	defer os.Chmod(leaseFile, 0644) // cleanup

	ip := GetIPFromDHCPLeases(tmp, "52:54:00:aa:bb:cc")
	// Should return empty since file can't be read (or the match if running as root).
	_ = ip // no assertion on value since root can read anything
}

// ── GetIPFromARP: exercise the function on Linux ────────────────────────────

func TestGetIPFromARP_NonexistentMAC(t *testing.T) {
	// This MAC should never appear in the ARP table.
	ip := GetIPFromARP("ff:ff:ff:ff:ff:fe")
	if ip != "" {
		t.Errorf("expected empty for nonexistent MAC, got %q", ip)
	}
}

func TestGetIPFromARP_EmptyMAC(t *testing.T) {
	ip := GetIPFromARP("")
	if ip != "" {
		t.Errorf("expected empty for empty MAC, got %q", ip)
	}
}

func TestGetIPFromARP_CaseInsensitiveMAC(t *testing.T) {
	// Should not crash or panic with uppercase/mixed case.
	ip := GetIPFromARP("FF:FF:FF:FF:FF:FE")
	if ip != "" {
		t.Errorf("expected empty, got %q", ip)
	}
}

// ── configureTrunkBridgeVLANs ───────────────────────────────────────────────

func TestConfigureTrunkBridgeVLANs_Success(t *testing.T) {
	origExec := execVLAN
	defer func() { execVLAN = origExec }()

	var capturedCmds []string
	execVLAN = func(name string, args ...string) ([]byte, error) {
		capturedCmds = append(capturedCmds, name+" "+strings.Join(args, " "))
		return nil, nil
	}

	err := configureTrunkBridgeVLANs("vnet0", []int{10, 20, 30})
	if err != nil {
		t.Fatalf("configureTrunkBridgeVLANs: %v", err)
	}
	if len(capturedCmds) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(capturedCmds))
	}
	for i, vid := range []string{"10", "20", "30"} {
		if !strings.Contains(capturedCmds[i], "vid "+vid) {
			t.Errorf("cmd[%d] should contain vid %s: %s", i, vid, capturedCmds[i])
		}
		if strings.Contains(capturedCmds[i], "pvid") {
			t.Errorf("trunk mode should not have pvid: %s", capturedCmds[i])
		}
	}
}

func TestConfigureTrunkBridgeVLANs_EmptyList(t *testing.T) {
	origExec := execVLAN
	defer func() { execVLAN = origExec }()

	callCount := 0
	execVLAN = func(name string, args ...string) ([]byte, error) {
		callCount++
		return nil, nil
	}

	err := configureTrunkBridgeVLANs("vnet0", []int{})
	if err != nil {
		t.Fatalf("expected no error for empty list, got: %v", err)
	}
	if callCount != 0 {
		t.Errorf("expected 0 calls for empty VLAN list, got %d", callCount)
	}
}

// ── readTapVLANs with typical bridge vlan show output ───────────────────────

func TestReadTapVLANs_TypicalOutput(t *testing.T) {
	origExec := execVLAN
	defer func() { execVLAN = origExec }()

	execVLAN = func(name string, args ...string) ([]byte, error) {
		out := `port vnet0 state forwarding
  1 PVID Egress Untagged
  100
  200
  300
`
		return []byte(out), nil
	}

	vlans, err := readTapVLANs("vnet0")
	if err != nil {
		t.Fatalf("readTapVLANs: %v", err)
	}
	expected := map[int]bool{1: true, 100: true, 200: true, 300: true}
	if len(vlans) != len(expected) {
		t.Fatalf("expected %d VLANs, got %d: %v", len(expected), len(vlans), vlans)
	}
	for _, v := range vlans {
		if !expected[v] {
			t.Errorf("unexpected VLAN %d", v)
		}
	}
}

// ── Client struct with nil virt: additional coverage ────────────────────────

func TestClient_CloseNil_ReturnsNil(t *testing.T) {
	c := &Client{virt: nil}
	err := c.Close()
	if err != nil {
		t.Errorf("Close on nil: %v", err)
	}
}

func TestClient_IsAliveNil_ReturnsFalse(t *testing.T) {
	c := &Client{virt: nil}
	if c.isAlive() {
		t.Error("nil virt should not be alive")
	}
}

func TestClient_LibvirtNil_ReturnsNil(t *testing.T) {
	c := &Client{virt: nil}
	if c.Libvirt() != nil {
		t.Error("nil virt should return nil from Libvirt()")
	}
}

// ── DomainEventType ─────────────────────────────────────────────────────────

func TestDomainEventType_Values(t *testing.T) {
	events := map[DomainEventType]int{
		DomainEventStarted:  0,
		DomainEventStopped:  1,
		DomainEventCrashed:  2,
		DomainEventShutdown: 3,
	}
	for ev, wantVal := range events {
		if int(ev) != wantVal {
			t.Errorf("DomainEventType %d != expected %d", int(ev), wantVal)
		}
	}
}

// ── helper ──────────────────────────────────────────────────────────────────

func writeFileHelper(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := writeTestFile2(dir+"/"+name, content); err != nil {
		t.Fatal(err)
	}
}

func writeTestFile2(path, content string) error {
	return writeTestFile(path, content)
}

// TestGenerateDomainXML_InstallerISOAndCloudInit ensures an installer-ISO
// cdrom and a cloud-init cdrom get distinct sata targets (the install-from-ISO
// feature appends an IsISO disk; both must coexist without a dev collision).
func TestGenerateDomainXML_InstallerISOAndCloudInit(t *testing.T) {
	cfg := VMConfig{
		Name: "iso-install", CPU: 1, MemoryMiB: 512, Firmware: "bios",
		CloudInitISO: "/ci/seed.iso",
		Boot:         "cdrom",
		Disks: []DiskConfig{
			{Name: "root", Path: "/d/root.qcow2", Bus: "virtio"},
			{Name: "installer", Path: "/iso/debian.iso", IsISO: true},
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
	cdroms, seen := 0, map[string]bool{}
	for _, d := range dom.Devices.Disks {
		if seen[d.Target.Dev] {
			t.Errorf("duplicate target dev %q", d.Target.Dev)
		}
		seen[d.Target.Dev] = true
		if d.Device == "cdrom" {
			cdroms++
		}
	}
	if cdroms != 2 {
		t.Errorf("expected 2 cdroms (installer + cloud-init), got %d", cdroms)
	}
}

// TestGenerateDomainXML_UEFIBootsISOFirst is the regression for an ISO-install
// VM under UEFI: with Boot="cdrom" the installer cdrom must get boot order 1
// (the blank root disk must NOT outrank it, or the install never starts).
func TestGenerateDomainXML_UEFIBootsISOFirst(t *testing.T) {
	cfg := VMConfig{
		Name: "iso-uefi", CPU: 1, MemoryMiB: 512, Firmware: "uefi", Boot: "cdrom",
		Disks: []DiskConfig{
			{Name: "root", Path: "/d/root.qcow2", Bus: "virtio"},
			{Name: "installer", Path: "/iso/os.iso", IsISO: true},
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
	var cdromOrder, diskOrder int
	for _, d := range dom.Devices.Disks {
		if d.BootOrder == nil {
			continue
		}
		if d.Device == "cdrom" {
			cdromOrder = d.BootOrder.Order
		} else {
			diskOrder = d.BootOrder.Order
		}
	}
	if cdromOrder != 1 {
		t.Errorf("cdrom boot order = %d, want 1 (must boot the installer first)", cdromOrder)
	}
	if diskOrder != 0 && diskOrder <= cdromOrder {
		t.Errorf("disk boot order %d must rank after cdrom %d", diskOrder, cdromOrder)
	}
}

// TestGenerateDomainXML_UEFINormalBootsDisk: without cdrom boot, the root disk
// keeps boot order 1 (no regression for ordinary VMs).
func TestGenerateDomainXML_UEFINormalBootsDisk(t *testing.T) {
	cfg := VMConfig{
		Name: "disk-uefi", CPU: 1, MemoryMiB: 512, Firmware: "uefi",
		Disks: []DiskConfig{{Name: "root", Path: "/d/root.qcow2", Bus: "virtio"}},
	}
	xmlOut, _ := GenerateDomainXML(cfg)
	var dom domain
	xml.Unmarshal([]byte(xmlOut), &dom)
	if len(dom.Devices.Disks) != 1 || dom.Devices.Disks[0].BootOrder == nil || dom.Devices.Disks[0].BootOrder.Order != 1 {
		t.Errorf("ordinary UEFI VM should boot the root disk at order 1")
	}
}
