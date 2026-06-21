package libvirt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiskPath_Variants(t *testing.T) {
	tests := []struct {
		dataDir  string
		vmName   string
		diskName string
		want     string
	}{
		{"/var/lib/litevirt", "web-1", "root", "/var/lib/litevirt/disks/web-1-root.qcow2"},
		{"/data", "db", "data", "/data/disks/db-data.qcow2"},
		{"/", "vm", "disk", "/disks/vm-disk.qcow2"},
	}
	for _, tt := range tests {
		got := DiskPath(tt.dataDir, tt.vmName, tt.diskName)
		if got != tt.want {
			t.Errorf("DiskPath(%q, %q, %q) = %q, want %q", tt.dataDir, tt.vmName, tt.diskName, got, tt.want)
		}
	}
}

func TestCloudInitISOPath_Variants(t *testing.T) {
	tests := []struct {
		dataDir string
		vmName  string
		want    string
	}{
		{"/var/lib/litevirt", "web-1", "/var/lib/litevirt/cloudinit/web-1.iso"},
		{"/data", "test-vm", "/data/cloudinit/test-vm.iso"},
	}
	for _, tt := range tests {
		got := CloudInitISOPath(tt.dataDir, tt.vmName)
		if got != tt.want {
			t.Errorf("CloudInitISOPath(%q, %q) = %q, want %q", tt.dataDir, tt.vmName, got, tt.want)
		}
	}
}

func TestImagePath_Variants(t *testing.T) {
	tests := []struct {
		dataDir   string
		imageName string
		want      string
	}{
		{"/data", "ubuntu-24", "/data/images/ubuntu-24.qcow2"},
		{"/data", "centos-9", "/data/images/centos-9.qcow2"},
		{"/data", "installer.iso", "/data/images/installer.iso"},
		{"/data", "my-image.iso", "/data/images/my-image.iso"},
		{"/var/lib/litevirt", "debian", "/var/lib/litevirt/images/debian.qcow2"},
	}
	for _, tt := range tests {
		got := ImagePath(tt.dataDir, tt.imageName)
		if got != tt.want {
			t.Errorf("ImagePath(%q, %q) = %q, want %q", tt.dataDir, tt.imageName, got, tt.want)
		}
	}
}

func TestGenerateMAC_Format(t *testing.T) {
	for i := 0; i < 10; i++ {
		mac := GenerateMAC()
		if !strings.HasPrefix(mac, "52:54:00:") {
			t.Errorf("MAC %q does not start with QEMU OUI", mac)
		}
		if len(mac) != 17 {
			t.Errorf("MAC %q has length %d, want 17", mac, len(mac))
		}
		// Validate hex format.
		parts := strings.Split(mac, ":")
		if len(parts) != 6 {
			t.Errorf("MAC %q has %d parts, want 6", mac, len(parts))
		}
	}
}

func TestGenerateMAC_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		mac := GenerateMAC()
		if seen[mac] {
			t.Errorf("duplicate MAC generated: %s", mac)
		}
		seen[mac] = true
	}
}

func TestParsePCIAddress_Variants(t *testing.T) {
	tests := []struct {
		input string
		want  ParsedPCIAddr
	}{
		{"0000:00:00.0", ParsedPCIAddr{"0x0000", "0x00", "0x00", "0x0"}},
		{"0000:ff:1f.7", ParsedPCIAddr{"0x0000", "0xff", "0x1f", "0x7"}},
		// Too few colons.
		{"short", ParsedPCIAddr{"0x0000", "0x00", "0x00", "0x0"}},
	}
	for _, tt := range tests {
		got := ParsePCIAddress(tt.input)
		if got != tt.want {
			t.Errorf("ParsePCIAddress(%q) = %+v, want %+v", tt.input, got, tt.want)
		}
	}
}

func TestCanHotModify(t *testing.T) {
	tests := []struct {
		oldCPU, oldMem, newCPU, newMem int
		wantOK                         bool
		wantReason                     string
	}{
		{2, 4096, 4, 8192, true, ""},
		{2, 4096, 2, 8192, true, ""},  // mem-only increase
		{2, 4096, 4, 4096, true, ""},  // cpu-only increase
		{4, 8192, 2, 8192, false, "CPU reduction not supported for hot-modify"},
		{4, 8192, 4, 4096, false, "memory reduction not supported for hot-modify"},
		{4, 8192, 4, 8192, false, "no change"},
	}
	for _, tt := range tests {
		ok, reason := CanHotModify(tt.oldCPU, tt.oldMem, tt.newCPU, tt.newMem)
		if ok != tt.wantOK {
			t.Errorf("CanHotModify(%d,%d,%d,%d) ok=%v, want %v", tt.oldCPU, tt.oldMem, tt.newCPU, tt.newMem, ok, tt.wantOK)
		}
		if reason != tt.wantReason {
			t.Errorf("CanHotModify(%d,%d,%d,%d) reason=%q, want %q", tt.oldCPU, tt.oldMem, tt.newCPU, tt.newMem, reason, tt.wantReason)
		}
	}
}

func TestDiskDevName_Exhaustive(t *testing.T) {
	tests := []struct {
		bus   string
		index int
		want  string
	}{
		{"virtio", 0, "vda"},
		{"virtio", 2, "vdc"},
		{"scsi", 0, "sda"},
		{"sata", 3, "sdd"},
		{"", 0, "vda"},       // empty = default (virtio)
		{"banana", 0, "vda"}, // unknown = default
	}
	for _, tt := range tests {
		got := diskDevName(tt.bus, tt.index)
		if got != tt.want {
			t.Errorf("diskDevName(%q, %d) = %q, want %q", tt.bus, tt.index, got, tt.want)
		}
	}
}

func TestPatchBootDev(t *testing.T) {
	tests := []struct {
		input   string
		bootDev string
		want    string
	}{
		{
			`<os><boot dev='disk'/></os>`,
			"cdrom",
			`<os><boot dev='cdrom'/></os>`,
		},
		{
			`<os><boot dev="disk"/></os>`,
			"network",
			`<os><boot dev="network"/></os>`,
		},
		{
			`<os><type>hvm</type><boot dev='disk'/></os>`,
			"cdrom",
			`<os><type>hvm</type><boot dev='cdrom'/></os>`,
		},
		{
			// No os section — unchanged.
			`<domain><name>test</name></domain>`,
			"cdrom",
			`<domain><name>test</name></domain>`,
		},
	}
	for _, tt := range tests {
		got := patchBootDev(tt.input, tt.bootDev)
		if got != tt.want {
			t.Errorf("patchBootDev(%q, %q) = %q, want %q", tt.input, tt.bootDev, got, tt.want)
		}
	}
}

func TestReplaceBootDev(t *testing.T) {
	tests := []struct {
		input   string
		bootDev string
		want    string
	}{
		{`<boot dev='disk'/>`, "cdrom", `<boot dev='cdrom'/>`},
		{`<boot dev="disk"/>`, "network", `<boot dev="network"/>`},
		{`no boot here`, "cdrom", `no boot here`},
	}
	for _, tt := range tests {
		got := replaceBootDev(tt.input, tt.bootDev)
		if got != tt.want {
			t.Errorf("replaceBootDev(%q, %q) = %q, want %q", tt.input, tt.bootDev, got, tt.want)
		}
	}
}

func TestGetIPFromDHCPLeases_NoFiles(t *testing.T) {
	tmp := t.TempDir()
	ip := GetIPFromDHCPLeases(tmp, "52:54:00:aa:bb:cc")
	if ip != "" {
		t.Errorf("expected empty, got %q", ip)
	}
}

func TestGetIPFromDHCPLeases_WithLease(t *testing.T) {
	tmp := t.TempDir()
	leaseFile := filepath.Join(tmp, "default.leases")
	content := "1234567890 52:54:00:aa:bb:cc 10.0.0.5 myvm *\n1234567891 52:54:00:dd:ee:ff 10.0.0.6 othervm *\n"
	os.WriteFile(leaseFile, []byte(content), 0644)

	ip := GetIPFromDHCPLeases(tmp, "52:54:00:aa:bb:cc")
	if ip != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %q", ip)
	}

	ip = GetIPFromDHCPLeases(tmp, "52:54:00:dd:ee:ff")
	if ip != "10.0.0.6" {
		t.Errorf("expected 10.0.0.6, got %q", ip)
	}

	ip = GetIPFromDHCPLeases(tmp, "00:00:00:00:00:00")
	if ip != "" {
		t.Errorf("expected empty for unknown MAC, got %q", ip)
	}
}

func TestGetIPFromDHCPLeases_CaseInsensitive(t *testing.T) {
	tmp := t.TempDir()
	leaseFile := filepath.Join(tmp, "test.leases")
	content := "1234567890 52:54:00:AA:BB:CC 10.0.0.7 myvm *\n"
	os.WriteFile(leaseFile, []byte(content), 0644)

	ip := GetIPFromDHCPLeases(tmp, "52:54:00:aa:bb:cc")
	if ip != "10.0.0.7" {
		t.Errorf("expected 10.0.0.7, got %q", ip)
	}
}

func TestReadTapVLANs(t *testing.T) {
	orig := execVLAN
	defer func() { execVLAN = orig }()

	execVLAN = func(name string, args ...string) ([]byte, error) {
		out := `port vnet0 state disabled
  100 PVID Egress Untagged
  200
  300
`
		return []byte(out), nil
	}

	vlans, err := readTapVLANs("vnet0")
	if err != nil {
		t.Fatalf("readTapVLANs: %v", err)
	}
	if len(vlans) != 3 {
		t.Fatalf("expected 3 VLANs, got %d: %v", len(vlans), vlans)
	}
	expected := map[int]bool{100: true, 200: true, 300: true}
	for _, v := range vlans {
		if !expected[v] {
			t.Errorf("unexpected VLAN %d", v)
		}
	}
}

func TestReadTapVLANs_EmptyOutput(t *testing.T) {
	orig := execVLAN
	defer func() { execVLAN = orig }()

	execVLAN = func(name string, args ...string) ([]byte, error) {
		return []byte(""), nil
	}

	vlans, err := readTapVLANs("vnet0")
	if err != nil {
		t.Fatalf("readTapVLANs: %v", err)
	}
	if len(vlans) != 0 {
		t.Errorf("expected 0 VLANs, got %d", len(vlans))
	}
}

func TestGenerateDomainXML_NoHugePages(t *testing.T) {
	cfg := VMConfig{
		Name:      "no-huge",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		HugePages: false,
		Disks:     []DiskConfig{{Name: "root", Path: "/disk.qcow2", Bus: "virtio"}},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if strings.Contains(xmlOut, "hugepages") {
		t.Error("should not have hugepages when HugePages=false")
	}
}

func TestGenerateDomainXML_NoIOThreads(t *testing.T) {
	cfg := VMConfig{
		Name:      "no-io",
		CPU:       1,
		MemoryMiB: 512,
		Firmware:  "bios",
		IOThreads: 0,
		Disks:     []DiskConfig{{Name: "root", Path: "/disk.qcow2", Bus: "virtio"}},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if strings.Contains(xmlOut, "iothreads") {
		t.Error("should not have iothreads when IOThreads=0")
	}
}

func TestGenerateDomainXML_NoCPUPinning(t *testing.T) {
	cfg := VMConfig{
		Name:       "no-pin",
		CPU:        2,
		MemoryMiB:  1024,
		Firmware:   "bios",
		CPUPinning: nil,
		Disks:      []DiskConfig{{Name: "root", Path: "/disk.qcow2", Bus: "virtio"}},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if strings.Contains(xmlOut, "cputune") {
		t.Error("should not have cputune when CPUPinning is nil")
	}
}

func TestGenerateDomainXML_NilNUMAPolicy(t *testing.T) {
	cfg := VMConfig{
		Name:       "no-numa",
		CPU:        2,
		MemoryMiB:  1024,
		Firmware:   "bios",
		NUMAPolicy: nil,
		Disks:      []DiskConfig{{Name: "root", Path: "/disk.qcow2", Bus: "virtio"}},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if strings.Contains(xmlOut, "numatune") {
		t.Error("should not have numatune when NUMAPolicy is nil")
	}
}
