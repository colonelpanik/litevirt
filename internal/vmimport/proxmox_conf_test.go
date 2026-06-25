package vmimport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// q35/UEFI guest: virtio-scsi-single controller, scsi0 boot disk, an efidisk0,
// a virtio NIC on vmbr0 tagged VLAN 10.
const confQ35UEFI = `name: vm-100
ostype: l26
cores: 4
sockets: 2
memory: 8192
bios: ovmf
machine: q35
scsihw: virtio-scsi-single
boot: order=scsi0;ide2;net0
scsi0: local-lvm:vm-100-disk-1,size=64G,cache=none,ssd=1
ide2: local:iso/debian-12.iso,media=cdrom
efidisk0: local-lvm:vm-100-disk-0,size=4M,efitype=4m
net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10,firewall=1
agent: 1
`

// i440fx/SeaBIOS guest: legacy bootdisk:, an IDE cdrom, a SATA data disk.
const confI440FXBIOS = `name: vm-200
ostype: win10
cores: 2
memory: 4096
machine: pc-i440fx-8.1
ide0: local:iso/virtio-win.iso,media=cdrom
sata0: local-lvm:vm-200-disk-0,size=120G
bootdisk: sata0
net0: e1000=12:34:56:78:9A:BC,bridge=vmbr1
`

// Guest with a vTPM (tpmstate0) — should set HasTPM and warn.
const confWithTPM = `name: vm-300
ostype: win11
cores: 4
memory: 8192
bios: ovmf
machine: q35
scsihw: virtio-scsi-pci
scsi0: local-lvm:vm-300-disk-0,size=80G
tpmstate0: local-lvm:vm-300-disk-1,size=4M,version=v2.0
efidisk0: local-lvm:vm-300-disk-2,size=4M
net0: virtio=DE:AD:BE:EF:00:01,bridge=vmbr0
`

func writeConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vm.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	return p
}

func hasWarning(fv *ForeignVM, substr string) bool {
	for _, w := range fv.Warnings {
		if strings.Contains(strings.ToLower(w), strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

func diskBySourceID(fv *ForeignVM, id string) *ForeignDisk {
	for i := range fv.Disks {
		if fv.Disks[i].SourceID == id {
			return &fv.Disks[i]
		}
	}
	return nil
}

func TestParseProxmoxConf_Q35UEFI(t *testing.T) {
	fv, err := ParseProxmoxConf(writeConf(t, confQ35UEFI))
	if err != nil {
		t.Fatalf("ParseProxmoxConf: %v", err)
	}
	if fv.Name != "vm-100" {
		t.Errorf("Name = %q, want vm-100", fv.Name)
	}
	if fv.CPUs != 8 { // cores 4 × sockets 2
		t.Errorf("CPUs = %d, want 8", fv.CPUs)
	}
	if fv.MemoryMiB != 8192 {
		t.Errorf("MemoryMiB = %d, want 8192", fv.MemoryMiB)
	}
	if fv.Firmware != "uefi" {
		t.Errorf("Firmware = %q, want uefi", fv.Firmware)
	}
	if fv.Machine != "q35" {
		t.Errorf("Machine = %q, want q35", fv.Machine)
	}
	if fv.GuestOS != "linux" {
		t.Errorf("GuestOS = %q, want linux", fv.GuestOS)
	}

	// Boot disk must be Disks[0] and be scsi0.
	if len(fv.Disks) == 0 {
		t.Fatal("no disks parsed")
	}
	boot := fv.Disks[0]
	if boot.SourceID != "scsi0" {
		t.Errorf("Disks[0].SourceID = %q, want scsi0", boot.SourceID)
	}
	if boot.Bus != "scsi" {
		t.Errorf("Disks[0].Bus = %q, want scsi", boot.Bus)
	}
	if boot.ControllerModel != "virtio-scsi" {
		t.Errorf("Disks[0].ControllerModel = %q, want virtio-scsi", boot.ControllerModel)
	}
	if boot.Name != "root" {
		t.Errorf("Disks[0].Name = %q, want root", boot.Name)
	}
	if boot.CapacityBytes != 64<<30 {
		t.Errorf("Disks[0].CapacityBytes = %d, want %d", boot.CapacityBytes, uint64(64)<<30)
	}
	if boot.LocalPath != "local-lvm:vm-100-disk-1" {
		t.Errorf("Disks[0].LocalPath = %q, want the volume reference", boot.LocalPath)
	}

	// ide2 cdrom present and flagged.
	cd := diskBySourceID(fv, "ide2")
	if cd == nil || !cd.IsCDROM {
		t.Errorf("ide2 should be a CDROM, got %+v", cd)
	}

	// NIC.
	if len(fv.NICs) != 1 {
		t.Fatalf("NICs = %d, want 1", len(fv.NICs))
	}
	n := fv.NICs[0]
	if n.Model != "virtio" {
		t.Errorf("NIC.Model = %q, want virtio", n.Model)
	}
	if n.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("NIC.MAC = %q, want lowercased aa:bb:cc:dd:ee:ff", n.MAC)
	}
	if n.Network != "vmbr0" {
		t.Errorf("NIC.Network = %q, want vmbr0", n.Network)
	}
	if n.VLAN != 10 {
		t.Errorf("NIC.VLAN = %d, want 10", n.VLAN)
	}

	if !hasWarning(fv, "efi vars") {
		t.Errorf("expected an efidisk warning, got %v", fv.Warnings)
	}
}

func TestParseProxmoxConf_I440FXBIOS(t *testing.T) {
	fv, err := ParseProxmoxConf(writeConf(t, confI440FXBIOS))
	if err != nil {
		t.Fatalf("ParseProxmoxConf: %v", err)
	}
	if fv.Machine != "pc" {
		t.Errorf("Machine = %q, want pc", fv.Machine)
	}
	if fv.Firmware != "bios" {
		t.Errorf("Firmware = %q, want bios", fv.Firmware)
	}
	if fv.GuestOS != "windows" {
		t.Errorf("GuestOS = %q, want windows", fv.GuestOS)
	}
	if fv.CPUs != 2 { // cores 2 × sockets default 1
		t.Errorf("CPUs = %d, want 2", fv.CPUs)
	}

	// Boot disk is sata0 and must be first.
	if fv.Disks[0].SourceID != "sata0" {
		t.Errorf("Disks[0].SourceID = %q, want sata0 (bootdisk)", fv.Disks[0].SourceID)
	}
	if fv.Disks[0].Bus != "sata" {
		t.Errorf("Disks[0].Bus = %q, want sata", fv.Disks[0].Bus)
	}
	if fv.Disks[0].Name != "root" {
		t.Errorf("Disks[0].Name = %q, want root", fv.Disks[0].Name)
	}

	// ide0 cdrom flagged.
	cd := diskBySourceID(fv, "ide0")
	if cd == nil || !cd.IsCDROM {
		t.Errorf("ide0 should be a CDROM, got %+v", cd)
	}
	// The CDROM must NOT be the boot/data root.
	if fv.Disks[0].IsCDROM {
		t.Error("boot disk must not be the CDROM")
	}

	// e1000 NIC.
	if len(fv.NICs) != 1 || fv.NICs[0].Model != "e1000" {
		t.Errorf("want one e1000 NIC, got %+v", fv.NICs)
	}
	if fv.NICs[0].MAC != "12:34:56:78:9a:bc" {
		t.Errorf("NIC.MAC = %q, want lowercased", fv.NICs[0].MAC)
	}
}

func TestParseProxmoxConf_TPM(t *testing.T) {
	fv, err := ParseProxmoxConf(writeConf(t, confWithTPM))
	if err != nil {
		t.Fatalf("ParseProxmoxConf: %v", err)
	}
	if !fv.HasTPM {
		t.Error("HasTPM = false, want true (tpmstate0 present)")
	}
	if !hasWarning(fv, "tpm") {
		t.Errorf("expected a vTPM warning, got %v", fv.Warnings)
	}
	// tpmstate0 / efidisk0 are not data disks: the only data disk is scsi0.
	if len(fv.Disks) != 1 || fv.Disks[0].SourceID != "scsi0" {
		t.Errorf("want a single scsi0 data disk, got %+v", fv.Disks)
	}
}

func TestParseProxmoxConf_DropsSnapshots(t *testing.T) {
	conf := confQ35UEFI + "\n[snap1]\nname: vm-100\nscsi9: local-lvm:vm-100-state-snap1,size=8G\n"
	fv, err := ParseProxmoxConf(writeConf(t, conf))
	if err != nil {
		t.Fatalf("ParseProxmoxConf: %v", err)
	}
	if diskBySourceID(fv, "scsi9") != nil {
		t.Error("snapshot-section disk scsi9 should have been ignored")
	}
	if !hasWarning(fv, "snapshot") {
		t.Errorf("expected a snapshot-dropped warning, got %v", fv.Warnings)
	}
}

func TestParseProxmoxConf_NoDataDisks(t *testing.T) {
	conf := "name: vm-400\ncores: 1\nmemory: 512\nide2: local:iso/x.iso,media=cdrom\n"
	if _, err := ParseProxmoxConf(writeConf(t, conf)); err == nil {
		t.Error("expected an error when no data disks are present")
	}
}

func TestParseProxmoxSize(t *testing.T) {
	cases := map[string]uint64{
		"32G":     32 << 30,
		"512M":    512 << 20,
		"1T":      1 << 40,
		"2048K":   2048 << 10,
		"1048576": 1048576, // bare bytes
		"":        0,
		"bad":     0,
	}
	for in, want := range cases {
		if got := parseProxmoxSize(in); got != want {
			t.Errorf("parseProxmoxSize(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestGuessGuestOSProxmox(t *testing.T) {
	cases := map[string]string{
		"l26": "linux", "l24": "linux",
		"win10": "windows", "win11": "windows", "w2k8": "windows", "wxp": "windows", "wvista": "windows",
		"other": "", "": "", "solaris": "",
	}
	for in, want := range cases {
		if got := guessGuestOSProxmox(in); got != want {
			t.Errorf("guessGuestOSProxmox(%q) = %q, want %q", in, got, want)
		}
	}
}
