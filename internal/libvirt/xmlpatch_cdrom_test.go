package libvirt

import (
	"strings"
	"testing"
)

// domainWithCDROMs is an inactive domain carrying the two CDROMs a real VM
// acquires and that no vm_disks row describes: the cloud-init NoCloud ISO
// (VMConfig.CloudInitISO) and an installer ISO (spec.Iso). Both are
// <disk device='cdrom'> — the same element name as a data disk.
func domainWithCDROMs() string {
	return `<domain type='kvm'>
  <name>ci-vm</name>
  <os>
    <type arch='x86_64' machine='pc-q35-9.0'>hvm</type>
    <boot dev='cdrom'/>
  </os>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='writeback'/>
      <source file='/var/lib/litevirt/disks/ci-vm-root.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/var/lib/litevirt/cloudinit/ci-vm.iso'/>
      <target dev='sdb' bus='sata'/>
      <readonly/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/var/lib/litevirt/isos/ubuntu-24.04.iso'/>
      <target dev='sdc' bus='sata'/>
      <readonly/>
    </disk>
  </devices>
</domain>`
}

// TestPatchInactiveDevices_KeepsCDROMs is the #183 regression.
//
// Three facts composed. scanDeviceElements classifies by element NAME only, so
// a <disk device='cdrom'> was collected as a "disk". The want set deliberately
// excludes CDROMs — reconcile.go skips any DeviceKind != "disk", commented
// "cdrom/etc. are not reconciled". And neither ISO is a vm_disks row at all:
// the cloud-init ISO travels as VMConfig.CloudInitISO and the installer ISO as
// spec.Iso.
//
// So the patcher looked up each cdrom in the want set, missed, and deleted it.
// Any stopped-VM device change — attach a disk, change a NIC — redefined the
// domain without both ISOs. A cloud-init VM loses its NoCloud datasource, so
// keys and network config are gone on next boot. A VM created with --iso keeps
// <boot dev='cdrom'/> pointing at a device that no longer exists and stops
// booting. No error, no warning.
//
// "Not reconciled" has to mean left alone, not removed. internal/health's
// reconciler restores CloudInitISO correctly, which shows the intent.
func TestPatchInactiveDevices_KeepsCDROMs(t *testing.T) {
	in := domainWithCDROMs()
	// The want set is what reconcile.go builds: data disks only.
	out, err := PatchInactiveDevices(in, WantDevices{
		Disks: []WantDisk{{
			TargetDev: "vda", Bus: "virtio",
			Path: "/var/lib/litevirt/disks/ci-vm-root.qcow2",
		}},
	})
	if err != nil {
		t.Fatalf("PatchInactiveDevices: %v", err)
	}

	if !strings.Contains(out, "/var/lib/litevirt/cloudinit/ci-vm.iso") {
		t.Errorf("the cloud-init ISO was deleted; the VM loses its NoCloud "+
			"datasource — keys and network config — on next boot.\n%s", out)
	}
	if !strings.Contains(out, "/var/lib/litevirt/isos/ubuntu-24.04.iso") {
		t.Errorf("the installer ISO was deleted while <boot dev='cdrom'/> still "+
			"points at it; the VM stops booting.\n%s", out)
	}
	if got := strings.Count(out, "device='cdrom'"); got != 2 {
		t.Errorf("cdrom count = %d, want 2\n%s", got, out)
	}
	if !strings.Contains(out, "dev='vda'") {
		t.Errorf("the data disk was lost\n%s", out)
	}
}

// A CDROM must not be matched against the want set either — its target dev
// must never satisfy a desired data disk, or a disk add would be silently
// swallowed by an unrelated cdrom that happens to share the key.
//
// The shared target dev is the only way to test that, and it is deliberately
// pathological: libvirt will reject the result for a duplicate <target dev>.
// That is the point. A loud refusal at define time is the correct outcome for a
// want set that asks for a dev a cdrom already holds — the behaviour it
// replaces was to delete the ISO and define successfully, losing the VM'"'"'s
// datasource with no error at all.
func TestPatchInactiveDevices_CDROMDoesNotSatisfyAWantedDisk(t *testing.T) {
	in := `<domain type='kvm'>
  <devices>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/isos/x.iso'/>
      <target dev='sdb' bus='sata'/>
      <readonly/>
    </disk>
  </devices>
</domain>`
	out, err := PatchInactiveDevices(in, WantDevices{
		Disks: []WantDisk{{TargetDev: "sdb", Bus: "sata", Path: "/disks/data.qcow2"}},
	})
	if err != nil {
		t.Fatalf("PatchInactiveDevices: %v", err)
	}
	if !strings.Contains(out, "/isos/x.iso") {
		t.Errorf("the cdrom's source was rewritten to a data disk's path\n%s", out)
	}
	if !strings.Contains(out, "/disks/data.qcow2") {
		t.Errorf("the wanted disk was not added — a cdrom sharing its target dev "+
			"absorbed it\n%s", out)
	}
	// Quote style differs by origin — libvirt serialises with single quotes,
	// a newly marshalled fragment with double — so match either.
	if strings.Count(out, `device='cdrom'`)+strings.Count(out, `device="cdrom"`) != 1 {
		t.Errorf("the cdrom was duplicated or lost\n%s", out)
	}
}

// A data disk that IS in the want set is still reconciled normally, and one
// that is not is still removed — the fix must not turn the patcher into a no-op.
func TestPatchInactiveDevices_StillRemovesAnUnwantedDataDisk(t *testing.T) {
	in := `<domain type='kvm'>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/disks/root.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/disks/old.qcow2'/>
      <target dev='vdb' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/isos/seed.iso'/>
      <target dev='sdb' bus='sata'/>
      <readonly/>
    </disk>
  </devices>
</domain>`
	out, err := PatchInactiveDevices(in, WantDevices{
		Disks: []WantDisk{{TargetDev: "vda", Bus: "virtio", Path: "/disks/root.qcow2"}},
	})
	if err != nil {
		t.Fatalf("PatchInactiveDevices: %v", err)
	}
	if strings.Contains(out, "/disks/old.qcow2") {
		t.Errorf("an unwanted DATA disk survived; the patcher stopped reconciling\n%s", out)
	}
	if !strings.Contains(out, "/isos/seed.iso") {
		t.Errorf("the cdrom was deleted\n%s", out)
	}
	if !strings.Contains(out, "/disks/root.qcow2") {
		t.Errorf("the wanted disk was lost\n%s", out)
	}
}

// libvirt defaults a missing device attribute to "disk", so an element without
// one is still the reconciler's. Getting this backwards would make every such
// disk immortal and quietly break removal.
func TestPatchInactiveDevices_DiskWithNoDeviceAttrIsStillReconciled(t *testing.T) {
	in := `<domain type='kvm'>
  <devices>
    <disk type='file'>
      <driver name='qemu' type='qcow2'/>
      <source file='/disks/old.qcow2'/>
      <target dev='vdb' bus='virtio'/>
    </disk>
  </devices>
</domain>`
	out, err := PatchInactiveDevices(in, WantDevices{})
	if err != nil {
		t.Fatalf("PatchInactiveDevices: %v", err)
	}
	if strings.Contains(out, "/disks/old.qcow2") {
		t.Errorf("a <disk> with no device attribute defaults to device='disk' and "+
			"must still be reconciled away when unwanted\n%s", out)
	}
}

// isReconciledDisk reads the opening tag only. A <source file='…cdrom…'> or an
// attribute on a nested element must not flip the classification.
func TestIsReconciledDisk_ReadsTheOpeningTagOnly(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"data disk", `<disk type='file' device='disk'><target dev='vda'/></disk>`, true},
		{"no device attr", `<disk type='file'><target dev='vda'/></disk>`, true},
		{"cdrom", `<disk type='file' device='cdrom'><target dev='sdb'/></disk>`, false},
		{"floppy", `<disk type='file' device='floppy'><target dev='fda'/></disk>`, false},
		{"lun", `<disk type='block' device='lun'><target dev='sda'/></disk>`, false},
		{"double quotes", `<disk type="file" device="cdrom"><target dev="sdb"/></disk>`, false},
		{"leading whitespace", "\n  <disk type='file' device='cdrom'></disk>", false},
		{"device= only on a child", `<disk type='file'><source device='cdrom'/></disk>`, true},
		{"cdrom named in a source path", `<disk type='file' device='disk'><source file='/x/cdrom.qcow2'/></disk>`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isReconciledDisk(tc.raw); got != tc.want {
				t.Errorf("isReconciledDisk = %v, want %v", got, tc.want)
			}
		})
	}
}
