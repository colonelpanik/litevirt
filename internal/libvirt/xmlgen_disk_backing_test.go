package libvirt

import (
	"encoding/xml"
	"strings"
	"testing"
)

// parsedDisks pulls the <disk> elements back out of a generated domain so the
// assertions read attributes rather than substrings — a substring match would
// happily pass on XML that libvirt rejects.
func parsedDisks(t *testing.T, xmlOut string) []diskDevice {
	t.Helper()
	var dom struct {
		Devices struct {
			Disks []diskDevice `xml:"disk"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("generated XML does not parse: %v\n%s", err, xmlOut)
	}
	return dom.Devices.Disks
}

func diskXMLFor(t *testing.T, path string) diskDevice {
	t.Helper()
	out, err := GenerateDomainXML(VMConfig{
		Name: "vm", CPU: 1, MemoryMiB: 512, Firmware: "bios",
		Disks: []DiskConfig{{Name: "root", Path: path, Bus: "virtio"}},
	})
	if err != nil {
		t.Fatalf("GenerateDomainXML(%q): %v", path, err)
	}
	disks := parsedDisks(t, out)
	if len(disks) != 1 {
		t.Fatalf("expected 1 disk for %q, got %d", path, len(disks))
	}
	return disks[0]
}

// TestGenerateDomainXML_BlockBackedDiskIsNotAFile is the #195 regression.
//
// The generator hardcoded type="file" / driver type="qcow2" / <source file=…>
// for every disk. The zfs, lvm-thin and iscsi drivers all return a block
// device path from CreateDisk — /dev/zvol/…, /dev/VG/LV,
// /dev/disk/by-path/ip-…-lun-… — and libvirt is then told that a block device
// is a qcow2 file. The domain does not start.
//
// It fails AFTER the volume has been allocated, so every attempt leaks one
// zvol / LV / LUN.
func TestGenerateDomainXML_BlockBackedDiskIsNotAFile(t *testing.T) {
	for _, path := range []string{
		"/dev/zvol/tank/vm-root", // zfs
		"/dev/vg0/vm-root",       // lvm-thin
		"/dev/disk/by-path/ip-10.0.0.5:3260-iscsi-iqn.x-lun-0", // iscsi
	} {
		t.Run(path, func(t *testing.T) {
			d := diskXMLFor(t, path)
			if d.Type != "block" {
				t.Errorf("disk type = %q, want block — %s is a block device, and "+
					"libvirt will not start a domain that calls it a file", d.Type, path)
			}
			if d.Source.Dev != path {
				t.Errorf("source dev = %q, want %q (source file = %q)",
					d.Source.Dev, path, d.Source.File)
			}
			if d.Source.File != "" {
				t.Errorf("a block-backed disk must not carry <source file=%q>", d.Source.File)
			}
			if d.Driver.Type != "raw" {
				t.Errorf("driver type = %q, want raw — there is no qcow2 header on a "+
					"raw block device", d.Driver.Type)
			}
		})
	}
}

// The ceph driver returns an "rbd:pool/image" URI, which is a qemu-style
// network locator and not a path at all. Emitted as <source file="rbd:…"> it
// names a file that does not exist.
func TestGenerateDomainXML_CephDiskIsANetworkDisk(t *testing.T) {
	d := diskXMLFor(t, "rbd:vms/myvm-root")
	if d.Type != "network" {
		t.Errorf("disk type = %q, want network", d.Type)
	}
	if d.Source.Protocol != "rbd" {
		t.Errorf("source protocol = %q, want rbd", d.Source.Protocol)
	}
	if d.Source.Name != "vms/myvm-root" {
		t.Errorf("source name = %q, want vms/myvm-root", d.Source.Name)
	}
	if d.Source.File != "" {
		t.Errorf("an rbd disk must not carry <source file=%q>", d.Source.File)
	}
	if d.Driver.Type != "raw" {
		t.Errorf("driver type = %q, want raw — an RBD image has no qcow2 header", d.Driver.Type)
	}
}

// A file-backed disk is unchanged: local and nfs both return a .qcow2 path and
// must keep emitting exactly what they always did.
func TestGenerateDomainXML_FileBackedDiskIsUnchanged(t *testing.T) {
	d := diskXMLFor(t, "/var/lib/litevirt/disks/vm-root.qcow2")
	if d.Type != "file" {
		t.Errorf("disk type = %q, want file", d.Type)
	}
	if d.Source.File != "/var/lib/litevirt/disks/vm-root.qcow2" {
		t.Errorf("source file = %q", d.Source.File)
	}
	if d.Driver.Type != "qcow2" {
		t.Errorf("driver type = %q, want qcow2", d.Driver.Type)
	}
	if d.Source.Dev != "" || d.Source.Protocol != "" {
		t.Errorf("a file-backed disk gained block/network attributes: %+v", d.Source)
	}
}

// An ISO is a raw file whatever else changes — the cdrom path must not be
// re-classified by the new logic.
func TestGenerateDomainXML_ISOStaysARawFile(t *testing.T) {
	out, err := GenerateDomainXML(VMConfig{
		Name: "vm", CPU: 1, MemoryMiB: 512, Firmware: "bios",
		Disks: []DiskConfig{
			{Name: "root", Path: "/dev/vg0/vm-root", Bus: "virtio"},
			{Name: "inst", Path: "/isos/ubuntu.iso", Bus: "sata", IsISO: true},
		},
	})
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	disks := parsedDisks(t, out)
	if len(disks) != 2 {
		t.Fatalf("expected 2 disks, got %d", len(disks))
	}
	iso := disks[1]
	if iso.Device != "cdrom" || iso.Type != "file" || iso.Driver.Type != "raw" {
		t.Errorf("iso disk = device %q type %q driver %q; want cdrom/file/raw",
			iso.Device, iso.Type, iso.Driver.Type)
	}
	if iso.Source.File != "/isos/ubuntu.iso" {
		t.Errorf("iso source file = %q", iso.Source.File)
	}
	if !strings.Contains(out, "<readonly></readonly>") && !strings.Contains(out, "<readonly/>") {
		t.Error("the cdrom lost its <readonly/>")
	}
}

// marshalNewDisk is the second site with the same defect: a disk hot-attached
// or added by the reconciler goes through the patcher, not the generator, and
// hardcoded file/qcow2 in exactly the same way. A ceph or zfs volume attached
// to a running VM would be described to libvirt as a qcow2 file.
func TestMarshalNewDisk_UsesTheRightBacking(t *testing.T) {
	cases := []struct {
		path, wantType, wantDriver string
	}{
		{"/var/lib/litevirt/disks/d.qcow2", "file", "qcow2"},
		{"/dev/vg0/data", "block", "raw"},
		{"rbd:vms/data", "network", "raw"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			frag, err := marshalNewDisk("      ", WantDisk{
				Path: tc.path, Bus: "virtio", TargetDev: "vdb",
			})
			if err != nil {
				t.Fatalf("marshalNewDisk: %v", err)
			}
			var d diskDevice
			if err := xml.Unmarshal([]byte(strings.TrimSpace(frag)), &d); err != nil {
				t.Fatalf("fragment does not parse: %v\n%s", err, frag)
			}
			if d.Type != tc.wantType {
				t.Errorf("type = %q, want %q", d.Type, tc.wantType)
			}
			if d.Driver.Type != tc.wantDriver {
				t.Errorf("driver type = %q, want %q", d.Driver.Type, tc.wantDriver)
			}
			switch tc.wantType {
			case "file":
				if d.Source.File != tc.path {
					t.Errorf("source file = %q, want %q", d.Source.File, tc.path)
				}
			case "block":
				if d.Source.Dev != tc.path {
					t.Errorf("source dev = %q, want %q", d.Source.Dev, tc.path)
				}
			case "network":
				if d.Source.Protocol != "rbd" || d.Source.Name != "vms/data" {
					t.Errorf("source = %+v, want rbd vms/data", d.Source)
				}
			}
		})
	}
}
