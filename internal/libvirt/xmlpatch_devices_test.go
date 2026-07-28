package libvirt

import (
	"encoding/xml"
	"errors"
	"strings"
	"testing"
)

// sampleInactiveDomainXML returns a libvirt-serialized INACTIVE domain (single
// quotes, self-closing children, libvirt-assigned guest topology) with one disk
// (target vda), one NIC (mac 52:54:00:aa:bb:cc) and one PCI hostdev carrying an
// assigned guest <address slot='0x06'> plus its stable <alias name='ua-d1-m0'>.
// It also embeds elements the generator does NOT model (disk <alias>, interface
// <target>/<alias>, guest <address> on disk+iface) so tests can prove those
// survive a patch verbatim.
func sampleInactiveDomainXML() string {
	return `<domain type='kvm'>
  <name>hw-vm</name>
  <uuid>11111111-2222-3333-4444-555555555555</uuid>
  <memory unit='KiB'>4194304</memory>
  <currentMemory unit='KiB'>2097152</currentMemory>
  <vcpu placement='static'>2</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-9.0'>hvm</type>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none'/>
      <source file='/var/lib/litevirt/disks/hw-vm-root.qcow2'/>
      <target dev='vda' bus='virtio'/>
      <alias name='ua-disk-root'/>
      <address type='pci' domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>
    </disk>
    <interface type='bridge'>
      <mac address='52:54:00:aa:bb:cc'/>
      <source bridge='br0'/>
      <model type='virtio'/>
      <target dev='vnet0'/>
      <alias name='ua-net-0'/>
      <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
    </interface>
    <hostdev mode='subsystem' type='pci' managed='yes'>
      <source>
        <address domain='0x0000' bus='0x41' slot='0x00' function='0x0'/>
      </source>
      <alias name='ua-d1-m0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </hostdev>
    <serial type='pty'>
      <target type='isa-serial' port='0'/>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <memballoon model='virtio'/>
  </devices>
</domain>`
}

// assertWellFormed fails if s is not parseable as a libvirt domain document.
func assertWellFormed(t *testing.T, s string) {
	t.Helper()
	var d struct {
		XMLName xml.Name `xml:"domain"`
	}
	if err := xml.Unmarshal([]byte(s), &d); err != nil {
		t.Fatalf("patched XML is not well-formed: %v\n%s", err, s)
	}
}

func TestPatchInactiveDevices_NoopPreservesTopology(t *testing.T) {
	in := sampleInactiveDomainXML()
	want := WantDevices{
		Disks:    []WantDisk{{TargetDev: "vda", Bus: "virtio", Path: "/var/lib/litevirt/disks/hw-vm-root.qcow2"}},
		NICs:     []WantNIC{{MAC: "52:54:00:aa:bb:cc", Bridge: "br0", Model: "virtio"}},
		Hostdevs: []WantHostdev{{Alias: "ua-d1-m0", Address: "0000:41:00.0"}},
	}
	out, err := PatchInactiveDevices(in, want)
	if err != nil {
		t.Fatal(err)
	}
	assertWellFormed(t, out)

	// The load-bearing guarantee: the hostdev's libvirt-assigned guest PCI slot
	// and its stable alias survive.
	if !strings.Contains(out, `slot='0x06'`) {
		t.Fatalf("hostdev guest PCI slot not preserved:\n%s", out)
	}
	if !strings.Contains(out, "ua-d1-m0") {
		t.Fatalf("hostdev alias not preserved:\n%s", out)
	}
	// A pure no-op must be byte-identical: no device changed, nothing added or
	// removed, so every unmodeled/topology element survives verbatim.
	if out != in {
		t.Fatalf("no-op patch was not byte-identical:\n--- in ---\n%s\n--- out ---\n%s", in, out)
	}
}

func TestPatchInactiveDevices_DiskPathChangeKeepsTarget(t *testing.T) {
	in := sampleInactiveDomainXML()
	want := WantDevices{
		Disks:    []WantDisk{{TargetDev: "vda", Bus: "virtio", Path: "/data/relocated-root.qcow2"}},
		NICs:     []WantNIC{{MAC: "52:54:00:aa:bb:cc", Bridge: "br0"}},
		Hostdevs: []WantHostdev{{Alias: "ua-d1-m0", Address: "0000:41:00.0"}},
	}
	out, err := PatchInactiveDevices(in, want)
	if err != nil {
		t.Fatal(err)
	}
	assertWellFormed(t, out)

	if !strings.Contains(out, `file='/data/relocated-root.qcow2'`) {
		t.Fatalf("disk source not repointed:\n%s", out)
	}
	if strings.Contains(out, `file='/var/lib/litevirt/disks/hw-vm-root.qcow2'`) {
		t.Fatalf("old disk source still present:\n%s", out)
	}
	// Target dev (the match key) and the libvirt-assigned guest <address> on the
	// disk must survive untouched.
	if !strings.Contains(out, `<target dev='vda' bus='virtio'/>`) {
		t.Fatalf("disk target reshuffled:\n%s", out)
	}
	if !strings.Contains(out, `<address type='pci' domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>`) {
		t.Fatalf("disk guest PCI address not preserved:\n%s", out)
	}
	if !strings.Contains(out, "ua-disk-root") {
		t.Fatalf("disk alias not preserved:\n%s", out)
	}
}

func TestPatchInactiveDevices_HostdevBDFReresolveKeepsGuestSlot(t *testing.T) {
	// Blocker #2 behavior: re-resolve the host BDF (source) to a DIFFERENT PCI
	// device while keeping the same guest slot and alias.
	in := sampleInactiveDomainXML()
	want := WantDevices{
		Disks:    []WantDisk{{TargetDev: "vda", Bus: "virtio", Path: "/var/lib/litevirt/disks/hw-vm-root.qcow2"}},
		NICs:     []WantNIC{{MAC: "52:54:00:aa:bb:cc", Bridge: "br0"}},
		Hostdevs: []WantHostdev{{Alias: "ua-d1-m0", Address: "0000:42:00.0"}}, // was 0000:41:00.0
	}
	out, err := PatchInactiveDevices(in, want)
	if err != nil {
		t.Fatal(err)
	}
	assertWellFormed(t, out)

	// Host BDF in <source> re-resolved (bus 0x41 -> 0x42).
	if !strings.Contains(out, `<address domain='0x0000' bus='0x42' slot='0x00' function='0x0'/>`) {
		t.Fatalf("hostdev source BDF not re-resolved:\n%s", out)
	}
	if strings.Contains(out, `bus='0x41'`) {
		t.Fatalf("stale host BDF still present:\n%s", out)
	}
	// Guest slot + alias unchanged — the guest sees the SAME device topology.
	if !strings.Contains(out, `<address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>`) {
		t.Fatalf("guest PCI slot reshuffled by a BDF re-resolve:\n%s", out)
	}
	if !strings.Contains(out, `<alias name='ua-d1-m0'/>`) {
		t.Fatalf("hostdev alias not preserved:\n%s", out)
	}
}

func TestPatchInactiveDevices_AddNewDiskHasNoAddress(t *testing.T) {
	in := sampleInactiveDomainXML()
	want := WantDevices{
		Disks: []WantDisk{
			{TargetDev: "vda", Bus: "virtio", Path: "/var/lib/litevirt/disks/hw-vm-root.qcow2"},
			{TargetDev: "vdb", Bus: "virtio", Path: "/data/hw-vm-data.qcow2", Cache: "none"},
		},
		NICs:     []WantNIC{{MAC: "52:54:00:aa:bb:cc", Bridge: "br0"}},
		Hostdevs: []WantHostdev{{Alias: "ua-d1-m0", Address: "0000:41:00.0"}},
	}
	out, err := PatchInactiveDevices(in, want)
	if err != nil {
		t.Fatal(err)
	}
	assertWellFormed(t, out)

	if !strings.Contains(out, `<target dev="vdb" bus="virtio">`) {
		t.Fatalf("new disk not added:\n%s", out)
	}
	if !strings.Contains(out, `file="/data/hw-vm-data.qcow2"`) {
		t.Fatalf("new disk source missing:\n%s", out)
	}
	// The new disk carries NO <address> — libvirt assigns the slot. The document
	// gained no <address element (existing ones untouched, new one has none).
	if got, orig := strings.Count(out, "<address"), strings.Count(in, "<address"); got != orig {
		t.Fatalf("added disk introduced an <address> (count %d, was %d):\n%s", got, orig, out)
	}
	// Existing disk still present and intact.
	if !strings.Contains(out, `<target dev='vda' bus='virtio'/>`) {
		t.Fatalf("existing disk lost:\n%s", out)
	}
}

func TestPatchInactiveDevices_RemoveNIC(t *testing.T) {
	in := sampleInactiveDomainXML()
	want := WantDevices{
		Disks:    []WantDisk{{TargetDev: "vda", Bus: "virtio", Path: "/var/lib/litevirt/disks/hw-vm-root.qcow2"}},
		NICs:     nil, // drop the only NIC
		Hostdevs: []WantHostdev{{Alias: "ua-d1-m0", Address: "0000:41:00.0"}},
	}
	out, err := PatchInactiveDevices(in, want)
	if err != nil {
		t.Fatal(err)
	}
	assertWellFormed(t, out)

	if strings.Contains(out, "52:54:00:aa:bb:cc") {
		t.Fatalf("removed NIC's MAC still present:\n%s", out)
	}
	if strings.Contains(out, "<interface") {
		t.Fatalf("interface element not removed:\n%s", out)
	}
	// Disk and hostdev untouched.
	if !strings.Contains(out, `<target dev='vda' bus='virtio'/>`) {
		t.Fatalf("disk lost while removing NIC:\n%s", out)
	}
	if !strings.Contains(out, `<alias name='ua-d1-m0'/>`) {
		t.Fatalf("hostdev lost while removing NIC:\n%s", out)
	}
	if !strings.Contains(out, `slot='0x06'`) {
		t.Fatalf("hostdev guest slot lost while removing NIC:\n%s", out)
	}
}

func TestPatchInactiveDevices_AmbiguousHostdevAlias(t *testing.T) {
	// Two existing hostdevs share the same alias — a want entry referencing it is
	// an ambiguous mapping the patcher must refuse.
	in := `<domain type='kvm'>
  <name>dup</name>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <hostdev mode='subsystem' type='pci' managed='yes'>
      <source><address domain='0x0000' bus='0x41' slot='0x00' function='0x0'/></source>
      <alias name='ua-d1-m0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </hostdev>
    <hostdev mode='subsystem' type='pci' managed='yes'>
      <source><address domain='0x0000' bus='0x42' slot='0x00' function='0x0'/></source>
      <alias name='ua-d1-m0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x07' function='0x0'/>
    </hostdev>
  </devices>
</domain>`
	_, err := PatchInactiveDevices(in, WantDevices{
		Hostdevs: []WantHostdev{{Alias: "ua-d1-m0", Address: "0000:43:00.0"}},
	})
	if !errors.Is(err, ErrDeviceCardinality) {
		t.Fatalf("want ErrDeviceCardinality, got %v", err)
	}
}

func TestPatchInactiveDevices_MetadataDevicesSurviveVerbatim(t *testing.T) {
	// A <metadata> subtree that itself contains a <devices> block — both a
	// foreign-namespaced <lv:devices><lv:disk/></lv:devices> AND a nested
	// no-namespace <devices><disk/></devices> — must NOT be mistaken for real
	// domain devices. Device detection is anchored to the domain>devices path and
	// the default namespace, so these metadata "disks" are left untouched.
	in := `<domain type='kvm'>
  <name>hw-vm</name>
  <metadata>
    <lv:info xmlns:lv='http://example.org/litevirt/1'>
      <lv:devices>
        <lv:disk lv:dev='metaXns'/>
      </lv:devices>
    </lv:info>
    <devices>
      <disk type='file' device='disk'>
        <target dev='metaNested' bus='virtio'/>
      </disk>
    </devices>
  </metadata>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none'/>
      <source file='/var/lib/litevirt/disks/hw-vm-root.qcow2'/>
      <target dev='vda' bus='virtio'/>
      <alias name='ua-disk-root'/>
      <address type='pci' domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>
    </disk>
  </devices>
</domain>`
	// want names ONLY the real disk (target vda) with its current path — a pure
	// no-op that must produce byte-identical output, proving the metadata subtree
	// (including its *:disk children) is never scanned or deleted.
	want := WantDevices{
		Disks: []WantDisk{{TargetDev: "vda", Bus: "virtio", Path: "/var/lib/litevirt/disks/hw-vm-root.qcow2"}},
	}
	out, err := PatchInactiveDevices(in, want)
	if err != nil {
		t.Fatal(err)
	}
	assertWellFormed(t, out)

	if out != in {
		t.Fatalf("metadata <devices> subtree was mutated (not byte-identical):\n--- in ---\n%s\n--- out ---\n%s", in, out)
	}
	// Belt-and-braces: the metadata disks' identifying fragments still present.
	if !strings.Contains(out, "metaXns") {
		t.Fatalf("namespaced metadata <lv:disk> was deleted:\n%s", out)
	}
	if !strings.Contains(out, "metaNested") {
		t.Fatalf("nested no-namespace metadata <disk> was deleted:\n%s", out)
	}
}

func TestPatchInactiveDevices_DuplicateWantHostdevAlias(t *testing.T) {
	in := sampleInactiveDomainXML()
	_, err := PatchInactiveDevices(in, WantDevices{
		Hostdevs: []WantHostdev{
			{Alias: "ua-d1-m0", Address: "0000:41:00.0"},
			{Alias: "ua-d1-m0", Address: "0000:42:00.0"},
		},
	})
	if !errors.Is(err, ErrDeviceCardinality) {
		t.Fatalf("want ErrDeviceCardinality for duplicate want alias, got %v", err)
	}
}
