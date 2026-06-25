package vmimport

import (
	"strings"
	"testing"
)

const ovfWindowsSCSI = `<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
  xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
  xmlns:vmw="http://www.vmware.com/schema/ovf">
  <References>
    <File ovf:href="disk-0.vmdk" ovf:id="file1" ovf:size="1048576"/>
  </References>
  <DiskSection>
    <Disk ovf:capacity="40" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection><Network ovf:name="VM Network"/></NetworkSection>
  <VirtualSystem ovf:id="win2022">
    <OperatingSystemSection ovf:id="103" vmw:osType="windows9Server64Guest"><Description>Microsoft Windows Server</Description></OperatingSystemSection>
    <VirtualHardwareSection>
      <System><vssd:VirtualSystemType>vmx-14</vssd:VirtualSystemType></System>
      <Item><rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>4</rasd:VirtualQuantity></Item>
      <Item><rasd:ResourceType>4</rasd:ResourceType><rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits><rasd:VirtualQuantity>8192</rasd:VirtualQuantity></Item>
      <Item><rasd:ResourceType>6</rasd:ResourceType><rasd:ResourceSubType>lsilogicsas</rasd:ResourceSubType><rasd:InstanceID>3</rasd:InstanceID></Item>
      <Item><rasd:ResourceType>15</rasd:ResourceType><rasd:InstanceID>4</rasd:InstanceID></Item>
      <Item><rasd:ResourceType>17</rasd:ResourceType><rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource><rasd:Parent>3</rasd:Parent><rasd:AddressOnParent>0</rasd:AddressOnParent></Item>
      <Item><rasd:ResourceType>10</rasd:ResourceType><rasd:ResourceSubType>E1000</rasd:ResourceSubType><rasd:Connection>VM Network</rasd:Connection><rasd:Address>00:50:56:01:02:03</rasd:Address></Item>
      <vmw:Config ovf:key="firmware" vmw:value="efi"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>`

func TestParseOVF_WindowsSCSI(t *testing.T) {
	fv, err := ParseOVFBytes([]byte(ovfWindowsSCSI))
	if err != nil {
		t.Fatalf("ParseOVFBytes: %v", err)
	}
	if fv.CPUs != 4 {
		t.Errorf("CPUs = %d, want 4", fv.CPUs)
	}
	if fv.MemoryMiB != 8192 {
		t.Errorf("MemoryMiB = %d, want 8192", fv.MemoryMiB)
	}
	if fv.Firmware != "uefi" {
		t.Errorf("Firmware = %q, want uefi", fv.Firmware)
	}
	if fv.GuestOS != "windows" {
		t.Errorf("GuestOS = %q, want windows", fv.GuestOS)
	}

	data := fv.dataDisks()
	if len(data) != 1 {
		t.Fatalf("data disks = %d, want 1", len(data))
	}
	d := data[0]
	if d.Name != "root" || d.Bus != "scsi" {
		t.Errorf("disk = %+v, want name=root bus=scsi", d)
	}
	if d.ControllerModel != "lsisas1068" {
		t.Errorf("ControllerModel = %q, want lsisas1068", d.ControllerModel)
	}
	if d.CapacityBytes != 40<<30 {
		t.Errorf("CapacityBytes = %d, want %d", d.CapacityBytes, uint64(40)<<30)
	}
	if d.SourceID != "vmdisk1" || d.Format != "vmdk" {
		t.Errorf("SourceID/Format = %q/%q, want vmdisk1/vmdk", d.SourceID, d.Format)
	}
	if !strings.HasSuffix(d.LocalPath, "disk-0.vmdk") {
		t.Errorf("LocalPath = %q, want .../disk-0.vmdk", d.LocalPath)
	}

	// One CDROM present (dropped at convert time).
	cdroms := 0
	for _, x := range fv.Disks {
		if x.IsCDROM {
			cdroms++
		}
	}
	if cdroms != 1 {
		t.Errorf("cdroms = %d, want 1", cdroms)
	}

	if len(fv.NICs) != 1 {
		t.Fatalf("NICs = %d, want 1", len(fv.NICs))
	}
	n := fv.NICs[0]
	if n.Model != "e1000" || n.Network != "VM Network" || n.MAC != "00:50:56:01:02:03" {
		t.Errorf("NIC = %+v, want model=e1000 net='VM Network' mac=00:50:56:01:02:03", n)
	}
}

func TestParseOVF_RejectsOVF2(t *testing.T) {
	ovf2 := strings.Replace(ovfWindowsSCSI,
		"<vmw:Config ovf:key=\"firmware\" vmw:value=\"efi\"/>",
		"<EthernetPortItem/>", 1)
	if _, err := ParseOVFBytes([]byte(ovf2)); err == nil {
		t.Fatal("expected error for OVF 2.x EthernetPortItem, got nil")
	}
}

func TestUnitMultiplier(t *testing.T) {
	cases := map[string]uint64{
		"":           1,
		"byte":       1,
		"byte * 2^20": 1 << 20,
		"byte * 2^30": 1 << 30,
		"MegaBytes":  1 << 20,
	}
	for in, want := range cases {
		if got := unitMultiplier(in); got != want {
			t.Errorf("unitMultiplier(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestToVMConfig_NoCloudInitPreservesController(t *testing.T) {
	fv, err := ParseOVFBytes([]byte(ovfWindowsSCSI))
	if err != nil {
		t.Fatal(err)
	}
	cfg := fv.ToVMConfig()
	if cfg.CloudInitISO != "" {
		t.Error("imported VM must not get a cloud-init ISO")
	}
	if len(cfg.Disks) != 1 || cfg.Disks[0].Bus != "scsi" || cfg.Disks[0].ControllerModel != "lsisas1068" {
		t.Errorf("VMConfig disk = %+v, want scsi/lsisas1068", cfg.Disks)
	}
	if cfg.Firmware != "uefi" {
		t.Errorf("VMConfig firmware = %q", cfg.Firmware)
	}
}
