package vmimport

import (
	"strings"
	"testing"
)

// A VMware OVF with Secure Boot + a virtual TPM (ResourceSubType vmware.vtpm)
// must be detected so the import comes in WITH a fresh vTPM, not silently
// without one (G1).
const ovfWin11VTPM = `<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
  xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
  xmlns:vmw="http://www.vmware.com/schema/ovf">
  <References><File ovf:href="disk-0.vmdk" ovf:id="file1" ovf:size="1048576"/></References>
  <DiskSection>
    <Disk ovf:capacity="64" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection><Network ovf:name="VM Network"/></NetworkSection>
  <VirtualSystem ovf:id="win11">
    <OperatingSystemSection ovf:id="103" vmw:osType="windows11_64Guest"><Description>Microsoft Windows 11</Description></OperatingSystemSection>
    <VirtualHardwareSection>
      <System><vssd:VirtualSystemType>vmx-19</vssd:VirtualSystemType></System>
      <Item><rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>4</rasd:VirtualQuantity></Item>
      <Item><rasd:ResourceType>4</rasd:ResourceType><rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits><rasd:VirtualQuantity>8192</rasd:VirtualQuantity></Item>
      <Item><rasd:ResourceType>6</rasd:ResourceType><rasd:ResourceSubType>VirtualSCSI</rasd:ResourceSubType><rasd:InstanceID>3</rasd:InstanceID></Item>
      <Item><rasd:ResourceType>17</rasd:ResourceType><rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource><rasd:Parent>3</rasd:Parent><rasd:AddressOnParent>0</rasd:AddressOnParent></Item>
      <Item><rasd:ResourceType>1</rasd:ResourceType><rasd:ResourceSubType>vmware.vtpm</rasd:ResourceSubType><rasd:ElementName>Virtual TPM</rasd:ElementName><rasd:InstanceID>5</rasd:InstanceID></Item>
      <vmw:Config ovf:key="firmware" vmw:value="efi"/>
      <vmw:Config ovf:key="uefi.secureBoot.enabled" vmw:value="true"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>`

func TestParseOVF_Win11SecureBootVTPM(t *testing.T) {
	fv, err := ParseOVFBytes([]byte(ovfWin11VTPM))
	if err != nil {
		t.Fatalf("ParseOVFBytes: %v", err)
	}
	if fv.Firmware != "uefi" {
		t.Errorf("Firmware = %q, want uefi", fv.Firmware)
	}
	if !fv.SecureBoot {
		t.Error("SecureBoot = false, want true")
	}
	if !fv.HasTPM {
		t.Error("HasTPM = false, want true (vmware.vtpm item present)")
	}
	var sawTPMWarn bool
	for _, w := range fv.Warnings {
		if strings.Contains(strings.ToLower(w), "vtpm") {
			sawTPMWarn = true
		}
	}
	if !sawTPMWarn {
		t.Errorf("expected a vTPM warning, got %v", fv.Warnings)
	}
}

// A source with Secure Boot / a vTPM is converted with those flags set on both
// the VMConfig and the stored spec (G1) — the handler then wires fresh firmware.
func TestToVM_FirmwareFlags(t *testing.T) {
	fv := &ForeignVM{
		Name: "win11", CPUs: 4, MemoryMiB: 8192, Machine: "q35", Firmware: "uefi",
		SecureBoot: true, HasTPM: true,
	}
	spec := fv.ToVMSpec("proj")
	if !spec.SecureBoot || !spec.Tpm {
		t.Errorf("spec firmware flags = (sb=%v tpm=%v), want both true", spec.SecureBoot, spec.Tpm)
	}
	cfg := fv.ToVMConfig()
	if !cfg.SecureBoot || !cfg.TPM {
		t.Errorf("cfg firmware flags = (sb=%v tpm=%v), want both true", cfg.SecureBoot, cfg.TPM)
	}

	// A plain source carries neither flag.
	plain := &ForeignVM{Name: "linux", CPUs: 2, MemoryMiB: 2048, Machine: "q35", Firmware: "uefi"}
	if ps := plain.ToVMSpec("proj"); ps.SecureBoot || ps.Tpm {
		t.Errorf("plain VM should have no firmware flags, got sb=%v tpm=%v", ps.SecureBoot, ps.Tpm)
	}
}
