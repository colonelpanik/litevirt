package vmimport

import "strings"

// scsiModelFromOVF maps a VMware/OVF SCSI controller ResourceSubType to a libvirt
// controller model. Empty = unknown (caller defaults + warns).
func scsiModelFromOVF(subType string) string {
	switch strings.ToLower(strings.TrimSpace(subType)) {
	case "lsilogic":
		return "lsilogic"
	case "lsilogicsas", "lsisas1068", "vmware.scsi.lsisas":
		return "lsisas1068"
	case "virtualscsi", "pvscsi", "vmware.scsi.pvscsi":
		return "vmpvscsi"
	case "buslogic":
		return "buslogic"
	case "virtio-scsi", "virtio":
		return "virtio-scsi"
	default:
		return ""
	}
}

// scsiModelFromProxmox maps a Proxmox `scsihw:` value to a libvirt controller model.
func scsiModelFromProxmox(scsihw string) string {
	switch strings.ToLower(strings.TrimSpace(scsihw)) {
	case "virtio-scsi-pci", "virtio-scsi-single", "virtio-scsi":
		return "virtio-scsi"
	case "lsi", "lsi53c810":
		return "lsilogic"
	case "megasas":
		return "lsisas1078"
	case "pvscsi":
		return "vmpvscsi"
	default:
		return ""
	}
}

// nicModel maps a foreign NIC type/subtype to a litevirt-supported model. For an
// imported guest the safest default is e1000 — every guest OS ships an e1000
// driver, whereas virtio/vmxnet3 need drivers that may be absent.
func nicModel(subType string) string {
	switch strings.ToLower(strings.TrimSpace(subType)) {
	case "virtio", "paravirtualized", "virtio-net", "virtio-net-pci":
		return "virtio"
	case "e1000":
		return "e1000"
	case "e1000e":
		return "e1000e"
	case "rtl8139", "rtl8129":
		return "rtl8139"
	default:
		// VMXNET3, PCNet32, Flexible, unknown → universal fallback.
		return "e1000"
	}
}

// supportedSCSIModels is the set of libvirt SCSI controller models litevirt can
// emit. Some (vmpvscsi, buslogic) are host/QEMU-dependent; the daemon validates
// against domain capabilities at define time and degrades with a warning.
var supportedSCSIModels = map[string]bool{
	"virtio-scsi": true, "lsilogic": true, "lsisas1068": true,
	"lsisas1078": true, "vmpvscsi": true, "buslogic": true,
}
