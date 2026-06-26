package vmimport

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// OVF/CIM RASD resource type codes.
const (
	rasdProcessor    = 3
	rasdMemory       = 4
	rasdIDE          = 5
	rasdSCSI         = 6
	rasdEthernet     = 10
	rasdCDDrive      = 15
	rasdDVDDrive     = 16
	rasdDisk         = 17
	rasdOtherStorage = 20 // SATA/AHCI in VMware exports
)

type ovfEnvelope struct {
	XMLName       xml.Name         `xml:"Envelope"`
	References    ovfReferences    `xml:"References"`
	DiskSection   ovfDiskSection   `xml:"DiskSection"`
	VirtualSystem ovfVirtualSystem `xml:"VirtualSystem"`
}

type ovfReferences struct {
	Files []ovfFile `xml:"File"`
}

type ovfFile struct {
	HRef        string `xml:"href,attr"`
	ID          string `xml:"id,attr"`
	Size        string `xml:"size,attr"`
	ChunkSize   string `xml:"chunkSize,attr"`
	Compression string `xml:"compression,attr"`
}

type ovfDiskSection struct {
	Disks []ovfDisk `xml:"Disk"`
}

type ovfDisk struct {
	DiskID        string `xml:"diskId,attr"`
	FileRef       string `xml:"fileRef,attr"`
	Capacity      string `xml:"capacity,attr"`
	CapacityUnits string `xml:"capacityAllocationUnits,attr"`
	Format        string `xml:"format,attr"`
}

type ovfVirtualSystem struct {
	ID string      `xml:"id,attr"`
	OS ovfOS       `xml:"OperatingSystemSection"`
	HW ovfHardware `xml:"VirtualHardwareSection"`
}

type ovfOS struct {
	ID          string `xml:"id,attr"`
	OSType      string `xml:"osType,attr"`
	Description string `xml:"Description"`
}

type ovfHardware struct {
	Items   []ovfItem   `xml:"Item"`
	Configs []ovfConfig `xml:"Config"`
	// OVF 2.x element forms litevirt does not parse yet — presence ⇒ explicit error.
	EthernetPortItems []ovfRaw `xml:"EthernetPortItem"`
	StorageItems      []ovfRaw `xml:"StorageItem"`
}

type ovfRaw struct{}

type ovfConfig struct {
	Key   string `xml:"key,attr"`
	Value string `xml:"value,attr"`
}

type ovfItem struct {
	ResourceType    string `xml:"ResourceType"`
	ResourceSubType string `xml:"ResourceSubType"`
	VirtualQuantity string `xml:"VirtualQuantity"`
	AllocationUnits string `xml:"AllocationUnits"`
	InstanceID      string `xml:"InstanceID"`
	Parent          string `xml:"Parent"`
	AddressOnParent string `xml:"AddressOnParent"`
	HostResource    string `xml:"HostResource"`
	Connection      string `xml:"Connection"`
	Address         string `xml:"Address"`
	ElementName     string `xml:"ElementName"`
}

// ParseOVF reads an .ovf descriptor from disk and resolves each disk's source
// file relative to the descriptor's directory.
func ParseOVF(ovfPath string) (*ForeignVM, error) {
	data, err := os.ReadFile(ovfPath)
	if err != nil {
		return nil, fmt.Errorf("read ovf: %w", err)
	}
	return parseOVF(data, filepath.Dir(ovfPath))
}

// ParseOVFBytes parses an in-memory descriptor (no on-disk file resolution); disk
// LocalPaths are the bare hrefs. Used by --inspect.
func ParseOVFBytes(data []byte) (*ForeignVM, error) {
	return parseOVF(data, "")
}

type ovfController struct {
	bus   string // ide | scsi | sata
	model string // scsi controller model (libvirt), if known
}

func parseOVF(data []byte, baseDir string) (*ForeignVM, error) {
	var env ovfEnvelope
	if err := xml.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse ovf xml: %w", err)
	}
	if len(env.VirtualSystem.HW.EthernetPortItems) > 0 || len(env.VirtualSystem.HW.StorageItems) > 0 {
		return nil, fmt.Errorf("OVF 2.x EthernetPortItem/StorageItem form is not supported yet; re-export as OVF 1.x")
	}

	fv := &ForeignVM{GuestOS: guessGuestOS(env.VirtualSystem.OS)}

	// file id -> href (+ compression/chunk flags we cannot handle)
	fileByID := map[string]ovfFile{}
	for _, f := range env.References.Files {
		fileByID[f.ID] = f
	}
	// disk id -> {href, capacity bytes, format}
	type diskMeta struct {
		href     string
		capBytes uint64
		format   string
		chunked  bool
	}
	diskByID := map[string]diskMeta{}
	for _, d := range env.DiskSection.Disks {
		f := fileByID[d.FileRef]
		if f.Compression != "" {
			return nil, fmt.Errorf("compressed OVF disk reference (%s) is not supported yet", f.Compression)
		}
		cap := uint64(0)
		if d.Capacity != "" {
			if n, e := strconv.ParseUint(d.Capacity, 10, 64); e == nil {
				cap = n * unitMultiplier(d.CapacityUnits)
			}
		}
		diskByID[d.DiskID] = diskMeta{
			href:     f.HRef,
			capBytes: cap,
			format:   formatFromOVF(d.Format),
			chunked:  f.ChunkSize != "",
		}
	}

	// Firmware / Secure Boot from vmw:Config.
	fv.Firmware = "bios"
	for _, c := range env.VirtualSystem.HW.Configs {
		switch strings.ToLower(c.Key) {
		case "firmware":
			if strings.EqualFold(c.Value, "efi") {
				fv.Firmware = "uefi"
			}
		case "uefi.secureboot.enabled", "secureboot":
			if strings.EqualFold(c.Value, "true") {
				fv.SecureBoot = true
			}
		}
		// A vTPM may also surface as a vmw:Config key (e.g. vtpm.present=true).
		if strings.Contains(strings.ToLower(c.Key), "tpm") && !strings.EqualFold(c.Value, "false") {
			fv.HasTPM = true
		}
	}
	// VMware exports a virtual TPM as a hardware item (ResourceSubType
	// "vmware.vtpm" / ElementName "Virtual TPM"). Detect it so the import comes in
	// WITH a vTPM (fresh) rather than silently dropping it (G1).
	for _, it := range env.VirtualSystem.HW.Items {
		if strings.Contains(strings.ToLower(it.ResourceSubType), "tpm") ||
			strings.Contains(strings.ToLower(it.ElementName), "tpm") {
			fv.HasTPM = true
			break
		}
	}
	if fv.HasTPM {
		fv.Warnf("source has a vTPM — imported with a fresh vTPM (the source TPM state is not carried; a BitLocker guest needs its recovery key) (G1)")
	}

	// First pass: controllers by InstanceID.
	controllers := map[string]ovfController{}
	for _, it := range env.VirtualSystem.HW.Items {
		switch atoiSafe(it.ResourceType) {
		case rasdIDE:
			controllers[it.InstanceID] = ovfController{bus: "ide"}
		case rasdSCSI:
			controllers[it.InstanceID] = ovfController{bus: "scsi", model: scsiModelFromOVF(it.ResourceSubType)}
		case rasdOtherStorage:
			if sub := strings.ToLower(it.ResourceSubType); strings.Contains(sub, "sata") || strings.Contains(sub, "ahci") {
				controllers[it.InstanceID] = ovfController{bus: "sata"}
			}
		}
	}

	// Second pass: cpu/mem/disks/nics.
	type pendingDisk struct {
		d     ForeignDisk
		order int
	}
	var pds []pendingDisk
	for _, it := range env.VirtualSystem.HW.Items {
		switch atoiSafe(it.ResourceType) {
		case rasdProcessor:
			fv.CPUs = atoiSafe(it.VirtualQuantity)
		case rasdMemory:
			bytes := uint64(atoiSafe(it.VirtualQuantity)) * unitMultiplier(it.AllocationUnits)
			fv.MemoryMiB = int(bytes / (1 << 20))
		case rasdEthernet:
			fv.NICs = append(fv.NICs, ForeignNIC{
				Network: it.Connection,
				Model:   nicModel(it.ResourceSubType),
				MAC:     normalizeMAC(it.Address),
			})
		case rasdCDDrive, rasdDVDDrive:
			fv.Disks = append(fv.Disks, ForeignDisk{IsCDROM: true})
		case rasdDisk:
			diskID := diskIDFromHostResource(it.HostResource)
			meta, ok := diskByID[diskID]
			if !ok {
				fv.Warnf("disk item %q references unknown diskId %q; skipped", it.ElementName, diskID)
				continue
			}
			if meta.chunked {
				return nil, fmt.Errorf("chunked OVF disk %q is not supported yet", meta.href)
			}
			ctrl := controllers[it.Parent]
			bus := ctrl.bus
			if bus == "" {
				bus = "scsi" // disk on an unknown controller — assume scsi
			}
			fd := ForeignDisk{
				SourceID:        diskID,
				LocalPath:       resolveHRef(baseDir, meta.href),
				Format:          meta.format,
				Bus:             bus,
				ControllerModel: ctrl.model,
				CapacityBytes:   meta.capBytes,
			}
			pds = append(pds, pendingDisk{d: fd, order: atoiSafe(it.AddressOnParent)})
		}
	}

	// Order disks by AddressOnParent so the boot disk (typically 0) is first.
	sort.SliceStable(pds, func(i, j int) bool { return pds[i].order < pds[j].order })
	di := 0
	for _, pd := range pds {
		fd := pd.d
		if di == 0 {
			fd.Name = "root"
		} else {
			fd.Name = fmt.Sprintf("disk%d", di)
		}
		fv.Disks = append(fv.Disks, fd)
		di++
	}

	if fv.SecureBoot {
		fv.Warnf("source has Secure Boot enabled — imported with Secure Boot (G1)")
	}
	fv.Normalize()
	if di == 0 {
		return nil, fmt.Errorf("OVF describes no disks")
	}
	return fv, nil
}

func guessGuestOS(os ovfOS) string {
	s := strings.ToLower(os.OSType + " " + os.Description)
	switch {
	case strings.Contains(s, "windows"):
		return "windows"
	case strings.Contains(s, "linux") || strings.Contains(s, "ubuntu") || strings.Contains(s, "centos") || strings.Contains(s, "rhel"):
		return "linux"
	default:
		return ""
	}
}

// unitMultiplier converts an OVF AllocationUnits/capacityAllocationUnits string to
// a byte multiplier. Handles "byte", "byte * 2^20", and the named SI-ish forms.
func unitMultiplier(units string) uint64 {
	u := strings.ToLower(strings.ReplaceAll(units, " ", ""))
	switch {
	case u == "", u == "byte", u == "bytes":
		return 1
	case strings.HasPrefix(u, "byte*2^"):
		if n, err := strconv.Atoi(strings.TrimPrefix(u, "byte*2^")); err == nil && n >= 0 && n < 64 {
			return uint64(1) << uint(n)
		}
		return 1
	case u == "kilobytes":
		return 1 << 10
	case u == "megabytes":
		return 1 << 20
	case u == "gigabytes":
		return 1 << 30
	default:
		return 1
	}
}

func formatFromOVF(format string) string {
	f := strings.ToLower(format)
	switch {
	case strings.Contains(f, "vmdk"):
		return "vmdk"
	case strings.Contains(f, "vhd"):
		return "vpc"
	case strings.Contains(f, "qcow"):
		return "qcow2"
	default:
		return "" // let qemu-img auto-detect
	}
}

func diskIDFromHostResource(hr string) string {
	// forms: "ovf:/disk/vmdisk1" or "/disk/vmdisk1"
	i := strings.LastIndex(hr, "/")
	if i < 0 {
		return hr
	}
	return hr[i+1:]
}

func resolveHRef(baseDir, href string) string {
	if baseDir == "" {
		return href
	}
	return filepath.Join(baseDir, filepath.Base(href))
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func normalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	if strings.Count(s, ":") == 5 {
		return strings.ToLower(s)
	}
	return ""
}
