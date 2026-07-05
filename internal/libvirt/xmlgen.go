package libvirt

import (
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/safename"
)

// VMConfig holds all parameters needed to generate a libvirt domain XML.
type VMConfig struct {
	Name       string
	CPU        int
	MemoryMiB  int
	// Memory ballooning (#4). MaxMemoryMiB (> MemoryMiB) raises the balloon
	// ceiling so the guest can be inflated up to it at runtime; MinMemoryMiB is
	// the advisory floor SetMemory won't go below. 0 = classic fixed memory.
	MinMemoryMiB int
	MaxMemoryMiB int
	Machine    string // q35 | pc
	Firmware   string // uefi | bios
	GuestAgent bool
	EnableVNC  bool // true = add VNC graphics device, false = headless
	// EnableSPICE adds a SPICE graphics device alongside (or instead of) VNC.
	// SPICE provides higher-fidelity graphics (USB redirection, audio, multi-
	// monitor); VNC remains the lowest-common-denominator browser viewer.
	// When both are true, both are emitted — clients pick which to connect to.
	EnableSPICE bool

	Disks    []DiskConfig
	Networks []NetworkConfig

	CloudInitISO string // path to cloud-init ISO, empty if not used
	Boot         string // disk | cdrom

	// CPU mode: host-passthrough | host-model | custom (empty = QEMU default)
	CPUMode string

	// Resource tuning
	HugePages  bool
	CPUPinning []int // host CPU IDs to pin vCPUs to
	IOThreads  int   // number of IO threads (0 = default)

	// NUMA policy
	NUMAPolicy *NUMAPolicy

	// PCI passthrough devices
	Hostdevs []HostdevConfig

	// Secure Boot + vTPM (G1). SecureBoot uses the secboot/MS OVMF pair + SMM
	// (q35-only); TPM adds an emulated TPM 2.0 device. LoaderPath/NvramTemplate
	// are daemon-resolved firmware paths (required when SecureBoot; else fall back
	// to the standard OVMF pair). NvramPath name-pins the per-VM UEFI vars file
	// under dataDir so it travels deterministically; vTPM state is NOT pinned here
	// (see UUID below) — TPMStateDir is a test-only escape hatch.
	// UUID is the stable domain identity. Setting it makes libvirt's default
	// swtpm state path (/var/lib/libvirt/swtpm/<uuid>/) deterministic, so vTPM
	// state can be located + carried across hosts without an explicit <source>
	// (which the stock swtpm AppArmor profile forbids outside /var/lib/libvirt).
	UUID          string
	SecureBoot    bool
	TPM           bool
	LoaderPath    string
	NvramTemplate string
	NvramPath     string
	// TPMStateDir, when set, emits an explicit swtpm <source> dir. PRODUCTION
	// leaves it empty (libvirt uses /var/lib/libvirt/swtpm/<uuid>/, AppArmor-OK);
	// it's an optional test escape hatch only.
	TPMStateDir string
}

// NUMAPolicy controls guest memory/CPU NUMA binding.
type NUMAPolicy struct {
	PreferredNode int  // NUMA node ID; -1 = auto
	Strict        bool // true = strict, false = preferred
}

// HostdevConfig describes a PCI device to pass through to the VM.
type HostdevConfig struct {
	Address string // PCI address "0000:41:00.0"
}

// DiskConfig describes a VM disk.
type DiskConfig struct {
	Name   string
	Path   string
	Bus    string // virtio | scsi | sata | ide
	Cache  string // none | writeback | writethrough
	IsISO  bool   // true for ISO/CDROM
	// ControllerModel is the SCSI controller model for bus=="scsi" disks
	// (virtio-scsi | lsisas1068 | lsilogic | vmpvscsi | buslogic). Empty =
	// virtio-scsi. Imported guests bind their boot driver to this model, so it
	// must be preserved; ignored for non-SCSI buses.
	ControllerModel string
}

// NetworkConfig describes a VM network interface.
type NetworkConfig struct {
	Bridge string
	Model  string // virtio | e1000
	MAC    string
	VLAN   int    // 0 = untagged, 1–4094 = 802.1Q VLAN ID
	Direct string // non-empty = macvtap direct attach to this interface (e.g. "bond0.206")
}

// MachineTypeFromXML extracts the resolved <os><type machine="…"> value from a
// libvirt domain XML. libvirt expands an alias like "q35" to a concrete,
// versioned type (e.g. "pc-q35-9.0") when it defines a domain, so reading it
// back from the persistent XML yields the exact machine the guest ABI is bound
// to. Returns "" if the XML has no machine attribute (or doesn't parse).
func MachineTypeFromXML(domXML string) string {
	var d struct {
		OS osType `xml:"os>type"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return ""
	}
	return d.OS.Machine
}

// isQ35Machine reports whether m is the q35 machine family, in either the
// unversioned alias form ("q35", or "" which GenerateDomainXML defaults to q35)
// or a pinned versioned form ("pc-q35-9.0"). Used to gate Secure Boot, which
// requires q35 — a check on the bare "pc" alias alone would wrongly accept a
// pinned i440fx type like "pc-i440fx-7.1".
func isQ35Machine(m string) bool {
	return m == "" || m == "q35" || strings.HasPrefix(m, "pc-q35-") || m == "pc-q35"
}

// IsPinnedMachineType reports whether m is a concrete, versioned machine type
// (e.g. "pc-q35-9.0") rather than an unversioned alias ("q35", "pc", "") that
// libvirt resolves differently per host qemu version. A pinned type travels
// with the VM so a migration/failover can't silently shift the guest ABI.
func IsPinnedMachineType(m string) bool {
	// Versioned types carry a "-X.Y" suffix; aliases do not. Require a digit
	// after the last '-' to distinguish "pc-q35-9.0" from the bare "pc-q35"/"q35".
	i := strings.LastIndex(m, "-")
	if i < 0 || i == len(m)-1 {
		return false
	}
	return m[i+1] >= '0' && m[i+1] <= '9'
}

// GenerateDomainXML produces libvirt domain XML from a VMConfig.
func GenerateDomainXML(cfg VMConfig) (string, error) {
	if cfg.Machine == "" {
		cfg.Machine = "q35"
	}
	if cfg.Boot == "" {
		cfg.Boot = "disk"
	}

	isUEFI := cfg.Firmware == "uefi" || cfg.Firmware == ""

	// Memory ballooning: <memory> is the ceiling the balloon works within and
	// <currentMemory> the boot-time allocation. With a max set, the guest can be
	// inflated up to max and deflated toward min at runtime via SetMemory.
	memCeilingMiB := cfg.MemoryMiB
	if cfg.MaxMemoryMiB > memCeilingMiB {
		memCeilingMiB = cfg.MaxMemoryMiB
	}

	dom := domain{
		UUID: cfg.UUID,
		Type: "kvm",
		Name: cfg.Name,
		Memory: memory{
			Value: memCeilingMiB * 1024, // libvirt uses KiB
			Unit:  "KiB",
		},
		VCPU: vcpu{Value: cfg.CPU},
		OS: domainOS{
			Type: osType{
				Arch:    "x86_64",
				Machine: cfg.Machine,
				Value:   "hvm",
			},
		},
		Features: features{
			ACPI: &struct{}{},
			APIC: &struct{}{},
		},
		Clock: clock{Offset: "utc"},
		OnPoweroff: "destroy",
		OnReboot:   "restart",
		OnCrash:    "destroy",
	}

	// When a balloon ceiling is set, pin the boot allocation via <currentMemory>.
	if memCeilingMiB != cfg.MemoryMiB && cfg.MemoryMiB > 0 {
		dom.CurrentMemory = &memory{Value: cfg.MemoryMiB * 1024, Unit: "KiB"}
	}

	// CPU mode: host-passthrough, host-model, or custom.
	if cfg.CPUMode != "" {
		dom.CPUDef = &cpuDef{Mode: cfg.CPUMode}
	}

	// Hugepages: back guest memory with host hugepages.
	if cfg.HugePages {
		dom.MemoryBacking = &memoryBacking{HugePages: &struct{}{}}
	}

	// CPU pinning: pin each vCPU to a specific host CPU.
	if len(cfg.CPUPinning) > 0 {
		ct := &cpuTune{}
		for i := 0; i < cfg.CPU && i < len(cfg.CPUPinning); i++ {
			ct.VCPUPin = append(ct.VCPUPin, vcpuPin{
				VCPU:   i,
				CPUSet: fmt.Sprintf("%d", cfg.CPUPinning[i]),
			})
		}
		dom.CPUTune = ct
	}

	// NUMA tune: bind guest memory to a specific host NUMA node.
	if cfg.NUMAPolicy != nil && cfg.NUMAPolicy.PreferredNode >= 0 {
		mode := "preferred"
		if cfg.NUMAPolicy.Strict {
			mode = "strict"
		}
		dom.NUMATune = &numaTune{
			Memory: numaMemory{
				Mode:    mode,
				Nodeset: fmt.Sprintf("%d", cfg.NUMAPolicy.PreferredNode),
			},
		}
	}

	// IO threads for virtio-blk/virtio-scsi.
	if cfg.IOThreads > 0 {
		dom.IOThreads = cfg.IOThreads
	}

	// Boot: BIOS uses <boot dev="..."> in <os>, UEFI uses boot order on devices.
	if !isUEFI {
		dom.OS.Boot = &osBoot{Dev: libvirtBootDev(cfg.Boot)}
	}

	// Secure Boot requires UEFI + q35 + SMM (G1).
	if cfg.SecureBoot {
		if !isUEFI {
			return "", fmt.Errorf("secure boot requires uefi firmware (got %q)", cfg.Firmware)
		}
		if !isQ35Machine(cfg.Machine) {
			return "", fmt.Errorf("secure boot requires the q35 machine type, got %q", cfg.Machine)
		}
		if cfg.LoaderPath == "" || cfg.NvramTemplate == "" {
			return "", fmt.Errorf("secure boot requires resolved firmware paths (LoaderPath/NvramTemplate) — the daemon must supply them")
		}
		dom.Features.SMM = &smmFeature{State: "on"}
	}

	// UEFI firmware. Paths are daemon-resolved (cfg.LoaderPath/NvramTemplate);
	// fall back to the standard non-secure OVMF pair for callers that don't set
	// them (backward compat). NvramPath, when set, pins the per-VM vars file under
	// dataDir so it travels deterministically across lifecycle ops; empty lets
	// libvirt auto-place it.
	if isUEFI {
		loader := cfg.LoaderPath
		if loader == "" {
			loader = "/usr/share/OVMF/OVMF_CODE_4M.fd"
		}
		varsTemplate := cfg.NvramTemplate
		if varsTemplate == "" {
			varsTemplate = "/usr/share/OVMF/OVMF_VARS_4M.fd"
		}
		dom.OS.Loader = &osLoader{Readonly: "yes", Type: "pflash", Value: loader}
		if cfg.SecureBoot {
			dom.OS.Loader.Secure = "yes"
		}
		dom.OS.Nvram = &osNvram{Template: varsTemplate, Value: cfg.NvramPath}
	}

	// Devices
	dev := &devices{}

	// Emulator
	dev.Emulator = "/usr/bin/qemu-system-x86_64"

	// virtio memory balloon: always present so the host can reclaim/grow guest
	// memory at runtime (#4). Harmless for fixed-memory VMs.
	dev.MemBalloon = &memballoon{Model: "virtio"}

	// VM disks. UEFI boots by per-device <boot order=N> (BIOS uses <os><boot dev>
	// set above). Honor cfg.Boot: when "cdrom", the installer ISO boots first
	// (order 1) and the root disk second (so the VM boots the installed OS once
	// the ISO is ejected); otherwise the first non-ISO disk boots.
	bootFromCDROM := cfg.Boot == "cdrom"
	diskBootAssigned := false
	for i, d := range cfg.Disks {
		disk := diskDevice{
			Type:   "file",
			Device: "disk",
			Driver: diskDriver{Name: "qemu", Type: "qcow2", Cache: d.Cache},
			Source: diskSource{File: d.Path},
			Target: diskTarget{Dev: DiskDevName(d.Bus, i), Bus: d.Bus},
		}
		if d.Cache == "" {
			disk.Driver.Cache = "writeback"
		}
		if d.IsISO {
			disk.Device = "cdrom"
			disk.Driver.Type = "raw"
			disk.Target = diskTarget{Dev: fmt.Sprintf("sd%c", 'a'+i), Bus: "sata"}
			disk.Readonly = &struct{}{}
		}
		if isUEFI {
			switch {
			case bootFromCDROM && d.IsISO:
				disk.BootOrder = &bootOrder{Order: 1}
			case bootFromCDROM && !d.IsISO && !diskBootAssigned:
				disk.BootOrder = &bootOrder{Order: 2}
				diskBootAssigned = true
			case !bootFromCDROM && !d.IsISO && !diskBootAssigned:
				disk.BootOrder = &bootOrder{Order: 1}
				diskBootAssigned = true
			}
		}
		dev.Disks = append(dev.Disks, disk)
	}

	// Cloud-init ISO. Place it after any regular/installer disks so its sata
	// target can't collide with an installer-ISO cdrom (which derives its dev
	// from its disk index). With a single root disk this is still "sdb".
	if cfg.CloudInitISO != "" {
		dev.Disks = append(dev.Disks, diskDevice{
			Type:     "file",
			Device:   "cdrom",
			Driver:   diskDriver{Name: "qemu", Type: "raw"},
			Source:   diskSource{File: cfg.CloudInitISO},
			Target:   diskTarget{Dev: fmt.Sprintf("sd%c", 'a'+len(cfg.Disks)), Bus: "sata"},
			Readonly: &struct{}{},
		})
	}

	// SCSI controller: when any disk is on the scsi bus, declare one explicit
	// controller so its MODEL can be set (libvirt would otherwise auto-add a
	// default-model controller). Imported guests bind their boot storage driver
	// to this model, so it must be preserved. v1 supports a single SCSI
	// controller model per VM — take the first non-empty model (disks[0] is the
	// boot disk for imports); default virtio-scsi.
	scsiModel := ""
	for _, d := range cfg.Disks {
		if d.Bus == "scsi" {
			if d.ControllerModel != "" {
				scsiModel = d.ControllerModel
				break
			}
			scsiModel = "virtio-scsi"
		}
	}
	if scsiModel != "" {
		dev.Controllers = append(dev.Controllers, controllerDevice{
			Type:  "scsi",
			Index: 0,
			Model: scsiModel,
		})
	}

	// Network interfaces
	for _, n := range cfg.Networks {
		mac := n.MAC
		if mac == "" {
			mac = GenerateMAC()
		}
		model := n.Model
		if model == "" {
			model = "virtio"
		}
		var iface interfaceDevice
		if n.Direct != "" {
			// macvtap: direct attach to parent interface (no bridge needed).
			iface = interfaceDevice{
				Type:   "direct",
				MAC:    ifaceMAC{Address: mac},
				Source: ifaceSource{Dev: n.Direct, Mode: "bridge"},
				Model:  ifaceModel{Type: model},
			}
		} else {
			iface = interfaceDevice{
				Type: "bridge",
				MAC:  ifaceMAC{Address: mac},
				Source: ifaceSource{Bridge: n.Bridge},
				Model:  ifaceModel{Type: model},
			}
		}
		dev.Interfaces = append(dev.Interfaces, iface)
	}

	// Serial console
	dev.Serials = append(dev.Serials, serialDevice{
		Type: "pty",
		Target: serialTarget{Type: "isa-serial", Port: 0},
	})
	dev.Consoles = append(dev.Consoles, consoleDevice{
		Type: "pty",
		Target: consoleTarget{Type: "serial", Port: 0},
	})

	// QEMU guest agent channel
	if cfg.GuestAgent {
		dev.Channels = append(dev.Channels, channelDevice{
			Type: "unix",
			Target: channelTarget{
				Type: "virtio",
				Name: "org.qemu.guest_agent.0",
			},
		})
	}

	// VNC graphics (for lv vnc / web UI noVNC viewer)
	if cfg.EnableVNC {
		dev.Graphics = append(dev.Graphics, graphicsDevice{
			Type:     "vnc",
			Port:     -1, // auto-assign
			Autoport: "yes",
			Listen:   graphicsListen{Type: "address", Address: "127.0.0.1"},
		})
	}
	// SPICE graphics — higher-fidelity console; works with `lv spice <vm>` or
	// any external client (`remote-viewer`, virt-manager). Listens on
	// localhost; the daemon proxies connections via ProxySPICE.
	if cfg.EnableSPICE {
		dev.Graphics = append(dev.Graphics, graphicsDevice{
			Type:     "spice",
			Port:     -1,
			Autoport: "yes",
			Listen:   graphicsListen{Type: "address", Address: "127.0.0.1"},
		})
	}
	if cfg.EnableVNC || cfg.EnableSPICE {
		// virtio-gpu has no VGA BIOS, so SeaBIOS/GRUB draw nothing on it — a BIOS
		// guest shows a black VNC through firmware/boot. OVMF drives virtio-gpu, so
		// UEFI is fine; use a legacy VGA model for BIOS so the console renders from
		// power-on.
		videoType := "virtio"
		if !isUEFI {
			videoType = "vga"
		}
		dev.Videos = append(dev.Videos, videoDevice{
			Model: videoModel{Type: videoType},
		})
	}

	// PCI passthrough hostdevs
	for _, hd := range cfg.Hostdevs {
		parsed := ParsePCIAddress(hd.Address)
		dev.Hostdevs = append(dev.Hostdevs, hostdevDevice{
			Mode:    "subsystem",
			Type:    "pci",
			Managed: "yes",
			Source: hostdevSource{
				Address: hostdevAddress{
					Domain:   parsed.Domain,
					Bus:      parsed.Bus,
					Slot:     parsed.Slot,
					Function: parsed.Function,
				},
			},
		})
	}

	// Emulated TPM 2.0 (G1). State is pinned at TPMStateDir (when set) so it
	// travels with the VM; persistent_state keeps it across power cycles. tpm-crb
	// is the Windows-11-friendly model on q35.
	if cfg.TPM {
		backend := tpmBackend{Type: "emulator", Version: "2.0", PersistentState: "yes"}
		if cfg.TPMStateDir != "" {
			backend.Source = &tpmSource{Type: "dir", Path: cfg.TPMStateDir}
		}
		dev.TPM = &tpmDevice{Model: "tpm-crb", Backend: backend}
	}

	dom.Devices = dev

	output, err := xml.MarshalIndent(dom, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal domain XML: %w", err)
	}

	return xml.Header + string(output), nil
}

// DiskDevName derives the libvirt target device name for a disk bus + index.
// Exported so the import path and UpdateVM rebuild compute target devs with the
// same rule rather than duplicating it.
func DiskDevName(bus string, index int) string {
	letter := 'a' + index
	switch bus {
	case "virtio":
		return fmt.Sprintf("vd%c", letter)
	case "scsi", "sata":
		return fmt.Sprintf("sd%c", letter)
	case "ide":
		return fmt.Sprintf("hd%c", letter)
	default:
		return fmt.Sprintf("vd%c", letter)
	}
}

// GenerateMAC produces a random MAC address with the QEMU OUI prefix.
func GenerateMAC() string {
	buf := make([]byte, 3)
	rand.Read(buf)
	// 52:54:00 is the QEMU OUI prefix
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", buf[0], buf[1], buf[2])
}

// DiskPath returns the standard path for a VM disk.
// Uses flat naming so all disks land in the pool target directory.
func DiskPath(dataDir, vmName, diskName string) string {
	return filepath.Join(dataDir, "disks", vmName+"-"+diskName+".qcow2")
}

// SafeDiskPath is DiskPath with the name components validated, so a name like
// "../../x" can't escape the disks dir. Callers acting on attacker-influenced or
// replicated names should use this instead of DiskPath.
func SafeDiskPath(dataDir, vmName, diskName string) (string, error) {
	if err := safename.ValidateVMName(vmName); err != nil {
		return "", err
	}
	if err := safename.ValidateDiskName(diskName); err != nil {
		return "", err
	}
	return DiskPath(dataDir, vmName, diskName), nil
}

// NvramPath returns the per-VM UEFI vars file, pinned under dataDir so it can be
// located/copied deterministically across the VM lifecycle (G1).
func NvramPath(dataDir, vmName string) string {
	return filepath.Join(dataDir, "nvram", vmName+"_VARS.fd")
}

// SafeNvramPath is NvramPath with the VM name validated.
func SafeNvramPath(dataDir, vmName string) (string, error) {
	if err := safename.ValidateVMName(vmName); err != nil {
		return "", err
	}
	return NvramPath(dataDir, vmName), nil
}


// CloudInitISOPath returns the standard path for a cloud-init ISO.
func CloudInitISOPath(dataDir, vmName string) string {
	return filepath.Join(dataDir, "cloudinit", vmName+".iso")
}

// SafeCloudInitISOPath is CloudInitISOPath with the VM name validated.
func SafeCloudInitISOPath(dataDir, vmName string) (string, error) {
	if err := safename.ValidateVMName(vmName); err != nil {
		return "", err
	}
	return CloudInitISOPath(dataDir, vmName), nil
}

// VMStatePath returns the standard path for a memory snapshot's saved RAM image
// (#3). snapName must already be path-safe (validated by the caller).
func VMStatePath(dataDir, vmName, snapName string) string {
	return filepath.Join(dataDir, "vmstate", vmName+"-"+snapName+".save")
}

// SafeVMStatePath is VMStatePath with the VM and snapshot names validated.
func SafeVMStatePath(dataDir, vmName, snapName string) (string, error) {
	if err := safename.ValidateVMName(vmName); err != nil {
		return "", err
	}
	if err := safename.ValidateSnapshotName(snapName); err != nil {
		return "", err
	}
	return VMStatePath(dataDir, vmName, snapName), nil
}

// ImagePath returns the standard path for a base image.
func ImagePath(dataDir, imageName string) string {
	ext := ".qcow2"
	if strings.HasSuffix(imageName, ".iso") {
		ext = ""
	}
	return filepath.Join(dataDir, "images", imageName+ext)
}

// SafeImagePath is ImagePath with the image name validated.
func SafeImagePath(dataDir, imageName string) (string, error) {
	if err := safename.ValidateImageName(imageName); err != nil {
		return "", err
	}
	return ImagePath(dataDir, imageName), nil
}

// ═══════════ XML Structs ═══════════

type domain struct {
	XMLName       xml.Name       `xml:"domain"`
	Type          string         `xml:"type,attr"`
	Name          string         `xml:"name"`
	UUID          string         `xml:"uuid,omitempty"` // stable VM identity; makes the libvirt-default swtpm path deterministic (G1)
	Memory        memory         `xml:"memory"`
	CurrentMemory *memory        `xml:"currentMemory,omitempty"`
	VCPU          vcpu           `xml:"vcpu"`
	IOThreads     int            `xml:"iothreads,omitempty"`
	CPUDef        *cpuDef         `xml:"cpu,omitempty"`
	CPUTune       *cpuTune       `xml:"cputune,omitempty"`
	NUMATune      *numaTune      `xml:"numatune,omitempty"`
	MemoryBacking *memoryBacking `xml:"memoryBacking,omitempty"`
	OS            domainOS       `xml:"os"`
	Features      features       `xml:"features"`
	Clock         clock          `xml:"clock"`
	OnPoweroff    string         `xml:"on_poweroff"`
	OnReboot      string         `xml:"on_reboot"`
	OnCrash       string         `xml:"on_crash"`
	Devices       *devices       `xml:"devices"`
}

type cpuDef struct {
	Mode string `xml:"mode,attr"`
}

type numaTune struct {
	Memory numaMemory `xml:"memory"`
}

type numaMemory struct {
	Mode    string `xml:"mode,attr"`
	Nodeset string `xml:"nodeset,attr"`
}

type memoryBacking struct {
	HugePages *struct{} `xml:"hugepages,omitempty"`
}

type cpuTune struct {
	VCPUPin []vcpuPin `xml:"vcpupin"`
}

type vcpuPin struct {
	VCPU   int    `xml:"vcpu,attr"`
	CPUSet string `xml:"cpuset,attr"`
}

type memory struct {
	Value int    `xml:",chardata"`
	Unit  string `xml:"unit,attr"`
}

type vcpu struct {
	Value int `xml:",chardata"`
}

type domainOS struct {
	Type   osType    `xml:"type"`
	Loader *osLoader `xml:"loader,omitempty"`
	Nvram  *osNvram  `xml:"nvram,omitempty"`
	Boot   *osBoot   `xml:"boot,omitempty"`
}

type osType struct {
	Arch    string `xml:"arch,attr"`
	Machine string `xml:"machine,attr"`
	Value   string `xml:",chardata"`
}

type osLoader struct {
	Readonly string `xml:"readonly,attr"`
	Secure   string `xml:"secure,attr,omitempty"`
	Type     string `xml:"type,attr"`
	Value    string `xml:",chardata"`
}

type osNvram struct {
	Template string `xml:"template,attr,omitempty"`
	Type     string `xml:"type,attr,omitempty"`
	Value    string `xml:",chardata"` // explicit per-VM vars path; empty = libvirt auto
}

type osBoot struct {
	Dev string `xml:"dev,attr"`
}

// libvirtBootDev maps litevirt's boot keyword (disk|cdrom|network) to a value
// libvirt accepts in <os><boot dev="...">. libvirt allows fd|hd|cdrom|network —
// notably NOT "disk" — so the default "disk" must be rendered as "hd", otherwise
// DomainDefineXML rejects the domain with
// "Invalid value for attribute 'dev' in element 'boot': 'disk'".
func libvirtBootDev(boot string) string {
	switch boot {
	case "cdrom":
		return "cdrom"
	case "network":
		return "network"
	default: // "disk", "" and anything unexpected → boot from the hard disk
		return "hd"
	}
}

type features struct {
	ACPI *struct{}   `xml:"acpi,omitempty"`
	APIC *struct{}   `xml:"apic,omitempty"`
	SMM  *smmFeature `xml:"smm,omitempty"` // required for Secure Boot
}

type smmFeature struct {
	State string `xml:"state,attr"` // "on"
}

type clock struct {
	Offset string `xml:"offset,attr"`
}

type devices struct {
	Emulator    string             `xml:"emulator"`
	Controllers []controllerDevice `xml:"controller"`
	Disks       []diskDevice       `xml:"disk"`
	Interfaces  []interfaceDevice  `xml:"interface"`
	Hostdevs   []hostdevDevice   `xml:"hostdev"`
	Serials    []serialDevice    `xml:"serial"`
	Consoles   []consoleDevice   `xml:"console"`
	Channels   []channelDevice   `xml:"channel"`
	Graphics   []graphicsDevice  `xml:"graphics"`
	Videos     []videoDevice     `xml:"video"`
	MemBalloon *memballoon       `xml:"memballoon,omitempty"`
	TPM        *tpmDevice        `xml:"tpm,omitempty"`
}

// tpmDevice is an emulated TPM 2.0 (G1). State lives at Backend.Source.Path
// (pinned under dataDir) so it travels with the VM.
type tpmDevice struct {
	XMLName xml.Name   `xml:"tpm"`
	Model   string     `xml:"model,attr"` // tpm-crb on q35
	Backend tpmBackend `xml:"backend"`
}

type tpmBackend struct {
	Type            string     `xml:"type,attr"`                        // "emulator"
	Version         string     `xml:"version,attr,omitempty"`           // "2.0"
	PersistentState string     `xml:"persistent_state,attr,omitempty"`  // "yes"
	Source          *tpmSource `xml:"source,omitempty"`
}

type tpmSource struct {
	Type string `xml:"type,attr"` // "dir"
	Path string `xml:"path,attr"`
}

// memballoon is the virtio memory-balloon device (#4): lets the host reclaim
// guest memory down to currentMemory and re-inflate up to <memory>.
type memballoon struct {
	Model string `xml:"model,attr"`
}

type controllerDevice struct {
	XMLName xml.Name `xml:"controller"`
	Type    string   `xml:"type,attr"`
	Index   int      `xml:"index,attr"`
	Model   string   `xml:"model,attr,omitempty"`
}

type diskDevice struct {
	XMLName   xml.Name    `xml:"disk"`
	Type      string      `xml:"type,attr"`
	Device    string      `xml:"device,attr"`
	Driver    diskDriver  `xml:"driver,omitempty"`
	Source    diskSource  `xml:"source,omitempty"`
	Target    diskTarget  `xml:"target"`
	BootOrder *bootOrder  `xml:"boot,omitempty"`
	Readonly  *struct{}   `xml:"readonly,omitempty"`
}

type bootOrder struct {
	Order int `xml:"order,attr"`
}

type diskDriver struct {
	Name  string `xml:"name,attr,omitempty"`
	Type  string `xml:"type,attr,omitempty"`
	Cache string `xml:"cache,attr,omitempty"`
}

type diskSource struct {
	File string `xml:"file,attr,omitempty"`
}

type diskTarget struct {
	Dev string `xml:"dev,attr"`
	Bus string `xml:"bus,attr,omitempty"`
}

type interfaceDevice struct {
	XMLName xml.Name    `xml:"interface"`
	Type    string      `xml:"type,attr"`
	MAC     ifaceMAC    `xml:"mac"`
	Source  ifaceSource `xml:"source"`
	Model   ifaceModel  `xml:"model"`
}

type ifaceMAC struct {
	Address string `xml:"address,attr"`
}

type ifaceSource struct {
	Bridge string `xml:"bridge,attr,omitempty"`
	Dev    string `xml:"dev,attr,omitempty"`
	Mode   string `xml:"mode,attr,omitempty"`
}

type ifaceModel struct {
	Type string `xml:"type,attr"`
}

type serialDevice struct {
	Type   string       `xml:"type,attr"`
	Target serialTarget `xml:"target"`
}

type serialTarget struct {
	Type string `xml:"type,attr,omitempty"`
	Port int    `xml:"port,attr"`
}

type consoleDevice struct {
	Type   string        `xml:"type,attr"`
	Target consoleTarget `xml:"target"`
}

type consoleTarget struct {
	Type string `xml:"type,attr"`
	Port int    `xml:"port,attr"`
}

type channelDevice struct {
	Type   string        `xml:"type,attr"`
	Target channelTarget `xml:"target"`
}

type channelTarget struct {
	Type string `xml:"type,attr"`
	Name string `xml:"name,attr"`
}

type graphicsDevice struct {
	Type     string         `xml:"type,attr"`
	Port     int            `xml:"port,attr"`
	Autoport string         `xml:"autoport,attr"`
	Listen   graphicsListen `xml:"listen"`
}

type graphicsListen struct {
	Type    string `xml:"type,attr"`
	Address string `xml:"address,attr"`
}

type videoDevice struct {
	Model videoModel `xml:"model"`
}

type videoModel struct {
	Type string `xml:"type,attr"`
}

// ── PCI hostdev XML types ──

type hostdevDevice struct {
	XMLName xml.Name      `xml:"hostdev"`
	Mode    string        `xml:"mode,attr"`
	Type    string        `xml:"type,attr"`
	Managed string        `xml:"managed,attr"`
	Source  hostdevSource `xml:"source"`
}

type hostdevSource struct {
	Address hostdevAddress `xml:"address"`
}

type hostdevAddress struct {
	Domain   string `xml:"domain,attr"`
	Bus      string `xml:"bus,attr"`
	Slot     string `xml:"slot,attr"`
	Function string `xml:"function,attr"`
}

// ParsedPCIAddr holds the four components of a PCI address.
type ParsedPCIAddr struct {
	Domain, Bus, Slot, Function string
}

// ParsePCIAddress splits "0000:41:00.0" into domain/bus/slot/function hex strings.
func ParsePCIAddress(addr string) ParsedPCIAddr {
	// Format: DDDD:BB:SS.F
	parts := strings.SplitN(addr, ":", 3)
	if len(parts) < 3 {
		return ParsedPCIAddr{Domain: "0x0000", Bus: "0x00", Slot: "0x00", Function: "0x0"}
	}
	slotFunc := strings.SplitN(parts[2], ".", 2)
	fn := "0"
	if len(slotFunc) == 2 {
		fn = slotFunc[1]
	}
	return ParsedPCIAddr{
		Domain:   "0x" + parts[0],
		Bus:      "0x" + parts[1],
		Slot:     "0x" + slotFunc[0],
		Function: "0x" + fn,
	}
}
