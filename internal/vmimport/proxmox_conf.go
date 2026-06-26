package vmimport

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ParseProxmoxConf reads a Proxmox /etc/pve/qemu-server/<vmid>.conf descriptor
// from disk and produces a ForeignVM. Disk volume references (storage:volume)
// are recorded in LocalPath for display; the import handler resolves them to
// real files via --disk-map (this adapter has no access to the Proxmox storage
// layer).
func ParseProxmoxConf(path string) (*ForeignVM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read proxmox conf: %w", err)
	}
	return parseProxmoxConfBytes(data)
}

// proxmoxConf holds the raw key→value pairs of the [main] section (snapshot
// sections are dropped), preserving first-seen wins (Proxmox conf keys are
// unique within a section).
type proxmoxConf struct {
	keys map[string]string
}

// parseProxmoxConfLines splits a Proxmox conf into the main-section key/value
// map, stopping at the first "[snapshotname]" header. Returns whether any
// snapshot section was seen so the caller can warn.
func parseProxmoxConfLines(data []byte) (proxmoxConf, bool) {
	pc := proxmoxConf{keys: map[string]string{}}
	hadSnapshot := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	// Conf lines are short; the default 64 KiB token size is plenty, but a
	// pathological description line could be long — bump the buffer.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// A "[name]" line starts a section. Anything other than the implicit
		// main section is a snapshot — stop here (snapshots are dropped).
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			hadSnapshot = true
			break
		}
		// key: value
		idx := strings.Index(trimmed, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:idx])
		val := strings.TrimSpace(trimmed[idx+1:])
		if _, seen := pc.keys[key]; !seen {
			pc.keys[key] = val
		}
	}
	return pc, hadSnapshot
}

// proxmox disk-bus key prefixes, in the order we scan device slots.
var proxmoxDiskBuses = []string{"virtio", "scsi", "sata", "ide"}

// diskEntry pairs a parsed disk with its source device key (scsi0, …) for
// ordering and boot-disk selection.
type diskEntry struct {
	key string
	d   ForeignDisk
}

// parseProxmoxConfBytes is the in-memory parser shared by ParseProxmoxConf and
// the VMA reader (which extracts an embedded qemu-server.conf blob).
func parseProxmoxConfBytes(data []byte) (*ForeignVM, error) {
	pc, hadSnapshot := parseProxmoxConfLines(data)
	fv := &ForeignVM{}
	if hadSnapshot {
		fv.Warnf("Proxmox snapshots are not imported; only the current configuration is converted")
	}

	fv.Name = pc.keys["name"]
	fv.GuestOS = guessGuestOSProxmox(pc.keys["ostype"])

	// CPUs = cores × sockets (sockets default 1, cores default 1).
	cores := atoiSafe(pc.keys["cores"])
	if cores <= 0 {
		cores = 1
	}
	sockets := atoiSafe(pc.keys["sockets"])
	if sockets <= 0 {
		sockets = 1
	}
	fv.CPUs = cores * sockets

	fv.MemoryMiB = atoiSafe(pc.keys["memory"]) // already MiB in Proxmox

	// Firmware: ovmf → uefi, seabios/absent → bios.
	if strings.EqualFold(pc.keys["bios"], "ovmf") {
		fv.Firmware = "uefi"
	} else {
		fv.Firmware = "bios"
	}

	// Machine: q35 → q35, pc-i440fx-*/absent → pc.
	if strings.Contains(strings.ToLower(pc.keys["machine"]), "q35") {
		fv.Machine = "q35"
	} else {
		fv.Machine = "pc"
	}

	// SCSI controller model (applied to all scsi-bus disks).
	scsiModel := scsiModelFromProxmox(pc.keys["scsihw"])
	if v, ok := pc.keys["scsihw"]; ok && scsiModel == "" {
		fv.Warnf("unrecognised scsihw %q; SCSI disks default to virtio-scsi", v)
		scsiModel = "virtio-scsi"
	}

	// Collect disks by device key (scsi0, virtio1, sata0, ide2, …).
	var disks []diskEntry
	for key, val := range pc.keys {
		bus := diskBusFromKey(key)
		if bus == "" {
			continue
		}
		fd := parseProxmoxDisk(key, val, bus, scsiModel)
		disks = append(disks, diskEntry{key: key, d: fd})
	}
	// Deterministic order: bus group (virtio, scsi, sata, ide), then index.
	sortDiskEntries(disks)

	// EFI vars / TPM state.
	if _, ok := pc.keys["efidisk0"]; ok {
		fv.Warnf("EFI vars disk (efidisk0) not imported; the VM boots with fresh NVRAM")
	}
	if _, ok := pc.keys["tpmstate0"]; ok {
		fv.HasTPM = true
		fv.Warnf("source has a vTPM (tpmstate0) — imported with a fresh vTPM (the source TPM state is not carried; a BitLocker guest needs its recovery key) (G1)")
	}

	// NICs.
	var netKeys []string
	for key := range pc.keys {
		if isNetKey(key) {
			netKeys = append(netKeys, key)
		}
	}
	sortIndexedKeys(netKeys, "net")
	for _, key := range netKeys {
		if nic, ok := parseProxmoxNIC(pc.keys[key]); ok {
			fv.NICs = append(fv.NICs, nic)
		} else {
			fv.Warnf("could not parse network device %q (%q); skipped", key, pc.keys[key])
		}
	}

	// Determine the boot disk and order it first.
	bootKey := bootDiskKey(pc)
	ordered := orderDisks(disks, bootKey)

	// Assign IR names: first non-CDROM data disk = "root", then disk1, disk2…
	di := 0
	dataDisks := 0
	for _, e := range ordered {
		fd := e.d
		if !fd.IsCDROM {
			if di == 0 {
				fd.Name = "root"
			} else {
				fd.Name = fmt.Sprintf("disk%d", di)
			}
			di++
			dataDisks++
		}
		fv.Disks = append(fv.Disks, fd)
	}

	if fv.SecureBoot {
		fv.Warnf("source has Secure Boot enabled — imported with Secure Boot (G1)")
	}

	fv.Normalize()
	if dataDisks == 0 {
		return nil, fmt.Errorf("proxmox conf describes no data disks")
	}
	return fv, nil
}

// guessGuestOSProxmox maps a Proxmox ostype to the IR's coarse hint.
func guessGuestOSProxmox(ostype string) string {
	o := strings.ToLower(strings.TrimSpace(ostype))
	switch {
	case o == "":
		return ""
	case strings.HasPrefix(o, "w"): // win7/win8/win10/win11/w2k/w2k3/w2k8/wvista/wxp
		return "windows"
	case o == "l24" || o == "l26" || strings.HasPrefix(o, "l"):
		return "linux"
	case o == "solaris" || o == "other":
		return ""
	default:
		return "linux"
	}
}

// diskBusFromKey returns the IR bus for a Proxmox disk device key, or "" if the
// key is not a disk slot.
func diskBusFromKey(key string) string {
	for _, prefix := range proxmoxDiskBuses {
		if rest, ok := strings.CutPrefix(key, prefix); ok && isAllDigits(rest) {
			return prefix
		}
	}
	return ""
}

// parseProxmoxDisk parses a disk value like
//
//	local-lvm:vm-100-disk-0,size=32G,cache=none,ssd=1
//	local:iso/debian.iso,media=cdrom
//	none,media=cdrom
//
// into a ForeignDisk. The leading token (before the first comma) is the volume
// reference (storage:volume) stored in LocalPath for the handler to resolve.
func parseProxmoxDisk(key, val, bus, scsiModel string) ForeignDisk {
	fd := ForeignDisk{SourceID: key, Bus: bus}
	if bus == "scsi" {
		fd.ControllerModel = scsiModel
	}

	parts := strings.Split(val, ",")
	volRef := strings.TrimSpace(parts[0])

	isCDROM := false
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		k, v, _ := strings.Cut(p, "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "media":
			if strings.EqualFold(strings.TrimSpace(v), "cdrom") {
				isCDROM = true
			}
		case "size":
			fd.CapacityBytes = parseProxmoxSize(strings.TrimSpace(v))
		}
	}

	// A bare value of "none" or "cdrom" (e.g. ide2: none,media=cdrom) is an
	// empty/optical drive; "cdrom" as the volume also implies optical media.
	switch strings.ToLower(volRef) {
	case "none", "cdrom":
		isCDROM = true
	}
	fd.IsCDROM = isCDROM
	fd.LocalPath = volRef // storage:volume reference for the handler
	return fd
}

// parseProxmoxSize converts a Proxmox size token (e.g. "32G", "512M", "1T",
// "1048576" bare-bytes) into bytes. Proxmox writes size= without a suffix as
// bytes in some versions and with G/M/T in others; default unsuffixed to bytes.
func parseProxmoxSize(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := uint64(1)
	last := s[len(s)-1]
	switch last {
	case 'T', 't':
		mult = 1 << 40
		s = s[:len(s)-1]
	case 'G', 'g':
		mult = 1 << 30
		s = s[:len(s)-1]
	case 'M', 'm':
		mult = 1 << 20
		s = s[:len(s)-1]
	case 'K', 'k':
		mult = 1 << 10
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n * mult
}

// isNetKey reports whether key is a Proxmox network device slot (net0, net1…).
func isNetKey(key string) bool {
	rest, ok := strings.CutPrefix(key, "net")
	return ok && isAllDigits(rest)
}

// parseProxmoxNIC parses a value like
//
//	virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10,firewall=1
//	e1000=12:34:56:78:9A:BC,bridge=vmbr1
//
// into a ForeignNIC. The first token is <model>=<MAC>.
func parseProxmoxNIC(val string) (ForeignNIC, bool) {
	parts := strings.Split(val, ",")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return ForeignNIC{}, false
	}
	model, mac, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
	if !ok {
		return ForeignNIC{}, false
	}
	nic := ForeignNIC{
		Model: nicModel(strings.TrimSpace(model)),
		MAC:   normalizeMAC(mac),
	}
	for _, p := range parts[1:] {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "bridge":
			nic.Network = v
		case "tag":
			nic.VLAN = atoiSafe(v)
		}
	}
	return nic, true
}

// bootDiskKey extracts the first bootable disk device key from the conf:
// modern "boot: order=scsi0;ide2" or legacy "bootdisk: scsi0". Returns "" when
// neither selects a known disk slot (caller falls back to natural order).
func bootDiskKey(pc proxmoxConf) string {
	if bd := strings.TrimSpace(pc.keys["bootdisk"]); bd != "" && diskBusFromKey(bd) != "" {
		return bd
	}
	boot := pc.keys["boot"]
	if boot == "" {
		return ""
	}
	// boot may be "order=scsi0;ide2;net0" or legacy "cdn"/"order=…".
	for _, seg := range strings.Split(boot, ",") {
		seg = strings.TrimSpace(seg)
		if rest, ok := strings.CutPrefix(seg, "order="); ok {
			for _, dev := range strings.Split(rest, ";") {
				dev = strings.TrimSpace(dev)
				if diskBusFromKey(dev) != "" {
					return dev
				}
			}
		}
	}
	return ""
}

// orderDisks puts the boot disk first (if found), preserving the bus/index
// order of the rest.
func orderDisks(disks []diskEntry, bootKey string) []diskEntry {
	if bootKey == "" {
		return disks
	}
	out := make([]diskEntry, 0, len(disks))
	bootIdx := -1
	for i := range disks {
		if disks[i].key == bootKey {
			bootIdx = i
			continue
		}
		out = append(out, disks[i])
	}
	if bootIdx < 0 {
		return disks // boot key references a slot we did not parse; leave order
	}
	return append([]diskEntry{disks[bootIdx]}, out...)
}

// sortDiskEntries orders disk entries by bus group (virtio, scsi, sata, ide)
// then by device index for determinism.
func sortDiskEntries(disks []diskEntry) {
	busRank := map[string]int{"virtio": 0, "scsi": 1, "sata": 2, "ide": 3}
	less := func(a, b int) bool {
		ra, rb := busRank[disks[a].d.Bus], busRank[disks[b].d.Bus]
		if ra != rb {
			return ra < rb
		}
		return keyIndex(disks[a].key) < keyIndex(disks[b].key)
	}
	// simple insertion sort (slices are tiny, avoids a sort import churn)
	for i := 1; i < len(disks); i++ {
		for j := i; j > 0 && less(j, j-1); j-- {
			disks[j], disks[j-1] = disks[j-1], disks[j]
		}
	}
}

// sortIndexedKeys sorts keys of the form <prefix><N> by their numeric index.
func sortIndexedKeys(keys []string, prefix string) {
	idx := func(k string) int {
		rest := strings.TrimPrefix(k, prefix)
		return atoiSafe(rest)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && idx(keys[j]) < idx(keys[j-1]); j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
}

// keyIndex returns the trailing numeric index of a device key (scsi0 → 0).
func keyIndex(key string) int {
	i := len(key)
	for i > 0 && key[i-1] >= '0' && key[i-1] <= '9' {
		i--
	}
	return atoiSafe(key[i:])
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
