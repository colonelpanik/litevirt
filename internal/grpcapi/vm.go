package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
	"github.com/litevirt/litevirt/internal/hooks"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/placement"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// validateSpecNames validates every name in a VM spec that lands in a
// filesystem path — the VM name, each disk name, and the base image reference —
// so a traversal can't enter the system at CreateVM/UpdateVM (defense-in-depth
// over the Safe* builders + the image store's write-layer checks).
func validateSpecNames(spec *pb.VMSpec) error {
	if spec == nil {
		return nil
	}
	if err := safename.ValidateVMName(spec.Name); err != nil {
		return err
	}
	if spec.Project != "" {
		if _, err := safename.CanonicalProjectName(spec.Project); err != nil {
			return err
		}
	}
	if spec.Image != "" {
		if err := safename.ValidateImageName(spec.Image); err != nil {
			return err
		}
	}
	for _, d := range spec.Disks {
		if err := safename.ValidateDiskName(d.Name); err != nil {
			return fmt.Errorf("disk %q: %w", d.Name, err)
		}
	}
	return nil
}

func (s *Server) CreateVM(ctx context.Context, req *pb.CreateVMRequest) (*pb.VM, error) {
	spec := req.Spec
	if spec == nil {
		return nil, status.Error(codes.InvalidArgument, "spec required")
	}
	if spec.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "VM name required")
	}
	if err := validateSpecNames(spec); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := s.RequirePerm(ctx, vmRBACPathFor(spec.Project, spec.Name), "vm.create", "operator"); err != nil {
		return nil, err
	}
	// F3: defining a lifecycle hook = the ability to run an arbitrary root
	// shell command on whatever host the VM lands on (hooks.Run shells out to
	// /bin/sh as root on every start/stop/migrate). That escalates past the
	// project boundary, so it requires admin — above the operator floor for
	// ordinary VM creation. Execution is intentionally NOT gated on caller role
	// (hooks fire on system-driven events like failover too); only DEFINITION
	// is restricted. This path also covers compose deploys (DeployStack →
	// CreateVM).
	if hooksDefined(spec.Hooks) {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, status.Error(codes.PermissionDenied,
				"defining VM lifecycle hooks requires the admin role (hooks execute as root on the target host)")
		}
	}

	// Check if VM already exists
	existing, _ := corrosion.GetVM(ctx, s.db, spec.Name)
	if existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "VM %q already exists", spec.Name)
	}

	// admission: prefer the tenancy engine (live billing +
	// public-IP/backup-GiB checks); fall back to the corrosion-direct
	// path for harnesses that haven't wired an Engine.
	project := tenancy.NormalizeProject(spec.Project)
	if project != tenancy.Default {
		if p, err := corrosion.GetProject(ctx, s.db, project); err != nil || p == nil {
			return nil, status.Errorf(codes.NotFound, "project %q not found", project)
		}
	}
	qreq := tenancy.QuotaRequest{
		VCPU:      int(spec.Cpu),
		MemMiB:    int(spec.MemoryMib),
		DiskGiB:   sumDiskGiB(spec.Disks),
		NIC:       len(spec.Network),
		PublicIPs: countPublicIPs(spec.Network),
	}
	if s.tenancy != nil {
		if err := s.tenancy.Admit(ctx, project, qreq); err != nil {
			s.notify(ctx, notify.Notification{Kind: "quota.exceeded", Severity: notify.SevWarn, Subject: project, Detail: err.Error()})
			return nil, status.Errorf(codes.ResourceExhausted, "%v", err)
		}
	} else if err := corrosion.CheckProjectQuota(ctx, s.db, project, corrosion.QuotaCheck{
		VCPU: qreq.VCPU, MemMiB: qreq.MemMiB, DiskGiB: qreq.DiskGiB, NIC: qreq.NIC,
	}); err != nil {
		s.notify(ctx, notify.Notification{Kind: "quota.exceeded", Severity: notify.SevWarn, Subject: project, Detail: err.Error()})
		return nil, status.Errorf(codes.ResourceExhausted, "%v", err)
	}

	// Placement: determine which host should run this VM.
	placementReq := placement.Request{
		VMName:       spec.Name,
		CPUNeeded:    int(spec.Cpu),
		MemMiBNeeded: int(spec.MemoryMib),
	}
	if p := spec.Placement; p != nil {
		placementReq.PinHost = p.Host
		placementReq.AntiAffinity = p.AntiAffinity
		placementReq.Affinity = p.Affinity
		placementReq.RequireLabels = p.Require
		placementReq.PreferLabels = p.Prefer
		placementReq.Spread = p.Spread
		if p.MaxPerNode > 0 {
			placementReq.MaxPerNode = int(p.MaxPerNode)
			placementReq.VMBaseName = vmBaseName(spec.Name)
		}
	}
	addCapabilityLabels(&placementReq, spec) // vTPM/Secure Boot → capable hosts only (G1)
	for _, dev := range spec.Devices {
		placementReq.Devices = append(placementReq.Devices, placement.DeviceRequest{
			Type:   dev.Type,
			Count:  int(dev.Count),
			Vendor: dev.Vendor,
		})
	}
	// Populate network requirements for placement scoring.
	for _, nic := range spec.Network {
		if nic.Name == "" {
			continue
		}
		nr, _ := corrosion.GetNetwork(ctx, s.db, nic.Name)
		ntype := "bridge"
		if nr != nil {
			ntype = nr.Type
		}
		placementReq.Networks = append(placementReq.Networks, placement.NetworkReq{
			Name: nic.Name,
			Type: ntype,
		})
	}

	targetHost, err := placement.Select(ctx, s.db, placementReq)
	if err != nil {
		return nil, status.Errorf(codes.ResourceExhausted, "placement failed: %v", err)
	}
	if targetHost != s.hostName {
		slog.Info("forwarding CreateVM to target host", "vm", spec.Name, "target", targetHost)
		client, conn, err := s.peerClient(ctx, targetHost)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", targetHost, err)
		}
		defer conn.Close()
		resp, err := client.CreateVM(ctx, req)
		if err != nil {
			return nil, err
		}
		// The remote host's mutation_log entry will be replicated to us
		// via the WAL-based replicator. No need to manually sync.
		return resp, nil
	}

	slog.Info("creating VM", "name", spec.Name, "image", spec.Image, "cpu", spec.Cpu, "memory", spec.MemoryMib)

	// Defaults
	if spec.Machine == "" {
		spec.Machine = "q35"
	}
	if spec.Firmware == "" {
		spec.Firmware = "uefi"
	}
	// Stable domain identity (G1): persisted in the spec so libvirt's default
	// swtpm path (/var/lib/libvirt/swtpm/<uuid>/) is deterministic across the VM's
	// life — letting vTPM state be located + carried without an explicit <source>.
	// UUID is SERVER-OWNED on create: always mint fresh, ignoring any caller-
	// supplied value, so a client can't bind a new VM to existing swtpm state.
	// Restore/migrate set the preserved UUID via their own record-building paths.
	spec.Uuid = uuid.NewString()
	if spec.Cpu == 0 {
		spec.Cpu = 2
	}
	if spec.MemoryMib == 0 {
		spec.MemoryMib = 4096
	}

	// Prepare disks — track created paths for cleanup on failure.
	var diskConfigs []lv.DiskConfig
	var diskRecords []corrosion.DiskRecord
	var createdDiskPaths []string
	cleanupDisks := func() {
		for _, p := range createdDiskPaths {
			if rmErr := os.Remove(p); rmErr != nil && !os.IsNotExist(rmErr) {
				slog.Warn("cleanup: failed to remove disk", "path", p, "error", rmErr)
			}
		}
	}

	if s.virt == nil {
		return nil, status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}

	// If a libvirt domain with this name exists but no active DB record does
	// (we already checked above), it's an orphan from an incomplete delete.
	// Only clean up if stopped — refuse if it's actually running.
	if s.virt.DomainExists(spec.Name) {
		state, _ := s.virt.DomainState(spec.Name)
		slog.Warn("cleaning up orphaned libvirt domain", "vm", spec.Name, "state", state)
		if state == "running" {
			s.virt.DestroyDomain(spec.Name)
		}
		s.virt.UndefineDomain(spec.Name, true)
	}

	// Clean up any orphaned disk files / cloud-init ISO left from a previous
	// incomplete delete, even if the libvirt domain is already gone.
	s.images.DeleteVMDisks(spec.Name)
	os.Remove(lv.CloudInitISOPath(s.dataDir, spec.Name))

	// Auto-pull image from a peer if not available locally.
	if spec.Image != "" && !s.images.ImageExists(spec.Image) {
		if err := s.autoPullImage(ctx, spec.Image); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition,
				"image %q not available locally and auto-pull failed: %v", spec.Image, err)
		}
	}

	for i, d := range spec.Disks {
		if d.Name == "" {
			d.Name = "root"
		}
		if d.Bus == "" {
			d.Bus = "virtio"
		}

		var diskPath string
		var err error
		storageType := "local"

		isRootDisk := d.Name == "root"

		if d.Storage != "" {
			// Use a named storage volume (nfs, ceph, iscsi, etc.).
			volCfg := s.resolveVolume(ctx, spec.StackName, d.Storage)
			drv, drvErr := storage.New(s.dataDir, volCfg)
			if drvErr != nil {
				return nil, status.Errorf(codes.Internal, "storage driver %q: %v", d.Storage, drvErr)
			}
			if pErr := drv.Prepare(ctx); pErr != nil {
				return nil, status.Errorf(codes.Internal, "storage prepare %q: %v", d.Storage, pErr)
			}
			sourceImage := ""
			if isRootDisk {
				sourceImage = spec.Image
			}
			diskPath, err = drv.CreateDisk(ctx, storage.DiskOptions{
				VMName:      spec.Name,
				DiskName:    d.Name,
				SizeBytes:   parseDiskSizeBytes(d.Size),
				SourceImage: sourceImage,
			})
			storageType = volCfg.Driver
			if storageType == "" {
				storageType = "local"
			}
		} else if spec.Image != "" && isRootDisk {
			// Cloud image mode: only the root disk gets the backing image
			diskPath, err = s.images.CreateOverlayDisk(spec.Name, d.Name, spec.Image, d.Size)
		} else {
			// Empty disk (data disks, or no image specified)
			diskPath, err = s.images.CreateEmptyDisk(spec.Name, d.Name, d.Size)
		}
		if err != nil {
			cleanupDisks()
			return nil, status.Errorf(codes.Internal, "create disk %s: %v", d.Name, err)
		}
		createdDiskPaths = append(createdDiskPaths, diskPath)

		diskConfigs = append(diskConfigs, lv.DiskConfig{
			Name:  d.Name,
			Path:  diskPath,
			Bus:   d.Bus,
			Cache: d.Cache,
		})

		backingImage := ""
		if isRootDisk {
			backingImage = spec.Image
		}
		diskRecords = append(diskRecords, corrosion.DiskRecord{
			VMName:        spec.Name,
			DiskName:      d.Name,
			HostName:      s.hostName,
			Path:          diskPath,
			SizeBytes:     parseDiskSizeBytes(d.Size),
			BackingImage:  backingImage,
			StorageType:   storageType,
			StorageVolume: d.Storage,
			TargetDev:     lv.DiskDevName(d.Bus, i),
		})
	}

	// If no disks specified, create a default root disk
	if len(diskConfigs) == 0 && spec.Image != "" {
		diskPath, err := s.images.CreateOverlayDisk(spec.Name, "root", spec.Image, "20G")
		if err != nil {
			cleanupDisks()
			return nil, status.Errorf(codes.Internal, "create default disk: %v", err)
		}
		createdDiskPaths = append(createdDiskPaths, diskPath)
		diskConfigs = append(diskConfigs, lv.DiskConfig{
			Name: "root",
			Path: diskPath,
			Bus:  "virtio",
		})
		diskRecords = append(diskRecords, corrosion.DiskRecord{
			VMName:       spec.Name,
			DiskName:     "root",
			HostName:     s.hostName,
			Path:         diskPath,
			SizeBytes:    parseDiskSizeBytes("20G"),
			BackingImage: spec.Image,
			StorageType:  "local",
			TargetDev:    lv.DiskDevName("virtio", 0),
		})
	}

	// Installer ISO: attach as a read-only CDROM and boot from it by default so
	// the guest can install an OS (xmlgen renders IsISO disks as <cdrom>). The
	// path is on the target host. Persisted in the spec JSON, so it survives.
	if spec.Iso != "" {
		diskConfigs = append(diskConfigs, lv.DiskConfig{
			Name:  "installer",
			Path:  spec.Iso,
			IsISO: true,
		})
		if spec.Boot == "" {
			spec.Boot = "cdrom"
		}
	}

	// Prepare network interfaces
	var netConfigs []lv.NetworkConfig
	var ifaceRecords []corrosion.InterfaceRecord

	for i, n := range spec.Network {
		bridge := n.Name // default: use network name as bridge
		mac := n.Mac
		if mac == "" {
			mac = lv.GenerateMAC()
		}

		// Attempt network provisioning if the network is defined in the stack.
		if provBridge, err := provisionNetworkForVM(ctx, s.db, n.Name, s.hostName); err != nil {
			slog.Warn("network provision failed, falling back to bridge name", "network", n.Name, "error", err)
		} else if provBridge != "" {
			bridge = provBridge
			// For VXLAN networks, notify existing peers about our VTEP
			// so they can add our flood entry (reverse-sync).
			s.notifyVTEPPeersForNetwork(ctx, n.Name)
		}

		vlan := 0
		if len(n.Trunk) > 0 {
			vlan = int(n.Trunk[0])
		}

		// Direct (macvtap) networks return "direct:<iface>" from provisioning.
		if strings.HasPrefix(bridge, "direct:") {
			netConfigs = append(netConfigs, lv.NetworkConfig{
				Direct: strings.TrimPrefix(bridge, "direct:"),
				Model:  n.Model,
				MAC:    mac,
			})
		} else {
			// Bridge preflight: ensure the bridge exists on this host.
			// For plain bridges, auto-create if missing.
			if _, err := net.InterfaceByName(bridge); err != nil {
				if err := network.EnsureBridge(bridge); err != nil {
					return nil, status.Errorf(codes.FailedPrecondition,
						"network bridge %q not found on host %s and auto-create failed: %v", bridge, s.hostName, err)
				}
				slog.Info("auto-created bridge", "bridge", bridge, "host", s.hostName)
			}
			netConfigs = append(netConfigs, lv.NetworkConfig{
				Bridge: bridge,
				Model:  n.Model,
				MAC:    mac,
				VLAN:   vlan,
			})
		}

		ifaceRecords = append(ifaceRecords, corrosion.InterfaceRecord{
			VMName:         spec.Name,
			NetworkName:    n.Name,
			Ordinal:        i,
			MAC:            mac,
			IP:             n.Ip,
			SecurityGroups: n.SecurityGroups,
		})
	}

	// Build cloud-init network-config for interfaces with static IPs.
	// Applies to any network type (bridge, vxlan, isolated) where the compose
	// specifies an explicit IP. Uses V1 format for distro-agnostic MAC matching.
	var staticNetCfg string
	var staticIfaces []isolatedIface
	for i, n := range spec.Network {
		netDef := lookupNetworkDef(ctx, s.db, n.Name)
		ip := n.Ip
		if ip == "" && i < len(ifaceRecords) {
			ip = ifaceRecords[i].IP
		}

		// Skip interfaces without a static IP unless host-isolated (which
		// always needs cloud-init config to avoid DHCP).
		if ip == "" {
			continue
		}
		needsConfig := ip != "" // explicit static IP in compose
		if netDef != nil && netDef.HostIsolation {
			needsConfig = true
		}
		if !needsConfig {
			continue
		}

		// Determine subnet prefix and gateway from network def or attachment.
		gateway := n.Gateway
		address := ip
		if netDef != nil && netDef.Subnet != "" {
			gw, _, _, _, err := network.SubnetRange(netDef.Subnet)
			if err == nil {
				if gateway == "" {
					gateway = gw
				}
				parts := splitCIDR(netDef.Subnet)
				if parts[1] != "" {
					address = ip + "/" + parts[1]
				}
			}
		} else if !strings.Contains(address, "/") {
			// No subnet in network def — pick a sensible default based on
			// address family. /24 for v4, /64 for v6 (the standard host
			// prefix for end-user assignments).
			if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
				address = ip + "/64"
			} else {
				address = ip + "/24"
			}
		}
		var dnsServers []string
		if netDef != nil {
			dnsServers = netDef.DNS
		}
		if len(dnsServers) == 0 {
			dnsServers = []string{"1.1.1.1", "8.8.8.8"}
		}
		mac := ""
		if i < len(ifaceRecords) {
			mac = ifaceRecords[i].MAC
		}

		// IPv6 handling: a NIC can carry an explicit `ipv6:` (with
		// optional `ipv6-gateway:`); when omitted we fall through to
		// SLAAC / RA, which dnsmasq emits when the network's subnet
		// is IPv6. Static v6 assignment is rare but useful for
		// well-known endpoints (DNS, mail) where SLAAC's privacy
		// extensions are inconvenient.
		address6 := n.Ipv6
		gateway6 := n.Ipv6Gateway
		if address6 != "" && !strings.Contains(address6, "/") {
			address6 = address6 + "/64"
		}

		staticIfaces = append(staticIfaces, isolatedIface{
			MAC:      mac,
			Address:  address,
			Gateway:  gateway,
			DNS:      dnsServers,
			Address6: address6,
			Gateway6: gateway6,
		})
	}
	if len(staticIfaces) > 0 {
		staticNetCfg = buildIsolatedNetworkConfig(staticIfaces)
	}

	// Generate cloud-init ISO if this is a cloud image
	var cloudInitISO string
	if spec.Image != "" && spec.CloudInit != nil {
		isoPath := lv.CloudInitISOPath(s.dataDir, spec.Name)
		userData := spec.CloudInit.Userdata
		if userData == "" {
			userData = "#cloud-config\n{}\n"
		}
		netCfg := spec.CloudInit.Networkconfig
		if netCfg == "" && staticNetCfg != "" {
			netCfg = staticNetCfg
		}
		err := cloudinit.GenerateISO(cloudinit.Config{
			InstanceID:    spec.Name,
			LocalHostname: spec.Name,
			UserData:      userData,
			NetworkConfig: netCfg,
		}, isoPath)
		if err != nil {
			cleanupDisks()
			return nil, status.Errorf(codes.Internal, "generate cloud-init ISO: %v", err)
		}
		cloudInitISO = isoPath
	} else if spec.Image != "" {
		// Auto-generate minimal cloud-init for cloud images
		isoPath := lv.CloudInitISOPath(s.dataDir, spec.Name)
		err := cloudinit.GenerateISO(cloudinit.Config{
			InstanceID:    spec.Name,
			LocalHostname: spec.Name,
			UserData:      "#cloud-config\n{}\n",
			NetworkConfig: staticNetCfg,
		}, isoPath)
		if err != nil {
			slog.Warn("failed to generate cloud-init ISO", "error", err)
			// Non-fatal: VM may not need cloud-init
		} else {
			cloudInitISO = isoPath
		}
	}

	// Generate libvirt domain XML
	vmCfg := lv.VMConfig{
		Name:         spec.Name,
		UUID:         spec.Uuid,
		CPU:          int(spec.Cpu),
		CPUMode:      spec.CpuMode,
		MemoryMiB:    int(spec.MemoryMib),
		MinMemoryMiB: int(spec.MinMemoryMib),
		MaxMemoryMiB: int(spec.MaxMemoryMib),
		Machine:      spec.Machine,
		Firmware:     spec.Firmware,
		GuestAgent:   spec.GuestAgent,
		EnableVNC:    !spec.DisableVnc,
		EnableSPICE:  spec.EnableSpice,
		Disks:        diskConfigs,
		Networks:     netConfigs,
		CloudInitISO: cloudInitISO,
		Boot:         spec.Boot,
	}
	// Secure Boot + vTPM (G1). Use the host-resolved firmware paths and pin per-VM
	// nvram + swtpm state under dataDir so they travel across the lifecycle. Refuse
	// to silently adopt firmware state left by a prior `delete --keep-disks`.
	if err := s.applyFirmwareConfig(&vmCfg, spec); err != nil {
		cleanupDisks()
		return nil, err
	}
	if r := spec.Resources; r != nil {
		vmCfg.HugePages = r.Hugepages
		vmCfg.IOThreads = int(r.IoThreads)
		for _, pin := range r.CpuPinning {
			vmCfg.CPUPinning = append(vmCfg.CPUPinning, int(pin))
		}
		if np := r.NumaPolicy; np != nil {
			vmCfg.NUMAPolicy = &lv.NUMAPolicy{
				PreferredNode: int(np.PreferredNode),
				Strict:        np.Strict,
			}
		}
	}

	// PCI device passthrough.
	if len(spec.Devices) > 0 {
		pciAddrs, devErr := s.allocateDevices(ctx, spec.Name, spec.Devices)
		if devErr != nil {
			cleanupDisks()
			return nil, devErr
		}
		for _, addr := range pciAddrs {
			vmCfg.Hostdevs = append(vmCfg.Hostdevs, lv.HostdevConfig{Address: addr})
		}
	}

	domXML, err := lv.GenerateDomainXML(vmCfg)
	if err != nil {
		cleanupDisks()
		return nil, status.Errorf(codes.Internal, "generate domain XML: %v", err)
	}

	// pre_start hook — fires before the domain is started for the first time.
	stubVM := &pb.VM{Name: spec.Name, HostName: s.hostName, State: pb.VMState_VM_STARTING}
	hooks.Run(ctx, hooks.PreStart, stubVM, spec.Hooks)

	// Define and start in libvirt
	if err := s.virt.DefineDomain(domXML); err != nil {
		cleanupDisks()
		lv.WipeFirmwareState(s.dataDir, spec.Name, spec.Uuid) // no orphan nvram/swtpm (G1)
		return nil, status.Errorf(codes.Internal, "define domain: %v", err)
	}

	if err := s.virt.StartDomain(spec.Name); err != nil {
		s.virt.UndefineDomain(spec.Name, false)
		cleanupDisks()
		lv.WipeFirmwareState(s.dataDir, spec.Name, spec.Uuid) // failed first boot must not strand TPM/NVRAM (G1)
		return nil, status.Errorf(codes.Internal, "start domain: %v", err)
	}

	// Configure VLAN tags on tap interfaces for any networks that need it.
	for i, n := range spec.Network {
		nc := netConfigs[i]
		switch {
		case len(n.Trunk) > 1:
			// Trunk mode: multiple VLANs — VM handles its own VLAN demux.
			vlanIDs := make([]int, len(n.Trunk))
			for j, v := range n.Trunk {
				vlanIDs[j] = int(v)
			}
			if err := s.virt.ConfigureTrunkTap(spec.Name, nc.Bridge, nc.MAC, vlanIDs); err != nil {
				slog.Warn("VLAN trunk tap config failed", "vm", spec.Name, "vlans", vlanIDs, "error", err)
			}
		case len(n.Trunk) == 1:
			// Single VLAN: access mode (pvid + untagged).
			if err := s.virt.ConfigureVLANTap(spec.Name, nc.Bridge, nc.MAC, int(n.Trunk[0])); err != nil {
				slog.Warn("VLAN tap config failed", "vm", spec.Name, "vlan", n.Trunk[0], "error", err)
			}
		default:
			// Flat mode: no VLAN tagging needed.
		}
	}

	// Record the host tap device for each NIC now that the domain is running
	// (libvirt assigns vnetN at start). The distributed firewall's per-NIC tier
	// keys off vm_interfaces.tap_device — without this the reconciler can't emit
	// per-NIC chains, so security-group bindings would never be enforced.
	// Best-effort: a lookup failure just leaves the firewall unable to target
	// that NIC, which is better than failing the whole VM create.
	for i := range ifaceRecords {
		tap, err := s.virt.TapDevice(spec.Name, ifaceRecords[i].MAC)
		if err != nil {
			slog.Warn("could not resolve tap device for NIC (firewall per-NIC rules won't apply)",
				"vm", spec.Name, "mac", ifaceRecords[i].MAC, "error", err)
			continue
		}
		ifaceRecords[i].TapDevice = tap
	}

	// Serialize spec to JSON for storage
	specJSON, _ := json.Marshal(spec)

	// Write to corrosion
	vmRecord := corrosion.VMRecord{
		Name:      spec.Name,
		StackName: spec.StackName,
		HostName:  s.hostName,
		Spec:      string(specJSON),
		State:     "running",
		CPUActual: int(spec.Cpu),
		MemActual: int(spec.MemoryMib),
		Project:   project, // tenancy label
	}

	if err := corrosion.InsertVM(ctx, s.db, vmRecord, ifaceRecords, diskRecords); err != nil {
		slog.Error("failed to write VM to corrosion", "error", err)
		// VM is running, but state may not be synced — log and continue
	}

	slog.Info("VM created successfully", "name", spec.Name, "host", s.hostName)
	s.recordVMEvent(ctx, spec.Name, "vm.created", "ok", "host="+s.hostName)
	if s.tenancy != nil {
		s.tenancy.EmitVMCreated(ctx, project, spec.Name, qreq)
	}

	// Apply LB config if the VM spec includes a load balancer definition.
	// Use a detached context so the goroutine survives after the RPC returns.
	if spec.Loadbalancer != nil && spec.Loadbalancer.Enabled {
		go s.applyLBFromSpecWithRetry(context.Background(), spec)
	}

	// post_start hook
	stubVM.State = pb.VMState_VM_RUNNING
	hooks.Run(ctx, hooks.PostStart, stubVM, spec.Hooks)

	return s.vmToProto(ctx, spec.Name)
}

func (s *Server) ListVMs(ctx context.Context, req *pb.ListVMsRequest) (*pb.ListVMsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	vms, err := corrosion.ListVMs(ctx, s.db, req.StackName, req.HostName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list VMs: %v", err)
	}

	// Batch-load all interfaces in a single query instead of per-VM N+1.
	allIfaces, _ := corrosion.BatchGetVMInterfaces(ctx, s.db)

	resp := &pb.ListVMsResponse{}
	for _, vm := range vms {
		// Reconcile DB state with libvirt for local VMs.
		state := vm.State
		if vm.HostName == s.hostName && s.virt != nil {
			if liveState, err := s.virt.DomainState(vm.Name); err == nil {
				switch {
				case vm.State == "stopped" && liveState == "running":
					// Graceful shutdown in progress — trust DB
				case vm.State == "running" && liveState == "stopped":
					// VM crashed or was stopped externally — trust libvirt
					state = liveState
					corrosion.UpdateVMState(ctx, s.db, vm.Name, liveState, "")
				default:
					state = liveState
				}
			}
		}

		pbVM := &pb.VM{
			Name:         vm.Name,
			StackName:    vm.StackName,
			HostName:     vm.HostName,
			State:        vmStateToPB(state),
			CpuActual:    int32(vm.CPUActual),
			MemActualMib: int32(vm.MemActual),
			IsTemplate:   vm.IsTemplate,
		}

		// Surface labels (tags) for the list view without shipping the whole
		// spec — a cheap labels-only unmarshal so the table can render chips.
		if vm.Spec != "" {
			var lite struct {
				Labels map[string]string `json:"labels"`
			}
			if json.Unmarshal([]byte(vm.Spec), &lite) == nil && len(lite.Labels) > 0 {
				pbVM.Spec = &pb.VMSpec{Labels: lite.Labels}
			}
		}

		for _, iface := range allIfaces[vm.Name] {
			ip := iface.IP
			if ip == "" && vm.HostName == s.hostName {
				ip = lv.GetIPFromARP(iface.MAC)
			}
			if ip == "" && vm.HostName == s.hostName {
				ip = lv.GetIPFromDHCPLeases("/var/lib/libvirt/dnsmasq", iface.MAC)
			}
			if ip != "" && ip != iface.IP {
				corrosion.UpdateVMInterfaceIP(ctx, s.db, vm.Name, iface.NetworkName, ip)
			}
			pbVM.Interfaces = append(pbVM.Interfaces, &pb.VMInterface{
				NetworkName: iface.NetworkName,
				Ordinal:     int32(iface.Ordinal),
				Mac:         iface.MAC,
				Ip:          ip,
			})
		}

		resp.Vms = append(resp.Vms, pbVM)
	}

	return resp, nil
}

func (s *Server) InspectVM(ctx context.Context, req *pb.InspectVMRequest) (*pb.VM, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	// Forward to the VM's host so local-only operations (disk size discovery,
	// VNC port, ARP lookup) work correctly.
	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err == nil {
			defer conn.Close()
			return client.InspectVM(ctx, req)
		}
		// Fall through to local view if peer unreachable.
	}
	return s.vmToProto(ctx, req.Name)
}

func (s *Server) StartVM(ctx context.Context, req *pb.StartVMRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if vm.IsTemplate {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%q is a template and cannot be started; clone it first (lv vm clone %s <new-name>)", req.Name, req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.start", "operator"); err != nil {
		return nil, err
	}

	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.StartVM(ctx, req)
	}

	hspec := vmHooks(vm)
	pbVM := &pb.VM{Name: vm.Name, HostName: vm.HostName, State: pb.VMState_VM_STARTING}
	hooks.Run(ctx, hooks.PreStart, pbVM, hspec)

	if err := s.virt.StartDomain(req.Name); err != nil {
		// Heal a state desync: if libvirt reports the domain is already
		// running, the cluster record was stale (an out-of-band start, or an
		// RPC that mutated libvirt but failed before writing state). Reconcile
		// the record to "running" rather than surfacing "already running".
		if st, sErr := s.virt.DomainState(req.Name); sErr == nil && st == "running" {
			corrosion.UpdateVMState(ctx, s.db, req.Name, "running", "reconciled: already running in libvirt")
			slog.Warn("StartVM: domain already running in libvirt, reconciled cluster state", "vm", req.Name)
			pbVM.State = pb.VMState_VM_RUNNING
			hooks.Run(ctx, hooks.PostStart, pbVM, hspec)
			return s.vmToProto(ctx, req.Name)
		}
		return nil, status.Errorf(codes.Internal, "start: %v", err)
	}

	corrosion.UpdateVMState(ctx, s.db, req.Name, "running", "")
	s.recordVMEvent(ctx, req.Name, "vm.started", "ok", "")

	// Reapply VLAN tap config: VLAN tagging lives on the host tap (libvirt assigns
	// a fresh vnetN at each start), not the domain XML — so a VM defined-then-
	// started later (an import) or any stopped→started VM would otherwise lose its
	// VLAN. Best-effort, mirroring CreateVM (vm.go ~579): a tap failure warns,
	// never fails an already-running domain.
	s.reapplyVLANTaps(ctx, vm)

	pbVM.State = pb.VMState_VM_RUNNING
	hooks.Run(ctx, hooks.PostStart, pbVM, hspec)

	return s.vmToProto(ctx, req.Name)
}

func (s *Server) StopVM(ctx context.Context, req *pb.StopVMRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	unlock := s.lockVM(req.Name)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.stop", "operator"); err != nil {
		return nil, err
	}

	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.StopVM(ctx, req)
	}

	hspec := vmHooks(vm)
	pbVM := &pb.VM{Name: vm.Name, HostName: vm.HostName, State: pb.VMState_VM_STOPPING}
	hooks.Run(ctx, hooks.PreStop, pbVM, hspec)

	if req.Force {
		if err := s.virt.DestroyDomain(req.Name); err != nil {
			return nil, status.Errorf(codes.Internal, "destroy: %v", err)
		}
	} else {
		if err := s.virt.ShutdownDomain(req.Name); err != nil {
			return nil, status.Errorf(codes.Internal, "shutdown: %v", err)
		}
		// Wait for graceful shutdown with timeout, then force-kill.
		timeout := resolveStopTimeout(req.Timeout, vm.Spec)
		if timeout > 0 {
			if !s.virt.WaitForShutdown(req.Name, time.Duration(timeout)*time.Second) {
				slog.Info("ACPI shutdown timed out, force-killing", "vm", req.Name, "timeout_sec", timeout)
				_ = s.virt.DestroyDomain(req.Name)
			}
		}
	}

	// Release PCI passthrough devices and unbind from vfio-pci.
	s.releaseDevices(ctx, req.Name)

	// Mark as "stopped" with detail indicating operator-initiated stop.
	// This distinguishes operator stops from crashes (#29).
	corrosion.UpdateVMState(ctx, s.db, req.Name, "stopped", "operator-stop")
	s.recordVMEvent(ctx, req.Name, "vm.stopped", "ok", "")

	// Refresh LB backends so stopped VM is removed from rotation.
	go s.refreshLBForStack(context.Background(), vm.StackName)

	pbVM.State = pb.VMState_VM_STOPPED
	hooks.Run(ctx, hooks.PostStop, pbVM, hspec)

	return s.vmToProto(ctx, req.Name)
}

func (s *Server) RestartVM(ctx context.Context, req *pb.RestartVMRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.restart", "operator"); err != nil {
		return nil, err
	}

	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.RestartVM(ctx, req)
	}

	// Destroy then start
	s.virt.DestroyDomain(req.Name)
	if err := s.virt.StartDomain(req.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "restart: %v", err)
	}

	corrosion.UpdateVMState(ctx, s.db, req.Name, "running", "")
	s.recordVMEvent(ctx, req.Name, "vm.restarted", "ok", "")
	return s.vmToProto(ctx, req.Name)
}

// deleteLocalOnly reports whether this DeleteVM call is a peer-search probe
// (carries the x-lv-delete-local-only header), meaning it must act on the local
// host only and never proxy or fan out to peers.
func deleteLocalOnly(ctx context.Context) bool {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		return len(md.Get("x-lv-delete-local-only")) > 0
	}
	return false
}

func (s *Server) DeleteVM(ctx context.Context, req *pb.DeleteVMRequest) (*emptypb.Empty, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	unlock := s.lockVM(req.Name)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.delete", "operator"); err != nil {
		s.audit(ctx, "vm.delete", req.Name, "permission denied", "denied")
		return nil, err
	}

	// localOnly: this is a peer-search probe from another node's DeleteVM. Such a
	// probe must NOT proxy back to the recorded host or re-fan-out to peers —
	// otherwise, because every node's CRDT record points at the same recorded
	// host, the probe proxies back to the origin which re-searches, ping-ponging
	// into an exponential storm (a real hang observed in the field). A probe just
	// deletes locally if the domain is here, else reports NotFound.
	localOnly := deleteLocalOnly(ctx)

	if !localOnly && vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		proxyCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		return client.DeleteVM(proxyCtx, req)
	}

	// Verify the domain actually exists in libvirt on this host. If the
	// Corrosion record says this host but the domain isn't here (stale CRDT,
	// non-deterministic placement, etc.), don't proceed — the soft-delete
	// would orphan the real domain on another host.
	if s.virt != nil && !s.virt.DomainExists(req.Name) {
		// A local-only probe stops here: the domain isn't on this host.
		if localOnly {
			return nil, status.Errorf(codes.NotFound, "VM %q not on host %s", req.Name, s.hostName)
		}
		slog.Warn("DeleteVM: Corrosion says VM is on this host but libvirt domain not found — trying peers",
			"vm", req.Name, "host", s.hostName)
		// Probe every other active host with a local-only flag (so the peer does
		// NOT proxy back / re-search), each with a bounded timeout so an
		// unreachable peer can't stall the delete.
		hosts, _ := corrosion.ListHosts(ctx, s.db)
		for _, h := range hosts {
			if h.Name == s.hostName || h.State != "active" {
				continue
			}
			client, conn, peerErr := s.peerClient(ctx, h.Name)
			if peerErr != nil {
				continue
			}
			probeCtx, cancel := context.WithTimeout(
				metadata.AppendToOutgoingContext(ctx, "x-lv-delete-local-only", "1"), 15*time.Second)
			_, peerErr = client.DeleteVM(probeCtx, req)
			cancel()
			conn.Close()
			if peerErr == nil {
				slog.Info("DeleteVM: domain found and deleted on peer", "vm", req.Name, "peer", h.Name)
				return &emptypb.Empty{}, nil
			}
			// NotFound/unreachable on this peer — keep trying.
		}
		// No peer had it either. Clean up the stale Corrosion record.
		slog.Warn("DeleteVM: domain not found on any host — cleaning up stale record", "vm", req.Name)
		if err := corrosion.DeleteVM(ctx, s.db, req.Name); err != nil {
			slog.Error("failed to clean up stale VM record", "vm", req.Name, "error", err)
		}
		return &emptypb.Empty{}, nil
	}

	// Reject delete if VM is mid-backup or mid-migration.
	if vm.State == "backing-up" {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q is being backed up — wait for backup to complete", req.Name)
	}

	// Refuse to free disks that still back live linked clones — removing the
	// backing file would corrupt them. --keep-disks bypasses (the record goes
	// but the disks stay, so the clones remain valid).
	if !req.KeepDisks {
		if clones, gErr := s.linkedClonesOf(ctx, req.Name); gErr == nil && len(clones) > 0 {
			return nil, status.Errorf(codes.FailedPrecondition,
				"%q still backs %d linked clone(s) (%s); delete or full-clone them first, or pass --keep-disks",
				req.Name, len(clones), strings.Join(clones, ", "))
		}
	}

	// Stop if running
	if vm.State == "running" {
		s.virt.DestroyDomain(req.Name)
	}

	// Release PCI passthrough devices and unbind from vfio-pci.
	s.releaseDevices(ctx, req.Name)

	// Undefine from libvirt. With --keep-disks, KEEP firmware state too (NVRAM is
	// name-keyed and DomainUndefineNvram would delete it — bricking the retained
	// BitLocker disk); the explicit WipeFirmwareState in the !KeepDisks branch
	// below handles true delete (G1).
	if req.KeepDisks {
		if err := s.virt.UndefineDomainPreservingState(req.Name); err != nil {
			slog.Warn("failed to undefine domain (keep-disks)", "vm", req.Name, "error", err)
		}
	} else if err := s.virt.UndefineDomain(req.Name, true); err != nil {
		slog.Warn("failed to undefine domain", "vm", req.Name, "error", err)
		// Retry without flags in case the domain has no managed save/snapshots.
		if err2 := s.virt.UndefineDomain(req.Name, false); err2 != nil {
			slog.Error("failed to undefine domain (retry)", "vm", req.Name, "error", err2)
		}
	}

	// Delete disks unless keep-disks. Free each disk at its RECORDED location
	// (driver-dispatched, so non-default pools and block backends are released)
	// BEFORE the corrosion tombstone, then glob the default dir for any debris.
	if !req.KeepDisks {
		s.deleteRecordedVMDiskVolumes(ctx, req.Name)
		s.images.DeleteVMDisks(req.Name)
		// Remove cloud-init ISO
		os.Remove(lv.CloudInitISOPath(s.dataDir, req.Name))
		// Firmware state (G1): wipe nvram (name-keyed) + swtpm (uuid-keyed). With
		// --keep-disks we deliberately KEEP it too — else a retained BitLocker disk
		// would be unbootable (the swtpm tree at the stable uuid stays for restore).
		var sp struct {
			Uuid string `json:"uuid"`
		}
		_ = json.Unmarshal([]byte(vm.Spec), &sp)
		lv.WipeFirmwareState(s.dataDir, req.Name, sp.Uuid)
	} else if usesFirmwareState(vm.Spec) {
		// --keep-disks keeps firmware state too; record name→uuid so the retained
		// (UUID-keyed) swtpm tree is locatable for an explicit restore later (G1).
		if err := lv.WriteRetainedFirmwareMarker(s.dataDir, req.Name, parseFirmwareSpec(vm.Spec).UUID); err != nil {
			slog.Warn("failed to write retained-firmware marker", "vm", req.Name, "error", err)
		}
	}

	// Remove the VM's DNS A-record UNCONDITIONALLY — not gated on a live
	// interface. The record name is per-VM (vm.stack.domain), so one delete
	// covers it; gating on `iface.IP != ""` leaked the record whenever the
	// interfaces were already gone (or removed first), which is how the
	// web-app orphans accumulated. The reaper (ReapOrphanDNSRecords) is the
	// backstop for any that still slip through.
	domain := s.dnsDomain
	if domain == "" {
		domain = "lv.local"
	}
	if err := dns.DeleteRecord(ctx, s.db, dns.VMRecordName(req.Name, vm.StackName, domain)); err != nil {
		slog.Warn("failed to delete DNS record", "vm", req.Name, "error", err)
	}

	// Release per-interface IP allocations.
	ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, req.Name)
	for _, iface := range ifaces {
		if err := network.ReleaseIP(ctx, s.db, iface.NetworkName, req.Name); err != nil {
			slog.Warn("failed to release IP", "vm", req.Name, "network", iface.NetworkName, "error", err)
		}
	}

	// Broadcast FDB removal for VXLAN networks so peers remove stale entries.
	s.CleanupFDBForVM(ctx, req.Name)

	// Tombstone in corrosion
	if err := corrosion.DeleteVM(ctx, s.db, req.Name); err != nil {
		slog.Error("failed to delete VM from corrosion", "error", err)
	}

	slog.Info("VM deleted", "name", req.Name)
	s.recordVMEvent(ctx, req.Name, "vm.deleted", "ok", "")
	s.audit(ctx, "vm.delete", req.Name, "project="+tenancy.NormalizeProject(vm.Project)+" keep_disks="+fmt.Sprintf("%t", req.KeepDisks), "ok")
	if s.tenancy != nil {
		s.tenancy.EmitVMDeleted(ctx, vm.Project, req.Name)
	}

	// Refresh LB backends so deleted VM is removed from rotation.
	go s.refreshLBForStack(context.Background(), vm.StackName)

	return &emptypb.Empty{}, nil
}

func (s *Server) vmToProto(ctx context.Context, name string) (*pb.VM, error) {
	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get VM: %v", err)
	}
	if vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", name)
	}

	// Get live state from libvirt if local.
	// Only override DB state if the DB hasn't been explicitly set by an operator action
	// (e.g., "stopped" from StopVM). This avoids showing stale libvirt state during
	// graceful shutdown where libvirt still reports "running" briefly.
	state := vm.State
	if vm.HostName == s.hostName && s.virt != nil {
		if liveState, err := s.virt.DomainState(name); err == nil {
			// Trust libvirt for running detection (catches unexpected starts/crashes),
			// but trust DB for operator-initiated stops/starts.
			switch {
			case vm.State == "stopped" && liveState == "running":
				// Graceful shutdown in progress — trust DB
			case vm.State == "running" && liveState == "stopped":
				// VM crashed or was stopped externally — trust libvirt
				state = liveState
			default:
				state = liveState
			}
		}
	}

	pbVM := &pb.VM{
		Name:         vm.Name,
		StackName:    vm.StackName,
		HostName:     vm.HostName,
		State:        vmStateToPB(state),
		StateDetail:  vm.StateDetail,
		CpuActual:    int32(vm.CPUActual),
		MemActualMib: int32(vm.MemActual),
		IsTemplate:   vm.IsTemplate,
	}

	// Interfaces — run IP discovery fallback if IP is unknown.
	ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, name)
	for _, iface := range ifaces {
		ip := iface.IP
		if ip == "" && vm.HostName == s.hostName {
			ip = lv.GetIPFromARP(iface.MAC)
		}
		if ip == "" && vm.HostName == s.hostName {
			ip = lv.GetIPFromDHCPLeases("/var/lib/libvirt/dnsmasq", iface.MAC)
		}
		// If we discovered a new IP, persist it.
		if ip != "" && ip != iface.IP {
			corrosion.UpdateVMInterfaceIP(ctx, s.db, name, iface.NetworkName, ip)
		}
		pbVM.Interfaces = append(pbVM.Interfaces, &pb.VMInterface{
			NetworkName: iface.NetworkName,
			Ordinal:     int32(iface.Ordinal),
			Mac:         iface.MAC,
			Ip:          ip,
		})
	}

	// Deserialize spec early so we can use disk sizes from it.
	var spec *pb.VMSpec
	if vm.Spec != "" {
		spec = &pb.VMSpec{}
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			spec = nil
		}
	}

	// Build a map of disk name → spec size for backfill.
	specDiskSizes := make(map[string]int64)
	if spec != nil {
		for _, ds := range spec.Disks {
			if sz := parseDiskSizeBytes(ds.Size); sz > 0 {
				specDiskSizes[ds.Name] = sz
			}
		}
	}
	// Default root disk is 20G when no disks are specified.
	if _, ok := specDiskSizes["root"]; !ok && spec != nil && len(spec.Disks) == 0 && spec.Image != "" {
		specDiskSizes["root"] = parseDiskSizeBytes("20G")
	}

	// Disks
	disks, _ := corrosion.GetVMDisks(ctx, s.db, name)
	for _, disk := range disks {
		sizeBytes := disk.SizeBytes
		// Fix missing or wrong size from the stored spec (works from any host).
		if specSize, ok := specDiskSizes[disk.DiskName]; ok && specSize > sizeBytes {
			sizeBytes = specSize
			if sizeBytes != disk.SizeBytes {
				corrosion.UpdateDiskSize(ctx, s.db, name, disk.DiskName, sizeBytes) //nolint:errcheck
			}
		}
		pbVM.Disks = append(pbVM.Disks, &pb.VMDisk{
			Name:         disk.DiskName,
			HostName:     disk.HostName,
			Path:         disk.Path,
			SizeBytes:    sizeBytes,
			BackingImage: disk.BackingImage,
			StorageType:  disk.StorageType,
		})
	}

	// VNC address — only available for running VMs on this host
	if vm.HostName == s.hostName && state == "running" && s.virt != nil {
		if port, err := s.virt.GetVMVNCPort(name); err == nil && port >= 0 {
			if host, err := corrosion.GetHost(ctx, s.db, s.hostName); err == nil && host != nil {
				pbVM.VncAddress = fmt.Sprintf("vnc://%s:%d", host.Address, port)
			}
		}
	}

	// Attach spec to proto (already deserialized above).
	if spec != nil {
		pbVM.Spec = spec
	}

	return pbVM, nil
}

func vmStateToPB(s string) pb.VMState {
	switch s {
	case "creating":
		return pb.VMState_VM_CREATING
	case "starting":
		return pb.VMState_VM_STARTING
	case "running":
		return pb.VMState_VM_RUNNING
	case "stopping":
		return pb.VMState_VM_STOPPING
	case "stopped":
		return pb.VMState_VM_STOPPED
	case "migrating":
		return pb.VMState_VM_MIGRATING
	case "error":
		return pb.VMState_VM_ERROR
	default:
		return pb.VMState_VM_UNKNOWN
	}
}

func (s *Server) ExecVM(ctx context.Context, req *pb.ExecVMRequest) (*pb.ExecVMResponse, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.exec", "operator"); err != nil {
		s.audit(ctx, "vm.exec", req.Name, "permission denied: "+strings.Join(req.Command, " "), "denied")
		return nil, err
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.ExecVM(ctx, req)
	}
	if vm.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q is not running", req.Name)
	}

	// Command is a []string: first element is the executable, rest are args.
	if len(req.Command) == 0 {
		return nil, status.Error(codes.InvalidArgument, "command required")
	}
	output, err := s.virt.ExecInGuest(req.Name, req.Command[0], req.Command[1:])
	if err != nil {
		s.audit(ctx, "vm.exec", req.Name, strings.Join(req.Command, " "), "error")
		return nil, status.Errorf(codes.Internal, "exec in guest: %v", err)
	}
	s.audit(ctx, "vm.exec", req.Name, strings.Join(req.Command, " "), "ok")
	return &pb.ExecVMResponse{Stdout: []byte(output)}, nil
}

// vmHooks extracts the HooksSpec from a stored VMRecord's JSON spec.
func vmHooks(vm *corrosion.VMRecord) *pb.HooksSpec {
	if vm.Spec == "" {
		return nil
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
		return nil
	}
	return spec.Hooks
}

// reapplyVLANTaps re-applies host-tap VLAN config for a VM that has just been
// started, from its stored spec's network[].trunk. VLAN tagging is a property of
// the host tap device (libvirt re-creates vnetN on every start), not the domain
// XML, so it must be re-driven at start — otherwise a VM that was defined while
// stopped (e.g. an import) and started later loses its VLAN. Best-effort: a tap
// failure is logged, never fatal (the domain is already running).
func (s *Server) reapplyVLANTaps(ctx context.Context, vm *corrosion.VMRecord) {
	if vm == nil || vm.Spec == "" {
		return
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
		return
	}
	ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)
	macByOrdinal := make(map[int]string, len(ifaces))
	for _, ir := range ifaces {
		macByOrdinal[ir.Ordinal] = ir.MAC
	}
	for i, n := range spec.Network {
		if len(n.Trunk) == 0 {
			continue
		}
		mac := n.Mac
		if mac == "" {
			mac = macByOrdinal[i]
		}
		bridge := resolveBridge(ctx, s.db, n.Name)
		if mac == "" || bridge == "" {
			continue
		}
		if len(n.Trunk) > 1 {
			vlanIDs := make([]int, len(n.Trunk))
			for j, v := range n.Trunk {
				vlanIDs[j] = int(v)
			}
			if err := s.virt.ConfigureTrunkTap(vm.Name, bridge, mac, vlanIDs); err != nil {
				slog.Warn("VLAN trunk tap reapply failed", "vm", vm.Name, "vlans", vlanIDs, "error", err)
			}
		} else if err := s.virt.ConfigureVLANTap(vm.Name, bridge, mac, int(n.Trunk[0])); err != nil {
			slog.Warn("VLAN tap reapply failed", "vm", vm.Name, "vlan", n.Trunk[0], "error", err)
		}
	}
}

// hooksDefined reports whether any lifecycle hook command is set. Defining one
// is an admin-only action (F3): hooks run as root on the target host.
func hooksDefined(h *pb.HooksSpec) bool {
	if h == nil {
		return false
	}
	return h.PreStart != "" || h.PostStart != "" || h.PreStop != "" ||
		h.PostStop != "" || h.PreMigrate != "" || h.PostMigrate != ""
}

// GenerateMAC generates a random locally-administered MAC address with the
// KVM prefix 52:54:00. Uses crypto/rand for uniqueness.
func GenerateMAC() string {
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", buf[0], buf[1], buf[2])
}

// provisionNetworkForVM delegates to network.ProvisionForVM.
// Kept as a local wrapper for backward compatibility within this file.
func provisionNetworkForVM(ctx context.Context, db *corrosion.Client, networkName, hostName string) (string, error) {
	return network.ProvisionForVM(ctx, db, networkName, hostName)
}

// resolveBridge maps a compose network name to the actual host bridge interface.
// Falls back to networkName itself if no network record exists (flat bridge mode).
func resolveBridge(ctx context.Context, db *corrosion.Client, networkName string) string {
	def := lookupNetworkDef(ctx, db, networkName)
	if def == nil {
		return networkName
	}
	switch def.Type {
	case "sriov":
		if def.PF != "" {
			return def.PF
		}
	case "direct":
		if def.Interface != "" {
			return "direct:" + def.Interface
		}
	case "isolated":
		// Must match the bridge name provisioning actually creates
		// (network.IsolatedBridgeName), otherwise a hot attach-nic plugs
		// into a non-existent device and fails with "Cannot get interface MTU".
		return network.IsolatedBridgeName(networkName)
	default:
		if def.Interface != "" {
			return def.Interface
		}
	}
	return networkName
}

// lookupNetworkDef fetches a network definition from Corrosion.
// Returns nil if the network is not found (flat bridge mode).
func lookupNetworkDef(ctx context.Context, db *corrosion.Client, networkName string) *compose.NetworkDef {
	rows, err := db.Query(ctx,
		`SELECT type, config FROM networks WHERE name = ? AND deleted_at IS NULL`,
		networkName)
	if err != nil || len(rows) == 0 {
		return nil
	}
	var def compose.NetworkDef
	if err := json.Unmarshal([]byte(rows[0].String("config")), &def); err != nil {
		return nil
	}
	def.Type = rows[0].String("type")
	return &def
}

// buildIsolatedNetworkConfig generates a cloud-init V1 network-config YAML
// for VMs on host-isolated networks. Uses MAC matching for distro-agnostic
// interface binding (works on Ubuntu, CentOS, Arch, Debian, Alpine, etc.).
//
// IPv6: when iface.Address6 is set we emit a second `static6` subnet on
// the same interface (cloud-init's V1 schema accepts dual-stack via
// repeated `subnets:` entries with type `static` for v4 and `static6`
// for v6).
func buildIsolatedNetworkConfig(ifaces []isolatedIface) string {
	if len(ifaces) == 0 {
		return ""
	}
	cfg := "version: 1\nconfig:\n"
	for i, iface := range ifaces {
		cfg += fmt.Sprintf("  - type: physical\n    name: eth%d\n    mac_address: %q\n    subnets:\n", i, iface.MAC)
		if iface.Address != "" {
			cfg += fmt.Sprintf("      - type: static\n        address: %s\n", iface.Address)
			if iface.Gateway != "" {
				cfg += fmt.Sprintf("        gateway: %s\n", iface.Gateway)
			}
			if len(iface.DNS) > 0 {
				cfg += "        dns_nameservers:\n"
				for _, ns := range iface.DNS {
					cfg += fmt.Sprintf("          - %s\n", ns)
				}
			}
		}
		if iface.Address6 != "" {
			cfg += fmt.Sprintf("      - type: static6\n        address: %s\n", iface.Address6)
			if iface.Gateway6 != "" {
				cfg += fmt.Sprintf("        gateway: %s\n", iface.Gateway6)
			}
		}
	}
	return cfg
}

type isolatedIface struct {
	MAC      string
	Address  string // IPv4 CIDR, e.g. "10.100.0.10/24"
	Gateway  string
	DNS      []string
	Address6 string // IPv6 CIDR, e.g. "2001:db8::10/64"; empty = no static v6 (SLAAC/RA)
	Gateway6 string
}

// splitCIDR splits "10.0.0.0/24" into ["10.0.0.0", "24"].
// Returns ["ip", ""] if no prefix is present.
func splitCIDR(cidr string) [2]string {
	for i := range cidr {
		if cidr[i] == '/' {
			return [2]string{cidr[:i], cidr[i+1:]}
		}
	}
	return [2]string{cidr, ""}
}

// getLocalIP returns the outbound IP of this host.
func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// SetVMIP updates the IP address of a VM interface in the state store.
func (s *Server) SetVMIP(ctx context.Context, req *pb.SetVMIPRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "VM name required")
	}
	if req.Ip == "" {
		return nil, status.Error(codes.InvalidArgument, "IP address required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.update", "operator"); err != nil {
		return nil, err
	}

	networkName := req.NetworkName
	if networkName == "" {
		networkName = "production"
	}

	if err := corrosion.UpdateVMInterfaceIP(ctx, s.db, req.Name, networkName, req.Ip); err != nil {
		return nil, status.Errorf(codes.Internal, "update VM interface IP: %v", err)
	}

	// Update DNS record so VM is reachable by name.
	if s.dnsDomain != "" {
		dnsName := dns.VMRecordName(req.Name, vm.StackName, s.dnsDomain)
		if err := dns.UpsertRecord(ctx, s.db, dnsName, req.Ip); err != nil {
			slog.Warn("SetVMIP: DNS upsert failed", "vm", req.Name, "error", err)
		}
	}

	slog.Info("VM interface IP updated", "vm", req.Name, "network", networkName, "ip", req.Ip)
	s.recordVMEvent(ctx, req.Name, "vm.ip-changed", "ok", networkName+"="+req.Ip)
	return s.vmToProto(ctx, req.Name)
}

// SetBootOrder updates the boot order of a VM by modifying its libvirt domain XML.
func (s *Server) SetBootOrder(ctx context.Context, req *pb.SetBootOrderRequest) (*pb.VM, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "VM name required")
	}
	if req.BootOrder == "" {
		return nil, status.Error(codes.InvalidArgument, "boot order required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.SetBootOrder(ctx, req)
	}

	if err := s.virt.SetBootOrder(req.Name, req.BootOrder); err != nil {
		return nil, status.Errorf(codes.Internal, "set boot order: %v", err)
	}

	slog.Info("VM boot order updated", "vm", req.Name, "boot", req.BootOrder)
	s.recordVMEvent(ctx, req.Name, "vm.bootorder-changed", "ok", req.BootOrder)
	return s.vmToProto(ctx, req.Name)
}

// RebuildVM destroys and recreates a VM from its stored spec, preserving IP/MAC allocations.
func (s *Server) RebuildVM(ctx context.Context, req *pb.RebuildVMRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "VM name required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.rebuild", "operator"); err != nil {
		return nil, err
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.RebuildVM(ctx, req)
	}

	// Parse the stored spec.
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
		return nil, status.Errorf(codes.Internal, "parse stored VM spec: %v", err)
	}

	// Preserve existing MAC and IP allocations.
	ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, req.Name)
	macMap := map[string]string{} // network -> mac
	ipMap := map[string]string{}  // network -> ip
	for _, iface := range ifaces {
		macMap[iface.NetworkName] = iface.MAC
		ipMap[iface.NetworkName] = iface.IP
	}
	for _, n := range spec.Network {
		if mac, ok := macMap[n.Name]; ok {
			n.Mac = mac
		}
		if ip, ok := ipMap[n.Name]; ok && n.Ip == "" {
			n.Ip = ip
		}
	}

	// Stop and undefine the current domain.
	if vm.State == "running" {
		s.virt.DestroyDomain(req.Name)
	}
	s.virt.UndefineDomain(req.Name, false)

	// Delete existing disks — at their recorded locations (driver-dispatched,
	// so a rebuilt VM doesn't leak its old non-default-pool backing volume),
	// then glob the default dir. Must run before the tombstone below.
	s.deleteRecordedVMDiskVolumes(ctx, req.Name)
	s.images.DeleteVMDisks(req.Name)
	// Wipe the old firmware state — rebuild recreates with a FRESH identity, so the
	// old name-keyed NVRAM + old-UUID swtpm tree would otherwise be orphaned (G1).
	lv.WipeFirmwareState(s.dataDir, req.Name, spec.Uuid)
	os.Remove(lv.CloudInitISOPath(s.dataDir, req.Name))

	// Tombstone old records (they'll be replaced by CreateVM).
	corrosion.DeleteVM(ctx, s.db, req.Name)

	// Recreate the VM using the stored spec.
	slog.Info("rebuilding VM", "name", req.Name)
	s.recordVMEvent(ctx, req.Name, "vm.rebuilt", "ok", "image="+spec.Image)
	return s.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec})
}

// CutoverVM completes a snapshot-and-replace update. The "-next" VM replaces the original.
func (s *Server) CutoverVM(ctx context.Context, req *pb.CutoverVMRequest) (*pb.VM, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "VM name required")
	}

	nextName := req.VmName + "-next"
	nextVM, err := corrosion.GetVM(ctx, s.db, nextName)
	if err != nil || nextVM == nil {
		return nil, status.Errorf(codes.NotFound, "no pending cutover — VM %q not found", nextName)
	}

	// Verify the -next VM is running and ready.
	if nextVM.State != "running" && nextVM.State != "stopped" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q is in state %q, expected running or stopped", nextName, nextVM.State)
	}

	// The cutover must run on the host that owns the -next domain — its libvirt
	// domain and name-keyed NVRAM live there. Forward if we're not that host;
	// otherwise the libvirt rename below is skipped and a firmware VM's NVRAM is
	// never renamed on the real host, so it would come up with mismatched
	// firmware (G1). The forwarded call runs locally on the owning host.
	if nextVM.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, nextVM.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable,
				"cannot reach host %s that owns %q for cutover: %v", nextVM.HostName, nextName, err)
		}
		defer conn.Close()
		return client.CutoverVM(ctx, req)
	}

	// Resource pre-check: during the cutover overlap window, both the old and
	// new VM may be running simultaneously. Verify the host has enough resources
	// to handle 2x the allocation (#23).
	oldVM, _ := corrosion.GetVM(ctx, s.db, req.VmName)
	if oldVM != nil && oldVM.State == "running" && nextVM.State == "running" && nextVM.HostName == s.hostName {
		h, _ := corrosion.GetHost(ctx, s.db, s.hostName)
		if h != nil {
			cpuUsed, memUsed, _ := s.hostAllocatedResources(ctx, s.hostName)
			// The -next VM is already counted in hostAllocatedResources.
			// The old VM is also counted. After cutover the old VM is removed.
			// So the overlap cost is zero. But if oldVM is on a different host,
			// the -next VM on this host must fit. Check remaining capacity.
			cpuFree := int32(h.CPUTotal) - cpuUsed
			memFree := int32(h.MemTotal) - memUsed
			if cpuFree < 0 || memFree < 0 {
				return nil, status.Errorf(codes.ResourceExhausted,
					"host %s has insufficient resources for cutover overlap (cpu_free=%d, mem_free=%dMiB)",
					s.hostName, cpuFree, memFree)
			}
		}
	}

	// Stop and delete the old VM (re-fetch in case state changed).
	oldVM, _ = corrosion.GetVM(ctx, s.db, req.VmName)
	if oldVM != nil {
		if oldVM.HostName == s.hostName && oldVM.State == "running" {
			s.virt.DestroyDomain(req.VmName)
		}
		if oldVM.HostName == s.hostName {
			s.virt.UndefineDomain(req.VmName, false)
		}
		// Free the replaced VM's disks at their recorded locations (driver-
		// dispatched) before the tombstone, then glob the default dir.
		if oldVM.HostName == s.hostName {
			s.deleteRecordedVMDiskVolumes(ctx, req.VmName)
			// Wipe the replaced VM's firmware state (its old UUID-keyed swtpm +
			// name-keyed NVRAM) so cutover doesn't orphan it (G1).
			lv.WipeFirmwareState(s.dataDir, req.VmName, parseFirmwareSpec(oldVM.Spec).UUID)
		}
		s.images.DeleteVMDisks(req.VmName)
		os.Remove(lv.CloudInitISOPath(s.dataDir, req.VmName))
		corrosion.DeleteVM(ctx, s.db, req.VmName)
	}

	// Rename the -next VM to the original name.
	if err := corrosion.RenameVM(ctx, s.db, nextName, req.VmName); err != nil {
		return nil, status.Errorf(codes.Internal, "rename VM: %v", err)
	}

	// Rename in libvirt if on this host. For a Secure-Boot/vTPM VM, a failure here
	// (NVRAM rename, redefine, start) is HARD — the reconciler can't reliably heal
	// a firmware VM (a fresh redefine would mint new firmware) — so mark it errored
	// and return rather than reporting a successful cutover. For a plain VM the
	// reconciler rebuilds, so log + continue (G1).
	fwVM := usesFirmwareState(nextVM.Spec)
	if nextVM.HostName == s.hostName {
		cutoverFail := func(step string, e error) error {
			slog.Error("cutover: "+step+" failed", "vm", req.VmName, "error", e, "firmware_vm", fwVM)
			s.recordVMEvent(ctx, req.VmName, "vm.cutover", "error", step+" failed: "+e.Error())
			if fwVM {
				corrosion.UpdateVMState(ctx, s.db, req.VmName, "error", "cutover "+step+" failed: "+e.Error())
				return status.Errorf(codes.Internal, "cutover %s for %q: %v", step, req.VmName, e)
			}
			return nil // plain VM — reconciler will rebuild
		}
		// Libvirt doesn't support rename directly — dump XML, undefine, redefine.
		xml, derr := s.virt.DumpXML(nextName)
		if derr != nil {
			if e := cutoverFail("dump XML", derr); e != nil {
				return nil, e
			}
		} else {
			// KEEP NVRAM/vTPM — the dumped XML retains the stable <uuid> so the
			// UUID-keyed swtpm follows it automatically; only the name-keyed NVRAM
			// file needs renaming. Undefine MUST succeed before we rename NVRAM —
			// renaming the vars file out from under a still-defined -next domain
			// would leave a dangling <nvram> path (G1), so treat failure as hard.
			if e := s.virt.UndefineDomainPreservingState(nextName); e != nil {
				if e := cutoverFail("undefine -next", e); e != nil {
					return nil, e
				}
			}
			xml = replaceDomainName(xml, nextName, req.VmName)
			oldNvram, newNvram := lv.NvramPath(s.dataDir, nextName), lv.NvramPath(s.dataDir, req.VmName)
			if _, e := os.Stat(oldNvram); e == nil {
				if e := os.Rename(oldNvram, newNvram); e == nil {
					xml = strings.ReplaceAll(xml, oldNvram, newNvram)
				} else if e := cutoverFail("nvram rename", e); e != nil {
					return nil, e
				}
			}
			if e := s.virt.DefineDomain(xml); e != nil {
				if e := cutoverFail("redefine", e); e != nil {
					return nil, e
				}
			} else if nextVM.State == "running" {
				if e := s.virt.StartDomain(req.VmName); e != nil {
					if e := cutoverFail("start", e); e != nil {
						return nil, e
					}
				}
			}
		}
	}

	slog.Info("cutover complete", "vm", req.VmName, "replaced_from", nextName)
	s.recordVMEvent(ctx, req.VmName, "vm.cutover", "ok", "from="+nextName)
	return s.vmToProto(ctx, req.VmName)
}

// replaceDomainName swaps the domain name in libvirt XML.
func replaceDomainName(xml, oldName, newName string) string {
	// Simple string replacement of <name>old</name> -> <name>new</name>
	old := "<name>" + oldName + "</name>"
	new := "<name>" + newName + "</name>"
	return fmt.Sprintf("%s", fmt.Sprintf("%s", // force through fmt to avoid import issues
		replaceFirst(xml, old, new)))
}

func replaceFirst(s, old, new string) string {
	i := len(s) // find manually to avoid strings import
	for j := 0; j+len(old) <= len(s); j++ {
		if s[j:j+len(old)] == old {
			i = j
			break
		}
	}
	if i == len(s) {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

// resolveVolume looks up a named volume from the stack's compose YAML, then
// falls back to host-level storage pools, then defaults to local driver.
func (s *Server) resolveVolume(ctx context.Context, stackName, volumeName string) storage.Config {
	// 1. Try compose volumes.
	if stackName != "" {
		st, err := corrosion.GetStack(ctx, s.db, stackName)
		if err == nil && st != nil && st.ComposeYAML != "" {
			f, err := compose.ParseBytes([]byte(st.ComposeYAML))
			if err == nil {
				if vol, ok := f.Volumes[volumeName]; ok {
					return storage.Config{
						Driver:  vol.Driver,
						Source:  vol.Source,
						Target:  vol.Target,
						Options: vol.Options,
					}
				}
			}
		}
	}

	// 2. Try host-level storage pools.
	{
		if pool, ok := s.lookupStoragePool(volumeName); ok {
			return storage.Config{
				Driver:  pool.Driver,
				Source:  pool.Source,
				Target:  pool.Target,
				Options: pool.Options,
			}
		}
	}

	// 3. Fallback to local.
	return storage.Config{Driver: "local"}
}

// parseDiskSizeBytes converts a human-readable size string (e.g. "20G", "512M")
// to bytes. Returns 0 if unparseable.
func parseDiskSizeBytes(s string) int64 {
	if s == "" {
		return 0
	}
	// Trim and uppercase for matching.
	upper := ""
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			upper += string(c - 32)
		} else {
			upper += string(c)
		}
	}

	var multiplier int64 = 1
	numStr := upper
	switch {
	case len(upper) > 0 && upper[len(upper)-1] == 'G':
		multiplier = 1024 * 1024 * 1024
		numStr = upper[:len(upper)-1]
	case len(upper) > 0 && upper[len(upper)-1] == 'M':
		multiplier = 1024 * 1024
		numStr = upper[:len(upper)-1]
	case len(upper) > 0 && upper[len(upper)-1] == 'T':
		multiplier = 1024 * 1024 * 1024 * 1024
		numStr = upper[:len(upper)-1]
	}

	var n int64
	for _, c := range numStr {
		if c >= '0' && c <= '9' {
			n = n*10 + int64(c-'0')
		}
	}
	return n * multiplier
}

// vmBaseName strips a trailing "-N" replica suffix to get the base VM name.
// "web-3" → "web", "db" → "db".
func vmBaseName(instanceName string) string {
	idx := len(instanceName) - 1
	// Walk backwards past digits.
	for idx >= 0 && instanceName[idx] >= '0' && instanceName[idx] <= '9' {
		idx--
	}
	// If we found a dash before the digits, strip it.
	if idx >= 0 && instanceName[idx] == '-' && idx < len(instanceName)-1 {
		return instanceName[:idx]
	}
	return instanceName
}

// ResizeDisk expands a VM's disk to a new total size.
// Works on both running (live resize) and stopped VMs.
func (s *Server) ResizeDisk(ctx context.Context, req *pb.ResizeDiskRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" || req.DiskName == "" || req.Size == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name, disk_name, and size are required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.resize", "operator"); err != nil {
		return nil, err
	}

	// Forward to the correct host.
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.ResizeDisk(ctx, req)
	}

	// Find the disk record.
	disks, err := corrosion.GetVMDisks(ctx, s.db, req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list disks: %v", err)
	}
	var disk *corrosion.DiskRecord
	for i := range disks {
		if disks[i].DiskName == req.DiskName {
			disk = &disks[i]
			break
		}
	}
	if disk == nil {
		return nil, status.Errorf(codes.NotFound, "disk %q not found on VM %q", req.DiskName, req.VmName)
	}

	newSizeBytes := parseDiskSizeBytes(req.Size)
	if newSizeBytes <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid size %q", req.Size)
	}
	if disk.SizeBytes > 0 && newSizeBytes <= disk.SizeBytes {
		return nil, status.Errorf(codes.InvalidArgument, "new size must be larger than current size (%d bytes)", disk.SizeBytes)
	}

	if vm.State == "running" && s.virt != nil {
		// Use libvirt DomainBlockResize — resizes the image and notifies the guest in one call.
		if err := s.virt.BlockResize(req.VmName, disk.Path, newSizeBytes); err != nil {
			return nil, status.Errorf(codes.Internal, "block resize: %v", err)
		}
	} else {
		// VM is stopped — resize the qcow2 image directly.
		if err := qcow2.Resize(disk.Path, uint64(newSizeBytes)); err != nil {
			return nil, status.Errorf(codes.Internal, "resize disk: %v", err)
		}
	}

	// Update DB.
	if err := corrosion.UpdateDiskSize(ctx, s.db, req.VmName, req.DiskName, newSizeBytes); err != nil {
		slog.Warn("failed to update disk size in DB", "vm", req.VmName, "disk", req.DiskName, "error", err)
	}

	slog.Info("disk resized", "vm", req.VmName, "disk", req.DiskName, "new_size", req.Size)
	s.recordVMEvent(ctx, req.VmName, "disk.resized", "ok", req.DiskName+":"+req.Size)
	return s.vmToProto(ctx, req.VmName)
}

// UpdateVM modifies the spec of a stopped VM (CPU, memory, VNC toggle),
// regenerates domain XML, and redefines the libvirt domain.
func (s *Server) UpdateVM(ctx context.Context, req *pb.UpdateVMRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.update", "operator"); err != nil {
		return nil, err
	}
	// Forward to the owning host first — it has authoritative state.
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.UpdateVM(ctx, req)
	}

	// Deserialize stored spec.
	spec := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			return nil, status.Errorf(codes.Internal, "parse stored spec: %v", err)
		}
	}

	// LIVE metadata fields — applied whether the VM is running or stopped. The
	// reconciler/vmcheck read these fresh from the spec each sweep, so no redefine
	// is needed. A nil restart means "unchanged"; restart.condition=="none"|""
	// CLEARS the policy. The optional scalars are nil when unchanged.
	if req.Restart != nil {
		if c := req.Restart.Condition; c == "" || c == "none" {
			spec.Restart = nil
		} else {
			spec.Restart = req.Restart
		}
	}
	if req.Onboot != nil {
		spec.Onboot = *req.Onboot
	}
	if req.StartupOrder != nil {
		spec.StartupOrder = *req.StartupOrder
	}
	if req.StartDelaySec != nil {
		spec.StartDelaySec = *req.StartDelaySec
	}
	if req.StopDelaySec != nil {
		spec.StopDelaySec = *req.StopDelaySec
	}

	// REDEFINE-class fields bake into the domain XML, so they need the VM stopped.
	// Only require stopped (and redefine) when one of them is actually changing —
	// a metadata-only update applies live above.
	redefine := req.Cpu > 0 || req.MemoryMib > 0 || req.CpuMode != "" ||
		req.Machine != "" || req.Firmware != "" ||
		req.GuestAgent != nil || req.MinMemoryMib != nil || req.MaxMemoryMib != nil ||
		req.SecureBoot != nil || req.Tpm != nil
	if redefine {
		if vm.State != "stopped" {
			return nil, status.Errorf(codes.FailedPrecondition,
				"VM %q must be stopped to change cpu/memory/machine/firmware/mem-bounds (current: %s); restart policy, onboot and startup ordering can be changed live",
				req.Name, vm.State)
		}
		if req.Cpu > 0 {
			spec.Cpu = req.Cpu
		}
		if req.MemoryMib > 0 {
			spec.MemoryMib = req.MemoryMib
		}
		if req.CpuMode != "" {
			spec.CpuMode = req.CpuMode
		}
		if req.Machine != "" {
			spec.Machine = req.Machine
		}
		if req.Firmware != "" {
			spec.Firmware = req.Firmware
		}
		if req.GuestAgent != nil {
			spec.GuestAgent = *req.GuestAgent
		}
		if req.MinMemoryMib != nil {
			spec.MinMemoryMib = *req.MinMemoryMib
		}
		if req.MaxMemoryMib != nil {
			spec.MaxMemoryMib = *req.MaxMemoryMib
		}
		// Toggling secure_boot/tpm once firmware state exists can brick an
		// unsigned guest (SB) or orphan BitLocker (TPM) — refuse without --force.
		if req.SecureBoot != nil && *req.SecureBoot != spec.SecureBoot {
			if !req.Force && (lv.HasNvram(s.dataDir, spec.Name) || lv.HasTPMState(spec.Uuid)) {
				return nil, status.Errorf(codes.FailedPrecondition,
					"changing secure_boot on %q with existing firmware state may render it unbootable; pass --force to override", req.Name)
			}
			spec.SecureBoot = *req.SecureBoot
		}
		if req.Tpm != nil && *req.Tpm != spec.Tpm {
			if !req.Force && lv.HasTPMState(spec.Uuid) {
				return nil, status.Errorf(codes.FailedPrecondition,
					"changing tpm on %q with existing TPM state may orphan BitLocker; pass --force to override", req.Name)
			}
			spec.Tpm = *req.Tpm
		}
		// Backfill a stable UUID for a pre-G1 VM being redefined (it had none in
		// its stored spec). Without this, enabling --tpm would let libvirt assign
		// its own UUID while the spec stays empty — making the swtpm tree
		// unlocatable for state travel. Persisted via the specJSON marshal below (G1).
		if spec.Uuid == "" {
			spec.Uuid = uuid.NewString()
		}
		spec.DisableVnc = req.DisableVnc
	}

	// Re-serialize spec.
	specJSON, _ := json.Marshal(spec)

	// Metadata-only update: persist the spec and return — no domain redefine, so a
	// running VM keeps running untouched.
	if !redefine {
		if err := corrosion.UpdateVMSpec(ctx, s.db, req.Name, string(specJSON), int(spec.Cpu), int(spec.MemoryMib)); err != nil {
			return nil, status.Errorf(codes.Internal, "update VM spec: %v", err)
		}
		slog.Info("VM metadata updated (live)", "vm", req.Name,
			"restart", spec.Restart.GetCondition(), "onboot", spec.Onboot, "startup_order", spec.StartupOrder)
		s.recordVMEvent(ctx, req.Name, "vm.updated", "ok", "live metadata update")
		return s.vmToProto(ctx, req.Name)
	}

	// Build disk configs from the AUTHORITATIVE stored spec (preserves order +
	// bus + SCSI controller model), joining to vm_disks by name only for the
	// on-host path. The legacy fallback below rebuilds from DB records with a
	// target_dev[0]=='s' heuristic that is lossy — it conflates sata/scsi, can't
	// represent ide, and loses ordering — so a redefine (e.g. an imported Windows
	// VM after `lv update`) would silently flip the boot disk to virtio. Only use
	// it for old VMs whose spec carries no disk list.
	dbDisks, _ := corrosion.GetVMDisks(ctx, s.db, req.Name)
	pathByName := make(map[string]string, len(dbDisks))
	for _, d := range dbDisks {
		pathByName[d.DiskName] = d.Path
	}
	var diskConfigs []lv.DiskConfig
	if len(spec.Disks) > 0 {
		for _, d := range spec.Disks {
			name := d.Name
			if name == "" {
				name = "root"
			}
			bus := d.Bus
			if bus == "" {
				bus = "virtio"
			}
			diskConfigs = append(diskConfigs, lv.DiskConfig{
				Name:            name,
				Path:            pathByName[name],
				Bus:             bus,
				Cache:           d.Cache,
				ControllerModel: d.ControllerModel,
			})
		}
	} else {
		for _, d := range dbDisks {
			bus := "virtio"
			if d.TargetDev != "" && d.TargetDev[0] == 's' {
				bus = "scsi"
			}
			diskConfigs = append(diskConfigs, lv.DiskConfig{
				Name: d.DiskName,
				Path: d.Path,
				Bus:  bus,
			})
		}
	}

	// Build network configs from stored interfaces.
	ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, req.Name)
	var netConfigs []lv.NetworkConfig
	for _, iface := range ifaces {
		bridge := resolveBridge(ctx, s.db, iface.NetworkName)
		if strings.HasPrefix(bridge, "direct:") {
			netConfigs = append(netConfigs, lv.NetworkConfig{
				Direct: strings.TrimPrefix(bridge, "direct:"),
				Model:  "virtio",
				MAC:    iface.MAC,
			})
			continue
		}
		netConfigs = append(netConfigs, lv.NetworkConfig{
			Bridge: bridge,
			Model:  "virtio",
			MAC:    iface.MAC,
		})
	}

	// Regenerate domain XML.
	vmCfg := lv.VMConfig{
		Name:        spec.Name,
		UUID:        spec.Uuid,
		CPU:         int(spec.Cpu),
		CPUMode:     spec.CpuMode,
		MemoryMiB:   int(spec.MemoryMib),
		Machine:     spec.Machine,
		Firmware:    spec.Firmware,
		GuestAgent:  spec.GuestAgent,
		EnableVNC:   !spec.DisableVnc,
		EnableSPICE: spec.EnableSpice,
		Disks:       diskConfigs,
		Networks:    netConfigs,
		Boot:        spec.Boot,
	}
	// Preserve Secure Boot + vTPM across the redefine (G1): without this a stopped
	// SB/vTPM VM updated for cpu/mem would be redefined with no <uuid>/<tpm>/SB
	// loader/SMM/nvram — silent BitLocker breakage. ApplyTo only sets fields (no
	// create-time guard), so existing nvram is reused. A SB toggle was capability-
	// checked above; verify the host can still satisfy it.
	if spec.SecureBoot && !s.firmware.SecureBootAvailable() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %s has no Secure Boot OVMF firmware; cannot redefine %q with Secure Boot", s.hostName, req.Name)
	}
	if spec.Tpm {
		if err := s.checkTPMHostSupport(); err != nil {
			return nil, err
		}
	}
	s.firmware.ApplyTo(&vmCfg, s.dataDir, spec.Name, spec.SecureBoot, spec.Tpm)
	if r := spec.Resources; r != nil {
		vmCfg.HugePages = r.Hugepages
		vmCfg.IOThreads = int(r.IoThreads)
		for _, pin := range r.CpuPinning {
			vmCfg.CPUPinning = append(vmCfg.CPUPinning, int(pin))
		}
		if np := r.NumaPolicy; np != nil {
			vmCfg.NUMAPolicy = &lv.NUMAPolicy{
				PreferredNode: int(np.PreferredNode),
				Strict:        np.Strict,
			}
		}
	}

	domXML, err := lv.GenerateDomainXML(vmCfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate domain XML: %v", err)
	}

	// Capture the current domain XML so a failure below can restore it: libvirt
	// running the new (e.g. Secure Boot/vTPM) XML while the durable spec still
	// describes the old flags/UUID would desync backup/migrate/delete/reconciler
	// logic — they'd preserve or wipe the wrong firmware state (G1).
	oldXML, _ := s.virt.DumpXML(req.Name)

	// Undefine the existing domain first — DefineDomain (DomainDefineXML)
	// can fail with "already exists with uuid" when the generated XML has no
	// UUID and libvirt tries to assign a new one that collides. KEEP NVRAM/vTPM
	// — this is a same-VM redefine; deleting them would break a SB/vTPM guest (G1).
	_ = s.virt.UndefineDomainPreservingState(req.Name)

	// Redefine the domain with the updated XML.
	if err := s.virt.DefineDomain(domXML); err != nil {
		if oldXML != "" { // restore the prior definition (state preserved)
			_ = s.virt.DefineDomain(oldXML)
		}
		return nil, status.Errorf(codes.Internal, "redefine domain: %v", err)
	}

	// The durable spec MUST match the live domain. If the write fails, roll the
	// domain back to its old XML rather than return success with libvirt and the
	// stored spec desynced (fatal — never report a half-applied firmware update).
	if err := corrosion.UpdateVMSpec(ctx, s.db, req.Name, string(specJSON), int(spec.Cpu), int(spec.MemoryMib)); err != nil {
		if oldXML != "" {
			_ = s.virt.UndefineDomainPreservingState(req.Name)
			_ = s.virt.DefineDomain(oldXML)
		}
		return nil, status.Errorf(codes.Internal,
			"persist updated spec for %q failed; rolled the domain back to its previous definition: %v", req.Name, err)
	}

	slog.Info("VM spec updated", "vm", req.Name, "cpu", spec.Cpu, "memory_mib", spec.MemoryMib, "disable_vnc", spec.DisableVnc)
	s.recordVMEvent(ctx, req.Name, "vm.updated", "ok", fmt.Sprintf("cpu=%d mem=%d vnc=%v", spec.Cpu, spec.MemoryMib, !spec.DisableVnc))

	return s.vmToProto(ctx, req.Name)
}

// resolveStopTimeout determines the ACPI shutdown timeout in seconds.
// Priority: request timeout > spec stop_timeout_sec > default 30s.
func resolveStopTimeout(reqTimeout int32, specJSON string) int32 {
	if reqTimeout > 0 {
		return reqTimeout
	}
	if specJSON != "" {
		var spec struct {
			StopTimeoutSec int32 `json:"stop_timeout_sec"`
		}
		if json.Unmarshal([]byte(specJSON), &spec) == nil && spec.StopTimeoutSec > 0 {
			return spec.StopTimeoutSec
		}
	}
	return 30
}
