package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// CloneVM creates a new VM from a template or a stopped source VM. Linked clones
// (qcow2 overlay) are instant + space-efficient; full clones (qcow2 convert)
// are independent. The clone is created on — and (v1) runs on — the source's
// host, since the source disks live there; it gets a fresh identity (new MACs +
// regenerated cloud-init instance-id/hostname → clean first boot, new SSH host
// keys). Storage-aware default: linked on shared storage, full on local.
func (s *Server) CloneVM(ctx context.Context, req *pb.CloneVMRequest) (*pb.VM, error) {
	if req.Source == "" || req.Target == "" {
		return nil, status.Error(codes.InvalidArgument, "source and target are required")
	}
	if !validResourceName(req.Target) {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid target name %q: only letters, digits, '_', '.', '-' are allowed", req.Target)
	}
	src, err := corrosion.GetVM(ctx, s.db, req.Source)
	if err != nil || src == nil {
		return nil, status.Errorf(codes.NotFound, "source %q not found", req.Source)
	}
	project := tenancy.NormalizeProject(req.Project)
	if req.Project == "" {
		project = tenancy.NormalizeProject(src.Project)
	}
	if err := s.RequirePerm(ctx, vmRBACPathFor(project, req.Target), "vm.create", "operator"); err != nil {
		return nil, err
	}
	if existing, _ := corrosion.GetVM(ctx, s.db, req.Target); existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "VM %q already exists", req.Target)
	}
	// The clone is created where the source's disks live.
	if src.HostName != s.hostName {
		client, conn, perr := s.peerClient(ctx, src.HostName)
		if perr != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach source host %s: %v", src.HostName, perr)
		}
		defer conn.Close()
		return client.CloneVM(ctx, req)
	}
	// Consistent disk state: clone a template or a stopped VM (a running VM's
	// disk isn't crash-consistent). Snapshot-based clone is a follow-up.
	if !src.IsTemplate && src.State != "stopped" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"source %q must be a template or stopped to clone (current: %s); stop it or convert it to a template first",
			req.Source, src.State)
	}
	if req.Snapshot != "" {
		return nil, status.Error(codes.Unimplemented, "clone-from-snapshot is not supported yet; clone from the template/VM directly")
	}
	if s.virt == nil {
		return nil, status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}

	srcDisks, err := corrosion.GetVMDisks(ctx, s.db, req.Source)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load source disks: %v", err)
	}
	if len(srcDisks) == 0 {
		return nil, status.Errorf(codes.FailedPrecondition, "source %q has no disks to clone", req.Source)
	}

	var srcSpec pb.VMSpec
	if src.Spec != "" {
		_ = json.Unmarshal([]byte(src.Spec), &srcSpec)
	}

	mode := cloneMode(req.Mode, allDisksShared(srcDisks))

	// Preserve disk bus + SCSI controller model from the source spec (a Windows
	// scsi/lsisas guest cloned as virtio wouldn't boot — and would falsify
	// "BitLocker survives clone"). Cross-cutting G1 fix.
	diskSpecByName := map[string]*pb.DiskSpec{}
	for _, ds := range srcSpec.Disks {
		diskSpecByName[ds.Name] = ds
	}

	// ── Clone the disks ──────────────────────────────────────────────────
	var diskConfigs []lv.DiskConfig
	var diskRecords []corrosion.DiskRecord
	var created []string
	cleanup := func() {
		for _, p := range created {
			if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
				slog.Warn("clone cleanup: remove disk", "path", p, "error", e)
			}
		}
	}
	for _, d := range srcDisks {
		clonePath, err := s.images.SafeDiskPath(req.Target, d.DiskName)
		if err != nil {
			cleanup()
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if err := os.MkdirAll(filepath.Dir(clonePath), 0755); err != nil {
			cleanup()
			return nil, status.Errorf(codes.Internal, "prepare disk dir: %v", err)
		}
		size := uint64(d.SizeBytes)
		var backing string
		if mode == "linked" {
			if err := qcow2.CreateWithBacking(clonePath, d.Path, size, nil); err != nil {
				cleanup()
				return nil, status.Errorf(codes.Internal, "create linked clone disk %s: %v", d.DiskName, err)
			}
			backing = d.Path
		} else {
			// Uncompressed flatten: fast to write and fast for the clone's guest
			// to read (a compressed convert would be CPU-bound here and inflate
			// on every guest read). Pure-Go — no qemu-img dependency.
			if err := qcow2.Convert(ctx, d.Path, clonePath, &qcow2.Options{Uncompressed: true}); err != nil {
				cleanup()
				return nil, status.Errorf(codes.Internal, "full-clone disk %s: %v", d.DiskName, err)
			}
		}
		created = append(created, clonePath)
		bus, controller := "virtio", ""
		if ds := diskSpecByName[d.DiskName]; ds != nil {
			if ds.Bus != "" {
				bus = ds.Bus
			}
			controller = ds.ControllerModel
		}
		diskConfigs = append(diskConfigs, lv.DiskConfig{Name: d.DiskName, Path: clonePath, Bus: bus, ControllerModel: controller})
		diskRecords = append(diskRecords, corrosion.DiskRecord{
			VMName: req.Target, DiskName: d.DiskName, HostName: s.hostName, Path: clonePath,
			SizeBytes: d.SizeBytes, StorageType: d.StorageType, BackingDisk: backing,
			TargetDev: lv.DiskDevName(bus, len(diskRecords)),
		})
	}

	// ── Networks: fresh MACs (don't duplicate the source's) ──────────────
	var netConfigs []lv.NetworkConfig
	var ifaceRecords []corrosion.InterfaceRecord
	for i, n := range srcSpec.Network {
		mac := lv.GenerateMAC()
		bridge := n.Name
		if pb, perr := provisionNetworkForVM(ctx, s.db, n.Name, s.hostName); perr == nil && pb != "" {
			bridge = pb
		}
		ip := ""
		if i == 0 {
			ip = req.Ip // optional static IP for the first NIC
		}
		if strings.HasPrefix(bridge, "direct:") {
			netConfigs = append(netConfigs, lv.NetworkConfig{Direct: strings.TrimPrefix(bridge, "direct:"), Model: n.Model, MAC: mac})
		} else {
			if _, e := net.InterfaceByName(bridge); e != nil {
				if e := network.EnsureBridge(bridge); e != nil {
					cleanup()
					return nil, status.Errorf(codes.FailedPrecondition, "bridge %q unavailable: %v", bridge, e)
				}
			}
			netConfigs = append(netConfigs, lv.NetworkConfig{Bridge: bridge, Model: n.Model, MAC: mac})
		}
		ifaceRecords = append(ifaceRecords, corrosion.InterfaceRecord{
			VMName: req.Target, NetworkName: n.Name, Ordinal: i, MAC: mac, IP: ip,
		})
	}

	// ── Fresh cloud-init identity (new instance-id ⇒ clean first boot) ───
	cloudInitISO := ""
	if srcSpec.Image != "" || srcSpec.CloudInit != nil {
		userData := "#cloud-config\n{}\n"
		if srcSpec.CloudInit != nil && srcSpec.CloudInit.Userdata != "" {
			userData = srcSpec.CloudInit.Userdata
		}
		isoPath, perr := lv.SafeCloudInitISOPath(s.dataDir, req.Target)
		if perr != nil {
			cleanup()
			return nil, status.Errorf(codes.InvalidArgument, "%v", perr)
		}
		if err := cloudinit.GenerateISO(cloudinit.Config{
			InstanceID:    req.Target, // NEW id forces first-boot (regen SSH host keys, machine-id)
			LocalHostname: req.Target,
			UserData:      userData,
		}, isoPath); err != nil {
			cleanup()
			return nil, status.Errorf(codes.Internal, "generate cloud-init ISO: %v", err)
		}
		cloudInitISO = isoPath
	}

	// ── Derive the clone's spec + domain ─────────────────────────────────
	// Mutate srcSpec in place for the clone's identity (it's our local copy,
	// unmarshalled fresh above) — copying a proto message by value would copy
	// its internal mutex.
	cpu := int(srcSpec.Cpu)
	mem := int(srcSpec.MemoryMib)
	srcSpec.Name = req.Target
	srcSpec.Project = project
	srcSpec.Devices = nil          // v1: don't clone PCI passthrough (device may be in use)
	srcSpec.Uuid = uuid.NewString() // fresh identity ⇒ fresh vTPM (never copy the source TPM secret) (G1)
	for i := range srcSpec.Network {
		if i < len(ifaceRecords) {
			srcSpec.Network[i].Mac = ifaceRecords[i].MAC
			srcSpec.Network[i].Ip = ifaceRecords[i].IP
		}
	}
	specJSON, _ := json.Marshal(&srcSpec)

	machine := srcSpec.Machine
	if machine == "" {
		machine = "q35"
	}
	firmware := srcSpec.Firmware
	if firmware == "" {
		firmware = "uefi"
	}
	vmCfg := lv.VMConfig{
		Name: req.Target, UUID: srcSpec.Uuid, CPU: cpu, CPUMode: srcSpec.CpuMode, MemoryMiB: mem,
		Machine: machine, Firmware: firmware, GuestAgent: srcSpec.GuestAgent,
		EnableVNC: !srcSpec.DisableVnc, EnableSPICE: srcSpec.EnableSpice,
		Disks: diskConfigs, Networks: netConfigs, CloudInitISO: cloudInitISO, Boot: srcSpec.Boot,
	}
	// Thread Secure Boot + vTPM (fresh vTPM at the new UUID; fresh NVRAM from
	// template) into the clone domain (G1).
	if err := s.applyFirmwareConfig(&vmCfg, &srcSpec); err != nil {
		cleanup()
		return nil, err
	}
	domXML, err := lv.GenerateDomainXML(vmCfg)
	if err != nil {
		cleanup()
		return nil, status.Errorf(codes.Internal, "generate domain XML: %v", err)
	}
	if err := s.virt.DefineDomain(domXML); err != nil {
		cleanup()
		return nil, status.Errorf(codes.Internal, "define clone domain: %v", err)
	}

	// Roll back everything the clone built until the DB row lands — including the
	// fresh UUID-keyed swtpm + name-keyed NVRAM, so a failed clone strands nothing (G1).
	rollbackClone := func(running bool) {
		if running {
			s.virt.DestroyDomain(req.Target)
		}
		s.virt.UndefineDomain(req.Target, false)
		cleanup()
		os.Remove(cloudInitISO)
		lv.WipeFirmwareState(s.dataDir, req.Target, srcSpec.Uuid)
	}

	state := "stopped"
	if req.Start {
		if err := s.virt.StartDomain(req.Target); err != nil {
			rollbackClone(false)
			return nil, status.Errorf(codes.Internal, "start clone: %v", err)
		}
		state = "running"
	}

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: req.Target, StackName: src.StackName, HostName: s.hostName, Spec: string(specJSON),
		State: state, CPUActual: cpu, MemActual: mem, Project: project,
	}, ifaceRecords, diskRecords); err != nil {
		rollbackClone(state == "running")
		return nil, status.Errorf(codes.Internal, "persist clone: %v", err)
	}

	slog.Info("VM cloned", "source", req.Source, "target", req.Target, "mode", mode, "host", s.hostName)
	s.audit(ctx, "vm.clone", req.Target, fmt.Sprintf("source=%s mode=%s", req.Source, mode), "ok")
	s.recordVMEvent(ctx, req.Target, "vm.cloned", "ok", "source="+req.Source+" mode="+mode)
	s.publish("vm.cloned", req.Target, "source="+req.Source)
	return s.vmToProto(ctx, req.Target)
}

// ConvertToTemplate marks a stopped VM as a template (Proxmox-style): a VM that
// can no longer start, whose disks become immutable clone sources. With
// req.Revert it turns a template back into a normal VM.
//
// The is_template flag lives in the replicated vms table, so this is a pure
// state mutation — no per-host action — and any node can serve it; the change
// replicates to the owning host.
func (s *Server) ConvertToTemplate(ctx context.Context, req *pb.ConvertToTemplateRequest) (*pb.VM, error) {
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

	if req.Revert {
		if !vm.IsTemplate {
			return nil, status.Errorf(codes.FailedPrecondition, "%q is not a template", req.Name)
		}
		// Reverting makes the VM startable again — but if its disks still back
		// live linked clones, starting it would corrupt them. Refuse until the
		// clones are gone (or were full-cloned).
		if clones, gErr := s.linkedClonesOf(ctx, req.Name); gErr != nil {
			return nil, status.Errorf(codes.Internal, "check linked clones: %v", gErr)
		} else if len(clones) > 0 {
			return nil, status.Errorf(codes.FailedPrecondition,
				"cannot revert %q to a VM: %d linked clone(s) still depend on its disks (%s); delete or full-clone them first",
				req.Name, len(clones), strings.Join(clones, ", "))
		}
		if err := corrosion.SetVMTemplate(ctx, s.db, req.Name, false); err != nil {
			return nil, status.Errorf(codes.Internal, "revert template: %v", err)
		}
		s.audit(ctx, "vm.template.revert", req.Name, "", "ok")
		s.publish("vm.template.revert", req.Name, "")
		return s.InspectVM(ctx, &pb.InspectVMRequest{Name: req.Name})
	}

	if vm.IsTemplate {
		return nil, status.Errorf(codes.FailedPrecondition, "%q is already a template", req.Name)
	}
	// A template must not be running (its disks are about to become immutable
	// clone sources). Require it stopped.
	if vm.State != "stopped" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q must be stopped to convert to a template (current: %s)", req.Name, vm.State)
	}
	if err := corrosion.SetVMTemplate(ctx, s.db, req.Name, true); err != nil {
		return nil, status.Errorf(codes.Internal, "convert to template: %v", err)
	}
	s.audit(ctx, "vm.template.convert", req.Name, "", "ok")
	s.publish("vm.template.convert", req.Name, "")
	return s.InspectVM(ctx, &pb.InspectVMRequest{Name: req.Name})
}

// linkedClonesOf returns the names of VMs whose disks are linked-clone overlays
// backed by any disk of the named source VM/template. Used to guard template
// revert and (later) template/snapshot deletion.
func (s *Server) linkedClonesOf(ctx context.Context, sourceVM string) ([]string, error) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, sourceVM)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var clones []string
	for _, d := range disks {
		names, err := corrosion.LinkedCloneNames(ctx, s.db, d.Path)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if n != sourceVM && !seen[n] {
				seen[n] = true
				clones = append(clones, n)
			}
		}
	}
	return clones, nil
}

// cloneMode resolves the effective clone mode given the requested mode and
// whether the source's disks all live on shared storage. Storage-aware auto
// (the default): linked when every disk is on shared storage (instant, freely
// placeable), full otherwise (so a local-storage clone isn't host-pinned).
func cloneMode(requested string, allShared bool) string {
	switch requested {
	case "linked", "full":
		return requested
	default: // "" / auto
		if allShared {
			return "linked"
		}
		return "full"
	}
}

// diskIsShared reports whether a disk lives on cluster-shared storage (so a
// linked clone backed by it can run on any host). Local/dir/btrfs/lvm are
// host-local; nfs/ceph/iscsi are shared.
func diskIsShared(d corrosion.DiskRecord) bool {
	switch strings.ToLower(d.StorageType) {
	case "nfs", "ceph", "rbd", "iscsi":
		return true
	default:
		return false
	}
}

// allDisksShared reports whether every disk is on shared storage.
func allDisksShared(disks []corrosion.DiskRecord) bool {
	if len(disks) == 0 {
		return false
	}
	for _, d := range disks {
		if !diskIsShared(d) {
			return false
		}
	}
	return true
}
