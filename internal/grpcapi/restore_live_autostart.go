package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// resolveRestoreSpec determines the VMSpec to define a restored VM from,
// in precedence order:
//  1. an operator-supplied spec on the request,
//  2. the spec embedded in the manifest at backup time (vm_spec_json),
//  3. (only with from_existing) the spec of an existing vms record.
//
// If none yields a spec it returns FailedPrecondition — the caller must
// then restore without --auto-start (NBD + overlay only) and define the
// VM by hand. This is the backward-compat path for manifests written
// before metadata capture.
func (s *Server) resolveRestoreSpec(ctx context.Context, req *pb.RestoreLiveRequest, manifest *pbsstore.Manifest) (*pb.VMSpec, error) {
	if req.Spec != nil {
		return req.Spec, nil
	}
	if manifest.VMSpecJSON != "" {
		var spec pb.VMSpec
		if err := json.Unmarshal([]byte(manifest.VMSpecJSON), &spec); err != nil {
			return nil, status.Errorf(codes.Internal, "parse embedded vm spec: %v", err)
		}
		return &spec, nil
	}
	if req.FromExisting {
		if rec, err := corrosion.GetVM(ctx, s.db, req.VmName); err == nil && rec != nil && rec.Spec != "" {
			var spec pb.VMSpec
			if err := json.Unmarshal([]byte(rec.Spec), &spec); err != nil {
				return nil, status.Errorf(codes.Internal, "parse existing vm spec: %v", err)
			}
			return &spec, nil
		}
	}
	return nil, status.Error(codes.FailedPrecondition,
		"manifest has no embedded VM metadata; pass --spec/--name or --from-existing, or restore without --auto-start")
}

// autoDefineRestoredVM reconstructs and starts a VM from the resolved spec
// with its root disk pointed at the NBD-backed overlay. It returns the name the
// VM was defined under and the root disk's target dev (for blockpull). The
// domain XML never references NBD — the overlay qcow2 carries the nbd:// URI in
// its own header — so the disk survives a later blockpull that makes it
// self-contained.
func (s *Server) autoDefineRestoredVM(
	ctx context.Context,
	req *pb.RestoreLiveRequest,
	repo *pbsstore.Repo,
	manifest *pbsstore.Manifest,
	overlayPath string,
	send func(*pb.RestoreLiveProgress) error,
) (string, string, error) {
	if s.virt == nil {
		return "", "", status.Error(codes.FailedPrecondition, "no libvirt backend wired on this daemon")
	}
	spec, err := s.resolveRestoreSpec(ctx, req, manifest)
	if err != nil {
		return "", "", err
	}

	originalName := spec.Name
	targetName := req.NewName
	if targetName == "" {
		targetName = originalName
	}
	if targetName == "" {
		targetName = req.VmName
	}
	if !validRestoreName(targetName) {
		return "", "", status.Errorf(codes.InvalidArgument, "invalid restore name %q", targetName)
	}

	// Collision guard: never clobber a live VM. The operator passes
	// --name to restore alongside the original.
	if rec, _ := corrosion.GetVM(ctx, s.db, targetName); rec != nil {
		return "", "", status.Errorf(codes.AlreadyExists,
			"vm %q already exists; pass --name to restore alongside it", targetName)
	}
	if s.virt.DomainExists(targetName) {
		return "", "", status.Errorf(codes.AlreadyExists,
			"domain %q already defined; pass --name to restore alongside it", targetName)
	}

	renamed := targetName != originalName
	spec.Name = targetName

	// Firmware-state travel (G1): a Secure-Boot/vTPM VM's NVRAM + swtpm bind
	// BitLocker. Re-home them onto this host under a FRESH identity (so a
	// restore-alongside can't collide with the still-running original's
	// UUID-keyed swtpm dir) BEFORE defining the domain. Refuse if the host lacks
	// the capability or the backup captured no firmware — booting a fresh-TPM VM
	// would silently brick BitLocker.
	fwVM := spec.SecureBoot || spec.Tpm
	// restoreOK gates the deferred firmware rollback below: a firmware VM that
	// fails ANY step after materialization (bridge/XML/define/start/persist) must
	// not strand name-keyed NVRAM + UUID-keyed swtpm that lifecycle code can't
	// reconcile, so we tear it all down unless the restore fully succeeds (G1).
	restoreOK := false
	if fwVM {
		if spec.SecureBoot && !s.firmware.SecureBootAvailable() {
			return "", "", status.Errorf(codes.FailedPrecondition,
				"host %s has no Secure Boot firmware; cannot restore VM %q here", s.hostName, targetName)
		}
		if spec.Tpm {
			if err := s.checkTPMHostSupport(); err != nil {
				return "", "", err
			}
		}
		if len(spec.Disks) > 1 {
			return "", "", status.Errorf(codes.Unimplemented,
				"VM %q is a multi-disk Secure Boot / vTPM VM; only its root disk + firmware are restored, which would boot it missing its data disks — not supported yet", targetName)
		}
		if len(manifest.FirmwareChunks) == 0 {
			return "", "", status.Errorf(codes.FailedPrecondition,
				"backup of Secure Boot / vTPM VM %q captured no firmware state; cannot restore it consistently (re-take the backup on a firmware-aware build)", req.VmName)
		}
		spec.Uuid = uuid.NewString()
		if err := s.materializeFirmwareBundle(repo, manifest, targetName, spec.Uuid); err != nil {
			return "", "", err
		}
		defer func() {
			if restoreOK {
				return
			}
			// Failed partway after materialization: destroy/undefine any domain we
			// defined and wipe the materialized firmware so a retry re-materializes
			// cleanly (and lifecycle never sees orphaned state).
			s.virt.DestroyDomain(targetName)
			_ = s.virt.UndefineDomain(targetName, false)
			lv.WipeFirmwareState(s.dataDir, targetName, spec.Uuid)
		}()
	}

	// Root disk → the overlay. Rebuild bus/controller from the stored spec (not
	// hardcoded virtio) so an imported scsi/sata guest — e.g. Windows — boots
	// after restore instead of stalling on a missing controller (G1). Multi-disk
	// auto-restore is out of scope: only the root disk is NBD-backed.
	rootBus, rootCtrl := "virtio", ""
	for _, ds := range spec.Disks {
		if ds.Name == "root" {
			if ds.Bus != "" {
				rootBus = ds.Bus
			}
			rootCtrl = ds.ControllerModel
			break
		}
	}
	rootDev := lv.DiskDevName(rootBus, 0)
	diskCfg := []lv.DiskConfig{{Name: "root", Path: overlayPath, Bus: rootBus, ControllerModel: rootCtrl}}
	diskRecords := []corrosion.DiskRecord{{
		VMName: targetName, DiskName: "root", HostName: s.hostName,
		Path: overlayPath, SizeBytes: manifest.TotalSize, StorageType: "local",
		TargetDev: rootDev,
	}}

	// Networks from the spec. On a rename we regenerate MACs so the
	// restored VM can't collide on L2 with the still-running original.
	var netCfg []lv.NetworkConfig
	var ifaceRecords []corrosion.InterfaceRecord
	for i, n := range spec.Network {
		mac := n.Mac
		if renamed || mac == "" {
			mac = lv.GenerateMAC()
		}
		bridge := n.Name
		if _, err := net.InterfaceByName(bridge); err != nil {
			if err := network.EnsureBridge(bridge); err != nil {
				return "", "", status.Errorf(codes.FailedPrecondition,
					"network bridge %q not available on host %s: %v", bridge, s.hostName, err)
			}
		}
		netCfg = append(netCfg, lv.NetworkConfig{Bridge: bridge, Model: n.Model, MAC: mac})
		ifaceRecords = append(ifaceRecords, corrosion.InterfaceRecord{
			VMName: targetName, NetworkName: n.Name, Ordinal: i, MAC: mac, IP: n.Ip,
		})
	}

	vmCfg := lv.VMConfig{
		Name:        targetName,
		CPU:         int(spec.Cpu),
		CPUMode:     spec.CpuMode,
		MemoryMiB:   int(spec.MemoryMib),
		Machine:     spec.Machine,
		Firmware:    spec.Firmware,
		GuestAgent:  spec.GuestAgent,
		EnableVNC:   !spec.DisableVnc,
		EnableSPICE: spec.EnableSpice,
		Disks:       diskCfg,
		Networks:    netCfg,
		Boot:        spec.Boot,
	}
	// Firmware fields (G1): point the domain at the just-materialized NVRAM
	// (name-keyed) + the fresh UUID whose swtpm dir we re-homed the state into.
	if fwVM {
		s.firmware.ApplyTo(&vmCfg, s.dataDir, targetName, spec.SecureBoot, spec.Tpm)
		vmCfg.UUID = spec.Uuid
	}
	domXML, err := lv.GenerateDomainXML(vmCfg)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "generate domain XML: %v", err)
	}

	_ = send(&pb.RestoreLiveProgress{
		Phase: pb.RestoreLiveProgress_DEFINING, VmName: targetName,
		TargetPath: overlayPath, Status: "defining domain against overlay",
	})
	if err := s.virt.DefineDomain(domXML); err != nil {
		return "", "", status.Errorf(codes.Internal, "define domain: %v", err)
	}
	if err := s.virt.StartDomain(targetName); err != nil {
		// Roll back the definition but KEEP the overlay + NBD so the operator can
		// retry define/start against the still-valid source. For a firmware VM the
		// deferred rollback additionally wipes the materialized NVRAM/swtpm.
		_ = s.virt.UndefineDomain(targetName, false)
		return "", "", status.Errorf(codes.Internal, "start domain: %v", err)
	}
	_ = send(&pb.RestoreLiveProgress{
		Phase: pb.RestoreLiveProgress_STARTED, VmName: targetName,
		TargetPath: overlayPath, Status: "VM started off overlay",
	})

	// Persist the VM so lifecycle / migration / UI treat it like any
	// other. Best-effort: the VM is already running.
	specJSON, _ := json.Marshal(spec)
	vmRecord := corrosion.VMRecord{
		Name: targetName, HostName: s.hostName, Spec: string(specJSON),
		State: "running", CPUActual: int(spec.Cpu), MemActual: int(spec.MemoryMib),
	}
	if err := corrosion.InsertVM(ctx, s.db, vmRecord, ifaceRecords, diskRecords); err != nil {
		if fwVM {
			// A running firmware domain with no DB row is unmanageable — lifecycle
			// code wouldn't know to preserve/wipe its state — so fail hard; the
			// deferred rollback destroys the domain + wipes the firmware.
			return "", "", status.Errorf(codes.Internal, "persist restored firmware VM %q: %v", targetName, err)
		}
		slog.Error("live-restore: failed to write VM to corrosion", "vm", targetName, "error", err)
	}
	restoreOK = true
	s.recordVMEvent(ctx, targetName, "vm.created", "ok", "host="+s.hostName+" (live-restore)")
	return targetName, rootDev, nil
}

// driveBlockpull localizes the restored disk by flattening the NBD backing
// chain into the overlay, then returns once the job completes so the
// caller's deferred NBD teardown can run. On a failed/partial pull it
// returns ok=false so the caller keeps the stream open instead of
// bricking a half-pulled disk.
func (s *Server) driveBlockpull(ctx context.Context, vmName, dev string, send func(*pb.RestoreLiveProgress) error) (ok bool) {
	if dev == "" {
		dev = "vda"
	}
	_ = send(&pb.RestoreLiveProgress{
		Phase: pb.RestoreLiveProgress_BLOCKPULL, VmName: vmName,
		Status: "localizing disk via blockpull",
	})
	if err := s.virt.BlockPull(vmName, dev); err != nil {
		_ = send(&pb.RestoreLiveProgress{
			Phase: pb.RestoreLiveProgress_READY, VmName: vmName,
			Status: "blockpull failed (" + err.Error() + ") — keeping NBD up; localize manually then close the stream",
		})
		return false
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			st, err := s.virt.BlockJobStatus(vmName, dev)
			if err != nil {
				_ = send(&pb.RestoreLiveProgress{
					Phase: pb.RestoreLiveProgress_READY, VmName: vmName,
					Status: "blockpull status error (" + err.Error() + ") — keeping NBD up",
				})
				return false
			}
			if !st.Found || (st.End > 0 && st.Cur >= st.End) {
				_ = send(&pb.RestoreLiveProgress{
					Phase: pb.RestoreLiveProgress_LOCALIZED, VmName: vmName,
					Status: "disk localized — NBD server stopping",
				})
				return true
			}
		}
	}
}
