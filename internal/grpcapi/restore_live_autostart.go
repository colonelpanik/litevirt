package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"time"

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
// with its root disk pointed at the NBD-backed overlay. It returns the
// name the VM was defined under. The domain XML never references NBD — the
// overlay qcow2 carries the nbd:// URI in its own header — so the disk
// survives a later blockpull that makes it self-contained.
func (s *Server) autoDefineRestoredVM(
	ctx context.Context,
	req *pb.RestoreLiveRequest,
	manifest *pbsstore.Manifest,
	overlayPath string,
	send func(*pb.RestoreLiveProgress) error,
) (string, error) {
	if s.virt == nil {
		return "", status.Error(codes.FailedPrecondition, "no libvirt backend wired on this daemon")
	}
	spec, err := s.resolveRestoreSpec(ctx, req, manifest)
	if err != nil {
		return "", err
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
		return "", status.Errorf(codes.InvalidArgument, "invalid restore name %q", targetName)
	}

	// Collision guard: never clobber a live VM. The operator passes
	// --name to restore alongside the original.
	if rec, _ := corrosion.GetVM(ctx, s.db, targetName); rec != nil {
		return "", status.Errorf(codes.AlreadyExists,
			"vm %q already exists; pass --name to restore alongside it", targetName)
	}
	if s.virt.DomainExists(targetName) {
		return "", status.Errorf(codes.AlreadyExists,
			"domain %q already defined; pass --name to restore alongside it", targetName)
	}

	renamed := targetName != originalName
	spec.Name = targetName

	// Root disk → the overlay. (Multi-disk auto-restore is out of scope:
	// only the root disk is NBD-backed; data disks would need their own
	// streams.)
	diskCfg := []lv.DiskConfig{{Name: "root", Path: overlayPath, Bus: "virtio"}}
	diskRecords := []corrosion.DiskRecord{{
		VMName: targetName, DiskName: "root", HostName: s.hostName,
		Path: overlayPath, SizeBytes: manifest.TotalSize, StorageType: "local",
		TargetDev: "vda",
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
				return "", status.Errorf(codes.FailedPrecondition,
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
	domXML, err := lv.GenerateDomainXML(vmCfg)
	if err != nil {
		return "", status.Errorf(codes.Internal, "generate domain XML: %v", err)
	}

	_ = send(&pb.RestoreLiveProgress{
		Phase: pb.RestoreLiveProgress_DEFINING, VmName: targetName,
		TargetPath: overlayPath, Status: "defining domain against overlay",
	})
	if err := s.virt.DefineDomain(domXML); err != nil {
		return "", status.Errorf(codes.Internal, "define domain: %v", err)
	}
	if err := s.virt.StartDomain(targetName); err != nil {
		// Roll back the definition but KEEP the overlay + NBD so the
		// operator can retry define/start against the still-valid source.
		_ = s.virt.UndefineDomain(targetName, false)
		return "", status.Errorf(codes.Internal, "start domain: %v", err)
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
		slog.Error("live-restore: failed to write VM to corrosion", "vm", targetName, "error", err)
	}
	s.recordVMEvent(ctx, targetName, "vm.created", "ok", "host="+s.hostName+" (live-restore)")
	return targetName, nil
}

// driveBlockpull localizes the restored disk by flattening the NBD backing
// chain into the overlay, then returns once the job completes so the
// caller's deferred NBD teardown can run. On a failed/partial pull it
// returns ok=false so the caller keeps the stream open instead of
// bricking a half-pulled disk.
func (s *Server) driveBlockpull(ctx context.Context, vmName string, send func(*pb.RestoreLiveProgress) error) (ok bool) {
	_ = send(&pb.RestoreLiveProgress{
		Phase: pb.RestoreLiveProgress_BLOCKPULL, VmName: vmName,
		Status: "localizing disk via blockpull",
	})
	if err := s.virt.BlockPull(vmName, "vda"); err != nil {
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
			st, err := s.virt.BlockJobStatus(vmName, "vda")
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
