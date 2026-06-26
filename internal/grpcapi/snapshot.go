package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// snapshotDepthWarning is the number of snapshots at which we warn about deep chains.
const snapshotDepthWarning = 30

func (s *Server) CreateSnapshot(ctx context.Context, req *pb.CreateSnapshotRequest) (*pb.Snapshot, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "snapshot.create", "operator"); err != nil {
		return nil, err
	}
	// Snapshot names now feed a filesystem sidecar path (firmware state), so
	// validate for ALL snapshots (not just memory) to prevent a `../` escape (G1).
	if !validRestoreName(req.Name) {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid snapshot name %q: allowed [A-Za-z0-9_.-], not '.' or '..'", req.Name)
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.CreateSnapshot(ctx, req)
	}

	// Memory snapshots (#3) suspend the guest — refuse during transient/unsafe
	// states, and require a path-safe name (a vmstate file is written under
	// dataDir/vmstate). A memory snapshot of a stopped VM is meaningless, so
	// fall back to disk-only there rather than erroring.
	withMemory := req.WithMemory
	if withMemory {
		switch vm.State {
		case "migrating", "creating", "starting", "backing-up":
			return nil, status.Errorf(codes.FailedPrecondition,
				"VM %q is in state %q — cannot take a memory snapshot now", req.VmName, vm.State)
		}
		if !validRestoreName(req.Name) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid snapshot name %q", req.Name)
		}
		if st, _ := s.virt.DomainState(req.VmName); st != "running" {
			withMemory = false
			slog.Info("memory snapshot requested but VM not running — taking disk-only",
				"vm", req.VmName, "state", st)
		}
	}

	// Check snapshot chain depth and warn if deep (#45).
	existingSnaps, _ := corrosion.ListSnapshots(ctx, s.db, req.VmName)
	depth := len(existingSnaps) + 1
	if depth >= snapshotDepthWarning {
		slog.Warn("snapshot chain depth is deep — disk I/O performance may degrade",
			"vm", req.VmName, "depth", depth,
			"hint", "consolidate with 'lv snapshot flatten "+req.VmName+"'")
	}

	// Firmware-state capture (G1): a Secure-Boot/vTPM VM's NVRAM + swtpm must be
	// captured at the SAME instant as disk+RAM, or a revert pairs reverted disks
	// with current firmware (BitLocker desync). A running disk-only snapshot has no
	// consistent capture point — require --with-memory there.
	fwSpec := parseFirmwareSpec(vm.Spec)
	fwUUID := fwSpec.UUID
	hasFW := fwSpec.SecureBoot || fwSpec.Tpm
	if hasFW {
		// A running disk-only snapshot has no consistent firmware-capture point.
		if !withMemory {
			if st, _ := s.virt.DomainState(req.VmName); st == "running" {
				return nil, status.Errorf(codes.FailedPrecondition,
					"a running Secure Boot / vTPM VM must be snapshotted with --with-memory (its firmware state can't be captured from a live disk-only snapshot)")
			}
		}
		// Preflight: the firmware state must be present locally to capture it —
		// fail BEFORE touching libvirt so we never create an overlay we can't back.
		// NVRAM only exists for UEFI (a BIOS+vTPM VM has swtpm but no NVRAM).
		if (fwSpec.hasNvram() && !lv.HasNvram(s.dataDir, req.VmName)) || (fwSpec.Tpm && !lv.HasTPMState(fwUUID)) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"firmware state for %q is not present on this host; cannot snapshot it consistently", req.VmName)
		}
	}
	captureFW := func() error {
		if !hasFW {
			return nil
		}
		bundle, err := lv.SafeSnapshotFirmwareBundlePath(s.dataDir, req.VmName, req.Name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(bundle), 0o755); err != nil {
			return err
		}
		f, err := os.Create(bundle)
		if err != nil {
			return err
		}
		has, werr := lv.WriteFirmwareBundle(s.dataDir, req.VmName, fwUUID, f)
		f.Close()
		if werr != nil {
			return werr
		}
		if !has {
			return fmt.Errorf("no firmware state captured for %q", req.VmName)
		}
		return nil
	}

	snapType := "disk"
	var sizeBytes, vmstateBytes int64
	var vmstatePath string
	snapCreated := false
	if withMemory {
		vmstatePath, err = lv.SafeVMStatePath(s.dataDir, req.VmName, req.Name)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if mkErr := os.MkdirAll(filepath.Dir(vmstatePath), 0o755); mkErr != nil {
			return nil, status.Errorf(codes.Internal, "prepare vmstate dir: %v", mkErr)
		}
		sizeBytes, vmstateBytes, err = s.virt.CreateLiveSnapshot(req.VmName, req.Name, vmstatePath, captureFW)
		snapType = "memory"
		// CreateLiveSnapshot cuts the disk overlay over before capturing/saving, so
		// on failure the overlay may already exist — treat as created for cleanup.
		snapCreated = true
	} else {
		if sizeBytes, err = s.virt.CreateSnapshot(req.VmName, req.Name); err == nil {
			snapCreated = true
			// VM is stopped here (running+firmware was refused above), so capturing
			// after the disk snapshot is race-free.
			err = captureFW()
		}
	}
	if err != nil {
		// The disk overlay may already have cut over (a live snapshot always cuts
		// the overlay before the RAM save; a disk snapshot cuts on success) while
		// capture/RAM-save failed. A bare metadata delete would strand the VM on an
		// untracked overlay, so reconcile the active disk path and record the
		// snapshot ERRORED — visible + deletable, and DeleteSnapshot flattens an
		// error record even when it's memory-typed. Drop any partial firmware
		// sidecar (G1).
		if snapCreated {
			s.reconcileDiskPaths(ctx, req.VmName)
			if hasFW {
				_ = os.Remove(lv.SnapshotFirmwareBundlePath(s.dataDir, req.VmName, req.Name))
			}
			_ = corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
				VMName: req.VmName, HostName: s.hostName, Name: req.Name, State: "error",
				Type: snapType, VMStatePath: vmstatePath, SizeBytes: sizeBytes,
			})
		}
		return nil, status.Errorf(codes.Internal, "create snapshot: %v", err)
	}

	rec := corrosion.SnapshotRecord{
		VMName:       req.VmName,
		HostName:     s.hostName,
		Name:         req.Name,
		State:        "ok",
		SizeBytes:    sizeBytes,
		Type:         snapType,
		VMStatePath:  vmstatePath,
		VMStateBytes: vmstateBytes,
	}
	if err := corrosion.InsertSnapshot(ctx, s.db, rec); err != nil {
		slog.Error("failed to record snapshot in state store", "vm", req.VmName, "snap", req.Name, "error", err)
		return nil, status.Errorf(codes.Internal, "record snapshot: %v", err)
	}

	// The external snapshot cut the domain over to an overlay (<disk>.<name>);
	// sync the recorded disk path so backup/migration/restart use the live disk.
	s.reconcileDiskPaths(ctx, req.VmName)

	slog.Info("snapshot created", "vm", req.VmName, "snapshot", req.Name, "type", snapType,
		"chain_depth", depth, "size_bytes", sizeBytes, "vmstate_bytes", vmstateBytes)
	s.recordVMEvent(ctx, req.VmName, "snapshot.created", "ok", req.Name+" ("+snapType+")")
	return &pb.Snapshot{
		VmName:       req.VmName,
		HostName:     s.hostName,
		Name:         req.Name,
		State:        "ok",
		SizeBytes:    sizeBytes,
		Type:         snapType,
		VmstateBytes: vmstateBytes,
	}, nil
}

func (s *Server) ListSnapshots(ctx context.Context, req *pb.ListSnapshotsRequest) (*pb.ListSnapshotsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}

	// Forward to the VM's host so the result is immediately consistent
	// (snapshot records may not have replicated to this node yet).
	vm, _ := corrosion.GetVM(ctx, s.db, req.VmName)
	if vm != nil && vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err == nil {
			defer conn.Close()
			return client.ListSnapshots(ctx, req)
		}
		// Fall through to local view if peer unreachable.
	}

	snaps, err := corrosion.ListSnapshots(ctx, s.db, req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list snapshots: %v", err)
	}

	resp := &pb.ListSnapshotsResponse{}
	for _, sn := range snaps {
		resp.Snapshots = append(resp.Snapshots, &pb.Snapshot{
			Id:           sn.ID,
			VmName:       sn.VMName,
			HostName:     sn.HostName,
			Name:         sn.Name,
			State:        sn.State,
			SizeBytes:    sn.SizeBytes,
			Type:         sn.Type,
			VmstateBytes: sn.VMStateBytes,
		})
	}
	return resp, nil
}

func (s *Server) RestoreSnapshot(ctx context.Context, req *pb.RestoreSnapshotRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "snapshot.restore", "operator"); err != nil {
		return nil, err
	}
	if !validRestoreName(req.SnapshotName) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid snapshot name %q", req.SnapshotName)
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.RestoreSnapshot(ctx, req)
	}

	// Guard: block restore if VM is migrating or in an unsafe transient state.
	switch vm.State {
	case "migrating", "creating", "starting":
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q is in state %q — cannot restore snapshot now", req.VmName, vm.State)
	}

	// Branch on snapshot type: a memory snapshot restores RAM too, and its
	// vmstate file is host-local — refuse if the VM has since moved hosts.
	snap, _ := corrosion.GetSnapshot(ctx, s.db, req.VmName, req.SnapshotName)
	// An errored snapshot is a failed/partial capture (no consistent disk+RAM+
	// firmware point) — refuse to restore it rather than booting an inconsistent
	// state; the operator should delete it (which flattens its overlay).
	if snap != nil && snap.State == "error" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"snapshot %q is in error state (a failed capture) and cannot be restored — delete it instead", req.SnapshotName)
	}
	// Restore firmware state (NVRAM + swtpm) from the snapshot sidecar before the
	// domain is redefined, so reverted disks/RAM + firmware are a consistent set
	// (G1). No-op when the snapshot captured none (non-firmware VM).
	fwUUID := parseFirmwareSpec(vm.Spec).UUID
	hasFW := usesFirmwareState(vm.Spec)
	restoreFW := func() error {
		bundle := lv.SnapshotFirmwareBundlePath(s.dataDir, req.VmName, req.SnapshotName)
		f, err := os.Open(bundle)
		if os.IsNotExist(err) {
			if hasFW {
				// A Secure-Boot/vTPM VM whose snapshot captured no firmware (taken
				// before vTPM support, or the sidecar was lost) cannot be reverted
				// safely — reverting disk/RAM while keeping current/missing TPM
				// would desync BitLocker. Refuse rather than silently corrupt.
				return status.Errorf(codes.FailedPrecondition,
					"snapshot %q has no captured firmware state; cannot safely revert Secure Boot / vTPM VM %q", req.SnapshotName, req.VmName)
			}
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		return lv.ReadFirmwareBundle(f, s.dataDir, req.VmName, fwUUID)
	}

	if snap != nil && snap.Type == "memory" && snap.VMStatePath != "" {
		if snap.HostName != s.hostName {
			return nil, status.Errorf(codes.FailedPrecondition,
				"memory snapshot %q was taken on host %q; the VM is now on %q and its RAM image is not available here — use a disk-only snapshot or take a new one",
				req.SnapshotName, snap.HostName, s.hostName)
		}
		if err := s.virt.RevertToLiveSnapshot(req.VmName, req.SnapshotName, snap.VMStatePath, restoreFW); err != nil {
			return nil, status.Errorf(codes.Internal, "revert to memory snapshot: %v", err)
		}
	} else if err := s.virt.RevertToSnapshot(req.VmName, req.SnapshotName, restoreFW); err != nil {
		return nil, status.Errorf(codes.Internal, "revert to snapshot: %v", err)
	}

	// Revert may leave the domain on an overlay (memory revert resets it in
	// place; disk-only revert restores the original) — reconcile either way.
	s.reconcileDiskPaths(ctx, req.VmName)

	// After revert, VM may be running or paused depending on snapshot type.
	corrosion.UpdateVMState(ctx, s.db, req.VmName, "running", "restored from "+req.SnapshotName)
	slog.Info("snapshot restored", "vm", req.VmName, "snapshot", req.SnapshotName)
	s.recordVMEvent(ctx, req.VmName, "snapshot.restored", "ok", req.SnapshotName)
	return s.vmToProto(ctx, req.VmName)
}

func (s *Server) DeleteSnapshot(ctx context.Context, req *pb.DeleteSnapshotRequest) (*emptypb.Empty, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "snapshot.delete", "operator"); err != nil {
		return nil, err
	}
	if !validRestoreName(req.SnapshotName) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid snapshot name %q", req.SnapshotName)
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.DeleteSnapshot(ctx, req)
	}

	// Fetch the record first so we know whether to clean up a vmstate file.
	snap, _ := corrosion.GetSnapshot(ctx, s.db, req.VmName, req.SnapshotName)

	// Flatten when removing the LAST snapshot of a running, disk-type VM: a plain
	// metadata-only delete leaves the VM on its overlay (the backing chain
	// persists), which both blocks migration and lets the chain grow on every
	// snapshot+delete cycle. FlattenSnapshot block-commits the overlay down into
	// its base so the disk collapses to a single standalone file. Memory
	// snapshots (own revert/RAM mechanism) and multi-snapshot chains keep the
	// metadata-only delete; a flatten failure falls back to it too, so the
	// snapshot is always removable.
	existing, _ := corrosion.ListSnapshots(ctx, s.db, req.VmName)
	// An errored snapshot (e.g. a failed --with-memory capture that still cut the
	// disk overlay over) has no usable RAM image — its only residue is the disk
	// overlay, so it must be flattened on delete even though Type=="memory";
	// otherwise the VM is left stranded on an untracked overlay chain (G1).
	flattenable := snap == nil || snap.Type != "memory" || snap.State == "error"
	flatten := vm.State == "running" && len(existing) <= 1 && flattenable

	var delErr error
	if flatten {
		if delErr = s.virt.FlattenSnapshot(req.VmName, req.SnapshotName); delErr != nil {
			slog.Warn("delete snapshot: flatten failed, falling back to metadata-only",
				"vm", req.VmName, "snap", req.SnapshotName, "error", delErr)
			delErr = s.virt.DeleteSnapshot(req.VmName, req.SnapshotName)
		}
	} else {
		delErr = s.virt.DeleteSnapshot(req.VmName, req.SnapshotName)
	}
	// A revert consumes the libvirt snapshot metadata, so it may already be gone
	// here — that must NOT block cleanup of the corrosion record + vmstate file
	// (otherwise they leak). Treat a missing libvirt snapshot as already-deleted.
	if delErr != nil {
		if strings.Contains(delErr.Error(), "not found") || strings.Contains(delErr.Error(), "no domain snapshot") {
			slog.Info("delete snapshot: libvirt metadata already gone — cleaning up record", "vm", req.VmName, "snap", req.SnapshotName)
		} else {
			return nil, status.Errorf(codes.Internal, "delete snapshot: %v", delErr)
		}
	}

	if err := corrosion.DeleteSnapshot(ctx, s.db, req.VmName, req.SnapshotName); err != nil {
		slog.Warn("failed to tombstone snapshot", "vm", req.VmName, "snap", req.SnapshotName, "error", err)
	}

	// Remove the saved RAM image for a memory snapshot (best-effort).
	if snap != nil && snap.VMStatePath != "" {
		if rmErr := os.Remove(snap.VMStatePath); rmErr != nil && !os.IsNotExist(rmErr) {
			slog.Warn("snapshot delete: remove vmstate file", "path", snap.VMStatePath, "error", rmErr)
		}
	}
	// Remove the firmware-state sidecar (G1), if any (best-effort).
	if rmErr := os.Remove(lv.SnapshotFirmwareBundlePath(s.dataDir, req.VmName, req.SnapshotName)); rmErr != nil && !os.IsNotExist(rmErr) {
		slog.Warn("snapshot delete: remove firmware sidecar", "vm", req.VmName, "snap", req.SnapshotName, "error", rmErr)
	}

	// Deleting an external snapshot makes libvirt consolidate the chain, often
	// leaving the active disk named after the (now-gone) snapshot — reconcile
	// the recorded path to whatever the live domain ended up on.
	s.reconcileDiskPaths(ctx, req.VmName)

	slog.Info("snapshot deleted", "vm", req.VmName, "snapshot", req.SnapshotName)
	s.recordVMEvent(ctx, req.VmName, "snapshot.deleted", "ok", req.SnapshotName)
	return &emptypb.Empty{}, nil
}
