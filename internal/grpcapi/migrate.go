package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
	"github.com/litevirt/litevirt/internal/hooks"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/vfio"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// authorizeMigrationHelper is the REAL authorization for the target-side
// migration helper RPCs (EnsureCloudInit/EnsureDisks/EnsureFirmwareState/
// CleanupMigrationArtifacts). requirePermPrecheck is NOT an auth grant (any
// binding-holder passes it), so these helpers — which create/remove host files
// and can define a domain — must additionally require vm.migrate on the VM
// being migrated. The VM record is replicated cluster-wide during migration, so
// it resolves on the target even though the source still owns it.
func (s *Server) authorizeMigrationHelper(ctx context.Context, vmName string) (*corrosion.VMRecord, error) {
	if err := safename.ValidateVMName(vmName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", vmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.migrate", "operator"); err != nil {
		return nil, err
	}
	return vm, nil
}

// withinDiskArtifactRoot reports whether p is inside a directory where VM disk
// artifacts legitimately live — the default disks dir or a file-backed storage
// pool's directory. The migration helpers bound their create/remove to these
// roots so they can never touch e.g. {dataDir}/state.db just because it's under
// the data dir.
func (s *Server) withinDiskArtifactRoot(p string) bool {
	if withinDir(filepath.Join(s.dataDir, "disks"), p) {
		return true
	}
	s.storagePoolsMu.RLock()
	pools := make([]StoragePoolRef, 0, len(s.storagePools))
	for _, pr := range s.storagePools {
		pools = append(pools, pr)
	}
	s.storagePoolsMu.RUnlock()
	for _, pr := range pools {
		if !isFileBasedDriver(pr.Driver) {
			continue
		}
		if dir, derr := fileBasedPoolDir(s.dataDir, pr); derr == nil && withinDir(dir, p) {
			return true
		}
	}
	return false
}

// MigrateVM performs a live migration of a VM to a target host.
// It streams MigrateProgress messages back to the caller.
func (s *Server) MigrateVM(req *pb.MigrateVMRequest, stream grpc.ServerStreamingServer[pb.MigrateProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}

	// Per-VM lock prevents concurrent snapshot/migrate/delete (#27).
	unlock := s.lockVM(req.VmName)
	defer unlock()

	send := func(phase pb.MigratePhase, memPct, diskPct float32) error {
		return stream.Send(&pb.MigrateProgress{
			Phase:     phase,
			MemoryPct: memPct,
			DiskPct:   diskPct,
		})
	}

	// Validate
	if err := send(pb.MigratePhase_MIGRATE_VALIDATING, 0, 0); err != nil {
		return err
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.migrate", "operator"); err != nil {
		s.audit(ctx, "vm.migrate", req.VmName, "permission denied: → "+req.TargetHost, "denied")
		return err
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		remote, err := client.MigrateVM(ctx, req)
		if err != nil {
			return err
		}
		for {
			msg, err := remote.Recv()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
	// Secure Boot / vTPM firmware-state travel (G1). A firmware VM's NVRAM + swtpm
	// are host-local and bind BitLocker, so they need a CONSISTENT capture:
	//   - LIVE is refused: libvirt's native swtpm/NVRAM carry is not yet validated
	//     on this build, and we must not wipe the source copy on an unverified
	//     carry (a fresh-TPM target would brick BitLocker). Use cold migration.
	//   - COLD requires the VM STOPPED: its firmware can't be captured at a single
	//     instant while the guest keeps mutating TPM state, so we copy it quiescent.
	fwSpec := parseFirmwareSpec(vm.Spec)
	fwVM := fwSpec.SecureBoot || fwSpec.Tpm
	if fwVM {
		if req.Strategy != pb.MigrateStrategy_MIGRATE_COLD {
			return status.Errorf(codes.FailedPrecondition,
				"Secure Boot / vTPM VM %q must be migrated cold (--strategy=cold); live firmware carry is not yet a validated path", req.VmName)
		}
		if vm.State != "stopped" {
			return status.Errorf(codes.FailedPrecondition,
				"stop Secure Boot / vTPM VM %q before migrating it — its firmware state can't be captured consistently while running", req.VmName)
		}
	} else if vm.State != "running" {
		return status.Errorf(codes.FailedPrecondition, "VM %q must be running to migrate (state: %s)", req.VmName, vm.State)
	}
	// Resolve target host
	targetHost, err := corrosion.GetHost(ctx, s.db, req.TargetHost)
	if err != nil || targetHost == nil {
		return status.Errorf(codes.NotFound, "target host %q not found", req.TargetHost)
	}
	if targetHost.State != "active" {
		return status.Errorf(codes.FailedPrecondition, "target host %q is not active", req.TargetHost)
	}

	// Gate the explicit target on the matching host capability (mirrors what
	// placement does for auto placement) — a firmware VM that lands on a
	// non-capable host can't define.
	if fwVM {
		if fwSpec.Tpm && targetHost.Labels[corrosion.LabelTPMCapable] != "true" {
			return status.Errorf(codes.FailedPrecondition,
				"target host %q is not vTPM-capable (no swtpm); cannot migrate vTPM VM %q there", req.TargetHost, req.VmName)
		}
		if fwSpec.SecureBoot && targetHost.Labels[corrosion.LabelSecureBootCapable] != "true" {
			return status.Errorf(codes.FailedPrecondition,
				"target host %q is not Secure-Boot-capable (no secboot OVMF); cannot migrate VM %q there", req.TargetHost, req.VmName)
		}
	}

	// Snapshot + local-disk preconditions. A VM running on a snapshot overlay
	// keeps its data in a qcow2 whose backing (base) file is NOT part of a
	// storage copy, so migrating its local storage leaves the backing chain
	// behind and qemu on the target cannot open the disk — the migration fails
	// mid-copy. Block it up-front with a clear, actionable error instead of that
	// confusing late failure. Shared storage (nfs/ceph/iscsi/...) is unaffected
	// because the whole chain stays in place and reachable from the target.
	disks, err := corrosion.GetVMDisks(ctx, s.db, req.VmName)
	if err != nil {
		return status.Errorf(codes.Internal, "query VM disks: %v", err)
	}
	hasLocal := false
	for _, d := range disks {
		// Both local and dir keep the disk as a host-local file (same path = two
		// distinct files on two hosts) — match the source-cleanup predicate so a
		// dir-pool VM isn't mistaken for shared storage and migrated without its
		// disk (G1 #3 / pre-existing for dir pools).
		if isHostLocalDiskDriver(d.StorageType) {
			hasLocal = true
			break
		}
	}
	snaps, _ := corrosion.ListSnapshots(ctx, s.db, req.VmName)
	if hasLocal && len(snaps) > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q has %d snapshot(s) on local storage — a snapshotted VM cannot be migrated "+
				"(its disk overlay's backing chain would be left behind). Remove them first: "+
				"`lv snapshot rm %s <name>` for each, then migrate.",
			req.VmName, len(snaps), req.VmName)
	}

	// Local disks require --with-storage for live migration.
	withStorage := req.WithStorage
	if req.Strategy != pb.MigrateStrategy_MIGRATE_COLD && hasLocal && !withStorage {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q has a local disk — use --with-storage for live migration or --strategy=cold", req.VmName)
	}

	// NUMA topology pre-flight: warn if source and target have different NUMA
	// layouts when the VM has CPU pinning configured (#55).
	if vm.Spec != "" {
		var specCheck struct {
			Resources *struct {
				CpuPinning []int32 `json:"cpu_pinning"`
			} `json:"resources"`
		}
		if json.Unmarshal([]byte(vm.Spec), &specCheck) == nil &&
			specCheck.Resources != nil && len(specCheck.Resources.CpuPinning) > 0 {
			// Log a warning — the target host may have different NUMA topology.
			slog.Warn("migration pre-flight: VM has CPU pinning — verify NUMA topology on target host",
				"vm", vm.Name, "target", req.TargetHost,
				"pinning", specCheck.Resources.CpuPinning)
			if err := send(pb.MigratePhase_MIGRATE_VALIDATING, 0, 0); err != nil {
				return err
			}
		}
	}

	// PCI passthrough guard: classify assigned devices as VFs (hot-unplug OK) vs PFs (block live).
	assignedDevices, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	var detachedVFs []corrosion.PCIDeviceRecord
	for _, d := range assignedDevices {
		if d.VMName != req.VmName {
			continue
		}
		if vfio.IsVF(d.Address) {
			// SR-IOV VFs can be hot-unplugged before migration.
			detachedVFs = append(detachedVFs, d)
		} else if req.Strategy == pb.MigrateStrategy_MIGRATE_LIVE {
			return status.Errorf(codes.FailedPrecondition,
				"VM %q has PCI passthrough device %s (%s) — live migration is not possible; use --strategy=cold",
				req.VmName, d.Address, d.Type)
		}
	}

	// PCI pre-flight: verify target host has compatible devices for any PCI
	// devices the VM spec requires (covers both VF reattach and cold migration).
	if vm.Spec != "" {
		var specDevices struct {
			Devices []struct {
				Type   string `json:"type"`
				Vendor string `json:"vendor"`
				Count  int32  `json:"count"`
			} `json:"devices"`
		}
		if json.Unmarshal([]byte(vm.Spec), &specDevices) == nil && len(specDevices.Devices) > 0 {
			for _, ds := range specDevices.Devices {
				if ds.Count == 0 {
					continue
				}
				targetDevices, err := corrosion.ListPCIDevices(ctx, s.db, req.TargetHost, ds.Type)
				if err != nil {
					return status.Errorf(codes.Internal, "query target host PCI devices: %v", err)
				}
				freeCount := int32(0)
				for _, d := range targetDevices {
					if d.VMName == "" {
						freeCount++
					}
				}
				if freeCount < ds.Count {
					return status.Errorf(codes.FailedPrecondition,
						"target host %q has %d free %s devices but VM %q requires %d",
						req.TargetHost, freeCount, ds.Type, req.VmName, ds.Count)
				}
			}
		}
	}

	// Pre-provision networks on target host. This ensures bridges, DHCP, NAT,
	// VXLAN tunnels, and IRB gateways exist before the VM arrives — critical for
	// both live and cold migrations (#38).
	{
		preIfaces, _ := corrosion.GetVMInterfaces(ctx, s.db, req.VmName)
		for _, iface := range preIfaces {
			if iface.NetworkName == "" {
				continue
			}
			s.provisionNetworkOnRemote(ctx, req.TargetHost, iface.NetworkName)
		}
	}

	// Ensure cloud-init ISO exists on target before migration — libvirt will
	// reject the domain if the CDROM file path doesn't exist (#62).
	s.ensureCloudInitOnTarget(ctx, req.TargetHost, vm)

	// Ensure disk files exist on target before --with-storage migration.
	// libvirt validates all file paths in the domain XML before block copy starts.
	if withStorage {
		s.ensureDisksOnTarget(ctx, req.TargetHost, vm.Name)
	}

	// Firmware-state travel (G1): a Secure-Boot/vTPM VM is migrated cold from a
	// STOPPED state WITHOUT libvirt runtime migration — that path can't carry the
	// host-local NVRAM/swtpm and would need a running (or OFFLINE-flagged) domain.
	// Instead push the quiescent firmware to the target, hand the VM over with its
	// state preserved (the target defines+starts it on demand with firmware
	// present), and clean up the source. Returns early — the runtime-migration
	// machinery below is for running VMs only.
	if fwVM {
		return s.coldMigrateFirmwareVM(ctx, vm, targetHost, fwSpec, send)
	}

	// Hot-detach SR-IOV VFs before migration.
	for _, vf := range detachedVFs {
		if err := s.virt.DetachHostdev(req.VmName, vf.Address); err != nil {
			return status.Errorf(codes.Internal, "detach VF %s before migration: %v", vf.Address, err)
		}
		if err := vfio.Unbind(vf.Address, ""); err != nil {
			slog.Warn("VFIO unbind failed during migration", "address", vf.Address, "error", err)
		}
		corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, vf.Address)
		slog.Info("VF detached for migration", "vm", req.VmName, "address", vf.Address)
	}

	// pre_migrate hook
	hspec := vmHooks(vm)
	pbVM := &pb.VM{Name: vm.Name, HostName: vm.HostName, State: pb.VMState_VM_RUNNING}
	hooks.Run(ctx, hooks.PreMigrate, pbVM, hspec)

	// Preparing
	if err := send(pb.MigratePhase_MIGRATE_PREPARING, 0, 0); err != nil {
		return err
	}

	// Default (zero value) and MIGRATE_LIVE both mean live migration.
	live := req.Strategy != pb.MigrateStrategy_MIGRATE_COLD
	strategyLabel := "live"
	if !live {
		strategyLabel = "cold"
	}

	// Read migration policy from stored VM spec for tuning parameters.
	// Keep it as a pointer (nil = no policy) and use the nil-safe generated
	// getters — copying the proto message by value would drag its embedded
	// mutex/MessageState along (go vet: "copies lock value").
	var migratePolicy *pb.MigrationPolicy
	if vm.Spec != "" {
		var storedSpec pb.VMSpec
		if json.Unmarshal([]byte(vm.Spec), &storedSpec) == nil {
			migratePolicy = storedSpec.Migrate
		}
	}

	bandwidthMiB := int(migratePolicy.GetBandwidthMibSec())
	autoConverge := migratePolicy.GetAutoConverge()
	// Default auto-converge to true for live migrations when no policy is set,
	// preserving previous behaviour.
	if migratePolicy == nil || migratePolicy.GetBandwidthMibSec() == 0 && !migratePolicy.GetAutoConverge() && migratePolicy.GetStrategy() == 0 {
		autoConverge = live
	}
	var maxDowntimeMS int64
	if migratePolicy.GetMaxDowntime() != "" {
		if d, err := time.ParseDuration(migratePolicy.GetMaxDowntime()); err == nil {
			maxDowntimeMS = d.Milliseconds()
		}
	}

	// Build destination URI: use TLS transport with our existing PKI certs.
	// Combined with MigrateTunnelled, all data flows over the single libvirt
	// TLS port (16514) — no SSH or extra ports required.
	dconnuri := fmt.Sprintf("qemu+tls://%s/system", targetHost.Address)

	// Mark as migrating in state store
	corrosion.UpdateVMState(ctx, s.db, vm.Name, "migrating", fmt.Sprintf("→ %s", req.TargetHost))
	migrationStart := time.Now()

	if err := send(pb.MigratePhase_MIGRATE_COPYING, 0, 0); err != nil {
		return err
	}

	if s.virt == nil {
		return status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}

	// Apply migration timeout if configured.
	migrateCtx := ctx
	if migratePolicy.GetTimeoutSec() > 0 {
		var cancel context.CancelFunc
		migrateCtx, cancel = context.WithTimeout(ctx, time.Duration(migratePolicy.GetTimeoutSec())*time.Second)
		defer cancel()
	}

	// Build the list of writable disk targets to migrate (exclude CDROMs).
	var diskTargets []string
	if withStorage {
		disks, _ := corrosion.GetVMDisks(ctx, s.db, vm.Name)
		for _, d := range disks {
			if d.TargetDev != "" {
				diskTargets = append(diskTargets, d.TargetDev)
			}
		}
	}

	// Run migration in background; poll progress.
	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		done <- result{s.virt.MigrateToTarget(vm.Name, dconnuri, lv.MigrateParams{
			Live:          live,
			WithStorage:   withStorage,
			BandwidthMiB:  bandwidthMiB,
			AutoConverge:  autoConverge,
			MaxDowntimeMS: maxDowntimeMS,
			TargetAddress: targetHost.Address,
			DiskTargets:   diskTargets,
		})}
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

poll:
	for {
		select {
		case <-migrateCtx.Done():
			return migrateCtx.Err()
		case res := <-done:
			if res.err != nil {
				// Migration failed — VM is still on the source host.
				// Check if the domain is still alive; if so, restore to "running"
				// instead of leaving it in "error" (#21).
				if state, sErr := s.virt.DomainState(vm.Name); sErr == nil && state == "running" {
					corrosion.UpdateVMState(ctx, s.db, vm.Name, "running",
						fmt.Sprintf("migration to %s failed: %v", req.TargetHost, res.err))
					slog.Warn("migration failed but VM still running on source",
						"vm", vm.Name, "target", req.TargetHost, "error", res.err)
				} else {
					corrosion.UpdateVMState(ctx, s.db, vm.Name, "error", res.err.Error())
				}
				// Remove the disk stubs + cloud-init ISO we pre-created on the
				// target — the VM never got defined there, so they're orphaned
				// and would otherwise leak space and shadow a retry. Detached
				// context: the request ctx may itself be the cause of failure.
				var stubPaths []string
				if withStorage {
					if ds, derr := corrosion.GetVMDisks(ctx, s.db, vm.Name); derr == nil {
						for _, d := range ds {
							if d.Path != "" {
								stubPaths = append(stubPaths, d.Path)
							}
						}
					}
				}
				// (Firmware VMs never reach this runtime-migration path — they take
				// the stopped cold-move in coldMigrateFirmwareVM — so no firmware
				// cleanup is needed here.)
				cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 15*time.Second)
				s.cleanupMigrationArtifactsOnTarget(cleanupCtx, req.TargetHost, vm.Name, stubPaths, "")
				cancelCleanup()

				send(pb.MigratePhase_MIGRATE_FAILED, 0, 0) //nolint:errcheck
				s.recordMigrationMetrics(strategyLabel, "failure", time.Since(migrationStart), 0, 0)
				return status.Errorf(codes.Internal, "migration failed: %v", res.err)
			}
			break poll
		case <-ticker.C:
			memPct, diskPct := s.virt.DomainJobProgress(vm.Name)
			if memPct >= 0 {
				send(pb.MigratePhase_MIGRATE_CONVERGING, memPct, diskPct) //nolint:errcheck
			}
		}
	}

	// Cutover / completing
	cutoverStart := time.Now()
	send(pb.MigratePhase_MIGRATE_CUTOVER, 100, 0)    //nolint:errcheck
	send(pb.MigratePhase_MIGRATE_COMPLETING, 100, 0) //nolint:errcheck

	downtimeMs := float64(time.Since(cutoverStart).Milliseconds())
	s.recordMigrationMetrics(strategyLabel, "success", time.Since(migrationStart), downtimeMs, 0)

	// Update state: VM now lives on target host
	corrosion.UpdateVMHost(ctx, s.db, vm.Name, req.TargetHost, "running")
	slog.Info("migration complete", "vm", vm.Name, "from", s.hostName, "to", req.TargetHost)
	s.recordVMEvent(ctx, vm.Name, "vm.migrated", "ok", "from="+s.hostName+" to="+req.TargetHost)
	s.audit(ctx, "vm.migrate", vm.Name, "from="+s.hostName+" to="+req.TargetHost, "ok")

	// Update disk path records to reflect the target host.
	// For cold migration with --with-storage, libvirt copies files to the same
	// relative path on the target. Update host_name so queries work correctly.
	if disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name); err == nil {
		for _, d := range disks {
			corrosion.UpdateDiskHostAndPath(ctx, s.db, vm.Name, d.DiskName, req.TargetHost, d.Path)
			// A --with-storage migration COPIES the disk to the target's own
			// filesystem, leaving the source's local copy orphaned. Remove it
			// (we run on the source host). Host-local drivers ONLY: for shared
			// pools (nfs/ceph/iscsi) the source path is the same file the target
			// now uses, so deleting it would destroy the live disk.
			if withStorage && isHostLocalDiskDriver(d.StorageType) && d.Path != "" {
				// Never delete a source disk that still backs a linked clone or
				// is referenced by another VM — doing so corrupts the clone's
				// backing chain / destroys a live disk (bug-sweep #1). Mirrors
				// the guard MoveVolume/DeleteVM already enforce.
				if referenced, reason, _ := s.pathStillReferenced(ctx, d.Path, vm.Name, d.DiskName); referenced {
					slog.Warn("post-migration: source disk still referenced — NOT deleting",
						"vm", vm.Name, "path", d.Path, "referenced_by", reason)
				} else if rmErr := os.Remove(d.Path); rmErr != nil && !os.IsNotExist(rmErr) {
					slog.Warn("post-migration: could not remove orphaned source disk",
						"vm", vm.Name, "path", d.Path, "error", rmErr)
				} else if rmErr == nil {
					slog.Info("post-migration: removed orphaned source disk",
						"vm", vm.Name, "path", d.Path)
				}
			}
		}
	}

	// (Firmware-state cleanup is handled in coldMigrateFirmwareVM, which firmware
	// VMs take instead of this runtime-migration path — see the early return above.)

	// Re-attach equivalent VFs on the target host for any VFs detached pre-migration.
	if len(detachedVFs) > 0 {
		s.reattachVFsOnTarget(ctx, req.TargetHost, targetHost.Address, targetHost.GRPCPort, vm.Name, detachedVFs)
	}

	// Send gratuitous ARP for each VM interface to update switch MAC tables.
	ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)
	for _, iface := range ifaces {
		if iface.IP != "" {
			go network.SendGARPBestEffort(iface.NetworkName, iface.IP)
		}
	}

	// Update DNS records so VM names resolve correctly after migration.
	if s.dnsDomain != "" {
		for _, iface := range ifaces {
			if iface.IP != "" {
				dnsName := dns.VMRecordName(vm.Name, vm.StackName, s.dnsDomain)
				if err := dns.UpsertRecord(ctx, s.db, dnsName, iface.IP); err != nil {
					slog.Warn("post-migration DNS update failed", "vm", vm.Name, "name", dnsName, "error", err)
				}
				break // one A record per VM
			}
		}
	}

	// Refresh LB backends so traffic routes to the new host.
	go s.refreshLBForStack(context.Background(), vm.StackName)

	// Update FDB entries: VM MACs now live on target host's VTEP.
	for _, iface := range ifaces {
		s.updateFDBForMigration(ctx, iface, s.hostName, req.TargetHost)
	}

	// post_migrate hook (notify with new host)
	pbVM.HostName = req.TargetHost
	pbVM.State = pb.VMState_VM_RUNNING
	hooks.Run(ctx, hooks.PostMigrate, pbVM, hspec)

	// Dial target host to re-establish gRPC so it can load TLS creds.
	go s.notifyTargetHostOfVM(req.TargetHost, targetHost.Address, targetHost.GRPCPort, vm.Name)

	// Clean up orphaned files on the source host (cloud-init ISO, and disk
	// files for --with-storage migrations where copies now live on target).
	go s.cleanupPostMigration(vm.Name)

	return send(pb.MigratePhase_MIGRATE_DONE, 100, 0)
}

// cleanupPostMigration removes the source host's cloud-init ISO after migration.
//
// It deliberately does NOT touch disk files: for --with-storage migrations the
// orphaned source disks are already removed, per-disk and storage-type-aware,
// at the migration site above (only for host-local local/dir drivers, at each
// disk's RECORDED path). The previous os.RemoveAll(<dataDir>/disks/<vm>) here
// assumed a per-VM subdirectory that the flat <vm>-<disk>.qcow2 naming never
// uses — at best a no-op, at worst a path-wrong removal — so it's gone.
func (s *Server) cleanupPostMigration(vmName string) {
	// Always clean up cloud-init ISO — target regenerates from stored spec if needed.
	isoPath := filepath.Join(s.dataDir, "cloudinit", vmName+".iso")
	if err := os.Remove(isoPath); err == nil {
		slog.Info("post-migration: removed cloud-init ISO", "vm", vmName, "path", isoPath)
	}
}

// MigrateVMForHealthCheck is an exported wrapper for use by the health checker.
// It calls the full MigrateVM path (with all post-migration steps) using a
// discard stream that drops progress updates. Injects admin auth context.
func (s *Server) MigrateVMForHealthCheck(ctx context.Context, vmName, targetHost string) error {
	req := &pb.MigrateVMRequest{
		VmName:     vmName,
		TargetHost: targetHost,
		Strategy:   pb.MigrateStrategy_MIGRATE_LIVE,
	}
	// Inject an admin principal so RequirePerm/RequireRole pass for this
	// internal (health-checker-driven) call. Both username and role must
	// be present — RequirePerm rejects an empty principal before reaching
	// the role fallback.
	authCtx := context.WithValue(ctx, ctxKeyRole, "admin")
	authCtx = context.WithValue(authCtx, ctxKeyUsername, "system:healthcheck")
	return s.MigrateVM(req, &discardMigrateStream{ctx: authCtx})
}

// discardMigrateStream implements grpc.ServerStreamingServer[pb.MigrateProgress]
// by discarding all progress messages. Used for internal migration calls.
type discardMigrateStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (d *discardMigrateStream) Send(*pb.MigrateProgress) error { return nil }
func (d *discardMigrateStream) Context() context.Context       { return d.ctx }

// recordMigrationMetrics records duration, downtime, and transfer metrics if available.
func (s *Server) recordMigrationMetrics(strategy, result string, duration time.Duration, downtimeMs, transferBytes float64) {
	if s.migrationMetrics == nil {
		return
	}
	s.migrationMetrics.Duration.WithLabelValues(strategy, result).Observe(duration.Seconds())
	if downtimeMs > 0 {
		s.migrationMetrics.Downtime.WithLabelValues(strategy).Observe(downtimeMs)
	}
	if transferBytes > 0 {
		s.migrationMetrics.Transfer.WithLabelValues(strategy).Observe(transferBytes)
	}
}

// reattachVFsOnTarget sends AttachDevice RPCs to the target host for each VF
// that was detached before migration. The target allocates equivalent VFs from its own pool.
func (s *Server) reattachVFsOnTarget(ctx context.Context, targetHostName, addr string, grpcPort int, vmName string, vfs []corrosion.PCIDeviceRecord) {
	conn, err := pki.PeerDial(s.pkiDir, peerTarget(addr, grpcPort))
	if err != nil {
		slog.Warn("reattach VFs: dial target", "host", targetHostName, "error", err)
		return
	}
	defer conn.Close()

	client := pb.NewLiteVirtClient(conn)
	for _, vf := range vfs {
		_, err := client.AttachDevice(ctx, &pb.AttachDeviceRequest{
			VmName: vmName,
			PciDevice: &pb.DeviceSpec{
				Type:   vf.Type,
				Vendor: vf.VendorID,
				Count:  1,
				Sriov:  true,
			},
		})
		if err != nil {
			slog.Warn("reattach VF on target failed", "vm", vmName, "type", vf.Type,
				"vendor", vf.VendorID, "target", targetHostName, "error", err)
		} else {
			slog.Info("VF reattached on target", "vm", vmName, "type", vf.Type, "target", targetHostName)
		}
	}
}

// EnsureCloudInit generates a cloud-init ISO on this host if it doesn't already exist.
// Called by the source host before migration so the target has the ISO ready.
func (s *Server) EnsureCloudInit(ctx context.Context, req *pb.EnsureCloudInitRequest) (*emptypb.Empty, error) {
	if _, err := s.authorizeMigrationHelper(ctx, req.VmName); err != nil {
		return nil, err
	}
	isoPath, err := lv.SafeCloudInitISOPath(s.dataDir, req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if _, err := os.Stat(isoPath); err == nil {
		return &emptypb.Empty{}, nil // already exists
	}

	userData := req.Userdata
	if userData == "" {
		userData = "#cloud-config\n{}\n"
	}
	if err := cloudinit.GenerateISO(cloudinit.Config{
		InstanceID:    req.VmName,
		LocalHostname: req.VmName,
		UserData:      userData,
		NetworkConfig: req.Networkconfig,
	}, isoPath); err != nil {
		return nil, status.Errorf(codes.Internal, "generate cloud-init ISO: %v", err)
	}
	slog.Info("cloud-init ISO generated for migration", "vm", req.VmName, "path", isoPath)
	return &emptypb.Empty{}, nil
}

// EnsureDisks creates empty qcow2 images at the requested paths so that
// libvirt's domain XML validation passes before block copy starts.
// Called by the source host before --with-storage migration.
func (s *Server) EnsureDisks(ctx context.Context, req *pb.EnsureDisksRequest) (*emptypb.Empty, error) {
	if _, err := s.authorizeMigrationHelper(ctx, req.VmName); err != nil {
		return nil, err
	}
	for _, stub := range req.Disks {
		// Only ever create stubs in a real disk-artifact root (the disks dir or a
		// file-backed pool dir) — never an arbitrary path under the data dir such
		// as state.db.
		if !s.withinDiskArtifactRoot(stub.Path) {
			return nil, status.Errorf(codes.InvalidArgument, "disk stub path %q is not in a disk-artifact root", stub.Path)
		}
		if _, err := os.Stat(stub.Path); err == nil {
			continue // already exists
		}
		dir := filepath.Dir(stub.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, status.Errorf(codes.Internal, "create disk dir %s: %v", dir, err)
		}
		// Create a valid qcow2 image — QEMU validates the format header
		// before block copy starts. Use a minimal size; migration overwrites it.
		sizeBytes := uint64(1024 * 1024 * 1024) // 1G default
		if stub.SizeBytes > 0 {
			sizeBytes = uint64(stub.SizeBytes)
		}
		if err := qcow2.Create(stub.Path, sizeBytes, nil); err != nil {
			return nil, status.Errorf(codes.Internal, "create stub %s: %v", stub.Path, err)
		}
		slog.Info("disk stub created for migration", "vm", req.VmName, "path", stub.Path, "size_bytes", stub.SizeBytes)
	}
	return &emptypb.Empty{}, nil
}

// EnsureFirmwareState materializes a Secure-Boot/vTPM VM's firmware-state bundle
// (NVRAM + swtpm) pushed by a cold-migration source, so libvirt can define the
// domain here with its BitLocker-binding state intact (G1). Mirrors EnsureDisks.
func (s *Server) EnsureFirmwareState(ctx context.Context, req *pb.EnsureFirmwareStateRequest) (*emptypb.Empty, error) {
	if req.VmName == "" || len(req.Bundle) == 0 {
		return nil, status.Error(codes.InvalidArgument, "vm_name and a non-empty firmware bundle are required")
	}
	if _, err := s.authorizeMigrationHelper(ctx, req.VmName); err != nil {
		return nil, err
	}
	// vm_name + uuid index into on-disk firmware paths, so validate them to a safe
	// charset (no path traversal). And refuse to materialize state under a domain
	// that already exists here — this RPC is for a migration TARGET that hasn't
	// defined the VM yet; clobbering a live VM's firmware would be destructive (G1).
	if !validRestoreName(req.VmName) || (req.Uuid != "" && !validRestoreName(req.Uuid)) {
		return nil, status.Error(codes.InvalidArgument, "invalid vm_name or uuid")
	}
	if s.virt != nil && s.virt.DomainExists(req.VmName) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"refusing to materialize firmware over already-defined domain %q", req.VmName)
	}
	if err := lv.ReadFirmwareBundle(bytes.NewReader(req.Bundle), s.dataDir, req.VmName, req.Uuid); err != nil {
		return nil, status.Errorf(codes.Internal, "materialize firmware state for %q: %v", req.VmName, err)
	}
	// Define (shut off) the domain from the source's own XML now that its firmware
	// is materialized, so the migrated VM is immediately startable here (a plain
	// reassigned-stopped VM is otherwise undefined on this host, and StartDomain /
	// the reconciler won't rebuild it). DefineDomain does NOT start it — the VM
	// stays stopped as intended (G1).
	if req.DomainXml != "" && s.virt != nil {
		// The XML embeds the SOURCE's absolute firmware paths (loader / VARS
		// template / NVRAM). It's only portable to a host with an identical layout,
		// so refuse a fingerprint mismatch rather than define a domain pointing at
		// the source host's paths.
		if req.SourceFirmwareFingerprint != "" && req.SourceFirmwareFingerprint != s.firmwareLayoutFingerprint() {
			lv.WipeFirmwareState(s.dataDir, req.VmName, req.Uuid)
			return nil, status.Errorf(codes.FailedPrecondition,
				"firmware path layout differs between source and target (dataDir/OVMF paths); cold firmware migration requires an identical layout on both hosts")
		}
		// Validate the XML identity matches the request — never define a mismatched
		// or unrelated domain via this RPC.
		if xn, xu := domainIdentity(req.DomainXml); xn != req.VmName || (req.Uuid != "" && xu != req.Uuid) {
			lv.WipeFirmwareState(s.dataDir, req.VmName, req.Uuid)
			return nil, status.Errorf(codes.InvalidArgument,
				"domain XML identity (name=%q uuid=%q) does not match request (name=%q uuid=%q)", xn, xu, req.VmName, req.Uuid)
		}
		if err := s.virt.DefineDomain(req.DomainXml); err != nil {
			// Roll back the firmware we just materialized so a retry is clean.
			lv.WipeFirmwareState(s.dataDir, req.VmName, req.Uuid)
			return nil, status.Errorf(codes.Internal, "define migrated domain %q: %v", req.VmName, err)
		}
	}
	slog.Info("firmware state received for migration", "vm", req.VmName, "bytes", len(req.Bundle), "defined", req.DomainXml != "")
	return &emptypb.Empty{}, nil
}

// ensureFirmwareStateOnTarget captures this host's firmware-state bundle for a
// Secure-Boot/vTPM VM and pushes it to the cold-migration target before the
// libvirt migrate, so the target defines the domain with the BitLocker-binding
// state present. Unlike disks, this is NOT best-effort — a firmware VM that
// migrates without its state would boot a fresh TPM, so a failure aborts (G1).
func (s *Server) ensureFirmwareStateOnTarget(ctx context.Context, targetHost, vmName string, fs firmwareSpec, domainXML string) error {
	// Per-component preflight: never push a PARTIAL bundle (WriteFirmwareBundle
	// alone would accept NVRAM-only or swtpm-only) — that restores a fresh TPM.
	if err := s.firmwarePresent(vmName, fs); err != nil {
		return err
	}
	var buf bytes.Buffer
	has, err := lv.WriteFirmwareBundle(s.dataDir, vmName, fs.UUID, &buf)
	if err != nil {
		return status.Errorf(codes.Internal, "capture firmware state for %q: %v", vmName, err)
	}
	if !has {
		return status.Errorf(codes.FailedPrecondition,
			"firmware state for %q is not present on this host; cannot migrate it consistently", vmName)
	}
	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach target host %s to push firmware: %v", targetHost, err)
	}
	defer conn.Close()
	if _, err := client.EnsureFirmwareState(ctx, &pb.EnsureFirmwareStateRequest{
		VmName: vmName, Uuid: fs.UUID, Bundle: buf.Bytes(), DomainXml: domainXML,
		SourceFirmwareFingerprint: s.firmwareLayoutFingerprint(),
	}); err != nil {
		return status.Errorf(codes.Internal, "push firmware state to %s: %v", targetHost, err)
	}
	return nil
}

// coldMigrateFirmwareVM moves a STOPPED Secure-Boot/vTPM VM to targetHost WITHOUT
// libvirt runtime migration: it pushes the quiescent firmware bundle, hands the
// VM over with its stopped state preserved (the target defines+starts it on
// demand with firmware present), and cleans up the source. Requires shared
// storage — a stopped VM's host-local disk can't be block-copied here (G1).
func (s *Server) coldMigrateFirmwareVM(ctx context.Context, vm *corrosion.VMRecord, targetHost *corrosion.HostRecord, fwSpec firmwareSpec, send func(pb.MigratePhase, float32, float32) error) error {
	start := time.Now()
	if s.virt == nil {
		return status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}
	// Must read disks successfully — proceeding on an error would skip the
	// host-local refusal AND the disk-ownership updates, diverging VM/disk records.
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "query disks for %q: %v", vm.Name, err)
	}
	for _, d := range disks {
		if isHostLocalDiskDriver(d.StorageType) {
			return status.Errorf(codes.FailedPrecondition,
				"Secure Boot / vTPM VM %q has a host-local disk (%s) and can't be migrated while stopped — move it to shared storage first (host-local firmware-VM migration is a follow-up)", vm.Name, d.StorageType)
		}
	}
	// PCI/hostdev passthrough isn't carried by this path — the source XML embeds
	// source host PCI addresses that won't be valid (or assigned) on the target.
	// Refuse for now rather than define a domain with stale hostdevs (G1).
	if assigned, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, ""); len(assigned) > 0 {
		for _, d := range assigned {
			if d.VMName == vm.Name {
				return status.Errorf(codes.FailedPrecondition,
					"Secure Boot / vTPM VM %q has PCI passthrough device %s — migrating firmware VMs with hostdevs is not supported yet", vm.Name, d.Address)
			}
		}
	}
	// Dump the source's (shut-off) domain XML so the target can DEFINE the same
	// domain — a plain reassigned-stopped VM would otherwise be undefined on the
	// target and unstartable. Shared-storage disk paths + dataDir-relative NVRAM +
	// the UUID-keyed swtpm dir are identical across hosts, so the XML is portable.
	domXML, err := s.virt.DumpXML(vm.Name)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"cannot dump domain XML for %q (it must be defined to migrate its firmware): %v", vm.Name, err)
	}
	_ = send(pb.MigratePhase_MIGRATE_COPYING, 0, 0)

	// Push the quiescent firmware to the target AND define the domain there (the
	// handler materializes firmware then DefineDomain — shut off, not started).
	// Per-component preflight is inside. Source is untouched on failure.
	if err := s.ensureFirmwareStateOnTarget(ctx, targetHost.Name, vm.Name, fwSpec, domXML); err != nil {
		return err
	}

	// Repoint the (shared-storage) disk records at the target — same path. Treat
	// these as part of the handoff: on ANY failure (mid-loop or the VM-host flip),
	// roll back EVERY disk we already moved and the target firmware, and abort, so
	// VM/disk records never diverge and nothing on the source is lost.
	rollbackDisks := func() {
		for _, d := range disks {
			_ = corrosion.UpdateDiskHostAndPath(ctx, s.db, vm.Name, d.DiskName, s.hostName, d.Path)
		}
	}
	for _, d := range disks {
		if err := corrosion.UpdateDiskHostAndPath(ctx, s.db, vm.Name, d.DiskName, targetHost.Name, d.Path); err != nil {
			rollbackDisks() // includes the ones updated so far (idempotent re-point to source)
			s.rollbackFirmwareTarget(targetHost.Name, vm.Name, fwSpec.UUID)
			return status.Errorf(codes.Internal, "repoint disk %q to %s: %v", d.DiskName, targetHost.Name, err)
		}
	}

	// Hand the VM to the target, PRESERVING its (stopped) state. On failure, roll
	// the disks AND target back and abort (source still owns it + is intact).
	if err := corrosion.UpdateVMHost(ctx, s.db, vm.Name, targetHost.Name, vm.State); err != nil {
		rollbackDisks()
		s.rollbackFirmwareTarget(targetHost.Name, vm.Name, fwSpec.UUID)
		return status.Errorf(codes.Internal, "reassign VM %q to %s: %v", vm.Name, targetHost.Name, err)
	}

	// Clean up the source ONLY after a fully successful handoff: undefine the
	// shut-off domain, then wipe the now-orphaned firmware. Do NOT wipe firmware
	// if the undefine fails — keep the source copy as a recoverable fallback and
	// surface the leftover (the VM is already correctly running on the target).
	if s.virt.DomainExists(vm.Name) {
		if err := s.virt.UndefineDomainPreservingState(vm.Name); err != nil {
			slog.Error("cold firmware migration: source domain undefine failed — leaving source firmware as a fallback; clean up manually",
				"vm", vm.Name, "host", s.hostName, "error", err)
			s.recordVMEvent(ctx, vm.Name, "vm.migrated", "warn", "migrated to "+targetHost.Name+" but source domain undefine failed (firmware retained on source)")
		} else {
			lv.WipeFirmwareState(s.dataDir, vm.Name, fwSpec.UUID)
		}
	} else {
		lv.WipeFirmwareState(s.dataDir, vm.Name, fwSpec.UUID)
	}

	_ = send(pb.MigratePhase_MIGRATE_CUTOVER, 100, 0)
	_ = send(pb.MigratePhase_MIGRATE_COMPLETING, 100, 0)
	s.recordMigrationMetrics("cold", "success", time.Since(start), 0, 0)
	slog.Info("cold firmware migration complete", "vm", vm.Name, "from", s.hostName, "to", targetHost.Name, "state", vm.State)
	s.recordVMEvent(ctx, vm.Name, "vm.migrated", "ok", "from="+s.hostName+" to="+targetHost.Name+" (cold firmware, "+vm.State+")")
	s.audit(ctx, "vm.migrate", vm.Name, "from="+s.hostName+" to="+targetHost.Name+" (cold firmware)", "ok")
	return nil
}

// rollbackFirmwareTarget best-effort tears down the firmware + defined domain a
// failed cold firmware migration left on the target (undefine + wipe), so the
// target isn't left with an orphan and a retry is clean (G1).
func (s *Server) rollbackFirmwareTarget(targetHost, vmName, uuid string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		slog.Warn("rollbackFirmwareTarget: cannot reach target", "host", targetHost, "vm", vmName, "error", err)
		return
	}
	defer conn.Close()
	if _, err := client.CleanupMigrationArtifacts(ctx, &pb.CleanupMigrationArtifactsRequest{
		VmName: vmName, FirmwareUuid: uuid, UndefineDomain: true,
	}); err != nil {
		slog.Warn("rollbackFirmwareTarget: cleanup failed", "host", targetHost, "vm", vmName, "error", err)
	}
}

// CleanupMigrationArtifacts removes the stub disks + cloud-init ISO that this
// host pre-created as a migration target, after the migration failed. The VM
// was never defined here (PersistDest only persists on success), so the files
// are orphaned; leaving them leaks space and shadows a later retry. Best-effort
// per file — a missing file is not an error.
func (s *Server) CleanupMigrationArtifacts(ctx context.Context, req *pb.CleanupMigrationArtifactsRequest) (*emptypb.Empty, error) {
	if err := safename.ValidateVMName(req.VmName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// Require vm.migrate on the VM being cleaned up. A failed migration leaves the
	// VM record intact (the source still owns it); only when the VM has truly
	// vanished do we fall back to admin (orphan cleanup), so a binding-holder
	// can't drive this RPC against a VM they don't control.
	if vm, _ := corrosion.GetVM(ctx, s.db, req.VmName); vm != nil {
		if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.migrate", "operator"); err != nil {
			return nil, err
		}
	} else if err := RequireRole(ctx, "admin"); err != nil {
		return nil, status.Error(codes.PermissionDenied,
			"cleaning up artifacts of a vanished VM requires the admin role")
	}
	for _, p := range req.DiskPaths {
		if p == "" {
			continue
		}
		// Only ever remove paths in a real disk-artifact root (disks dir or a
		// file-backed pool dir) — never an arbitrary file under the data dir such
		// as state.db.
		if !s.withinDiskArtifactRoot(p) {
			slog.Warn("cleanup migration artifacts: refusing to remove path outside a disk-artifact root", "vm", req.VmName, "path", p)
			continue
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			slog.Warn("cleanup migration artifacts: remove disk stub", "vm", req.VmName, "path", p, "error", err)
		}
	}
	if req.RemoveCloudInit {
		if iso, perr := lv.SafeCloudInitISOPath(s.dataDir, req.VmName); perr != nil {
			slog.Warn("cleanup migration artifacts: invalid vm name for cloud-init path", "vm", req.VmName, "error", perr)
		} else if err := os.Remove(iso); err != nil && !os.IsNotExist(err) {
			slog.Warn("cleanup migration artifacts: remove cloud-init iso", "vm", req.VmName, "path", iso, "error", err)
		}
	}
	// Undefine a domain this host pre-defined for a failed firmware migration,
	// BEFORE wiping its firmware (so we never wipe firmware out from under a still-
	// defined domain). If the undefine FAILS, keep the firmware as a recoverable
	// fallback and surface the error rather than stranding a defined domain whose
	// firmware we erased (G1).
	if req.UndefineDomain && req.VmName != "" && s.virt != nil && s.virt.DomainExists(req.VmName) {
		if err := s.virt.UndefineDomainPreservingState(req.VmName); err != nil {
			slog.Warn("cleanup migration artifacts: undefine pre-defined domain", "vm", req.VmName, "error", err)
			return nil, status.Errorf(codes.Internal,
				"undefine domain %q failed; left firmware in place (recoverable): %v", req.VmName, err)
		}
	}
	// Wipe firmware state we pushed to this (failed) target so it can't be
	// adopted by a retry / orphan the swtpm tree (G1).
	if req.FirmwareUuid != "" {
		lv.WipeFirmwareState(s.dataDir, req.VmName, req.FirmwareUuid)
	}
	return &emptypb.Empty{}, nil
}

// cleanupMigrationArtifactsOnTarget best-effort removes the stubs + ISO the
// target pre-created, after a failed migration. Never blocks/fails the caller.
func (s *Server) cleanupMigrationArtifactsOnTarget(ctx context.Context, targetHost, vmName string, diskPaths []string, firmwareUUID string) {
	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		slog.Warn("cleanupMigrationArtifactsOnTarget: cannot reach host", "host", targetHost, "error", err)
		return
	}
	defer conn.Close()
	if _, err := client.CleanupMigrationArtifacts(ctx, &pb.CleanupMigrationArtifactsRequest{
		VmName:          vmName,
		DiskPaths:       diskPaths,
		RemoveCloudInit: true,
		FirmwareUuid:    firmwareUUID,
	}); err != nil {
		slog.Warn("cleanupMigrationArtifactsOnTarget: cleanup failed", "host", targetHost, "vm", vmName, "error", err)
	}
}

// isHostLocalDiskDriver reports whether a disk's storage driver keeps the disk
// as a host-local file, so the same path on two hosts is two distinct files.
// Deliberately conservative: only the plain-file local/dir drivers qualify, so
// the post-migration source-disk cleanup never touches shared (nfs/ceph/iscsi)
// or volume-manager (zfs/lvm/btrfs) backends, where deleting "the source" could
// destroy the live disk.
func isHostLocalDiskDriver(t string) bool {
	return t == "local" || t == "dir"
}

// diskVirtualSize returns the virtual size of a qcow2 image.
func diskVirtualSize(_ context.Context, path string) (int64, error) {
	info, err := qcow2.Info(path)
	if err != nil {
		return 0, err
	}
	return int64(info.VirtualSize), nil
}

// ensureDisksOnTarget creates empty stub files on the target host for each
// local disk so libvirt accepts the domain XML before block copy starts.
// Reads actual virtual size from source disk files to ensure exact match.
func (s *Server) ensureDisksOnTarget(ctx context.Context, targetHost, vmName string) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil || len(disks) == 0 {
		return
	}

	req := &pb.EnsureDisksRequest{VmName: vmName}
	for _, d := range disks {
		if d.Path == "" {
			continue
		}
		// Get the actual virtual size from the source disk file,
		// not the DB — they can differ (e.g. backing image size).
		size, err := diskVirtualSize(ctx, d.Path)
		if err != nil {
			slog.Warn("ensureDisksOnTarget: cannot read virtual size, using DB value",
				"path", d.Path, "db_size", d.SizeBytes, "error", err)
			size = d.SizeBytes
		} else {
			slog.Info("ensureDisksOnTarget: read virtual size from source",
				"path", d.Path, "virtual_size", size, "db_size", d.SizeBytes)
		}
		req.Disks = append(req.Disks, &pb.DiskStub{
			Path:      d.Path,
			SizeBytes: size,
		})
	}
	if len(req.Disks) == 0 {
		return
	}

	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		slog.Warn("ensureDisksOnTarget: cannot reach host", "host", targetHost, "error", err)
		return
	}
	defer conn.Close()

	if _, err := client.EnsureDisks(ctx, req); err != nil {
		slog.Warn("ensureDisksOnTarget: failed", "host", targetHost, "vm", vmName, "error", err)
	}
}

// ensureCloudInitOnTarget calls the target host to generate the cloud-init ISO
// before migration starts, so libvirt can find the file when the domain arrives.
func (s *Server) ensureCloudInitOnTarget(ctx context.Context, targetHost string, vm *corrosion.VMRecord) {
	// Parse spec to extract cloud-init data.
	var spec pb.VMSpec
	if vm.Spec == "" {
		return
	}
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		slog.Warn("ensureCloudInitOnTarget: parse spec", "vm", vm.Name, "error", err)
		return
	}

	// Build the request — send cloud-init data if present, otherwise send
	// minimal data so the target generates a basic ISO.
	req := &pb.EnsureCloudInitRequest{VmName: vm.Name}
	if spec.CloudInit != nil {
		req.Userdata = spec.CloudInit.Userdata
		req.Networkconfig = spec.CloudInit.Networkconfig
	}

	// Check if the cloud-init ISO exists locally — if not, the VM was created
	// without one (e.g. non-cloud image) and we don't need it on the target.
	isoPath := lv.CloudInitISOPath(s.dataDir, vm.Name)
	if _, err := os.Stat(isoPath); err != nil {
		return // no ISO on source, skip
	}

	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		slog.Warn("ensureCloudInitOnTarget: cannot reach host", "host", targetHost, "error", err)
		return
	}
	defer conn.Close()

	if _, err := client.EnsureCloudInit(ctx, req); err != nil {
		slog.Warn("ensureCloudInitOnTarget: failed", "host", targetHost, "vm", vm.Name, "error", err)
	}
}

// notifyTargetHostOfVM pings the target daemon so it picks up the migrated VM.
func (s *Server) notifyTargetHostOfVM(targetHostName, addr string, grpcPort int, vmName string) {
	conn, err := pki.PeerDial(s.pkiDir, peerTarget(addr, grpcPort))
	if err != nil {
		slog.Warn("migrate notify: dial target", "host", targetHostName, "error", err)
		return
	}
	defer conn.Close()

	client := pb.NewLiteVirtClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.InspectVM(ctx, &pb.InspectVMRequest{Name: vmName})
	if err != nil {
		slog.Warn("migrate notify: InspectVM on target failed", "host", targetHostName, "vm", vmName, "error", err)
		return
	}
	slog.Info("migrate: target acknowledged VM", "host", targetHostName, "vm", vmName)
}
