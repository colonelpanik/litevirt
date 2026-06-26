package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// PromoteReplica brings an inert replica online for disaster recovery: it
// locates the chosen (or newest) replica of a VM's root disk, ensures it runs
// on the host that physically holds the replica file, builds a self-contained
// live disk from it, then defines + starts the VM there and persists the
// record. The VM's durable record (replicated via Corrosion) supplies the spec,
// so promotion works even after the original host is gone.
func (s *Server) PromoteReplica(req *pb.PromoteReplicaRequest, stream grpc.ServerStreamingServer[pb.PromoteReplicaProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.VmName == "" {
		return status.Error(codes.InvalidArgument, "vm_name required")
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "vm %q has no durable record to reconstruct from", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.create", "operator"); err != nil {
		return err
	}
	return s.promoteResolved(ctx, req, vm, stream.Send)
}

// AutoPromoteReplica is the failover coordinator's trusted, non-streaming entry
// point: after a host is fenced, promote the freshest replica of vmName onto a
// healthy peer so a VM on lost local storage can resume. Force is set because
// the original host is dead (no split-brain). Returns an error when there is no
// replica to promote, so the coordinator can fall back to a bare reschedule.
func (s *Server) AutoPromoteReplica(ctx context.Context, vmName string) error {
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return fmt.Errorf("vm %q not found", vmName)
	}
	req := &pb.PromoteReplicaRequest{VmName: vmName, Force: true}
	return s.promoteResolved(ctx, req, vm, func(*pb.PromoteReplicaProgress) error { return nil })
}

// promoteResolved is the shared promotion core (no RBAC): resolve the replica's
// pool + host, then run locally or relay to the holding host.
func (s *Server) promoteResolved(ctx context.Context, req *pb.PromoteReplicaRequest, vm *corrosion.VMRecord, send func(*pb.PromoteReplicaProgress) error) error {
	// A replica carries only disk data — not the VM's UEFI NVRAM or swtpm state.
	// Promoting a Secure-Boot/vTPM VM from one would boot it with a fresh TPM and
	// silently brick BitLocker, so refuse rather than recover it half-formed.
	// Recovery of such a VM is an explicit restore from a backup that captured the
	// firmware (G1).
	if usesFirmwareState(vm.Spec) {
		return status.Errorf(codes.FailedPrecondition,
			"vm %q uses Secure Boot / vTPM; its firmware state isn't in the disk replica, so promotion can't recover it — restore from a backup that captured firmware", req.VmName)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, req.VmName)
	if err != nil {
		return status.Errorf(codes.Internal, "list disks: %v", err)
	}
	src := pickReplicaSource(disks)
	if src == nil {
		return status.Errorf(codes.FailedPrecondition, "vm %q has no disk records", req.VmName)
	}

	// Resolve the target pool: explicit, else inferred from the VM's
	// replication schedule.
	pool := req.TargetPool
	schedHost := req.TargetHost
	if pool == "" {
		sp, sh, ok := s.replicationTargetForVM(ctx, req.VmName)
		if !ok {
			return status.Errorf(codes.FailedPrecondition,
				"no target_pool given and vm %q has no replication schedule to infer one", req.VmName)
		}
		pool = sp
		if schedHost == "" {
			schedHost = sh
		}
	}

	_ = send(&pb.PromoteReplicaProgress{
		Phase: pb.PromoteReplicaProgress_RESOLVING, VmName: req.VmName,
		Status: "locating replica of disk " + src.DiskName + " in pool " + pool,
	})

	host, replica, err := s.findReplicaHost(ctx, req, src.DiskName, pool, schedHost)
	if err != nil {
		return err
	}

	// The replica file + libvirt live on `host`; forward there if it isn't us.
	if host != s.hostName {
		fwd := &pb.PromoteReplicaRequest{
			VmName: req.VmName, TargetPool: pool, TargetHost: host, Replica: replica,
			NewName: req.NewName, Force: req.Force, NoLocalize: req.NoLocalize,
		}
		return s.relayPromote(ctx, host, fwd, send)
	}

	return s.doPromoteLocal(ctx, req, vm, src, pool, replica, send)
}

// replicationTargetForVM returns the (pool, host) of the VM's first vm-scoped
// replication schedule, used to infer where its replicas live.
func (s *Server) replicationTargetForVM(ctx context.Context, vmName string) (pool, host string, ok bool) {
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return "", "", false
	}
	for _, r := range rows {
		if r.Type == "replication" && r.VMName == vmName && r.TargetPool != "" {
			return r.TargetPool, r.TargetHost, true
		}
	}
	return "", "", false
}

// replicaPattern matches a replica file for (vm, disk): both the full-copy
// qcow2 form and the incremental raw form.
func isReplicaOf(name, vmName, diskName string) bool {
	prefix := fmt.Sprintf("%s-%s-", vmName, diskName)
	return strings.HasPrefix(name, prefix) &&
		(strings.HasSuffix(name, ".qcow2") || strings.HasSuffix(name, ".raw"))
}

// findReplicaHost locates the host holding the chosen (req.replica) or newest
// replica of (vm, disk) in pool. Candidates come from an explicit target host,
// the schedule's host, or every active host that has the pool.
//
// It lists pool files via poolContentNames (local read or host-cert peer call),
// NOT the RBAC-gated ListStoragePoolContents handler: AutoPromoteReplica runs
// from the failover coordinator with an unauthenticated context, which the
// handler's RequireRole would reject (manual promote, with an operator ctx,
// worked — auto-promote did not).
func (s *Server) findReplicaHost(ctx context.Context, req *pb.PromoteReplicaRequest, diskName, pool, schedHost string) (host, replica string, err error) {
	var candidates []string
	switch {
	case req.TargetHost != "":
		candidates = []string{req.TargetHost}
	case schedHost != "":
		candidates = []string{schedHost}
	default:
		hs, herr := corrosion.HostsWithPool(ctx, s.db, pool, "")
		if herr != nil || len(hs) == 0 {
			// Fall back to this host (a same-host/shared pool).
			candidates = []string{s.hostName}
		} else {
			candidates = hs
		}
	}

	bestHost, bestName := "", ""
	for _, h := range candidates {
		for _, n := range s.poolContentNames(ctx, pool, h) {
			if !isReplicaOf(n, req.VmName, diskName) {
				continue
			}
			if req.Replica != "" {
				if n == req.Replica {
					return h, n, nil
				}
				continue
			}
			// Timestamped suffix sorts lexically oldest→newest.
			if n > bestName {
				bestName, bestHost = n, h
			}
		}
	}
	if req.Replica != "" {
		return "", "", status.Errorf(codes.NotFound, "replica %q not found in pool %q", req.Replica, pool)
	}
	if bestHost == "" {
		return "", "", status.Errorf(codes.NotFound, "no replica of %q disk %q found in pool %q", req.VmName, diskName, pool)
	}
	return bestHost, bestName, nil
}

// poolContentNames lists file names in a pool WITHOUT the RBAC gate, so it is
// safe from unauthenticated internal contexts (scheduler / failover
// coordinator). Local pool → read the directory; peer → dial with the host cert
// (which the peer authorizes). Any error yields an empty list.
func (s *Server) poolContentNames(ctx context.Context, pool, host string) []string {
	if host == "" || host == s.hostName {
		poolRef, ok := s.resolvePool(ctx, pool)
		if !ok {
			return nil
		}
		dir, err := fileBasedPoolDir(s.dataDir, poolRef)
		if err != nil {
			return nil
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		return names
	}
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return nil
	}
	defer conn.Close()
	resp, err := client.ListStoragePoolContents(ctx, &pb.ListStoragePoolContentsRequest{PoolName: pool, Host: host})
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(resp.GetContents()))
	for _, c := range resp.GetContents() {
		names = append(names, c.GetName())
	}
	return names
}

// relayPromote forwards a PromoteReplica stream to the host that holds the
// replica and relays its progress back to the caller.
func (s *Server) relayPromote(ctx context.Context, host string, req *pb.PromoteReplicaRequest, send func(*pb.PromoteReplicaProgress) error) error {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
	}
	defer conn.Close()
	up, err := client.PromoteReplica(ctx, req)
	if err != nil {
		return status.Errorf(codes.Unavailable, "promote on %q: %v", host, err)
	}
	for {
		msg, rerr := up.Recv()
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		if err := send(msg); err != nil {
			return err
		}
	}
}

// doPromoteLocal performs the promotion on the host that holds the replica:
// build a self-contained live disk from the replica, define + start the VM, and
// persist it. Runs only when this host owns the replica file + libvirt.
func (s *Server) doPromoteLocal(ctx context.Context, req *pb.PromoteReplicaRequest, vm *corrosion.VMRecord, src *corrosion.DiskRecord, pool, replica string, send func(*pb.PromoteReplicaProgress) error) error {
	if s.virt == nil {
		return status.Error(codes.FailedPrecondition, "no libvirt backend on this host")
	}
	poolRef, ok := s.resolvePool(ctx, pool)
	if !ok {
		return status.Errorf(codes.FailedPrecondition, "pool %q not configured on host %q", pool, s.hostName)
	}
	if !isFileBasedDriver(poolRef.Driver) {
		return status.Errorf(codes.FailedPrecondition, "pool %q (%s) is not file-based", pool, poolRef.Driver)
	}
	poolDir, err := fileBasedPoolDir(s.dataDir, poolRef)
	if err != nil {
		return status.Errorf(codes.Internal, "resolve pool dir: %v", err)
	}
	replicaPath := filepath.Join(poolDir, replica)
	if _, err := os.Stat(replicaPath); err != nil {
		return status.Errorf(codes.NotFound, "replica %q not present on %q: %v", replica, s.hostName, err)
	}

	targetName := vm.Name
	renamed := false
	if req.NewName != "" && req.NewName != vm.Name {
		targetName = req.NewName
		renamed = true
	}
	if !validRestoreName(targetName) {
		return status.Errorf(codes.InvalidArgument, "invalid promotion name %q", targetName)
	}

	// Split-brain guard. Taking over the original name while the original is
	// still on a healthy host (and not force) would double-run the VM.
	if !req.Force {
		if renamed {
			if rec, _ := corrosion.GetVM(ctx, s.db, targetName); rec != nil {
				return status.Errorf(codes.AlreadyExists, "vm %q already exists; choose another --new-name", targetName)
			}
		} else if vm.HostName != "" && vm.HostName != s.hostName {
			if h, _ := corrosion.GetHost(ctx, s.db, vm.HostName); h != nil && h.State == "active" {
				return status.Errorf(codes.FailedPrecondition,
					"vm %q still owned by healthy host %q; fence it or pass --force/--new-name to avoid split-brain", vm.Name, vm.HostName)
			}
		}
	}
	if s.virt.DomainExists(targetName) {
		if !req.Force {
			return status.Errorf(codes.AlreadyExists, "domain %q already defined on %q; pass --force or --new-name", targetName, s.hostName)
		}
		// Force takeover: the domain may be actively running on THIS host
		// (same-host promote). Stop it first — UndefineDomain alone only drops
		// the persistent config, leaving the live domain to collide on UUID at
		// DefineDomain. (In a real failover the VM ran on the fenced host, so
		// the promotion host has no such domain and this is a no-op.)
		_ = s.virt.DestroyDomain(targetName)
		_ = s.virt.UndefineDomain(targetName, false)
	}

	// Build the live disk from the replica.
	ts := strings.TrimSuffix(strings.TrimSuffix(replica, ".qcow2"), ".raw")
	livePath := filepath.Join(poolDir, fmt.Sprintf("%s-promoted-%s.qcow2", targetName, ts))
	if req.NoLocalize {
		backingFmt := "qcow2"
		if strings.HasSuffix(replica, ".raw") {
			backingFmt = "raw"
		}
		_ = send(&pb.PromoteReplicaProgress{
			Phase: pb.PromoteReplicaProgress_LOCALIZING, VmName: targetName, Host: s.hostName, Replica: replica,
			Status: "creating overlay backed by replica (fast; pins the replica)",
		})
		if err := qcow2.CreateWithBackingFormat(livePath, replicaPath, backingFmt, 0, nil); err != nil {
			return status.Errorf(codes.Internal, "create overlay: %v", err)
		}
	} else if !qemuImgAvailable() && strings.HasSuffix(replica, ".raw") {
		// Localize would convert raw→qcow2, but without qemu-img convertQcow2
		// falls back to a verbatim byte copy — landing raw bytes in a
		// qcow2-declared file → an unbootable/corrupt promoted VM (bug-sweep #9).
		// Degrade to a correct qcow2 overlay backed by the raw replica
		// (backingFmt=raw), like the NoLocalize path; it pins the replica but
		// boots correctly. Full localization needs qemu-img on the host.
		_ = send(&pb.PromoteReplicaProgress{
			Phase: pb.PromoteReplicaProgress_LOCALIZING, VmName: targetName, Host: s.hostName, Replica: replica,
			Status: "qemu-img unavailable — overlay over raw replica (pins replica; install qemu-img to localize)",
		})
		if err := qcow2.CreateWithBackingFormat(livePath, replicaPath, "raw", 0, nil); err != nil {
			return status.Errorf(codes.Internal, "create overlay over raw replica: %v", err)
		}
		slog.Warn("promote: localized via raw-backed overlay (qemu-img absent) — replica is pinned",
			"vm", targetName, "replica", replica)
	} else {
		_ = send(&pb.PromoteReplicaProgress{
			Phase: pb.PromoteReplicaProgress_LOCALIZING, VmName: targetName, Host: s.hostName, Replica: replica,
			Status: "copying replica into a self-contained live disk",
		})
		emit := func(p *pb.MoveVolumeProgress) error {
			return send(&pb.PromoteReplicaProgress{
				Phase: pb.PromoteReplicaProgress_LOCALIZING, VmName: targetName, Host: s.hostName, Replica: replica,
				Status: fmt.Sprintf("copying replica… %.0f%%", p.CopyPct),
			})
		}
		// Copy into a .promote-*.tmp then atomically rename, so a crash
		// mid-copy leaves a sweepable temp (SweepStaleStaging) rather than an
		// orphan live disk — the qemu-img child survives KillMode=process and
		// would otherwise complete a final-named qcow2 with no domain.
		tmpLive := filepath.Join(poolDir, fmt.Sprintf(".promote-%s-%s.tmp", targetName, ts))
		if err := convertQcow2(ctx, replicaPath, tmpLive, emit); err != nil {
			os.Remove(tmpLive)
			return status.Errorf(codes.Internal, "copy replica: %v", err)
		}
		if err := os.Rename(tmpLive, livePath); err != nil {
			os.Remove(tmpLive)
			return status.Errorf(codes.Internal, "finalize live disk: %v", err)
		}
	}

	// Reconstruct the spec from the durable record.
	var spec pb.VMSpec
	if vm.Spec == "" {
		os.Remove(livePath)
		return status.Errorf(codes.FailedPrecondition, "vm %q record has no spec to define from", vm.Name)
	}
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		os.Remove(livePath)
		return status.Errorf(codes.Internal, "parse vm spec: %v", err)
	}
	spec.Name = targetName

	multiDiskNote := ""
	if len(spec.Disks) > 1 {
		multiDiskNote = fmt.Sprintf(" (only root disk promoted; %d data disk(s) not recovered)", len(spec.Disks)-1)
	}

	// Rebuild the promoted disk's bus/controller from the stored spec (not
	// hardcoded virtio) so an imported scsi/sata guest boots after promotion
	// instead of stalling on a missing controller (G1 cross-cutting fix).
	promBus, promCtrl := "virtio", ""
	for _, ds := range spec.Disks {
		if ds.Name == src.DiskName {
			if ds.Bus != "" {
				promBus = ds.Bus
			}
			promCtrl = ds.ControllerModel
			break
		}
	}
	diskCfg := []lv.DiskConfig{{Name: src.DiskName, Path: livePath, Bus: promBus, ControllerModel: promCtrl}}
	diskRecords := []corrosion.DiskRecord{{
		VMName: targetName, DiskName: src.DiskName, HostName: s.hostName,
		Path: livePath, SizeBytes: src.SizeBytes, StorageType: poolRef.Driver,
		StorageVolume: pool, TargetDev: lv.DiskDevName(promBus, 0),
	}}

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
				os.Remove(livePath)
				return status.Errorf(codes.FailedPrecondition, "network bridge %q unavailable on %q: %v", bridge, s.hostName, err)
			}
		}
		netCfg = append(netCfg, lv.NetworkConfig{Bridge: bridge, Model: n.Model, MAC: mac})
		ifaceRecords = append(ifaceRecords, corrosion.InterfaceRecord{
			VMName: targetName, NetworkName: n.Name, Ordinal: i, MAC: mac, IP: n.Ip,
		})
	}

	domXML, err := lv.GenerateDomainXML(lv.VMConfig{
		Name: targetName, CPU: int(spec.Cpu), CPUMode: spec.CpuMode,
		MemoryMiB: int(spec.MemoryMib), Machine: spec.Machine, Firmware: spec.Firmware,
		GuestAgent: spec.GuestAgent, EnableVNC: !spec.DisableVnc, EnableSPICE: spec.EnableSpice,
		Disks: diskCfg, Networks: netCfg, Boot: spec.Boot,
	})
	if err != nil {
		os.Remove(livePath)
		return status.Errorf(codes.Internal, "generate domain XML: %v", err)
	}

	_ = send(&pb.PromoteReplicaProgress{
		Phase: pb.PromoteReplicaProgress_DEFINING, VmName: targetName, Host: s.hostName,
		Replica: replica, DiskPath: livePath, Status: "defining domain" + multiDiskNote,
	})
	if err := s.virt.DefineDomain(domXML); err != nil {
		os.Remove(livePath)
		return status.Errorf(codes.Internal, "define domain: %v", err)
	}
	if err := s.virt.StartDomain(targetName); err != nil {
		_ = s.virt.UndefineDomain(targetName, false) // wipe by design: half-built promote
		os.Remove(livePath)
		return status.Errorf(codes.Internal, "start domain: %v", err)
	}
	_ = send(&pb.PromoteReplicaProgress{
		Phase: pb.PromoteReplicaProgress_STARTED, VmName: targetName, Host: s.hostName,
		Replica: replica, DiskPath: livePath, Status: "VM started off the promoted replica",
	})

	// Persist. Takeover (same name) re-homes the existing record; a renamed
	// promotion writes a fresh VM alongside the original.
	specJSON, _ := json.Marshal(&spec)
	if renamed {
		rec := corrosion.VMRecord{
			Name: targetName, HostName: s.hostName, Spec: string(specJSON),
			State: "running", CPUActual: int(spec.Cpu), MemActual: int(spec.MemoryMib),
			Project: vm.Project,
		}
		if err := corrosion.InsertVM(ctx, s.db, rec, ifaceRecords, diskRecords); err != nil {
			return status.Errorf(codes.Internal, "persist promoted vm: %v", err)
		}
	} else {
		if err := corrosion.UpdateVMHost(ctx, s.db, targetName, s.hostName, "running"); err != nil {
			return status.Errorf(codes.Internal, "re-home vm record: %v", err)
		}
		if err := corrosion.UpdateDiskHostAndPath(ctx, s.db, targetName, src.DiskName, s.hostName, livePath); err != nil {
			return status.Errorf(codes.Internal, "update disk record: %v", err)
		}
		_ = corrosion.UpdateDiskStorage(ctx, s.db, targetName, src.DiskName, poolRef.Driver, pool)
	}

	s.recordVMEvent(ctx, targetName, "vm.promoted", "ok",
		fmt.Sprintf("from replica %s on %s%s", replica, s.hostName, multiDiskNote))
	s.audit(ctx, "replica.promote", targetName, "replica="+replica+" host="+s.hostName, "ok")
	_ = send(&pb.PromoteReplicaProgress{
		Phase: pb.PromoteReplicaProgress_DONE, VmName: targetName, Host: s.hostName,
		Replica: replica, DiskPath: livePath, Status: "promotion complete" + multiDiskNote,
	})
	return nil
}
