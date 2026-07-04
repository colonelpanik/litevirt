package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/placement"
)

func (s *Server) ListHosts(ctx context.Context, req *pb.ListHostsRequest) (*pb.ListHostsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list hosts: %v", err)
	}

	// Single query for all VM counts instead of per-host N+1.
	vmCounts, _ := corrosion.CountVMsByHost(ctx, s.db)
	// Aggregate CPU/memory allocated to running VMs per host.
	resUsage, _ := corrosion.SumVMResourcesByHost(ctx, s.db)

	resp := &pb.ListHostsResponse{}
	for _, h := range hosts {
		usage := resUsage[h.Name]
		pools := s.storagePoolsForHost(ctx, h.Name)
		host := &pb.Host{
			Name:         h.Name,
			Address:      h.Address,
			State:        hostStateToPB(h.State),
			CpuTotal:     int32(h.CPUTotal),
			MemTotalMib:  int32(h.MemTotal),
			DiskTotalGib: int64(h.DiskTotal),
			CpuUsed:      int32(usage.CpuUsed),
			MemUsedMib:   int32(usage.MemUsedMiB),
			DiskUsedGib:  int64(usage.DiskUsedGiB),
			VmCount:      int32(vmCounts[h.Name]),
			Version:      h.Version,
			StoragePools: pools,
			Region:       h.Region,
			CreatedAt:    parseTimestamp(h.CreatedAt),
			UpdatedAt:    parseTimestamp(h.UpdatedAt),
		}
		resp.Hosts = append(resp.Hosts, host)
	}

	return resp, nil
}

func (s *Server) InspectHost(ctx context.Context, req *pb.InspectHostRequest) (*pb.Host, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get host: %v", err)
	}
	if h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}

	vms, _ := corrosion.ListVMs(ctx, s.db, "", h.Name)

	// Sum allocated CPU/memory/disk from VMs on this host.
	cpuUsed, memUsed, diskUsed := s.hostAllocatedResources(ctx, h.Name)

	return &pb.Host{
		Name:          h.Name,
		Address:       h.Address,
		State:         hostStateToPB(h.State),
		CpuTotal:      int32(h.CPUTotal),
		MemTotalMib:   int32(h.MemTotal),
		DiskTotalGib:  int64(h.DiskTotal),
		CpuUsed:       cpuUsed,
		MemUsedMib:    memUsed,
		DiskUsedGib:   diskUsed,
		VmCount:       int32(len(vms)),
		Labels:        h.Labels,
		Version:       h.Version,
		StoragePools:  s.storagePoolsForHost(ctx, h.Name),
		FenceStrategy: h.FenceStrategy,
		IpmiAddress:   h.IPMIAddress,
		WatchdogDev:   h.WatchdogDev,
		Region:        h.Region,
		CreatedAt:     parseTimestamp(h.CreatedAt),
		UpdatedAt:     parseTimestamp(h.UpdatedAt),
	}, nil
}

func (s *Server) GetHostHealth(ctx context.Context, _ *emptypb.Empty) (*pb.HostHealthMatrix, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx,
		`SELECT observer, target, status, consecutive_failures, last_seen
		 FROM host_health`)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query health: %v", err)
	}

	resp := &pb.HostHealthMatrix{}
	for _, r := range rows {
		resp.Entries = append(resp.Entries, &pb.HostHealthEntry{
			Observer:            r.String("observer"),
			Target:              r.String("target"),
			Status:              r.String("status"),
			ConsecutiveFailures: int32(r.Int("consecutive_failures")),
			LastSeen:            parseTimestamp(r.String("last_seen")),
		})
	}

	return resp, nil
}

func (s *Server) Ping(ctx context.Context, _ *pb.PingRequest) (*pb.PingResponse, error) {
	// SchemaVersion here is the BINARY const, deliberately — self-upgrade reads
	// it to decide "which binary to adopt" (a binary question), not "do my
	// columns exist" (the DB-applied question the replication handshake uses).
	// Sourcing it from the DB-applied schema would make every node report the
	// pre-staged forward version before any binary swap and wrongly think it's
	// behind, defeating pre-stage. See corrosion.EffectiveDBSchema.
	return &pb.PingResponse{
		HostName:      s.hostName,
		Version:       s.version,
		SchemaVersion: int32(corrosion.CurrentSchemaVersion),
		// Split-brain-hardening feature tokens this build supports. Read via a
		// fresh Ping to compute cluster-wide activation of fail-closed checks.
		Capabilities: s.advertisedCapabilities(),
	}, nil
}

// PeerCapabilities fresh-Pings a peer (or short-circuits for self) and returns
// its advertised split-brain-hardening capability tokens. It is injected into
// the health checker (SetPeerPinger) so cluster-wide activation is computed from
// live reachability, never from stale replicated rows. An unreachable peer
// returns an error so the caller can fail closed.
func (s *Server) PeerCapabilities(ctx context.Context, host string) ([]string, error) {
	if host == s.hostName {
		return s.advertisedCapabilities(), nil
	}
	c, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, err
	}
	defer closeConn()
	resp, err := c.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetCapabilities(), nil
}

// DrainHost marks the host as draining and migrates all its VMs to healthy hosts.
// Uses a worker pool of size req.Parallel (default 2) for concurrent migrations.
// VMs with shared storage use live migration; local-only VMs use cold migration.
func (s *Server) DrainHost(req *pb.DrainHostRequest, stream pb.LiteVirt_DrainHostServer) error {
	ctx := stream.Context()
	if err := RequireRole(ctx, "admin"); err != nil {
		return err
	}

	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}

	// Drain must run ON the host being drained: only there is this daemon the SOURCE
	// of the host's VMs, so it can STOP each VM before reassigning ownership (a
	// reassign WITHOUT a source stop is split-brain) and gate on the source's local
	// quorum. Forward the whole stream to req.Name if we're not it.
	if req.Name != s.hostName {
		client, conn, cerr := s.peerClient(ctx, req.Name)
		if cerr != nil {
			return status.Errorf(codes.Unavailable, "cannot reach drain host %s: %v", req.Name, cerr)
		}
		defer conn.Close()
		remote, rerr := client.DrainHost(ctx, req)
		if rerr != nil {
			return rerr
		}
		for {
			msg, rerr := remote.Recv()
			if rerr != nil {
				if rerr == io.EOF {
					return nil
				}
				return rerr
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}

	// Split-brain gate (Phase 1): draining moves this host's VMs to peers (runtime-
	// ownership moves), so the SOURCE must hold local quorum once enforced — else an
	// isolated host could evacuate its VMs onto peers without quorum. Checked before
	// marking "draining" so a refusal is a clean no-op. Fail-open until cluster-wide.
	if reason, refused := s.execGateRefused(ctx); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		return status.Errorf(codes.FailedPrecondition, "drain refused: %s", reason)
	}

	if err := corrosion.UpdateHostState(ctx, s.db, req.Name, "draining"); err != nil {
		return status.Errorf(codes.Internal, "mark draining: %v", err)
	}
	s.publish("host.draining", req.Name, "")
	s.audit(ctx, "host.drain", req.Name, "", "ok")

	vms, _ := corrosion.ListVMs(ctx, s.db, "", req.Name)
	slog.Info("draining host", "host", req.Name, "vms", len(vms))

	// Collect migratable VMs.
	var toMigrate []corrosion.VMRecord
	for _, vm := range vms {
		if vm.State == "running" || vm.State == "stopped" {
			toMigrate = append(toMigrate, vm)
		}
	}
	if len(toMigrate) == 0 {
		return nil
	}

	// Use placement engine to select targets per VM, respecting constraints.
	// Build placement requests from each VM's stored spec.
	type drainJob struct {
		vm     corrosion.VMRecord
		target corrosion.HostRecord
	}
	var drainJobs []drainJob
	for _, vm := range toMigrate {
		placementReq := placement.Request{
			VMName:       vm.Name,
			CPUNeeded:    vm.CPUActual,
			MemMiBNeeded: vm.MemActual,
		}

		// Extract placement constraints from stored VM spec.
		if vm.Spec != "" {
			spec := &pb.VMSpec{}
			if err := json.Unmarshal([]byte(vm.Spec), spec); err == nil {
				if p := spec.Placement; p != nil {
					// Override PinHost — cannot pin to the host being drained.
					if p.Host != "" && p.Host != req.Name {
						placementReq.PinHost = p.Host
					}
					placementReq.AntiAffinity = p.AntiAffinity
					placementReq.Affinity = p.Affinity
					placementReq.RequireLabels = p.Require
					placementReq.PreferLabels = p.Prefer
					placementReq.Spread = p.Spread
				}
				for _, dev := range spec.Devices {
					placementReq.Devices = append(placementReq.Devices, placement.DeviceRequest{
						Type:   dev.Type,
						Count:  int(dev.Count),
						Vendor: dev.Vendor,
					})
				}
				// A Secure-Boot/vTPM VM may only drain onto a capable host (G1).
				addCapabilityLabels(&placementReq, spec)
			}
		}

		// Ensure the drained host is excluded via anti-affinity on itself.
		// placement.Select() excludes non-active hosts, and we already set the host to "draining".

		targetName, err := placement.Select(ctx, s.db, placementReq)
		if err != nil {
			slog.Warn("drain: no placement target for VM", "vm", vm.Name, "error", err)
			if err := stream.Send(&pb.DrainProgress{
				VmName: vm.Name,
				Status: "failed",
				Error:  fmt.Sprintf("no eligible target: %v", err),
			}); err != nil {
				return err
			}
			continue
		}

		targetHost, err := corrosion.GetHost(ctx, s.db, targetName)
		if err != nil || targetHost == nil {
			continue
		}
		drainJobs = append(drainJobs, drainJob{vm: vm, target: *targetHost})
	}

	if len(drainJobs) == 0 {
		return nil
	}

	// Worker pool for parallel migrations.
	parallel := int(req.Parallel)
	if parallel <= 0 {
		parallel = 2
	}

	jobs := make(chan drainJob, len(drainJobs))
	results := make(chan *pb.DrainProgress, len(drainJobs))

	// Start workers.
	for w := 0; w < parallel; w++ {
		go func() {
			for job := range jobs {
				progress := s.drainOneVM(ctx, job.vm, job.target)
				results <- progress
			}
		}()
	}

	// Enqueue jobs.
	for _, job := range drainJobs {
		jobs <- job
	}
	close(jobs)

	// Collect results and stream progress.
	var failures int
	for range drainJobs {
		progress := <-results
		if progress.Status == "error" || progress.Status == "failed" {
			failures++
		}
		if err := stream.Send(progress); err != nil {
			return err
		}
	}

	// Check for VMs that were skipped (pinned, no placement target).
	// If any VMs remain on the host, report a partial drain (#25).
	remaining, _ := corrosion.ListVMs(ctx, s.db, "", req.Name)
	var stillRunning int
	for _, vm := range remaining {
		if vm.State == "running" || vm.State == "stopped" {
			stillRunning++
		}
	}
	if stillRunning > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"drain incomplete: %d VM(s) remain on host %q (pinned or no eligible target)",
			stillRunning, req.Name)
	}

	return nil
}

// drainOneVM migrates a single VM to the target host. Returns progress message.
func (s *Server) drainOneVM(ctx context.Context, vm corrosion.VMRecord, target corrosion.HostRecord) *pb.DrainProgress {
	// Acquire per-VM lock to avoid migrating while a backup is in progress (#54).
	unlock := s.lockVM(vm.Name)
	defer unlock()

	// Re-read under lock and act on the CURRENT row, not the queued snapshot:
	// ownership or state may have changed since the drain job was queued, and a stale
	// snapshot could otherwise live-migrate / cold-reassign a VM this daemon no longer
	// owns (split-brain). Everything below uses `fresh`.
	fresh, err := corrosion.GetVM(ctx, s.db, vm.Name)
	if err != nil || fresh == nil {
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped",
			Error: "VM no longer exists"}
	}
	if fresh.State == "backing-up" {
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped",
			Error: "active backup in progress — re-run drain after backup completes"}
	}
	// Only drain a VM we still OWN, in a drainable state. Never act on one that moved
	// off this host (or changed state) after the job was queued — a reassign of a VM
	// running elsewhere would double-run it.
	if fresh.HostName != s.hostName {
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped",
			Error: "VM no longer owned by this host (moved since drain was queued)"}
	}
	if fresh.State != "running" && fresh.State != "stopped" {
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped",
			Error: fmt.Sprintf("VM is %s — not drainable", fresh.State)}
	}

	progress := &pb.DrainProgress{
		VmName:     vm.Name,
		TargetHost: target.Name,
		Status:     "migrating",
	}

	// Determine if this VM can live migrate (shared storage only).
	disks, _ := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	hasLocalOnly := false
	for _, d := range disks {
		if d.StorageType == "local" {
			hasLocalOnly = true
			break
		}
	}

	// Drain moves a VM by either a raw libvirt live-migrate (shared storage) or a
	// stop-and-reassign (cold) — NEITHER carries the host-local NVRAM + swtpm of a
	// Secure-Boot/vTPM VM (and a stale live carry would race the TPM). Refuse such
	// VMs REGARDLESS of storage type (NVRAM is host-local even on shared disks) and
	// point the operator at explicit migration, which captures firmware quiescently
	// and transfers it (G1).
	if usesFirmwareState(fresh.Spec) {
		return &pb.DrainProgress{
			VmName: vm.Name, TargetHost: target.Name, Status: "skipped",
			Error: "Secure Boot / vTPM VM can't be drained automatically (its firmware state isn't transferred) — stop it and migrate it explicitly (`lv migrate " + vm.Name + " --strategy=cold`), which carries the firmware",
		}
	}

	// Split-brain gate, PER-VM re-check: DrainHost gated once up front, but drain is
	// long-running and batch-oriented, so quorum can be lost between VMs. Re-check on
	// the source right before THIS VM's irreversible move (live-migrate, or cold
	// shutdown+reassign below) so a mid-drain quorum loss stops further moves. Placed
	// after the fresh-row read and before any runtime/ownership mutation. Fail-open
	// until split_brain_gate_v1 is cluster-wide.
	if reason, refused := s.execGateRefused(ctx); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		return &pb.DrainProgress{
			VmName: vm.Name, TargetHost: target.Name, Status: "skipped",
			Error: "drain refused: " + reason,
		}
	}

	if fresh.State == "running" && !hasLocalOnly {
		// Live migrate — disks are on shared storage. (Ownership confirmed above.)
		progress.Strategy = pb.MigrateStrategy_MIGRATE_LIVE
		dconnuri := fmt.Sprintf("qemu+tls://%s/system", target.Address)
		if err := s.virt.MigrateToTarget(vm.Name, dconnuri, libvirt.MigrateParams{Live: true}); err != nil {
			slog.Warn("live migration failed during drain, falling back to cold",
				"vm", vm.Name, "error", err)
			// Fall through to cold migration.
		} else {
			corrosion.UpdateVMHost(ctx, s.db, vm.Name, target.Name, "running")
			progress.Status = "done"
			progress.ProgressPct = 100
			return progress
		}
	}

	// Split-brain gate, re-check before the COLD fallback: a failed live migration
	// above can run long enough to lose quorum, and cold migration shuts the VM down
	// and reassigns ownership (irreversible). Re-check so a quorum loss during the
	// live attempt stops the fallback. (Cheap/redundant on the direct-cold path, where
	// the per-VM check above just ran with no long op since.) On refusal the VM is
	// left running on the source (live migration failure leaves the source domain up).
	if reason, refused := s.execGateRefused(ctx); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		return &pb.DrainProgress{
			VmName: vm.Name, TargetHost: target.Name, Status: "skipped",
			Error: "drain refused: " + reason,
		}
	}

	// Cold migration: stop on source (we own it), reassign to target.
	progress.Strategy = pb.MigrateStrategy_MIGRATE_COLD
	if fresh.State == "running" {
		if err := s.virt.ShutdownDomain(vm.Name); err != nil {
			slog.Warn("shutdown failed during drain", "vm", vm.Name, "error", err)
			progress.Status = "error"
			progress.Error = err.Error()
			return progress
		}
	}

	// Reassign VM to target host. Target daemon will pick it up and start it.
	// Ownership was confirmed above (fresh.HostName == s.hostName), so this never
	// yanks a VM running elsewhere.
	if err := corrosion.UpdateVMHost(ctx, s.db, vm.Name, target.Name, "stopped"); err != nil {
		progress.Status = "error"
		progress.Error = err.Error()
		return progress
	}

	progress.Status = "done"
	progress.ProgressPct = 100
	return progress
}

// UndrainHost returns a host from draining/maintenance to active.
func (s *Server) UndrainHost(ctx context.Context, req *pb.UndrainHostRequest) (*pb.Host, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}

	if err := corrosion.UpdateHostState(ctx, s.db, req.Name, "active"); err != nil {
		return nil, status.Errorf(codes.Internal, "update host state: %v", err)
	}
	s.publish("host.undrained", req.Name, "")
	s.audit(ctx, "host.undrain", req.Name, "", "ok")

	return s.InspectHost(ctx, &pb.InspectHostRequest{Name: req.Name})
}

// SetHostLabels sets or removes labels on a host.
func (s *Server) SetHostLabels(ctx context.Context, req *pb.SetHostLabelsRequest) (*pb.Host, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}

	// Load existing labels from DB, merge, then remove requested keys.
	labels := map[string]string{}
	rows, err := s.db.Query(ctx, `SELECT labels FROM hosts WHERE name = ?`, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load host labels: %v", err)
	}
	if len(rows) > 0 {
		if raw := rows[0].String("labels"); raw != "" {
			_ = json.Unmarshal([]byte(raw), &labels)
		}
	}
	for k, v := range req.Labels {
		labels[k] = v
	}
	for _, k := range req.Remove {
		delete(labels, k)
	}

	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal labels: %v", err)
	}

	if err := s.db.Execute(ctx,
		`UPDATE hosts SET labels = ?, updated_at = ? WHERE name = ?`,
		string(labelsJSON), s.db.NowTS(), req.Name,
	); err != nil {
		return nil, status.Errorf(codes.Internal, "update labels: %v", err)
	}

	slog.Info("host labels updated", "host", req.Name, "labels", labels)
	s.publish("host.labels", req.Name, string(labelsJSON))
	s.audit(ctx, "host.labels", req.Name, string(labelsJSON), "ok")

	return s.InspectHost(ctx, &pb.InspectHostRequest{Name: req.Name})
}

// FenceHost forcibly powers off a host via SSH poweroff, then marks it offline.
// If the host has IPMI configured, ipmitool is preferred over SSH.
func (s *Server) FenceHost(ctx context.Context, req *pb.FenceHostRequest) (*pb.FenceResult, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if !req.Confirmed {
		return nil, status.Error(codes.InvalidArgument, "pass --confirmed to fence a host")
	}

	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}

	// confirm_manual_only path: operator has already powered the host off
	// (or otherwise ensured it's not running workloads) and is now telling
	// the cluster to clear the manual-fence-pending state so the failover
	// coordinator can reschedule its VMs. We do NOT execute a fence here.
	if req.ConfirmManualOnly {
		if err := corrosion.UpdateHostState(ctx, s.db, req.Name, "fenced"); err != nil {
			return nil, status.Errorf(codes.Internal, "update host state: %v", err)
		}
		if err := corrosion.InsertFenceLog(ctx, s.db, corrosion.FenceLogRecord{
			ID:       newID(),
			HostName: req.Name,
			Method:   "manual",
			Result:   "manual-confirmed",
			Detail:   "operator confirmation via FenceHost(confirm_manual_only)",
		}); err != nil {
			slog.Warn("manual-confirm log insert failed", "error", err)
		}
		slog.Warn("manual fence confirmed by operator", "host", req.Name)
		s.publish("host.fence-confirmed", req.Name, "manual")
		s.audit(ctx, "host.fence-confirm", req.Name,
			"operator confirmed manual fence", "manual-confirmed")
		return &pb.FenceResult{
			HostName: req.Name,
			Method:   "manual",
			Result:   "manual-confirmed",
			Detail:   "operator confirmation recorded; coordinator may now reschedule",
		}, nil
	}

	fr := fence.Execute(ctx, fence.HostConfig{
		Name:          h.Name,
		Address:       h.Address,
		SSHUser:       h.SSHUser,
		SSHPort:       h.SSHPort,
		FenceStrategy: h.FenceStrategy,
		IPMIAddress:   h.IPMIAddress,
		IPMIUser:      h.IPMIUser,
		IPMIPass:      h.IPMIPass,
		WatchdogDev:   h.WatchdogDev,
	})

	// Always mark offline regardless of fence success.
	if err := corrosion.UpdateHostState(ctx, s.db, req.Name, "offline"); err != nil {
		return nil, status.Errorf(codes.Internal, "update host state: %v", err)
	}

	method := fr.Method
	detail := fr.Detail
	result := "fenced"
	if !fr.Success {
		result = "partial"
		detail = fmt.Sprintf("fence failed (%s); host marked offline in state", fr.Detail)
	}

	// Record in fencing log.
	if logErr := corrosion.InsertFenceLog(ctx, s.db, corrosion.FenceLogRecord{
		ID:       newID(),
		HostName: req.Name,
		Method:   method,
		Result:   result,
		Detail:   detail,
	}); logErr != nil {
		slog.Warn("fence log insert failed", "error", logErr)
	}

	slog.Warn("host fenced", "host", req.Name, "method", method, "result", result)
	s.publish("host.fenced", req.Name, fmt.Sprintf("method=%s result=%s", method, result))
	s.audit(ctx, "host.fence", req.Name, detail, result)

	return &pb.FenceResult{
		HostName: req.Name,
		Method:   method,
		Result:   result,
		Detail:   detail,
	}, nil
}

// ConfigureHost updates host fencing and IPMI configuration.
func (s *Server) ConfigureHost(ctx context.Context, req *pb.ConfigureHostRequest) (*pb.Host, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}

	// Validate fence strategy if provided.
	if req.FenceStrategy != "" {
		switch req.FenceStrategy {
		case "ssh", "ipmi", "watchdog":
		default:
			return nil, status.Errorf(codes.InvalidArgument, "invalid fence strategy %q (valid: ssh, ipmi, watchdog)", req.FenceStrategy)
		}
	}

	// Build SET clauses from non-empty fields.
	sets := []string{}
	args := []interface{}{}
	if req.FenceStrategy != "" {
		sets = append(sets, "fence_strategy = ?")
		args = append(args, req.FenceStrategy)
	}
	if req.IpmiAddress != "" {
		sets = append(sets, "ipmi_address = ?")
		args = append(args, req.IpmiAddress)
	}
	if req.IpmiUser != "" {
		sets = append(sets, "ipmi_user = ?")
		args = append(args, req.IpmiUser)
	}
	if req.IpmiPass != "" {
		sets = append(sets, "ipmi_pass = ?")
		args = append(args, req.IpmiPass)
	}
	if req.WatchdogDev != "" {
		sets = append(sets, "watchdog_dev = ?")
		args = append(args, req.WatchdogDev)
	}
	if req.Role != "" {
		switch req.Role {
		case "worker", "witness":
		default:
			return nil, status.Errorf(codes.InvalidArgument,
				"invalid host role %q (valid: worker, witness)", req.Role)
		}
		// Refuse promotion to witness if the host still has any VMs.
		if req.Role == "witness" {
			vms, err := corrosion.ListVMs(ctx, s.db, "", req.Name)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "list vms on %s: %v", req.Name, err)
			}
			if len(vms) > 0 {
				return nil, status.Errorf(codes.FailedPrecondition,
					"host %q still has %d VM(s); drain before promoting to witness",
					req.Name, len(vms))
			}
		}
		sets = append(sets, "role = ?")
		args = append(args, req.Role)
	}
	if req.Region != "" {
		sets = append(sets, "region = ?")
		args = append(args, req.Region)
	}

	if len(sets) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no fields to update")
	}

	sets = append(sets, "updated_at = ?")
	args = append(args, s.db.NowTS()) // monotonic LWW key (hosts is replicated)
	args = append(args, req.Name)

	query := fmt.Sprintf("UPDATE hosts SET %s WHERE name = ?",
		strings.Join(sets, ", "))
	if err := s.db.Execute(ctx, query, args...); err != nil {
		return nil, status.Errorf(codes.Internal, "update host config: %v", err)
	}

	slog.Info("host configured", "host", req.Name)
	s.audit(ctx, "host.configure", req.Name, fmt.Sprintf("fields=%d", len(sets)-1), "ok")

	return s.InspectHost(ctx, &pb.InspectHostRequest{Name: req.Name})
}

// RemoveHost removes a host from the cluster. If force is false and the host
// has running VMs, the request is rejected. CRL revocation is handled here.
func (s *Server) RemoveHost(ctx context.Context, req *pb.RemoveHostRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}

	// Check for VMs on this host.
	vms, _ := corrosion.ListVMs(ctx, s.db, "", req.Name)
	if len(vms) > 0 && !req.Force {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %q has %d VMs — drain first or use --force", req.Name, len(vms))
	}

	// Soft-delete the host and clean up related records.
	if err := corrosion.DeleteHost(ctx, s.db, req.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "delete host: %v", err)
	}

	slog.Warn("host removed from cluster", "host", req.Name, "cert_serial", h.CertSerial)
	s.publish("host.removed", req.Name, "cert_serial="+h.CertSerial)

	return &emptypb.Empty{}, nil
}

func (s *Server) hostAllocatedResources(ctx context.Context, hostName string) (cpuUsed, memUsed int32, diskUsedGiB int64) {
	vms, _ := corrosion.ListVMs(ctx, s.db, "", hostName)
	for _, vm := range vms {
		if vm.State == "running" {
			cpuUsed += int32(vm.CPUActual)
			memUsed += int32(vm.MemActual)
		}
	}
	// Sum disk allocations (all VMs, not just running — disk is allocated regardless of state).
	rows, err := s.db.Query(ctx,
		`SELECT COALESCE(SUM(size_bytes),0) as disk_bytes FROM vm_disks WHERE host_name = ? AND deleted_at IS NULL`,
		hostName)
	if err == nil && len(rows) > 0 {
		diskUsedGiB = int64(rows[0].Int("disk_bytes")) / (1024 * 1024 * 1024)
	}
	return
}

// hostStateToPB maps a stored hosts.state string to the wire enum for display.
// Critically it must never report a non-active host as HOST_ACTIVE: a fenced
// (forcibly isolated after failover) or upgrading host shown as ACTIVE would
// hide a dead/transitioning node from operators. There is no HOST_FENCED /
// HOST_UPGRADING enum yet (would need a proto bump), so fenced maps to the
// honest "unavailable" state OFFLINE and upgrading to the transitional DRAINING.
// The default fails safe to OFFLINE so an unknown/future state can't masquerade
// as healthy.
func hostStateToPB(s string) pb.HostState {
	switch s {
	case "active":
		return pb.HostState_HOST_ACTIVE
	case "draining", "upgrading":
		return pb.HostState_HOST_DRAINING
	case "maintenance":
		return pb.HostState_HOST_MAINTENANCE
	case "suspect":
		return pb.HostState_HOST_SUSPECT
	case "offline", "fenced":
		return pb.HostState_HOST_OFFLINE
	default:
		return pb.HostState_HOST_OFFLINE
	}
}

func parseTimestamp(s string) *timestamppb.Timestamp {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return timestamppb.New(t)
}

// newID generates a random 8-byte hex ID.
func newID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
