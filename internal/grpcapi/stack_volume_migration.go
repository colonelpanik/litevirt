package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
)

// defaultStackHealthWait caps the inter-VM health gate when the request
// leaves health_wait_seconds at 0.
const defaultStackHealthWait = 60 * time.Second

// diskPlan is one resolved per-disk migration unit.
type diskPlan struct {
	disk       corrosion.DiskRecord
	targetPool string // "" => unresolved (preflight flags it)
	skip       bool   // already on target pool — nothing to do
	skipReason string
}

// vmPlan groups a VM with the per-disk moves planned for it. A VM is the
// unit of the rolling rollout: all its disks migrate before it counts done.
type vmPlan struct {
	vm    corrosion.VMRecord
	disks []diskPlan
}

// MigrateStackVolumes migrates every disk of every VM in a stack to a
// (per-VM/per-disk) target storage pool. It is an orchestration layer over
// the same-host MoveVolume primitive: it enumerates the stack's VMs,
// resolves a target pool per disk, preflights the whole plan, then rolls the
// moves out one VM at a time by default — dispatching each per-disk move to
// the VM's owning host (locally via moveOneVolume, remotely via a peer
// MoveVolume RPC). Running VMs migrate online (blockdev-mirror); stopped VMs
// use the offline convert path. File-based pools only.
func (s *Server) MigrateStackVolumes(req *pb.MigrateStackVolumesRequest, stream grpc.ServerStreamingServer[pb.StackVolumeProgress]) error {
	ctx := stream.Context()
	if req.StackName == "" {
		return status.Error(codes.InvalidArgument, "stack_name required")
	}
	if err := safename.ValidateStackName(req.StackName); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if req.DefaultPool == "" && len(req.Placements) == 0 {
		return status.Error(codes.InvalidArgument, "default_pool or at least one placement required")
	}
	if err := s.RequirePerm(ctx, stackRBACPath(req.StackName), "stack.move-volumes", "operator"); err != nil {
		return err
	}

	// 1. Enumerate stack members.
	vms, err := corrosion.ListVMs(ctx, s.db, req.StackName, "")
	if err != nil {
		return status.Errorf(codes.Internal, "list stack VMs: %v", err)
	}
	if len(vms) == 0 {
		return status.Errorf(codes.NotFound, "stack %q has no VMs", req.StackName)
	}

	// 2. Order the VMs.
	ordered, err := orderStackVMs(vms, req.Order)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	// 3. Resolve per-disk target pools.
	plans, err := s.resolveStackPlan(ctx, ordered, req)
	if err != nil {
		return err
	}
	vmsTotal := int32(len(plans))

	// 4. Preflight (no mutations). Surface every blocker at once; stream
	//    non-fatal warnings (e.g. capacity) before doing any work.
	problems, warnings := s.preflightStackPlan(ctx, plans)
	for _, w := range warnings {
		if err := stream.Send(&pb.StackVolumeProgress{
			Stage:    pb.StackVolumeProgress_PLANNING,
			Status:   "warning: " + w,
			VmsTotal: vmsTotal,
		}); err != nil {
			return err
		}
	}
	if len(problems) > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"preflight failed:\n  - %s", strings.Join(problems, "\n  - "))
	}

	// 5. Dry-run: stream the resolved plan and stop.
	if req.DryRun {
		for _, vp := range plans {
			for _, dp := range vp.disks {
				frame := &pb.StackVolumeProgress{
					VmName:   vp.vm.Name,
					DiskName: dp.disk.DiskName,
					HostName: vp.vm.HostName,
					Stage:    pb.StackVolumeProgress_PLANNING,
					VmsTotal: vmsTotal,
				}
				if dp.skip {
					frame.Stage = pb.StackVolumeProgress_SKIPPED
					frame.Status = dp.skipReason
				} else {
					mode := "offline"
					if vp.vm.State == "running" {
						mode = "online"
					}
					frame.Status = fmt.Sprintf("would move → pool %q (%s)", dp.targetPool, mode)
				}
				if err := stream.Send(frame); err != nil {
					return err
				}
			}
		}
		return stream.Send(&pb.StackVolumeProgress{
			Stage:    pb.StackVolumeProgress_COMPLETE,
			Status:   "dry-run complete",
			VmsTotal: vmsTotal,
			VmsDone:  vmsTotal,
		})
	}

	// 6. Execute the rolling rollout.
	return s.executeStackMigration(ctx, stream, plans, req, vmsTotal)
}

// orderStackVMs returns the stack VMs in execution order. With no explicit
// order it preserves listing order. An explicit order must reference only
// stack members; listed VMs go first (in the given order), the rest follow
// in listing order.
func orderStackVMs(vms []corrosion.VMRecord, order []string) ([]corrosion.VMRecord, error) {
	if len(order) == 0 {
		return vms, nil
	}
	byName := make(map[string]corrosion.VMRecord, len(vms))
	for _, vm := range vms {
		byName[vm.Name] = vm
	}
	var out []corrosion.VMRecord
	seen := map[string]bool{}
	for _, name := range order {
		vm, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("order references %q, which is not a VM in this stack", name)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, vm)
	}
	for _, vm := range vms {
		if !seen[vm.Name] {
			out = append(out, vm)
		}
	}
	return out, nil
}

// resolveStackPlan builds the per-VM/per-disk plan, resolving each disk's
// target pool by most-specific-wins precedence (disk-level placement >
// vm-level placement > default_pool) and marking disks already on target
// as skips.
func (s *Server) resolveStackPlan(ctx context.Context, vms []corrosion.VMRecord, req *pb.MigrateStackVolumesRequest) ([]vmPlan, error) {
	knownVMs := map[string]struct{}{}
	for _, vm := range vms {
		knownVMs[vm.Name] = struct{}{}
	}
	diskLevel := map[string]map[string]string{} // vm -> disk -> pool
	vmLevel := map[string]string{}              // vm -> pool
	for _, pl := range req.Placements {
		if pl.VmName == "" || pl.TargetPool == "" {
			return nil, status.Error(codes.InvalidArgument, "each placement needs vm_name and target_pool")
		}
		if _, ok := knownVMs[pl.VmName]; !ok {
			return nil, status.Errorf(codes.InvalidArgument, "placement references unknown vm %q", pl.VmName)
		}
		if pl.DiskName == "" {
			if _, exists := vmLevel[pl.VmName]; exists {
				return nil, status.Errorf(codes.InvalidArgument, "duplicate placement for vm %q", pl.VmName)
			}
			vmLevel[pl.VmName] = pl.TargetPool
			continue
		}
		if diskLevel[pl.VmName] == nil {
			diskLevel[pl.VmName] = map[string]string{}
		}
		if _, exists := diskLevel[pl.VmName][pl.DiskName]; exists {
			return nil, status.Errorf(codes.InvalidArgument, "duplicate placement for disk %q on vm %q", pl.DiskName, pl.VmName)
		}
		diskLevel[pl.VmName][pl.DiskName] = pl.TargetPool
	}
	resolve := func(vm, disk string) string {
		if m := diskLevel[vm]; m != nil {
			if p, ok := m[disk]; ok {
				return p
			}
		}
		if p, ok := vmLevel[vm]; ok {
			return p
		}
		return req.DefaultPool
	}

	var plans []vmPlan
	for _, vm := range vms {
		disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list disks for %q: %v", vm.Name, err)
		}
		if targets := diskLevel[vm.Name]; len(targets) > 0 {
			knownDisks := map[string]struct{}{}
			for _, d := range disks {
				knownDisks[d.DiskName] = struct{}{}
			}
			for disk := range targets {
				if _, ok := knownDisks[disk]; !ok {
					return nil, status.Errorf(codes.InvalidArgument, "placement references unknown disk %q on vm %q", disk, vm.Name)
				}
			}
		}
		vp := vmPlan{vm: vm}
		for _, d := range disks {
			dp := diskPlan{disk: d, targetPool: resolve(vm.Name, d.DiskName)}
			if dp.targetPool != "" && d.StorageVolume == dp.targetPool {
				dp.skip = true
				dp.skipReason = fmt.Sprintf("already on pool %q", dp.targetPool)
			}
			vp.disks = append(vp.disks, dp)
		}
		plans = append(plans, vp)
	}
	return plans, nil
}

// preflightStackPlan validates the plan without mutating anything. It
// returns blocking problems (which abort the run) and non-fatal warnings
// (streamed, e.g. tight capacity). Pool lookups are cached per (host, pool).
func (s *Server) preflightStackPlan(ctx context.Context, plans []vmPlan) (problems, warnings []string) {
	type poolKey struct{ host, pool string }
	poolCache := map[poolKey]*corrosion.StoragePoolRecord{}
	lookupPool := func(host, pool string) (*corrosion.StoragePoolRecord, bool) {
		k := poolKey{host, pool}
		if rec, cached := poolCache[k]; cached {
			return rec, rec != nil
		}
		rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, pool)
		if err != nil || !ok {
			poolCache[k] = nil
			return nil, false
		}
		poolCache[k] = &rec
		return &rec, true
	}

	need := map[poolKey]int64{} // bytes landing per (host, pool)
	for _, vp := range plans {
		for _, dp := range vp.disks {
			if dp.skip {
				continue
			}
			who := fmt.Sprintf("%s/%s", vp.vm.Name, dp.disk.DiskName)
			if dp.targetPool == "" {
				problems = append(problems, fmt.Sprintf("%s: no target pool (set --to or a --map rule)", who))
				continue
			}
			if !isFileBasedDriver(dp.disk.StorageType) {
				problems = append(problems, fmt.Sprintf(
					"%s: source pool driver %q not supported (file-based pools only: local/dir/nfs/btrfs)",
					who, dp.disk.StorageType))
			}
			rec, ok := lookupPool(vp.vm.HostName, dp.targetPool)
			if !ok {
				problems = append(problems, fmt.Sprintf(
					"%s: target pool %q is not configured on host %q (which owns %s)",
					who, dp.targetPool, vp.vm.HostName, vp.vm.Name))
				continue
			}
			if !isFileBasedDriver(rec.Driver) {
				problems = append(problems, fmt.Sprintf(
					"%s: target pool %q driver %q not supported (file-based pools only)",
					who, dp.targetPool, rec.Driver))
				continue
			}
			need[poolKey{vp.vm.HostName, dp.targetPool}] += dp.disk.SizeBytes
		}
	}

	for k, bytes := range need {
		rec, ok := poolCache[k]
		if !ok || rec == nil || rec.TotalBytes <= 0 {
			continue // capacity unknown — don't guess
		}
		if free := rec.TotalBytes - rec.UsedBytes; bytes > free {
			warnings = append(warnings, fmt.Sprintf(
				"pool %q on host %q may be short: need %d bytes, ~%d free",
				k.pool, k.host, bytes, free))
		}
	}
	return problems, warnings
}

// executeStackMigration runs the rolling rollout. parallel bounds how many
// VMs migrate at once (default 1 => strictly sequential in plan order). The
// first VM failure stops further VMs from being scheduled; already-migrated
// disks stay migrated (each move is atomic), so a re-run resumes.
func (s *Server) executeStackMigration(ctx context.Context, stream grpc.ServerStreamingServer[pb.StackVolumeProgress], plans []vmPlan, req *pb.MigrateStackVolumesRequest, vmsTotal int32) error {
	parallel := int(req.Parallel)
	if parallel < 1 {
		parallel = 1
	}
	healthWait := time.Duration(req.HealthWaitSeconds) * time.Second
	if healthWait <= 0 {
		healthWait = defaultStackHealthWait
	}

	// gRPC streams are not safe for concurrent Send; serialize all frames.
	var sendMu sync.Mutex
	safeSend := func(p *pb.StackVolumeProgress) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(p)
	}

	var (
		mu       sync.Mutex
		firstErr error
		aborted  bool
		vmsDone  atomic.Int32
		moved    atomic.Int32
		skipped  atomic.Int32
	)
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup

	for i := range plans {
		mu.Lock()
		stop := aborted
		mu.Unlock()
		if stop {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(vp vmPlan) {
			defer wg.Done()
			defer func() { <-sem }()
			mu.Lock()
			stop := aborted
			mu.Unlock()
			if stop {
				return
			}
			err := s.migrateVMVolumes(ctx, safeSend, vp, req.DeleteSource, healthWait, vmsTotal, &vmsDone, &moved, &skipped)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				aborted = true
				mu.Unlock()
			}
		}(plans[i])
	}
	wg.Wait()

	summary := fmt.Sprintf("migrated %d disk(s), skipped %d, %d/%d VMs done",
		moved.Load(), skipped.Load(), vmsDone.Load(), vmsTotal)
	if firstErr != nil {
		_ = safeSend(&pb.StackVolumeProgress{
			Stage:    pb.StackVolumeProgress_ERROR,
			Status:   "stack migration aborted: " + summary,
			Error:    firstErr.Error(),
			VmsTotal: vmsTotal,
			VmsDone:  vmsDone.Load(),
		})
		return firstErr
	}
	return safeSend(&pb.StackVolumeProgress{
		Stage:    pb.StackVolumeProgress_COMPLETE,
		Status:   summary,
		VmsTotal: vmsTotal,
		VmsDone:  vmsDone.Load(),
	})
}

// migrateVMVolumes migrates all of one VM's disks, then runs the inter-VM
// health gate. Local disks go through moveOneVolume; remote disks through a
// peer MoveVolume RPC. The first disk error aborts the VM.
func (s *Server) migrateVMVolumes(
	ctx context.Context,
	safeSend func(*pb.StackVolumeProgress) error,
	vp vmPlan,
	deleteSource bool,
	healthWait time.Duration,
	vmsTotal int32,
	vmsDone, moved, skipped *atomic.Int32,
) error {
	for _, dp := range vp.disks {
		if dp.skip {
			skipped.Add(1)
			if err := safeSend(&pb.StackVolumeProgress{
				VmName:   vp.vm.Name,
				DiskName: dp.disk.DiskName,
				HostName: vp.vm.HostName,
				Stage:    pb.StackVolumeProgress_SKIPPED,
				Status:   dp.skipReason,
				VmsTotal: vmsTotal,
				VmsDone:  vmsDone.Load(),
			}); err != nil {
				return err
			}
			continue
		}

		// Translate inner MoveVolume frames into stack-level frames.
		sink := func(p *pb.MoveVolumeProgress) error {
			return safeSend(&pb.StackVolumeProgress{
				VmName:      vp.vm.Name,
				DiskName:    dp.disk.DiskName,
				HostName:    vp.vm.HostName,
				Stage:       pb.StackVolumeProgress_PER_DISK,
				Phase:       p.Phase.String(),
				CopyPct:     p.CopyPct,
				BytesCopied: p.BytesCopied,
				BytesTotal:  p.BytesTotal,
				Status:      p.Status,
				Error:       p.Error,
				VmsTotal:    vmsTotal,
				VmsDone:     vmsDone.Load(),
			})
		}

		var err error
		if vp.vm.HostName == s.hostName {
			vm := vp.vm
			disk := dp.disk
			err = s.moveOneVolume(ctx, &vm, &disk, dp.targetPool, deleteSource, sink)
		} else {
			err = s.moveRemoteVolume(ctx, vp.vm.HostName, vp.vm.Name, dp.disk.DiskName, dp.targetPool, deleteSource, sink)
		}
		if err != nil {
			_ = safeSend(&pb.StackVolumeProgress{
				VmName:   vp.vm.Name,
				DiskName: dp.disk.DiskName,
				HostName: vp.vm.HostName,
				Stage:    pb.StackVolumeProgress_ERROR,
				Status:   fmt.Sprintf("move %s/%s failed", vp.vm.Name, dp.disk.DiskName),
				Error:    err.Error(),
				VmsTotal: vmsTotal,
				VmsDone:  vmsDone.Load(),
			})
			return fmt.Errorf("migrate %s/%s: %w", vp.vm.Name, dp.disk.DiskName, err)
		}
		moved.Add(1)
	}

	// Inter-VM health gate: confirm the VM is still serving before the next
	// one starts. Online moves never stop the VM, so this is a fast confirm;
	// it matters for the offline (stopped→running) path. Best-effort.
	if err := s.stackHealthGate(ctx, safeSend, vp.vm, healthWait, vmsTotal, vmsDone); err != nil {
		return err
	}

	vmsDone.Add(1)
	return safeSend(&pb.StackVolumeProgress{
		VmName:   vp.vm.Name,
		HostName: vp.vm.HostName,
		Stage:    pb.StackVolumeProgress_VM_DONE,
		Status:   fmt.Sprintf("all disks migrated for %s", vp.vm.Name),
		VmsTotal: vmsTotal,
		VmsDone:  vmsDone.Load(),
	})
}

// moveRemoteVolume drives a single disk move on the VM's owning host via a
// peer MoveVolume RPC, relaying each progress frame through sink.
func (s *Server) moveRemoteVolume(ctx context.Context, host, vmName, diskName, targetPool string, deleteSource bool, sink func(*pb.MoveVolumeProgress) error) error {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return fmt.Errorf("connect to host %q: %w", host, err)
	}
	defer conn.Close()

	rs, err := client.MoveVolume(ctx, &pb.MoveVolumeRequest{
		VmName:       vmName,
		DiskName:     diskName,
		TargetPool:   targetPool,
		DeleteSource: deleteSource,
	})
	if err != nil {
		return err
	}
	for {
		frame, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			return nil // clean end-of-stream — the remote move finished
		}
		if err != nil {
			return err
		}
		if err := sink(frame); err != nil {
			return err
		}
	}
}

// stackHealthGate waits (best-effort, up to timeout) for a VM that was
// running to report running again after its disks moved, so the rollout
// doesn't advance past a VM that fell over. Stopped VMs need no gate.
func (s *Server) stackHealthGate(ctx context.Context, safeSend func(*pb.StackVolumeProgress) error, vm corrosion.VMRecord, timeout time.Duration, vmsTotal int32, vmsDone *atomic.Int32) error {
	if vm.State != "running" {
		return nil
	}
	if err := safeSend(&pb.StackVolumeProgress{
		VmName:   vm.Name,
		HostName: vm.HostName,
		Stage:    pb.StackVolumeProgress_HEALTH_GATE,
		Status:   "waiting for VM to be healthy before next",
		VmsTotal: vmsTotal,
		VmsDone:  vmsDone.Load(),
	}); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		cur, err := corrosion.GetVM(ctx, s.db, vm.Name)
		if err == nil && cur != nil && cur.State == "running" {
			return nil
		}
		if time.Now().After(deadline) {
			return nil // best-effort: don't fail the rollout on a slow health read
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
