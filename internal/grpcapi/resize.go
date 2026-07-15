package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

const (
	// resizeApplyAttempts bounds the synchronous retry of an incomplete dimension
	// before the operation is left nonterminal for recovery.
	resizeApplyAttempts = 3
	// resourceRecoveryInterval is the reconciler cadence for resuming resize
	// operations that crashed after committing their desired spec.
	resourceRecoveryInterval = 60 * time.Second
)

// resizeVMLive is the single lock-owning combined live-resize coordinator: it grows
// vCPUs (within the running hotplug ceiling) and/or reballoons memory (within the
// domain's band) in ONE operation. It takes the FULL desired spec but applies ONLY
// the cpu and memory dimensions onto a fresh clone of the STORED spec — so a live
// resize never clobbers server-owned fields (UUID / resolved MACs / addresses /
// unknown fields). Callers must NOT hold the VM lock. Returns nil when there is
// nothing to do.
func (s *Server) resizeVMLive(ctx context.Context, name string, desired *pb.VMSpec, idemKey string) error {
	unlock := s.lockVM(name)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", name)
	}
	if vm.HostName != s.hostName {
		return status.Errorf(codes.Aborted, "ownership of %q moved to %s mid-operation; retry", name, vm.HostName)
	}
	if vm.ActiveOperationID != "" {
		return status.Errorf(codes.FailedPrecondition, "cannot resize %q: an operation is in progress", name)
	}
	if vm.State != "running" {
		return status.Errorf(codes.FailedPrecondition, "VM %q must be running to live-resize (current: %s)", name, vm.State)
	}

	stored := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), stored); err != nil {
			return status.Errorf(codes.Internal, "parse stored spec: %v", err)
		}
	}

	wantCPU := desired.Cpu
	if wantCPU == 0 {
		wantCPU = stored.Cpu
	}
	wantMem := desired.MemoryMib
	if wantMem == 0 {
		wantMem = stored.MemoryMib
	}
	cpuDelta := int(wantCPU) - int(stored.Cpu)
	memDelta := int(wantMem) - int(stored.MemoryMib)
	if cpuDelta == 0 && memDelta == 0 {
		return nil
	}

	// Preflight BOTH dimensions BEFORE mutating either — a change that can't be
	// applied live is a Restart-class refusal, never a partial apply.
	if cpuDelta != 0 {
		if wantCPU < stored.Cpu {
			return status.Errorf(codes.FailedPrecondition,
				"live resize only grows vCPUs; stop %q to shrink from %d to %d", name, stored.Cpu, wantCPU)
		}
		if stored.Resources != nil && len(stored.Resources.CpuPinning) > 0 {
			return status.Errorf(codes.FailedPrecondition,
				"VM %q has pinned vCPUs and cannot live-grow CPUs; stop it and update, or pass --restart-if-needed", name)
		}
		inactiveXML, xerr := s.virt.DumpXMLInactive(name)
		if xerr != nil {
			return status.Errorf(codes.Internal, "read domain XML for %q: %v", name, xerr)
		}
		if ceiling := lv.MaxVCPUFromXML(inactiveXML); ceiling < int(wantCPU) {
			return status.Errorf(codes.FailedPrecondition,
				"VM %q boots with a vCPU ceiling of %d; growing to %d needs a restart — set max_cpu (≥%d) and restart, or pass --restart-if-needed",
				name, ceiling, wantCPU, wantCPU)
		}
	}
	if memDelta != 0 {
		ceiling := stored.MaxMemoryMib
		if ceiling == 0 {
			ceiling = stored.MemoryMib
		}
		if wantMem > ceiling {
			return status.Errorf(codes.FailedPrecondition,
				"live resize target %d MiB exceeds %q's balloon ceiling %d MiB; raise max-memory and restart", wantMem, name, ceiling)
		}
		if stored.MinMemoryMib > 0 && wantMem < stored.MinMemoryMib {
			return status.Errorf(codes.FailedPrecondition,
				"live resize target %d MiB is below %q's minimum %d MiB", wantMem, name, stored.MinMemoryMib)
		}
	}

	// Admission (F2): the grow must fit host free capacity + project quota. Only
	// positive deltas consume capacity (a balloon-down / shrink frees it).
	if err := s.checkResourceAdmission(ctx, vm.HostName, vm.Project, posOnly(cpuDelta), posOnly(memDelta)); err != nil {
		return err
	}

	target := proto.Clone(stored).(*pb.VMSpec)
	target.Cpu = wantCPU
	target.MemoryMib = wantMem

	// Observe the changed dimension(s) at the new value; keep the untouched
	// dimension's real actual (a cpu-only grow must not clobber a ballooned mem_actual).
	obsCPU := vm.CPUActual
	if cpuDelta != 0 {
		obsCPU = int(wantCPU)
	}
	obsMem := vm.MemActual
	if memDelta != 0 {
		obsMem = int(wantMem)
	}

	if s.operationProtocolActive(ctx) {
		return s.resizeVMLiveCoordinated(ctx, vm, stored, target, obsCPU, obsMem, idemKey)
	}

	// Pre-latch direct path: apply persistent-then-live (per the fixed primitives),
	// then persist the desired spec + observed actuals under the barrier discipline.
	// Documented best-effort — no F1 durability/recovery.
	if err := s.applyLiveResize(ctx, name, target, stored); err != nil {
		return status.Errorf(codes.Internal, "live resize: %v", err)
	}
	applied, newGen, err := corrosion.MutateDesiredSpec(ctx, s.db, name, func(old string) (string, error) {
		fresh := &pb.VMSpec{}
		if old != "" {
			if uerr := json.Unmarshal([]byte(old), fresh); uerr != nil {
				return "", uerr
			}
		}
		fresh.Cpu = wantCPU
		fresh.MemoryMib = wantMem
		b, merr := json.Marshal(fresh)
		return string(b), merr
	})
	if err != nil {
		return status.Errorf(codes.Internal, "persist resize: %v", err)
	}
	if !applied {
		return status.Errorf(codes.FailedPrecondition, "cannot resize %q: an operation is in progress", name)
	}
	if _, err := corrosion.UpdateObservedActuals(ctx, s.db, name, obsCPU, obsMem, vm.OwnerEpoch, newGen); err != nil {
		slog.Error("resizeVMLive: persisting actuals failed — accounting will lag until reconciled", "vm", name, "error", err)
	}
	slog.Info("vm live-resized", "vm", name, "cpu", wantCPU, "mem_mib", wantMem)
	s.recordVMEvent(ctx, name, "vm.resized", "ok", fmt.Sprintf("cpu=%d mem=%dMiB", wantCPU, wantMem))
	return nil
}

// resizeVMLiveCoordinated is the post-latch (operation_protocol) combined resize: ONE
// BeginVMOperation atomically commits the full desired spec (cpu+mem), bumps the
// generation, and claims the mutation barrier; the apply then runs under the F1
// durability discipline. Caller holds the VM lock.
func (s *Server) resizeVMLiveCoordinated(ctx context.Context, vm *corrosion.VMRecord, stored, target *pb.VMSpec, obsCPU, obsMem int, idemKey string) error {
	principal := callerUsername(ctx) + "@" + callerRealm(ctx)
	_, _ = s.ensureProjectAuthority(ctx, vm.Project) // best-effort D1 authority establishment

	cpuDelta := posOnly(int(target.Cpu) - int(stored.Cpu))
	memDelta := posOnly(int(target.MemoryMib) - int(stored.MemoryMib))
	rv := corrosion.ReservationVector{
		Project: vm.Project, ProjectCPU: cpuDelta, ProjectMemMiB: memDelta,
		TargetHost: vm.HostName, TargetCPU: cpuDelta, TargetMemMiB: memDelta,
	}
	resJSON, err := rv.Encode()
	if err != nil {
		return status.Errorf(codes.Internal, "encode reservation: %v", err)
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		return status.Errorf(codes.Internal, "marshal spec: %v", err)
	}
	if idemKey == "" {
		// No client key: mint a per-attempt id so distinct resizes never collide on
		// one deterministic operation id (each deploy attempt is its own operation).
		idemKey = uuid.NewString()
	}

	op := corrosion.OperationRecord{
		ID:              corrosion.DeterministicOperationID("ResizeVMLive", principal, vm.Project, vm.Name, idemKey),
		Method:          "ResizeVMLive",
		Principal:       principal,
		Project:         vm.Project,
		ResourceKind:    "vm",
		ResourceID:      vm.Name,
		OperationKind:   string(corrosion.OpResourceUpdateRunning),
		RequestHash:     resizeRequestHash(vm.Name, target.Cpu, target.MemoryMib),
		IdempotencyKey:  idemKey,
		ReservationJSON: resJSON,
	}
	applied, err := s.db.BeginVMOperation(ctx, op, string(targetJSON), vm.OwnerEpoch, vm.SpecGeneration)
	if err != nil {
		if errors.Is(err, corrosion.ErrOperationHashConflict) {
			return status.Errorf(codes.AlreadyExists, "idempotency key reused with a different resize for %q", vm.Name)
		}
		return status.Errorf(codes.Internal, "begin operation: %v", err)
	}
	if !applied {
		return status.Errorf(codes.FailedPrecondition, "cannot resize %q: an operation is in progress or the VM changed underneath", vm.Name)
	}
	newGen := vm.SpecGeneration + 1
	return s.driveResourceUpdate(ctx, vm, op.ID, vm.OwnerEpoch, newGen, target, stored, obsCPU, obsMem)
}

// driveResourceUpdate applies target cpu+mem to a VM whose mutation barrier is
// ALREADY held by opID (freshly begun, or found by recovery), records the operation
// steps, persists observed actuals, and completes the operation. The desired spec is
// already committed durably (BeginVMOperation), so the operation is DURABLE, not
// runtime-atomic: on an apply failure it is left NONTERMINAL (recoverable) — never
// aborted, never force-completed — and startup/reconciler recovery resumes it toward
// the committed desired spec. applyPrev selects which dimensions still need applying
// (stored for the first attempt, observed actuals for recovery). Caller holds the
// VM lock.
func (s *Server) driveResourceUpdate(ctx context.Context, vm *corrosion.VMRecord, opID string, ownerEpoch, newGen int64, target, applyPrev *pb.VMSpec, obsCPU, obsMem int) error {
	s.appendOpStep(ctx, opID, ownerEpoch, corrosion.OpResourceUpdateRunning, corrosion.OpStepDesiredPersisted)

	var applyErr error
	for attempt := 0; attempt < resizeApplyAttempts; attempt++ {
		if applyErr = s.applyLiveResize(ctx, vm.Name, target, applyPrev); applyErr == nil {
			break
		}
	}
	if applyErr != nil {
		// Persistent-config failure or an incomplete dimension: leave the operation
		// nonterminal for recovery (desired is already committed) — do NOT abort.
		slog.Error("resize: apply incomplete after retries — operation left recoverable", "vm", vm.Name, "op", opID, "error", applyErr)
		return status.Errorf(codes.Internal, "live resize partially applied for %q; recovery will converge: %v", vm.Name, applyErr)
	}
	s.appendOpStep(ctx, opID, ownerEpoch, corrosion.OpResourceUpdateRunning, corrosion.OpStepConfigApplied)
	s.appendOpStep(ctx, opID, ownerEpoch, corrosion.OpResourceUpdateRunning, corrosion.OpStepLiveApplied)

	if _, err := corrosion.UpdateObservedActuals(ctx, s.db, vm.Name, obsCPU, obsMem, ownerEpoch, newGen); err != nil {
		slog.Error("resize: persisting actuals failed — accounting will lag until reconciled", "vm", vm.Name, "error", err)
	}
	s.appendOpStep(ctx, opID, ownerEpoch, corrosion.OpResourceUpdateRunning, corrosion.OpStepObserved)

	if _, err := s.db.CompleteVMOperation(ctx, vm.Name, opID, ownerEpoch, newGen); err != nil {
		slog.Error("resize: completing operation failed — recovery will reconcile", "vm", vm.Name, "op", opID, "error", err)
	}
	slog.Info("vm live-resized (coordinated)", "vm", vm.Name, "cpu", target.Cpu, "mem_mib", target.MemoryMib)
	s.recordVMEvent(ctx, vm.Name, "vm.resized", "ok", fmt.Sprintf("cpu=%d mem=%dMiB", target.Cpu, target.MemoryMib))
	return nil
}

// applyLiveResize applies the changed dimensions to the domain via the config-first
// libvirt primitives (persistent config first, then live, then verify). A dimension
// whose target already equals applyPrev is skipped. The primitives are idempotent,
// so re-running this during recovery is safe.
func (s *Server) applyLiveResize(ctx context.Context, name string, target, applyPrev *pb.VMSpec) error {
	if target.Cpu != applyPrev.Cpu {
		if err := s.virt.SetVCPUs(name, int(target.Cpu)); err != nil {
			return fmt.Errorf("vcpus: %w", err)
		}
	}
	if target.MemoryMib != applyPrev.MemoryMib {
		if err := s.virt.SetMemory(name, int(target.MemoryMib)); err != nil {
			return fmt.Errorf("memory: %w", err)
		}
	}
	return nil
}

// applyLiveMetadata patches ONLY the named live-metadata fields from `desired` onto
// the VM's stored spec, via MutateDesiredSpec (barrier-respecting, applied to the
// FRESH stored spec). It must never overwrite the whole spec — that would discard
// server-owned fields (UUID, resolved addresses/MACs, unknown fields). The reconciler
// / vmcheck read these fields fresh each sweep, so no domain redefine is needed.
func (s *Server) applyLiveMetadata(ctx context.Context, name string, desired *pb.VMSpec, fields []string) error {
	if len(fields) == 0 {
		return nil
	}
	applied, _, err := corrosion.MutateDesiredSpec(ctx, s.db, name, func(old string) (string, error) {
		fresh := &pb.VMSpec{}
		if old != "" {
			if uerr := json.Unmarshal([]byte(old), fresh); uerr != nil {
				return "", uerr
			}
		}
		for _, f := range fields {
			switch f {
			case "restart":
				fresh.Restart = desired.Restart
			case "onboot":
				fresh.Onboot = desired.Onboot
			case "startup_order":
				fresh.StartupOrder = desired.StartupOrder
			case "start_delay":
				fresh.StartDelaySec = desired.StartDelaySec
			case "stop_delay":
				fresh.StopDelaySec = desired.StopDelaySec
			case "labels":
				fresh.Labels = desired.Labels
			case "placement":
				fresh.Placement = desired.Placement
			case "migrate":
				fresh.Migrate = desired.Migrate
			default:
				slog.Warn("applyLiveMetadata: ignoring unknown live-metadata field", "vm", name, "field", f)
			}
		}
		b, merr := json.Marshal(fresh)
		return string(b), merr
	})
	if err != nil {
		return status.Errorf(codes.Internal, "apply live metadata for %q: %v", name, err)
	}
	if !applied {
		return status.Errorf(codes.FailedPrecondition, "cannot update %q: an operation is in progress", name)
	}
	slog.Info("vm live metadata applied", "vm", name, "fields", fields)
	s.recordVMEvent(ctx, name, "vm.updated", "ok", fmt.Sprintf("live metadata: %v", fields))
	return nil
}

// appendOpStep appends a legal step to an operation, logging (never failing the
// caller) on an illegal step or a write error — a lost step is reduced correctly on
// the next observe/recovery.
func (s *Server) appendOpStep(ctx context.Context, opID string, ownerEpoch int64, kind corrosion.OperationKind, step string) {
	if !corrosion.IsLegalStep(kind, step) {
		slog.Error("resize: refusing to append illegal operation step", "op", opID, "kind", kind, "step", step)
		return
	}
	if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
		OperationID: opID, OwnerEpoch: ownerEpoch, StepName: step,
	}); err != nil {
		slog.Warn("resize: append operation step", "op", opID, "step", step, "error", err)
	}
}

// RecoverResourceOperations resumes locally-owned VMs whose mutation barrier points
// at a NONTERMINAL resource_update_running operation — a resize that crashed after
// committing its desired spec but before observing/completing. It converges the
// domain to the committed desired spec and completes the operation, so a partial
// failure converges instead of wedging active_operation_id. It takes the VM lock per
// VM (serializing with any in-flight resize) and re-checks terminality under it, so
// it never races a live handler. Safe at startup and on a reconciler tick.
func (s *Server) RecoverResourceOperations(ctx context.Context) {
	vms, err := corrosion.ListVMsWithActiveOperation(ctx, s.db, s.hostName)
	if err != nil {
		slog.Warn("resource op recovery: list wedged VMs failed", "error", err)
		return
	}
	for i := range vms {
		s.recoverOneResourceOperation(ctx, vms[i].Name)
	}
}

func (s *Server) recoverOneResourceOperation(ctx context.Context, name string) {
	unlock := s.lockVM(name)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil || vm.HostName != s.hostName || vm.ActiveOperationID == "" {
		return
	}
	view, ok, err := corrosion.GetVMActiveOperation(ctx, s.db, name)
	if err != nil || !ok || view.Operation == nil {
		return
	}
	if view.Operation.OperationKind != string(corrosion.OpResourceUpdateRunning) {
		return // other kinds (device leases, restart) are recovered by their own paths
	}
	if corrosion.IsOperationTerminal(view.State) {
		return
	}

	target := &pb.VMSpec{}
	if vm.Spec != "" {
		if uerr := json.Unmarshal([]byte(vm.Spec), target); uerr != nil {
			slog.Error("resource op recovery: parse committed spec failed", "vm", name, "error", uerr)
			return
		}
	}
	// Apply only the un-converged dimensions (compare against the observed actuals);
	// converge observed actuals to the committed desired.
	actuals := &pb.VMSpec{Cpu: int32(vm.CPUActual), MemoryMib: int32(vm.MemActual)}
	if err := s.driveResourceUpdate(ctx, vm, view.ActiveOperationID, view.OwnerEpoch, view.SpecGeneration,
		target, actuals, int(target.Cpu), int(target.MemoryMib)); err != nil {
		slog.Warn("resource op recovery: not yet converged; will retry", "vm", name, "error", err)
		return
	}
	slog.Info("resource op recovery: converged", "vm", name)
}

// RunResourceOperationRecovery periodically resumes wedged resize operations so a
// partial failure converges without operator action.
func (s *Server) RunResourceOperationRecovery(ctx context.Context) {
	t := time.NewTicker(resourceRecoveryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RecoverResourceOperations(ctx)
		}
	}
}

// resizeRequestHash is the canonical request hash for a live resize (name + target
// cpu + target mem), so a reused idempotency key with different targets is a conflict.
func resizeRequestHash(name string, cpu, mem int32) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("resize:%s:%d:%d", name, cpu, mem)))
	return hex.EncodeToString(sum[:])
}

// posOnly clamps a delta to its positive part (only growth consumes capacity).
func posOnly(d int) int {
	if d < 0 {
		return 0
	}
	return d
}
