package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/opjournal"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Journaled, stopped-capable, at-most-once disk attach/detach (Task 5.2b). The
// disk path of AttachDevice/DetachDevice is rewritten onto the v41 F1 operation
// protocol: it is gated on operation_protocol_v1 (and, for a STOPPED VM,
// hardware_v2), executes under the VM lock with a replicated at-most-once claim,
// journals its irreversible plan to the host-local opjournal before mutating, and
// on any failure compensates directionally (attach rolls back, detach rolls
// forward). The NIC and PCI paths keep their current running-only behavior and are
// converted onto this same machinery in Task 5.2c.

// ── peer-trusted operation identity ─────────────────────────────────────────

const (
	// deviceOpIDMDKey / deviceOpHashMDKey carry the entry node's minted operation
	// identity to the owner over a forwarded peer RPC, so the owner uses the SAME
	// deterministic operation id (at-most-once across the two-entries-both-forward
	// race) without re-entering the entry idempotency layer. Honored ONLY over peer
	// mTLS (see deviceOpFromPeer) — an operator/bearer caller cannot set them.
	deviceOpIDMDKey   = "x-litevirt-device-op-id"
	deviceOpHashMDKey = "x-litevirt-device-op-hash"
)

// deviceOpFromPeer returns the operation identity the ENTRY node minted, but ONLY
// when the markers arrive over a peer mTLS connection whose certificate CN is a
// known cluster host. Mirrors migrateSourceFromPeer's trust boundary: an
// unverified marker is IGNORED (ok=false), so the receiver safely acts as its own
// entry node rather than trusting an at-most-once identity from an untrusted
// source.
func (s *Server) deviceOpFromPeer(ctx context.Context) (opID, reqHash string, ok bool) {
	md, has := metadata.FromIncomingContext(ctx)
	if !has {
		return "", "", false
	}
	ids := md.Get(deviceOpIDMDKey)
	if len(ids) == 0 || ids[0] == "" {
		return "", "", false
	}
	hashes := md.Get(deviceOpHashMDKey)
	if len(hashes) == 0 {
		return "", "", false
	}
	if callerAuthMethod(ctx) != authMethodMTLS {
		slog.Warn("device op: ignoring peer op-identity markers — caller is not a peer mTLS connection")
		return "", "", false
	}
	cn := callerMTLSCommonName(ctx)
	if h, _ := corrosion.GetHost(ctx, s.db, cn); h == nil {
		slog.Warn("device op: ignoring peer op-identity markers — peer cert CN is not a known cluster host", "peer_cn", cn)
		return "", "", false
	}
	return ids[0], hashes[0], true
}

// withDeviceOpMetadata stamps the trusted operation identity onto an outbound peer
// RPC context so the owner reuses the entry node's deterministic operation id.
func withDeviceOpMetadata(ctx context.Context, opID, reqHash string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, deviceOpIDMDKey, opID, deviceOpHashMDKey, reqHash)
}

// ── request hashes ──────────────────────────────────────────────────────────

// attachDiskRequestHash is the canonical semantic hash for a disk attach, so a
// reused idempotency key with a DIFFERENT disk is a hash conflict (InvalidArgument).
func attachDiskRequestHash(vmName string, spec *pb.DiskSpec) string {
	bus := spec.Bus
	if bus == "" {
		bus = "virtio"
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("attach-disk|%s|%s|%s|%s", vmName, spec.Name, spec.Size, bus)))
	return hex.EncodeToString(sum[:])
}

// detachDiskRequestHash is the canonical semantic hash for a disk detach.
func detachDiskRequestHash(vmName, diskName string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("detach-disk|%s|%s", vmName, diskName)))
	return hex.EncodeToString(sum[:])
}

// ── at-most-once outcome reconstruction ─────────────────────────────────────

// deviceOpOutcomeFacts is the canonical terminal-failure outcome persisted on the
// operation's 'failed' step, so a same-key retry replays the SAME gRPC code +
// message rather than re-executing (§7.1 terminal-failed reconstruction).
type deviceOpOutcomeFacts struct {
	Code    uint32 `json:"code"`
	Message string `json:"message"`
}

func deviceFailureFacts(code codes.Code, cause error) string {
	b, _ := json.Marshal(deviceOpOutcomeFacts{Code: uint32(code), Message: cause.Error()})
	return string(b)
}

// deviceOpOutcome reduces the replicated operation's recorded state and, when the
// operation already exists, returns its authoritative outcome WITHOUT re-running:
// completed → a freshly projected VM; failed → the reconstructed canonical error;
// non-terminal → FailedPrecondition (in progress / awaiting recovery); a hash
// mismatch → InvalidArgument. handled=false means the operation is pristine and the
// caller should claim + execute it. Caller holds the VM lock. Fails CLOSED on a
// store error (never silently proceeds to a second execution).
func (s *Server) deviceOpOutcome(ctx context.Context, vm *corrosion.VMRecord, opID, reqHash string, kind corrosion.OperationKind) (out *pb.VM, err error, handled bool) {
	existing, gerr := corrosion.GetOperation(ctx, s.db, opID)
	if gerr != nil {
		return nil, status.Errorf(codes.Unavailable, "read operation state: %v", gerr), true
	}
	if existing == nil {
		return nil, nil, false // pristine
	}
	if existing.RequestHash != reqHash {
		return nil, status.Errorf(codes.InvalidArgument,
			"idempotency key reused with a different device request for %q", vm.Name), true
	}
	state, faulted, serr := corrosion.OperationCurrentState(ctx, s.db, opID, existing.VMOwnerEpoch, kind)
	if serr != nil {
		return nil, status.Errorf(codes.Unavailable, "reduce operation state: %v", serr), true
	}
	if faulted {
		return nil, status.Errorf(codes.Internal,
			"operation %q has conflicting terminal states; manual recovery required", opID), true
	}
	switch state {
	case corrosion.OpStepCompleted:
		v, verr := s.vmToProto(ctx, vm.Name)
		return v, verr, true
	case corrosion.OpStepFailed:
		return nil, s.reconstructDeviceFailure(ctx, opID, existing.VMOwnerEpoch), true
	case "":
		// Header exists but no legal step reduced — an initializing/torn claim. Not
		// safe to re-run; report transient.
		return nil, status.Errorf(codes.FailedPrecondition,
			"a device operation for %q is initializing; retry", vm.Name), true
	default:
		// Non-terminal progress (or rollback_completed without a terminal): an
		// execution is in flight or awaiting recovery. Never re-run.
		return nil, status.Errorf(codes.FailedPrecondition,
			"a device operation for %q is in progress or awaiting recovery", vm.Name), true
	}
}

// reconstructDeviceFailure returns the canonical error recorded on the operation's
// terminal 'failed' step (falling back to a generic FailedPrecondition).
func (s *Server) reconstructDeviceFailure(ctx context.Context, opID string, epoch int64) error {
	steps, err := corrosion.ListOperationSteps(ctx, s.db, opID, epoch)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read operation outcome: %v", err)
	}
	for _, st := range steps {
		if st.StepName == corrosion.OpStepFailed && st.Facts != "" {
			var f deviceOpOutcomeFacts
			if json.Unmarshal([]byte(st.Facts), &f) == nil && f.Code != 0 {
				return status.Error(codes.Code(f.Code), f.Message)
			}
		}
	}
	return status.Errorf(codes.FailedPrecondition, "device operation %q previously failed", opID)
}

// appendOpStepFacts appends a legal step carrying facts (e.g. the terminal-failure
// outcome), logging rather than failing the caller on an illegal step or write
// error — a lost step is reduced correctly on the next observe/recovery.
func (s *Server) appendOpStepFacts(ctx context.Context, opID string, ownerEpoch int64, kind corrosion.OperationKind, step, facts string) {
	if !corrosion.IsLegalStep(kind, step) {
		slog.Error("device op: refusing to append illegal operation step", "op", opID, "kind", kind, "step", step)
		return
	}
	if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
		OperationID: opID, OwnerEpoch: ownerEpoch, StepName: step, Facts: facts,
	}); err != nil {
		slog.Warn("device op: append operation step", "op", opID, "step", step, "error", err)
	}
}

// ── exclusive backing-file create ───────────────────────────────────────────

// exclusiveCreateQcow2 creates a new qcow2 at path such that a PRE-EXISTING file is
// never modified: it fails fast if the target already exists, creates into a temp
// file, then publishes it with a hardlink (which fails EEXIST if the final path
// materialized in the race window), so the publish is atomic AND exclusive. Returns
// an error without leaving a partial file on any failure.
func exclusiveCreateQcow2(path string, sizeBytes uint64) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("backing file already exists at %s; refusing to overwrite", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create disk dir: %w", err)
	}
	tmp := path + ".creating." + strconv.FormatInt(time.Now().UnixNano(), 16)
	if err := qcow2.Create(tmp, sizeBytes, nil); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("create backing file: %w", err)
	}
	if err := os.Link(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("publish backing file %s: %w", path, err)
	}
	os.Remove(tmp)
	return nil
}

// diskDevInXML reports whether a domain XML carries a <target dev='X'.../>.
func diskDevInXML(xml, targetDev string) bool {
	if xml == "" || targetDev == "" {
		return false
	}
	return strings.Contains(xml, "dev='"+targetDev+"'") || strings.Contains(xml, `dev="`+targetDev+`"`)
}

// ── ATTACH ──────────────────────────────────────────────────────────────────

// attachDiskEntry is the entry-node half: it enforces the operation_protocol_v1
// prerequisite, mints/derives the operation identity, runs the same-entry
// response-replay idempotency layer, and either forwards to the owner (raw key
// stripped, op identity in trusted peer metadata) or executes locally. Named
// returns so the deferred idempotencyFinish can fold a record-failure into the RPC
// result (mirrors CreateVM).
func (s *Server) attachDiskEntry(ctx context.Context, req *pb.AttachDeviceRequest, vmRec *corrosion.VMRecord) (resp *pb.VM, retErr error) {
	spec := req.Disk
	if spec.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "disk name is required")
	}
	if !s.operationProtocolActive(ctx) {
		return nil, status.Error(codes.FailedPrecondition,
			"disk attach requires the operation_protocol_v1 capability to be active")
	}

	// Owner leg of a peer forward: trust the entry node's op identity, skip the entry
	// idempotency layer, go straight to the at-most-once owner path.
	if opID, reqHash, ok := s.deviceOpFromPeer(ctx); ok {
		return s.attachDiskOwner(ctx, req, vmRec.Name, opID, reqHash, "")
	}

	principal := callerUsername(ctx) + "@" + callerRealm(ctx)
	idemKey := req.IdempotencyKey
	if idemKey == "" {
		idemKey = uuid.NewString() // keyless call: a per-attempt id (no cross-retry dedup)
	}
	opID := corrosion.DeterministicOperationID("AttachDevice", principal, vmRec.Project, vmRec.Name, idemKey)
	reqHash := attachDiskRequestHash(vmRec.Name, spec)

	// Layer 1: same-entry byte-exact replay (only when the CLIENT supplied a key).
	if req.IdempotencyKey != "" {
		replay, claimID, ierr := s.idempotencyBegin(ctx, req.IdempotencyKey, "AttachDevice", idempotencyRequestHash(req))
		if ierr != nil {
			return nil, ierr
		}
		if replay != nil {
			out := &pb.VM{}
			if proto.Unmarshal(replay, out) != nil {
				return nil, status.Error(codes.Internal, "corrupt idempotency record")
			}
			return out, nil
		}
		stopHB := s.startIdempotencyHeartbeat(ctx, req.IdempotencyKey, claimID)
		defer func() {
			stopHB()
			if ferr := s.idempotencyFinish(ctx, req.IdempotencyKey, claimID, resp, retErr); ferr != nil && retErr == nil {
				resp, retErr = nil, ferr
			}
		}()
	}

	// Forward to the owning host.
	if vmRec.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vmRec.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vmRec.HostName, err)
		}
		defer conn.Close()
		fwd := proto.Clone(req).(*pb.AttachDeviceRequest)
		fwd.IdempotencyKey = "" // owner must NOT re-enter the entry idempotency layer
		resp, retErr = client.AttachDevice(withDeviceOpMetadata(ctx, opID, reqHash), fwd)
		return resp, retErr
	}

	resp, retErr = s.attachDiskOwner(ctx, req, vmRec.Name, opID, reqHash, idemKey)
	return resp, retErr
}

// attachDiskOwner runs on the VM's owning host under the VM lock — the at-most-once
// execution point. BEFORE any side effect it reduces the replicated operation's
// state and reconstructs a prior outcome instead of re-running; only a pristine
// claim proceeds to BeginVMOperation + the attach DAG. This closes the
// two-entries-both-forward race the VM lock alone cannot.
func (s *Server) attachDiskOwner(ctx context.Context, req *pb.AttachDeviceRequest, vmName, opID, reqHash, idemKey string) (*pb.VM, error) {
	unlock := s.lockVM(vmName)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", vmName)
	}
	if vm.HostName != s.hostName {
		return nil, status.Errorf(codes.Aborted, "ownership of %q moved to %s mid-operation; retry", vmName, vm.HostName)
	}

	if out, oerr, handled := s.deviceOpOutcome(ctx, vm, opID, reqHash, corrosion.OpDeviceAttach); handled {
		return out, oerr
	}

	running := vm.State == "running"
	if !running && !s.hardwareV2Latched(ctx) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"stopped-VM disk attach for %q is not available until hardware_v2 is active", vmName)
	}

	spec := req.Disk
	bus := spec.Bus
	if bus == "" {
		bus = "virtio"
	}
	diskPath, err := lv.SafeDiskPath(s.dataDir, vmName, spec.Name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	sizeGB, err := parseDiskSize(spec.Size)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid disk size: %v", err)
	}
	// The disk name is the identity — refuse a duplicate up front (under the lock). A
	// read failure here must FAIL the operation (fail-closed) before any mutation:
	// swallowing it would let the duplicate-name check pass open and miscount the
	// target-dev allocation.
	disks, err := corrosion.ListDisks(ctx, s.db, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list disks for %q: %v", vmName, err)
	}
	for _, d := range disks {
		if d.DiskName == spec.Name {
			return nil, status.Errorf(codes.AlreadyExists, "disk %q is already attached to VM %q", spec.Name, vmName)
		}
	}
	targetDev := allocateDiskTargetDev(len(disks), bus)

	op := corrosion.OperationRecord{
		ID:             opID,
		Method:         "AttachDevice",
		Principal:      callerUsername(ctx) + "@" + callerRealm(ctx),
		Project:        vm.Project,
		ResourceKind:   "vm",
		ResourceID:     vmName,
		OperationKind:  string(corrosion.OpDeviceAttach),
		RequestHash:    reqHash,
		IdempotencyKey: idemKey,
	}
	applied, err := s.db.BeginVMOperation(ctx, op, vm.Spec, vm.OwnerEpoch, vm.SpecGeneration)
	if err != nil {
		if errors.Is(err, corrosion.ErrOperationHashConflict) {
			return nil, status.Errorf(codes.InvalidArgument, "idempotency key reused with a different device attach for %q", vmName)
		}
		return nil, status.Errorf(codes.Internal, "begin operation: %v", err)
	}
	if !applied {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot attach a disk to %q: an operation is in progress", vmName)
	}
	newGen := vm.SpecGeneration + 1
	return s.executeDiskAttach(ctx, vm, spec, bus, diskPath, uint64(sizeGB)*1024*1024*1024,
		int64(sizeGB)*1024*1024*1024, targetDev, opID, vm.OwnerEpoch, newGen, running)
}

// allocateDiskTargetDev picks the next target device name given the current disk
// count (root is 'a'), matching the historical non-racy scheme; safe under the VM
// lock + mutation barrier.
func allocateDiskTargetDev(diskCount int, bus string) string {
	prefix := "vd"
	if bus == "scsi" || bus == "sata" {
		prefix = "sd"
	}
	return fmt.Sprintf("%s%c", prefix, 'b'+diskCount)
}

// attachRollback carries the state needed to compensate a failed attach.
type attachRollback struct {
	vm          *corrosion.VMRecord
	opID        string
	epoch       int64
	newGen      int64
	diskName    string
	diskPath    string
	targetDev   string
	running     bool
	journaled   bool // durable plan (incl. file_created_by_operation) recorded
	fileCreated bool // this op exclusively created the backing file
	attached    bool // live attach succeeded (running path)
	rowWritten  bool // vm_disks row inserted
}

// executeDiskAttach realizes the attach DAG under the lock: journal the plan →
// exclusive-create the backing file → (running) live attach then commit the row, or
// (stopped) commit the row then reconcile the inactive definition → verify terminal
// membership → CompleteVMOperation. Any failure routes to failDeviceAttach, which
// rolls back directionally.
func (s *Server) executeDiskAttach(ctx context.Context, vm *corrosion.VMRecord, spec *pb.DiskSpec, bus, diskPath string,
	sizeBytes uint64, sizeBytesSigned int64, targetDev, opID string, epoch, newGen int64, running bool) (*pb.VM, error) {

	rb := attachRollback{vm: vm, opID: opID, epoch: epoch, newGen: newGen, diskName: spec.Name,
		diskPath: diskPath, targetDev: targetDev, running: running}

	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepReserved)

	// Journal the plan BEFORE the irreversible file-create/attach so a crash recovers.
	priorActive, _ := s.virt.DumpXML(vm.Name)
	priorInactive, _ := s.virt.DumpXMLInactive(vm.Name)
	if s.opJournal != nil {
		entry := opjournal.Entry{
			OperationID:    opID,
			OwnerEpoch:     epoch,
			SpecGeneration: newGen,
			ResourceID:     vm.Name,
			Kind:           "device_attach",
			Stage:          "planned",
			Artifacts: map[string]string{
				"disk_name":                 spec.Name,
				"target_dev":                targetDev,
				"bus":                       bus,
				"prior_active_xml":          priorActive,
				"prior_inactive_xml":        priorInactive,
				"member_active_before":      strconv.FormatBool(diskDevInXML(priorActive, targetDev)),
				"member_inactive_before":    strconv.FormatBool(diskDevInXML(priorInactive, targetDev)),
				"file_created_by_operation": diskPath, // this op will exclusively create it
			},
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := s.opJournal.Write(entry); err != nil {
			// Fail closed: without the durable plan we must not perform the irreversible
			// create/attach. No side effect yet → clean terminal failure.
			return s.failDeviceAttach(ctx, rb, codes.Unavailable, fmt.Errorf("journal attach plan: %w", err))
		}
		rb.journaled = true
	}

	// Exclusive-create the backing file (an existing path fails WITHOUT modifying it).
	if err := exclusiveCreateQcow2(diskPath, sizeBytes); err != nil {
		// Nothing op-owned to delete (pre-existing file, or create cleaned its temp).
		return s.failDeviceAttach(ctx, rb, codes.FailedPrecondition, err)
	}
	rb.fileCreated = true
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepClaimed)

	rec := corrosion.DiskRecord{
		VMName: vm.Name, DiskName: spec.Name, HostName: s.hostName,
		Path: diskPath, SizeBytes: sizeBytesSigned, StorageType: "local",
		TargetDev: targetDev, Bus: bus, DeviceKind: "disk", DeleteWithVM: true,
	}

	if running {
		if err := s.virt.AttachDisk(vm.Name, diskPath, targetDev, bus); err != nil {
			return s.failDeviceAttach(ctx, rb, codes.Internal, fmt.Errorf("attach disk: %w", err))
		}
		rb.attached = true
		if err := corrosion.InsertDisk(ctx, s.db, rec); err != nil {
			return s.failDeviceAttach(ctx, rb, codes.Internal, fmt.Errorf("record disk: %w", err))
		}
		rb.rowWritten = true
	} else {
		if err := corrosion.InsertDisk(ctx, s.db, rec); err != nil {
			return s.failDeviceAttach(ctx, rb, codes.Internal, fmt.Errorf("record disk: %w", err))
		}
		rb.rowWritten = true
		if err := s.reconcileDomainDefinition(ctx, vm, nil); err != nil {
			return s.failDeviceAttach(ctx, rb, codes.Internal, fmt.Errorf("reconcile definition: %w", err))
		}
	}
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepBound)

	// Verify terminal membership before completing (§8). On the running path the disk
	// must be present in BOTH the live domain AND the persistent (inactive) definition,
	// because AttachDisk applies live+config; a config-vs-live divergence must not
	// complete (it would surface as the disk (dis)appearing on the next VM start).
	divergence, verr := s.verifyDiskAttached(vm.Name, targetDev, running)
	if verr != nil {
		if running && divergence {
			// Reads succeeded but the disk is not in both defs — a config-vs-live
			// divergence. Compensate (roll back) rather than complete an inconsistent attach.
			return s.failDeviceAttach(ctx, rb, codes.Internal, fmt.Errorf("verify attach membership: %w", verr))
		}
		// Committed but unverifiable (a definition read failed), or the stopped-path
		// single-def check failed → leave NON-TERMINAL for recovery (never complete/fail).
		slog.Error("disk attach: membership unverifiable — left recoverable", "vm", vm.Name, "op", opID, "error", verr)
		return nil, status.Errorf(codes.Internal, "disk attach for %q could not be verified; left recoverable: %v", vm.Name, verr)
	}
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepAttached)

	if _, err := s.db.CompleteVMOperation(ctx, vm.Name, opID, epoch, newGen); err != nil {
		slog.Error("disk attach: completing operation failed — recovery will reconcile", "vm", vm.Name, "op", opID, "error", err)
	}
	if s.opJournal != nil {
		if err := s.opJournal.Remove(opID); err != nil {
			slog.Warn("disk attach: clear journal entry", "vm", vm.Name, "op", opID, "error", err)
		}
	}
	slog.Info("disk attached", "vm", vm.Name, "disk", spec.Name, "target", targetDev)
	s.recordVMEvent(ctx, vm.Name, "device.attached", "ok", "disk "+spec.Name)
	s.publish("device.attached", vm.Name, "disk:"+spec.Name)
	return s.vmToProto(ctx, vm.Name)
}

// failDeviceAttach compensates a failed attach by rolling BACK (§8): inverse
// live-detach the just-attached disk, soft-delete any committed row, restore the
// prior inactive definition, and delete the backing file ONLY IF this operation
// durably recorded that it created it (never a pre-existing path). If the rollback
// fully completes it records a terminal failure + clears the barrier; otherwise the
// operation is left NON-TERMINAL for recovery — never force-completed.
func (s *Server) failDeviceAttach(ctx context.Context, rb attachRollback, code codes.Code, cause error) (*pb.VM, error) {
	rolledBack := true

	if rb.attached {
		if err := s.virt.DetachDisk(rb.vm.Name, rb.targetDev); err != nil {
			slog.Error("disk attach rollback: inverse-detach failed", "vm", rb.vm.Name, "target", rb.targetDev, "error", err)
			rolledBack = false
		}
	}
	if rb.rowWritten {
		if err := corrosion.SoftDeleteDisk(ctx, s.db, rb.vm.Name, rb.diskName); err != nil {
			slog.Error("disk attach rollback: soft-delete row failed", "vm", rb.vm.Name, "disk", rb.diskName, "error", err)
			rolledBack = false
		} else if !rb.running {
			// Restore the prior inactive definition: re-reconcile now that the row is
			// gone drops the disk we added from the definition.
			if err := s.reconcileDomainDefinition(ctx, rb.vm, nil); err != nil {
				slog.Error("disk attach rollback: re-reconcile to drop disk failed", "vm", rb.vm.Name, "error", err)
				rolledBack = false
			}
		}
	}
	// Delete the op-owned backing file — only when durably recorded as ours.
	if rb.fileCreated && rb.journaled {
		if err := os.Remove(rb.diskPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Error("disk attach rollback: remove op-owned file failed", "path", rb.diskPath, "error", err)
			rolledBack = false
		}
	}

	if !rolledBack {
		// Compensation incomplete → leave NON-TERMINAL (recovery-required). Do NOT
		// force-complete/fail; keep the journal entry for recovery.
		slog.Error("disk attach: rollback incomplete — operation left recoverable", "vm", rb.vm.Name, "op", rb.opID, "cause", cause)
		return nil, status.Errorf(code, "disk attach for %q failed and rollback is incomplete; left recoverable: %v", rb.vm.Name, cause)
	}

	s.appendOpStep(ctx, rb.opID, rb.epoch, corrosion.OpDeviceAttach, corrosion.OpStepRollbackCompleted)
	if _, err := s.db.FailVMOperation(ctx, rb.vm.Name, rb.opID, rb.epoch, rb.newGen, deviceFailureFacts(code, cause)); err != nil {
		slog.Error("disk attach: recording terminal failure failed — recovery will reconcile", "vm", rb.vm.Name, "op", rb.opID, "error", err)
	}
	if s.opJournal != nil {
		_ = s.opJournal.Remove(rb.opID)
	}
	s.recordVMEvent(ctx, rb.vm.Name, "device.attached", "error", "disk "+rb.diskName)
	return nil, status.Error(code, cause.Error())
}

// verifyDiskAttached asserts the disk landed in the authoritative definition(s) after
// an attach. On the RUNNING path it must be present in BOTH the live domain AND the
// persistent (inactive) definition, because AttachDisk applies live+config; on the
// STOPPED path there is only the inactive definition. The returned divergence flag is
// meaningful only when err != nil: divergence==true means the definition(s) were read
// successfully but membership is wrong (a definitive divergence the caller compensates),
// while divergence==false means a read failed (unverifiable → leave recoverable).
func (s *Server) verifyDiskAttached(vmName, targetDev string, running bool) (divergence bool, err error) {
	if running {
		srcs, rerr := s.virt.DomainDiskSources(vmName)
		if rerr != nil {
			return false, fmt.Errorf("read live disks: %w", rerr)
		}
		if _, ok := srcs[targetDev]; !ok {
			return true, fmt.Errorf("disk %s absent from the live domain after attach", targetDev)
		}
		xml, rerr := s.virt.DumpXMLInactive(vmName)
		if rerr != nil {
			return false, fmt.Errorf("read inactive definition: %w", rerr)
		}
		if !diskDevInXML(xml, targetDev) {
			return true, fmt.Errorf("disk %s absent from the persistent definition after attach", targetDev)
		}
		return false, nil
	}
	xml, rerr := s.virt.DumpXMLInactive(vmName)
	if rerr != nil {
		return false, fmt.Errorf("read inactive definition: %w", rerr)
	}
	if !diskDevInXML(xml, targetDev) {
		return true, fmt.Errorf("disk %s absent from the inactive definition after reconcile", targetDev)
	}
	return false, nil
}

// ── DETACH ──────────────────────────────────────────────────────────────────

// detachDiskEntry mirrors attachDiskEntry for the detach path.
func (s *Server) detachDiskEntry(ctx context.Context, req *pb.DetachDeviceRequest, vmRec *corrosion.VMRecord) (resp *pb.VM, retErr error) {
	if req.DiskName == "" {
		return nil, status.Error(codes.InvalidArgument, "disk_name is required")
	}
	if !s.operationProtocolActive(ctx) {
		return nil, status.Error(codes.FailedPrecondition,
			"disk detach requires the operation_protocol_v1 capability to be active")
	}

	if opID, reqHash, ok := s.deviceOpFromPeer(ctx); ok {
		return s.detachDiskOwner(ctx, req, vmRec.Name, opID, reqHash, "")
	}

	principal := callerUsername(ctx) + "@" + callerRealm(ctx)
	idemKey := req.IdempotencyKey
	if idemKey == "" {
		idemKey = uuid.NewString()
	}
	opID := corrosion.DeterministicOperationID("DetachDevice", principal, vmRec.Project, vmRec.Name, idemKey)
	reqHash := detachDiskRequestHash(vmRec.Name, req.DiskName)

	if req.IdempotencyKey != "" {
		replay, claimID, ierr := s.idempotencyBegin(ctx, req.IdempotencyKey, "DetachDevice", idempotencyRequestHash(req))
		if ierr != nil {
			return nil, ierr
		}
		if replay != nil {
			out := &pb.VM{}
			if proto.Unmarshal(replay, out) != nil {
				return nil, status.Error(codes.Internal, "corrupt idempotency record")
			}
			return out, nil
		}
		stopHB := s.startIdempotencyHeartbeat(ctx, req.IdempotencyKey, claimID)
		defer func() {
			stopHB()
			if ferr := s.idempotencyFinish(ctx, req.IdempotencyKey, claimID, resp, retErr); ferr != nil && retErr == nil {
				resp, retErr = nil, ferr
			}
		}()
	}

	if vmRec.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vmRec.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vmRec.HostName, err)
		}
		defer conn.Close()
		fwd := proto.Clone(req).(*pb.DetachDeviceRequest)
		fwd.IdempotencyKey = ""
		resp, retErr = client.DetachDevice(withDeviceOpMetadata(ctx, opID, reqHash), fwd)
		return resp, retErr
	}

	resp, retErr = s.detachDiskOwner(ctx, req, vmRec.Name, opID, reqHash, idemKey)
	return resp, retErr
}

// detachDiskOwner is the at-most-once owner path for a disk detach.
func (s *Server) detachDiskOwner(ctx context.Context, req *pb.DetachDeviceRequest, vmName, opID, reqHash, idemKey string) (*pb.VM, error) {
	unlock := s.lockVM(vmName)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", vmName)
	}
	if vm.HostName != s.hostName {
		return nil, status.Errorf(codes.Aborted, "ownership of %q moved to %s mid-operation; retry", vmName, vm.HostName)
	}

	if out, oerr, handled := s.deviceOpOutcome(ctx, vm, opID, reqHash, corrosion.OpDeviceDetach); handled {
		return out, oerr
	}

	running := vm.State == "running"
	if !running && !s.hardwareV2Latched(ctx) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"stopped-VM disk detach for %q is not available until hardware_v2 is active", vmName)
	}

	// A read failure must FAIL the operation before any mutation (fail-closed):
	// swallowing it would mis-resolve the target dev and could detach the wrong disk.
	disks, err := corrosion.ListDisks(ctx, s.db, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list disks for %q: %v", vmName, err)
	}
	targetDev := ""
	for _, d := range disks {
		if d.DiskName == req.DiskName {
			targetDev = d.TargetDev
			break
		}
	}
	if targetDev == "" {
		return nil, status.Errorf(codes.NotFound, "disk %q not found on VM %q", req.DiskName, vmName)
	}

	op := corrosion.OperationRecord{
		ID:             opID,
		Method:         "DetachDevice",
		Principal:      callerUsername(ctx) + "@" + callerRealm(ctx),
		Project:        vm.Project,
		ResourceKind:   "vm",
		ResourceID:     vmName,
		OperationKind:  string(corrosion.OpDeviceDetach),
		RequestHash:    reqHash,
		IdempotencyKey: idemKey,
	}
	applied, err := s.db.BeginVMOperation(ctx, op, vm.Spec, vm.OwnerEpoch, vm.SpecGeneration)
	if err != nil {
		if errors.Is(err, corrosion.ErrOperationHashConflict) {
			return nil, status.Errorf(codes.InvalidArgument, "idempotency key reused with a different device detach for %q", vmName)
		}
		return nil, status.Errorf(codes.Internal, "begin operation: %v", err)
	}
	if !applied {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot detach a disk from %q: an operation is in progress", vmName)
	}
	newGen := vm.SpecGeneration + 1
	return s.executeDiskDetach(ctx, vm, req.DiskName, targetDev, opID, vm.OwnerEpoch, newGen, running)
}

// executeDiskDetach realizes the detach DAG under the lock: journal the plan →
// (running) live detach then soft-delete the row, or (stopped) soft-delete the row
// then reconcile → verify absence → CompleteVMOperation. It NEVER deletes the
// backing file (§12: storage is preserved). Compensation rolls FORWARD: once the
// live detach has run the row soft-delete is retried to completion; if it cannot
// complete the operation is left NON-TERMINAL for recovery — never re-attached.
func (s *Server) executeDiskDetach(ctx context.Context, vm *corrosion.VMRecord, diskName, targetDev, opID string, epoch, newGen int64, running bool) (*pb.VM, error) {
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceDetach, corrosion.OpStepReserved)

	priorActive, _ := s.virt.DumpXML(vm.Name)
	priorInactive, _ := s.virt.DumpXMLInactive(vm.Name)
	if s.opJournal != nil {
		entry := opjournal.Entry{
			OperationID:    opID,
			OwnerEpoch:     epoch,
			SpecGeneration: newGen,
			ResourceID:     vm.Name,
			Kind:           "device_detach",
			Stage:          "planned",
			Artifacts: map[string]string{
				"disk_name":              diskName,
				"target_dev":             targetDev,
				"prior_active_xml":       priorActive,
				"prior_inactive_xml":     priorInactive,
				"member_active_before":   strconv.FormatBool(diskDevInXML(priorActive, targetDev)),
				"member_inactive_before": strconv.FormatBool(diskDevInXML(priorInactive, targetDev)),
			},
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := s.opJournal.Write(entry); err != nil {
			// No side effect yet → clean terminal failure (nothing to roll back).
			return s.failDeviceDetachClean(ctx, vm, opID, epoch, newGen, diskName,
				codes.Unavailable, fmt.Errorf("journal detach plan: %w", err))
		}
	}

	if running {
		if err := s.virt.DetachDisk(vm.Name, targetDev); err != nil {
			// The irreversible step failed and nothing changed → clean terminal fail.
			return s.failDeviceDetachClean(ctx, vm, opID, epoch, newGen, diskName,
				codes.Internal, fmt.Errorf("detach disk: %w", err))
		}
		if !s.retrySoftDeleteDisk(ctx, vm.Name, diskName) {
			// Live-detached but the row soft-delete would not commit → roll FORWARD:
			// leave NON-TERMINAL for recovery, never re-attach.
			slog.Error("disk detach: row soft-delete failed after live detach — left recoverable", "vm", vm.Name, "op", opID)
			return nil, status.Errorf(codes.Internal, "disk detach for %q applied but bookkeeping incomplete; left recoverable", vm.Name)
		}
	} else {
		if err := corrosion.SoftDeleteDisk(ctx, s.db, vm.Name, diskName); err != nil {
			// Nothing applied to the domain yet → clean terminal fail.
			return s.failDeviceDetachClean(ctx, vm, opID, epoch, newGen, diskName,
				codes.Internal, fmt.Errorf("soft-delete disk row: %w", err))
		}
		if err := s.reconcileDomainDefinition(ctx, vm, nil); err != nil {
			// Row is gone; the definition still lists the disk → roll FORWARD: recovery
			// re-reconciles. Leave NON-TERMINAL, never re-attach.
			slog.Error("disk detach: reconcile after row soft-delete failed — left recoverable", "vm", vm.Name, "op", opID, "error", err)
			return nil, status.Errorf(codes.Internal, "disk detach for %q applied but definition not reconciled; left recoverable: %v", vm.Name, err)
		}
	}
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceDetach, corrosion.OpStepAttached)

	if err := s.verifyDiskDetached(vm.Name, targetDev, running); err != nil {
		slog.Error("disk detach: absence unverifiable — left recoverable", "vm", vm.Name, "op", opID, "error", err)
		return nil, status.Errorf(codes.Internal, "disk detach for %q could not be verified; left recoverable: %v", vm.Name, err)
	}

	if _, err := s.db.CompleteVMOperation(ctx, vm.Name, opID, epoch, newGen); err != nil {
		slog.Error("disk detach: completing operation failed — recovery will reconcile", "vm", vm.Name, "op", opID, "error", err)
	}
	if s.opJournal != nil {
		if err := s.opJournal.Remove(opID); err != nil {
			slog.Warn("disk detach: clear journal entry", "vm", vm.Name, "op", opID, "error", err)
		}
	}
	slog.Info("disk detached", "vm", vm.Name, "disk", diskName)
	s.recordVMEvent(ctx, vm.Name, "device.detached", "ok", "disk "+diskName)
	s.publish("device.detached", vm.Name, "disk:"+diskName)
	return s.vmToProto(ctx, vm.Name)
}

// retrySoftDeleteDisk retries the row soft-delete a bounded number of times (the
// forward-compensation retry after a successful live detach).
func (s *Server) retrySoftDeleteDisk(ctx context.Context, vmName, diskName string) bool {
	for attempt := 0; attempt < resizeApplyAttempts; attempt++ {
		if err := corrosion.SoftDeleteDisk(ctx, s.db, vmName, diskName); err == nil {
			return true
		}
	}
	return false
}

// failDeviceDetachClean records a terminal detach failure + clears the barrier when
// NOTHING was applied to the domain (the live/config detach never ran), so the VM is
// unchanged and mutable again. It never touches the backing file.
func (s *Server) failDeviceDetachClean(ctx context.Context, vm *corrosion.VMRecord, opID string, epoch, newGen int64, diskName string, code codes.Code, cause error) (*pb.VM, error) {
	if _, err := s.db.FailVMOperation(ctx, vm.Name, opID, epoch, newGen, deviceFailureFacts(code, cause)); err != nil {
		slog.Error("disk detach: recording terminal failure failed — recovery will reconcile", "vm", vm.Name, "op", opID, "error", err)
	}
	if s.opJournal != nil {
		_ = s.opJournal.Remove(opID)
	}
	s.recordVMEvent(ctx, vm.Name, "device.detached", "error", "disk "+diskName)
	return nil, status.Error(code, cause.Error())
}

// verifyDiskDetached asserts the disk is GONE from the authoritative definition(s). On
// the RUNNING path it must be absent from BOTH the live domain AND the persistent
// (inactive) definition, because DetachDisk applies live+config; a disk still lingering
// in the persistent config would silently reappear on the next VM start. On the STOPPED
// path there is only the inactive definition. Any failure routes to the detach path's
// forward compensation (leave NON-TERMINAL for recovery; never re-attach).
func (s *Server) verifyDiskDetached(vmName, targetDev string, running bool) error {
	if running {
		srcs, err := s.virt.DomainDiskSources(vmName)
		if err != nil {
			return fmt.Errorf("read live disks: %w", err)
		}
		if _, ok := srcs[targetDev]; ok {
			return fmt.Errorf("disk %s still present in the live domain after detach", targetDev)
		}
		xml, err := s.virt.DumpXMLInactive(vmName)
		if err != nil {
			return fmt.Errorf("read inactive definition: %w", err)
		}
		if diskDevInXML(xml, targetDev) {
			return fmt.Errorf("disk %s still present in the persistent definition after detach", targetDev)
		}
		return nil
	}
	xml, err := s.virt.DumpXMLInactive(vmName)
	if err != nil {
		return fmt.Errorf("read inactive definition: %w", err)
	}
	if diskDevInXML(xml, targetDev) {
		return fmt.Errorf("disk %s still present in the inactive definition after reconcile", targetDev)
	}
	return nil
}
