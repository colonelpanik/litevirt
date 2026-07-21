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

// Journaled, stopped-capable, at-most-once disk attach/detach — the journaled
// attach/detach machinery. The disk path of AttachDevice/DetachDevice is
// rewritten onto the v41 F1 operation protocol: it is gated on
// operation_protocol_v1 (and, for a STOPPED VM, hardware_v2), executes under
// the VM lock with a replicated at-most-once claim, journals its irreversible
// plan to the host-local opjournal before mutating, and on any failure
// compensates directionally (attach rolls back, detach rolls forward). The NIC
// path reuses this machinery, and concrete-address PCI reuses it
// (hotplug_pci.go); SR-IOV/type/vendor/mapping PCI selectors keep the legacy
// running-only path.

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

// ── staged backing-file create + publish ────────────────────────────────────

// The backing file is created in TWO steps so the FINAL disk path is never occupied
// until AFTER this operation has durably journaled that it owns it:
//   - stageQcow2 creates the qcow2 at an OP-SPECIFIC temp path (never the final);
//   - publishQcow2 hardlinks the staged temp onto the final path (fails EEXIST if the
//     final materialized meanwhile), leaving BOTH the temp and the final as the same
//     inode; the temp is removed later, only after the "published" stage is journaled.
//
// executeDiskAttach journals the INTENDED final path ("file_created_by_operation") at
// the claimed stage BEFORE the link, and the durable "published" stage AFTER the link
// (before removing the temp). Recovery deletes the final path only when it can PROVE
// this op published it — via the published stage OR os.SameFile(temp, final) — never
// from the mere presence of the intended-final artifact (which a crash BEFORE the link
// would leave over a foreign file). See executeDiskAttach for the crash-window argument.

// stageQcow2 creates a new qcow2 at tempPath (an op-specific staging path, NOT the
// final disk path). It does NOT stat or touch the final path. On any failure it
// leaves no partial file at tempPath.
func stageQcow2(tempPath string, sizeBytes uint64) error {
	if err := os.MkdirAll(filepath.Dir(tempPath), 0o755); err != nil {
		return fmt.Errorf("create disk dir: %w", err)
	}
	if err := qcow2.Create(tempPath, sizeBytes, nil); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("create backing file: %w", err)
	}
	return nil
}

// publishQcow2Fn is the seam through which executeDiskAttach publishes a staged
// backing file, overridable in tests to model a crash/error in the publish step.
var publishQcow2Fn = publishQcow2

// publishQcow2 promotes a staged backing file to its final path WITHOUT modifying any
// pre-existing file and WITHOUT removing the staged temp: it refuses if the final
// already exists, then hardlinks the staged temp onto the final path (os.Link also fails
// EEXIST if the final materialized in the race window, so the publish is atomic AND
// exclusive). After a successful link, temp and final are two hardlinks to the SAME
// inode. The temp is deliberately KEPT here so recovery can prove this op published the
// final via os.SameFile(temp, final); executeDiskAttach removes the temp only AFTER
// durably journaling the "published" stage, so whenever the temp is gone the published
// proof is durable. On failure the temp is left for the caller's rollback
// (failDeviceAttach) to clean.
func publishQcow2(tempPath, finalPath string) error {
	if _, err := os.Stat(finalPath); err == nil {
		return fmt.Errorf("backing file already exists at %s; refusing to overwrite", finalPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", finalPath, err)
	}
	if err := os.Link(tempPath, finalPath); err != nil {
		return fmt.Errorf("publish backing file %s: %w", finalPath, err)
	}
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
	// Bus allowlist, validated ONCE here before the op begins (any mutation or
	// BeginVMOperation claim below): the CLI/UI only offer these three, so an
	// arbitrary bus string is a backend validation gap, not a real request.
	if bus != "virtio" && bus != "scsi" && bus != "sata" {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported disk bus %q", bus)
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
	occupied := make(map[string]bool, len(disks))
	for _, d := range disks {
		if d.DiskName == spec.Name {
			return nil, status.Errorf(codes.AlreadyExists, "disk %q is already attached to VM %q", spec.Name, vmName)
		}
		occupied[d.TargetDev] = true
	}
	targetDev, err := allocateDiskTargetDev(occupied, bus)
	if err != nil {
		return nil, err
	}

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

// allocateDiskTargetDev returns the first free target device name given the
// OCCUPIED target-dev set of the VM's current live disks (root is normally
// "<prefix>a"). Allocating from the occupied set — rather than the disk COUNT —
// means a detach-then-add cycle can never recompute an in-use name: a count-based
// scheme recomputes the same slot a disk added in between the detach and the next
// attach already holds. Safe under the VM lock + mutation barrier (which
// serialize allocations for a given VM), combined with the caller's own
// duplicate-name check.
func allocateDiskTargetDev(occupied map[string]bool, bus string) (string, error) {
	prefix := "vd"
	if bus == "scsi" || bus == "sata" {
		prefix = "sd"
	}
	for c := byte('a'); c <= 'z'; c++ {
		cand := fmt.Sprintf("%s%c", prefix, c)
		if !occupied[cand] {
			return cand, nil
		}
	}
	return "", status.Errorf(codes.ResourceExhausted, "no free %s target device slot", prefix)
}

// attachRollback carries the state needed to compensate a failed attach.
type attachRollback struct {
	vm          *corrosion.VMRecord
	opID        string
	epoch       int64
	newGen      int64
	diskName    string
	diskPath    string
	tempPath    string // op-specific staging path (always safe to delete — unique to this op)
	targetDev   string
	running     bool
	journaled   bool // durable plan recorded (INTENDED-final added post-stage, pre-publish)
	fileCreated bool // this op PROVABLY published the backing file onto the final disk path
	attached    bool // live attach succeeded (running path)
	rowWritten  bool // vm_disks row inserted
}

// executeDiskAttach realizes the attach DAG under the lock: journal the plan → stage
// the backing file at an op-specific temp → journal the INTENDED final path → publish
// (hardlink temp→final) → journal the durable "published" stage → remove the temp →
// (running) live attach then commit the row, or (stopped) commit the row then reconcile
// the inactive definition → verify terminal membership → CompleteVMOperation. Any
// failure routes to failDeviceAttach, which rolls back directionally.
//
// Crash-safety invariant — recovery deletes the FINAL disk path on rollback ONLY when it
// can PROVE this op published there, so a foreign file that happens to sit at the final
// path is never wrongly deleted. Proof is the durable "published" stage OR
// os.SameFile(temp, final); the strict publish order (link → published-journal →
// remove-temp) makes every crash window safe:
//   - crash after the claimed journal (INTENDED final recorded) but BEFORE the link: a
//     foreign file at final has a DIFFERENT inode than the op's temp (SameFile false)
//     and there is no published stage → recovery does NOT delete it. The mere presence
//     of "file_created_by_operation" is NOT ownership.
//   - crash in the link→published-journal window: the temp is still present (removed
//     only after the published stage) → SameFile(temp, final) true → op owns final →
//     deleted. A crash before publish instead leaves only the op-specific temp, which
//     recovery deletes via the "creating_temp" artifact.
//   - crash after the published stage: the stage is durable → op owns final → deleted.
//     Safe because the operation BARRIER (active_operation_id, set by BeginVMOperation,
//     cleared only by recovery's terminal Complete/Fail) blocks any retry AttachDevice
//     for this VM until recovery resolves.
//
// This preserves FIX-2's no-wrongful-delete: a planned/unowned entry carries no proof of
// publication → recovery never deletes the final path, and an op-specific temp can never
// be a foreign file.
func (s *Server) executeDiskAttach(ctx context.Context, vm *corrosion.VMRecord, spec *pb.DiskSpec, bus, diskPath string,
	sizeBytes uint64, sizeBytesSigned int64, targetDev, opID string, epoch, newGen int64, running bool) (*pb.VM, error) {

	rb := attachRollback{vm: vm, opID: opID, epoch: epoch, newGen: newGen, diskName: spec.Name,
		diskPath: diskPath, targetDev: targetDev, running: running}

	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepReserved)

	// The backing file is staged at an op-specific temp (deterministic from opID so it
	// can collide neither with a retry under a different opID nor with the final path)
	// and published only after ownership of the final path is journaled (below).
	tempPath := diskPath + ".creating." + opID

	// Journal the plan BEFORE the irreversible file-create/attach so a crash recovers.
	// The plan records "creating_temp" (the op-specific staging path — ALWAYS safe for
	// recovery to delete) but NOT "file_created_by_operation": ownership of the FINAL
	// path is recorded only after staging + before publish (below). Recovery deletes the
	// final path only when it can PROVE this op published it — the durable "published"
	// stage, or the staged temp and the final path resolving to the same inode
	// (os.SameFile) — so a crash before publish, or a foreign file later appearing at the
	// path, is never mistaken for a file this op created.
	priorActive, _ := s.virt.DumpXML(vm.Name)
	priorInactive, _ := s.virt.DumpXMLInactive(vm.Name)
	entry := opjournal.Entry{
		OperationID:    opID,
		OwnerEpoch:     epoch,
		SpecGeneration: newGen,
		ResourceID:     vm.Name,
		Kind:           "device_attach",
		Stage:          "planned",
		Artifacts: map[string]string{
			"disk_name":              spec.Name,
			"target_dev":             targetDev,
			"bus":                    bus,
			"creating_temp":          tempPath,
			"prior_active_xml":       priorActive,
			"prior_inactive_xml":     priorInactive,
			"member_active_before":   strconv.FormatBool(diskDevInXML(priorActive, targetDev)),
			"member_inactive_before": strconv.FormatBool(diskDevInXML(priorInactive, targetDev)),
		},
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if s.opJournal != nil {
		if err := s.opJournal.Write(entry); err != nil {
			// Fail closed: without the durable plan we must not perform the irreversible
			// create/attach. No side effect yet → clean terminal failure.
			return s.failDeviceAttach(ctx, rb, codes.Unavailable, fmt.Errorf("journal attach plan: %w", err))
		}
		rb.journaled = true
	}

	// Refuse a pre-existing FINAL path before staging/claiming — the disk name is the
	// identity, and a stat here fails fast WITHOUT touching that file. This runs AFTER
	// the planned journal (so a crash here still leaves a retained planned entry with NO
	// ownership → recovery never deletes the pre-existing/foreign file), and BEFORE the
	// ownership journal (so this op never claims ownership of an already-occupied path).
	if _, err := os.Stat(diskPath); err == nil {
		return s.failDeviceAttach(ctx, rb, codes.FailedPrecondition,
			fmt.Errorf("backing file already exists at %s; refusing to overwrite", diskPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		return s.failDeviceAttach(ctx, rb, codes.Internal, fmt.Errorf("stat %s: %w", diskPath, err))
	}

	// Stage the backing file at the op-specific temp (NOT the final path yet).
	if err := stageQcow2(tempPath, sizeBytes); err != nil {
		// Nothing published; stageQcow2 cleaned its own partial, but record the temp for
		// rollback in case a partial survived.
		rb.tempPath = tempPath
		return s.failDeviceAttach(ctx, rb, codes.Internal, err)
	}
	rb.tempPath = tempPath

	// Record the INTENDED final path durably by re-writing the journal entry (same
	// OperationID → opjournal.Write overwrites atomically via temp+rename) — BEFORE the
	// file is published there. This artifact is NOT itself proof of publication (a crash
	// before the link would leave it over a foreign file); recovery proves ownership via
	// the later "published" stage or os.SameFile(temp, final) before deleting the final.
	if s.opJournal != nil {
		entry.Stage = "claimed"
		entry.Artifacts["file_created_by_operation"] = diskPath
		if err := s.opJournal.Write(entry); err != nil {
			// The temp is staged but the intended final could not be recorded: roll back
			// (rb.tempPath deletes the staged temp; the final was never published) and fail cleanly.
			return s.failDeviceAttach(ctx, rb, codes.Unavailable, fmt.Errorf("journal intended final path: %w", err))
		}
	}

	// Publish the staged file onto the final path — AFTER ownership is journaled. This
	// hardlinks temp→final (both are now the SAME inode); the temp is removed only AFTER
	// the durable "published" stage below. The strict order is
	// link → published-journal → remove-temp, so whenever the temp is gone the published
	// proof is durable — there is no window where recovery cannot prove ownership.
	if err := publishQcow2Fn(tempPath, diskPath); err != nil {
		// The final was not published (rb.fileCreated stays false → recovery/rollback
		// never deletes the final); rb.tempPath cleans the staged temp.
		return s.failDeviceAttach(ctx, rb, codes.FailedPrecondition, err)
	}
	rb.fileCreated = true

	// Journal the durable "published" proof — the conclusive record that this op linked
	// the final path. Written AFTER the link and BEFORE removing the temp, this makes
	// every crash window safe for recovery's ownership proof (published OR SameFile):
	//   - crash after claimed-journal, before link: a foreign file at final has a
	//     DIFFERENT inode than the op's temp → SameFile false, and no published stage →
	//     recovery does NOT delete it (foreign file safe);
	//   - crash in the link→published-journal window: the temp is still present (removed
	//     only after published) → SameFile(temp, final) true → op owns final → deleted;
	//   - crash after published-journal (temp maybe removed): the published stage is
	//     durable → op owns final → deleted.
	if s.opJournal != nil {
		entry.Stage = "published"
		entry.Artifacts["published"] = "true"
		if err := s.opJournal.Write(entry); err != nil {
			// The final is linked but the published proof could not be recorded: roll back
			// (rb.fileCreated deletes the op-published final; rb.tempPath deletes the temp,
			// still present because it is removed only after this write) and fail cleanly.
			return s.failDeviceAttach(ctx, rb, codes.Unavailable, fmt.Errorf("journal file publish: %w", err))
		}
	}

	// Remove the staging temp — ONLY after the published stage is durable. Best-effort:
	// the published proof already owns the final, so a failed unlink (leaving an
	// op-specific same-inode hardlink) does not affect correctness. Tolerate ErrNotExist.
	if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("disk attach: remove staged temp after publish", "vm", vm.Name, "op", opID, "path", tempPath, "error", err)
	}
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

	applied, cerr := s.db.CompleteVMOperation(ctx, vm.Name, opID, epoch, newGen)
	if cerr != nil || !applied {
		// The device is fully attached, but the barrier could not be cleared — the CAS
		// precondition no longer holds (ownership/generation moved underneath the op) or
		// the write failed. Do NOT remove the journal or report success; leave the
		// operation recovery-required — a later recovery pass or retry completes it.
		slog.Error("disk attach: completion could not be committed — left recoverable", "vm", vm.Name, "op", opID, "applied", applied, "error", cerr)
		return nil, status.Errorf(codes.Internal, "disk attach for %q completed but could not be committed; left recoverable: %v", vm.Name, cerr)
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
// prior inactive definition, delete the published backing file ONLY IF this operation
// durably recorded that it published it onto the final path (never a pre-existing
// path), and ALWAYS delete the op-specific staging temp (unique to this op → never a
// foreign file). If the rollback fully completes it records a terminal failure + clears
// the barrier; otherwise the operation is left NON-TERMINAL for recovery — never
// force-completed.
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
	// Delete the published backing file — only when durably recorded as published by
	// this op onto the final path (never a pre-existing/foreign file).
	if rb.fileCreated && rb.journaled {
		if err := os.Remove(rb.diskPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Error("disk attach rollback: remove op-owned file failed", "path", rb.diskPath, "error", err)
			rolledBack = false
		}
	}
	// ALWAYS delete the op-specific staging temp — it is unique to this op, so it can
	// never be a foreign file; a pre-publish crash/failure leaves the backing file only
	// here.
	if rb.tempPath != "" {
		if err := os.Remove(rb.tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Error("disk attach rollback: remove staging temp failed", "path", rb.tempPath, "error", err)
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
	applied, ferr := s.db.FailVMOperation(ctx, rb.vm.Name, rb.opID, rb.epoch, rb.newGen, deviceFailureFacts(code, cause))
	switch {
	case ferr != nil:
		slog.Error("disk attach: recording terminal failure failed — recovery will reconcile", "vm", rb.vm.Name, "op", rb.opID, "error", ferr)
	case !applied:
		// The barrier was NOT cleared (the CAS precondition no longer holds) — do not
		// remove the journal; leave the operation recovery-required.
		slog.Error("disk attach: terminal-failure CAS did not apply — left recoverable", "vm", rb.vm.Name, "op", rb.opID)
	default:
		if s.opJournal != nil {
			_ = s.opJournal.Remove(rb.opID)
		}
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

	applied, cerr := s.db.CompleteVMOperation(ctx, vm.Name, opID, epoch, newGen)
	if cerr != nil || !applied {
		slog.Error("disk detach: completion could not be committed — left recoverable", "vm", vm.Name, "op", opID, "applied", applied, "error", cerr)
		return nil, status.Errorf(codes.Internal, "disk detach for %q completed but could not be committed; left recoverable: %v", vm.Name, cerr)
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
	applied, ferr := s.db.FailVMOperation(ctx, vm.Name, opID, epoch, newGen, deviceFailureFacts(code, cause))
	switch {
	case ferr != nil:
		slog.Error("disk detach: recording terminal failure failed — recovery will reconcile", "vm", vm.Name, "op", opID, "error", ferr)
	case !applied:
		slog.Error("disk detach: terminal-failure CAS did not apply — left recoverable", "vm", vm.Name, "op", opID)
	default:
		if s.opJournal != nil {
			_ = s.opJournal.Remove(opID)
		}
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
