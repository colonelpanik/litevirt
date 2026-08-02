package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const vmCreateBeginSQL = `INSERT INTO vms (name, stack_name, host_name, spec, state, state_detail,
				cpu_actual, mem_actual, project, is_template, vm_owner_epoch,
				spec_generation, active_operation_id, created_at, updated_at,
				deleted_at, pending_action_id, hardware_adoption_state,
				hardware_adoption_error)
			 VALUES (?, ?, ?, ?, 'creating', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
			         NULL, '', 'pending', NULL)
			 ON CONFLICT(name) DO UPDATE SET
			   stack_name = excluded.stack_name,
			   host_name = excluded.host_name,
			   spec = excluded.spec,
			   state = excluded.state,
			   state_detail = excluded.state_detail,
			   cpu_actual = excluded.cpu_actual,
			   mem_actual = excluded.mem_actual,
			   project = excluded.project,
			   is_template = excluded.is_template,
			   vm_owner_epoch = excluded.vm_owner_epoch,
			   spec_generation = excluded.spec_generation,
			   active_operation_id = excluded.active_operation_id,
			   created_at = excluded.created_at,
			   updated_at = excluded.updated_at,
			   deleted_at = excluded.deleted_at,
			   pending_action_id = excluded.pending_action_id,
			   hardware_adoption_state = excluded.hardware_adoption_state,
			   hardware_adoption_error = excluded.hardware_adoption_error
			 WHERE vms.deleted_at IS NOT NULL
			   AND excluded.vm_owner_epoch > vms.vm_owner_epoch
			   AND excluded.spec_generation > vms.spec_generation`

const containerCreateBeginSQL = `INSERT INTO containers
			 (host_name, name, state, image, cpu_limit, memory_mib, labels,
			  restart_policy, state_detail, project, is_template, on_host_failure,
			  create_spec, relocate_token, owner_epoch, spec_generation,
			  active_operation_id, created_at, updated_at, deleted_at)
			 VALUES (?, ?, 'creating', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
			 ON CONFLICT(host_name, name) DO UPDATE SET
			   state = excluded.state,
			   image = excluded.image,
			   cpu_limit = excluded.cpu_limit,
			   memory_mib = excluded.memory_mib,
			   labels = excluded.labels,
			   restart_policy = excluded.restart_policy,
			   state_detail = excluded.state_detail,
			   project = excluded.project,
			   is_template = excluded.is_template,
			   on_host_failure = excluded.on_host_failure,
			   create_spec = excluded.create_spec,
			   relocate_token = excluded.relocate_token,
			   owner_epoch = excluded.owner_epoch,
			   spec_generation = excluded.spec_generation,
			   active_operation_id = excluded.active_operation_id,
			   created_at = excluded.created_at,
			   updated_at = excluded.updated_at,
			   deleted_at = excluded.deleted_at
			 WHERE containers.deleted_at IS NOT NULL
			   AND excluded.owner_epoch > containers.owner_epoch
			   AND excluded.spec_generation > containers.spec_generation`

const (
	vmCreateCommitSQL = `UPDATE vms SET state = 'running', state_detail = ?,
				cpu_actual = ?, mem_actual = ?,
				hardware_adoption_state = 'adopted', hardware_adoption_error = NULL,
				active_operation_id = '', updated_at = ?
			 WHERE name = ? AND state = 'creating' AND active_operation_id = ?
			   AND vm_owner_epoch = ? AND spec_generation = ? AND deleted_at IS NULL`
	vmCreateRollbackSQL = `UPDATE vms SET active_operation_id = '', deleted_at = ?, updated_at = ?
			 WHERE name = ? AND state = 'creating' AND active_operation_id = ?
			   AND vm_owner_epoch = ? AND deleted_at IS NULL`
	containerCreateCommitSQL = `UPDATE containers SET state = 'running', state_detail = ?,
				active_operation_id = '', updated_at = ?
			 WHERE host_name = ? AND name = ? AND state = 'creating'
			   AND active_operation_id = ? AND owner_epoch = ? AND spec_generation = ?
			   AND deleted_at IS NULL`
	containerCreateRollbackSQL = `UPDATE containers SET active_operation_id = '', deleted_at = ?, updated_at = ?
			 WHERE host_name = ? AND name = ? AND state = 'creating'
			   AND active_operation_id = ? AND owner_epoch = ? AND deleted_at IS NULL`
	vmInterfacesCreateCleanupSQL = `UPDATE vm_interfaces SET deleted_at = ?, updated_at = ? WHERE vm_name = ?`
	vmDisksCreateCleanupSQL      = `UPDATE vm_disks SET deleted_at = ?, updated_at = ? WHERE vm_name = ?`
	vmNICsCreateCleanupSQL       = `UPDATE vm_nics SET deleted_at = ?, updated_at = ? WHERE vm_name = ?`
	vmPCIIntentCreateCleanupSQL  = `UPDATE vm_pci_intent SET deleted_at = ?, updated_at = ? WHERE vm_name = ?`
	vmPCIRealCreateCleanupSQL    = `UPDATE vm_pci_realizations SET deleted_at = ?, updated_at = ? WHERE vm_name = ?`
	containerCreateCleanupSQL    = `UPDATE container_interfaces SET deleted_at = ?, updated_at = ?
			 WHERE host_name = ? AND ct_name = ?`
	containerCreateInterfaceSQL = `INSERT OR REPLACE INTO container_interfaces
			 (host_name, ct_name, network_name, ordinal, mac, ip, veth_device, security_groups, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`
)

// BeginVMCreateOperation atomically persists a create claim, its capacity
// reservation, and a provisional VM row. applied is true only for the first
// successful claim; an identical retry returns false without changing state.
// Callers may use this replicated protocol only after capacity_admission_v1 is
// latched cluster-wide; pre-latch peers do not understand Statement.Guard.
func (c *Client) BeginVMCreateOperation(ctx context.Context, op OperationRecord, vm VMRecord) (bool, error) {
	if err := normalizeCreateIdentity(&op, vm.Name, "vm", vm.OwnerEpoch); err != nil {
		return false, err
	}
	vm.OwnerEpoch = op.VMOwnerEpoch
	if vm.Project == "" {
		vm.Project = projectOrDefault(op.Project)
	} else {
		vm.Project = projectOrDefault(vm.Project)
	}
	if vm.Project != projectOrDefault(op.Project) {
		return false, fmt.Errorf("%w: operation project %q does not match VM project %q",
			ErrOperationIdentityConflict, op.Project, vm.Project)
	}
	op.Project = vm.Project
	if err := validateReservationProject(op.ReservationJSON, op.Project); err != nil {
		return false, err
	}
	if err := validateCreateReservationBinding(op.ReservationJSON, vm.HostName); err != nil {
		return false, err
	}
	reservedFacts, err := reservationStepFacts(op.ReservationFacts, op.Project)
	if err != nil {
		return false, err
	}
	provisionalGuard, err := vmCreateMutationGuard(op.ID, op.VMOwnerEpoch, vm, false)
	if err != nil {
		return false, err
	}
	beginGuard := vmCreateBeginMutationGuard(op.ID, op.VMOwnerEpoch, vm)
	claimHash := operationClaimHash(op)
	provisionalGuard.OperationClaimHash = claimHash
	beginGuard.OperationClaimHash = claimHash
	claimedGuard := *provisionalGuard
	claimedGuard.RequireOperation = true
	// wall stamps this begin's created_at — a fresh incarnation (see nowRFC3339Nano).
	now, wall := c.NowTS(), nowRFC3339Nano()
	guard := func(tx *sql.Tx) (bool, error) {
		existing, err := operationInTx(ctx, tx, op.ID)
		if err != nil {
			return false, err
		}
		if existing != nil {
			if err := compareOperationClaim(*existing, op); err != nil {
				return false, err
			}
			if err := compareReservedStepInTx(ctx, tx, op.ID, op.VMOwnerEpoch, reservedFacts); err != nil {
				return false, err
			}
			return false, compareVMCreateRetryInTx(ctx, tx, vm)
		}
		return c.mutationGuardMatches(ctx, tx, beginGuard)
	}
	stmts := []Statement{
		{
			SQL: vmCreateBeginSQL,
			Params: []interface{}{
				vm.Name, vm.StackName, vm.HostName, vm.Spec, vm.StateDetail,
				vm.CPUActual, vm.MemActual, vm.Project, boolToInt(vm.IsTemplate),
				vm.OwnerEpoch, vm.SpecGeneration, op.ID, wall, now,
			},
			Guard: beginGuard,
		},
		operationInsertStatement(op, wall, now, provisionalGuard),
		{
			SQL:    vmInterfacesCreateCleanupSQL,
			Params: []interface{}{wall, now, vm.Name},
			Guard:  &claimedGuard,
		},
		{
			SQL:    vmDisksCreateCleanupSQL,
			Params: []interface{}{wall, now, vm.Name},
			Guard:  &claimedGuard,
		},
		{
			SQL:    vmNICsCreateCleanupSQL,
			Params: []interface{}{wall, now, vm.Name},
			Guard:  &claimedGuard,
		},
		{
			SQL:    vmPCIIntentCreateCleanupSQL,
			Params: []interface{}{wall, now, vm.Name},
			Guard:  &claimedGuard,
		},
		{
			SQL:    vmPCIRealCreateCleanupSQL,
			Params: []interface{}{wall, now, vm.Name},
			Guard:  &claimedGuard,
		},
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepPlanned, "", wall, now, &claimedGuard),
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepReserved, reservedFacts, wall, now, &claimedGuard),
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepDesiredPersisted, "", wall, now, &claimedGuard),
	}
	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// CommitVMCreateOperation atomically installs the complete persisted hardware,
// marks the provisional VM running, clears its operation barrier, and terminates
// the journal. A stale owner, generation, operation id, or immutable provisional
// identity is a no-op.
func (c *Client) CommitVMCreateOperation(ctx context.Context, opID string, ownerEpoch int64, vm VMRecord, ifaces []InterfaceRecord, disks []DiskRecord, nics []NICRecord, intents []PCIIntentRecord) (bool, error) {
	claimHash, ok, err := c.liveOperationClaimHash(ctx, opID)
	if err != nil || !ok {
		return false, err
	}
	now, wall := c.NowTS(), nowRFC3339()
	commitGuard, err := vmCreateMutationGuard(opID, ownerEpoch, vm, true)
	if err != nil {
		return false, err
	}
	commitGuard.OperationClaimHash = claimHash
	guard := func(tx *sql.Tx) (bool, error) {
		return c.mutationGuardMatches(ctx, tx, commitGuard)
	}
	stmts, err := vmCreateHardwareStatements(vm.Name, ifaces, disks, nics, intents, now, commitGuard)
	if err != nil {
		return false, err
	}
	stmts = append(stmts,
		operationStepInsertStatement(opID, ownerEpoch, OpStepPrepared, "", wall, now, commitGuard),
		operationStepInsertStatement(opID, ownerEpoch, OpStepRuntimeStarted, "", wall, now, commitGuard),
		operationStepInsertStatement(opID, ownerEpoch, OpStepObserved, "", wall, now, commitGuard),
		operationStepInsertStatement(opID, ownerEpoch, OpStepCompleted, "", wall, now, commitGuard),
		Statement{
			SQL: vmCreateCommitSQL,
			Params: []interface{}{
				vm.StateDetail, vm.CPUActual, vm.MemActual, now, vm.Name, opID,
				ownerEpoch, vm.SpecGeneration,
			},
			Guard: commitGuard,
		},
	)
	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// RollbackVMCreateOperation tombstones only the matching provisional row and
// terminalizes the operation after compensation. It cannot affect a running VM
// or a row now owned by a different operation/epoch.
func (c *Client) RollbackVMCreateOperation(ctx context.Context, name, opID string, ownerEpoch int64, facts string) (bool, error) {
	claimHash, ok, err := c.liveOperationClaimHash(ctx, opID)
	if err != nil || !ok {
		return false, err
	}
	now, wall := c.NowTS(), nowRFC3339()
	rollbackGuard := vmRollbackMutationGuard(name, opID, ownerEpoch)
	rollbackGuard.OperationClaimHash = claimHash
	guard := func(tx *sql.Tx) (bool, error) {
		return c.mutationGuardMatches(ctx, tx, rollbackGuard)
	}
	return c.ExecuteBatchGuarded(ctx, guard, []Statement{
		operationStepInsertStatement(opID, ownerEpoch, OpStepRollbackCompleted, facts, wall, now, rollbackGuard),
		operationStepInsertStatement(opID, ownerEpoch, OpStepFailed, facts, wall, now, rollbackGuard),
		Statement{
			SQL:    vmCreateRollbackSQL,
			Params: []interface{}{wall, now, name, opID, ownerEpoch},
			Guard:  rollbackGuard,
		},
	})
}

// BeginContainerCreateOperation is the container equivalent of
// BeginVMCreateOperation. Container identity includes its host because v44 keeps
// the historical (host_name,name) primary key.
func (c *Client) BeginContainerCreateOperation(ctx context.Context, op OperationRecord, ct ContainerRecord) (bool, error) {
	if err := normalizeCreateIdentity(&op, ct.Name, "container", ct.OwnerEpoch); err != nil {
		return false, err
	}
	desiredRef := containerCreateDesiredRef(ct.HostName, ct.Name)
	if op.DesiredRef != "" && op.DesiredRef != desiredRef {
		return false, fmt.Errorf("%w: container desired_ref does not match host/name", ErrOperationIdentityConflict)
	}
	op.DesiredRef = desiredRef
	ct.OwnerEpoch = op.VMOwnerEpoch
	if ct.Project == "" {
		ct.Project = projectOrDefault(op.Project)
	} else {
		ct.Project = projectOrDefault(ct.Project)
	}
	if ct.Project != projectOrDefault(op.Project) {
		return false, fmt.Errorf("%w: operation project %q does not match container project %q",
			ErrOperationIdentityConflict, op.Project, ct.Project)
	}
	op.Project = ct.Project
	if err := validateReservationProject(op.ReservationJSON, op.Project); err != nil {
		return false, err
	}
	if err := validateCreateReservationBinding(op.ReservationJSON, ct.HostName); err != nil {
		return false, err
	}
	reservedFacts, err := reservationStepFacts(op.ReservationFacts, op.Project)
	if err != nil {
		return false, err
	}
	labels, err := encodeContainerLabels(ct.Labels)
	if err != nil {
		return false, err
	}
	provisionalGuard, err := containerCreateMutationGuard(op.ID, op.VMOwnerEpoch, ct, false)
	if err != nil {
		return false, err
	}
	beginGuard := containerCreateBeginMutationGuard(op.ID, op.VMOwnerEpoch, ct, labels)
	claimHash := operationClaimHash(op)
	provisionalGuard.OperationClaimHash = claimHash
	beginGuard.OperationClaimHash = claimHash
	claimedGuard := *provisionalGuard
	claimedGuard.RequireOperation = true
	// wall stamps this begin's created_at — a fresh incarnation (see nowRFC3339Nano).
	now, wall := c.NowTS(), nowRFC3339Nano()
	guard := func(tx *sql.Tx) (bool, error) {
		existing, err := operationInTx(ctx, tx, op.ID)
		if err != nil {
			return false, err
		}
		if existing != nil {
			if err := compareOperationClaim(*existing, op); err != nil {
				return false, err
			}
			if err := compareReservedStepInTx(ctx, tx, op.ID, op.VMOwnerEpoch, reservedFacts); err != nil {
				return false, err
			}
			return false, compareContainerCreateRetryInTx(ctx, tx, ct, labels)
		}
		return c.mutationGuardMatches(ctx, tx, beginGuard)
	}
	return c.ExecuteBatchGuarded(ctx, guard, []Statement{
		{
			SQL: containerCreateBeginSQL,
			Params: []interface{}{
				ct.HostName, ct.Name, ct.Image, ct.CPULimit, ct.MemMiB, labels,
				ct.RestartPolicy, ct.StateDetail, ct.Project, boolToInt(ct.IsTemplate),
				ct.OnHostFailure, ct.CreateSpec, ct.RelocateToken, ct.OwnerEpoch,
				ct.SpecGeneration, op.ID, wall, now,
			},
			Guard: beginGuard,
		},
		operationInsertStatement(op, wall, now, provisionalGuard),
		{
			SQL:    containerCreateCleanupSQL,
			Params: []interface{}{wall, now, ct.HostName, ct.Name},
			Guard:  &claimedGuard,
		},
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepPlanned, "", wall, now, &claimedGuard),
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepReserved, reservedFacts, wall, now, &claimedGuard),
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepDesiredPersisted, "", wall, now, &claimedGuard),
	})
}

// CommitContainerCreateOperation atomically persists the container's complete
// managed-interface set and commits its provisional row.
func (c *Client) CommitContainerCreateOperation(ctx context.Context, opID string, ownerEpoch int64, ct ContainerRecord, ifaces []ContainerInterfaceRecord) (bool, error) {
	claimHash, ok, err := c.liveOperationClaimHash(ctx, opID)
	if err != nil || !ok {
		return false, err
	}
	commitGuard, err := containerCreateMutationGuard(opID, ownerEpoch, ct, true)
	if err != nil {
		return false, err
	}
	commitGuard.OperationClaimHash = claimHash
	now, wall := c.NowTS(), nowRFC3339()
	guard := func(tx *sql.Tx) (bool, error) {
		return c.mutationGuardMatches(ctx, tx, commitGuard)
	}
	stmts := make([]Statement, 0, len(ifaces)+5)
	for _, ifc := range ifaces {
		ifc.HostName, ifc.CtName = ct.HostName, ct.Name
		sgs, err := encodeSGs(ifc.SecurityGroups)
		if err != nil {
			return false, err
		}
		stmts = append(stmts, Statement{
			SQL: containerCreateInterfaceSQL,
			Params: []interface{}{
				ifc.HostName, ifc.CtName, ifc.NetworkName, ifc.Ordinal, ifc.MAC,
				ifc.IP, ifc.VethDevice, sgs, now,
			},
			Guard: commitGuard,
		})
	}
	stmts = append(stmts,
		operationStepInsertStatement(opID, ownerEpoch, OpStepPrepared, "", wall, now, commitGuard),
		operationStepInsertStatement(opID, ownerEpoch, OpStepRuntimeStarted, "", wall, now, commitGuard),
		operationStepInsertStatement(opID, ownerEpoch, OpStepObserved, "", wall, now, commitGuard),
		operationStepInsertStatement(opID, ownerEpoch, OpStepCompleted, "", wall, now, commitGuard),
		Statement{
			SQL: containerCreateCommitSQL,
			Params: []interface{}{
				ct.StateDetail, now, ct.HostName, ct.Name, opID, ownerEpoch, ct.SpecGeneration,
			},
			Guard: commitGuard,
		},
	)
	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// RollbackContainerCreateOperation is the fenced container counterpart of
// RollbackVMCreateOperation.
func (c *Client) RollbackContainerCreateOperation(ctx context.Context, hostName, name, opID string, ownerEpoch int64, facts string) (bool, error) {
	claimHash, ok, err := c.liveOperationClaimHash(ctx, opID)
	if err != nil || !ok {
		return false, err
	}
	now, wall := c.NowTS(), nowRFC3339()
	rollbackGuard := containerRollbackMutationGuard(hostName, name, opID, ownerEpoch)
	rollbackGuard.OperationClaimHash = claimHash
	guard := func(tx *sql.Tx) (bool, error) {
		return c.mutationGuardMatches(ctx, tx, rollbackGuard)
	}
	return c.ExecuteBatchGuarded(ctx, guard, []Statement{
		operationStepInsertStatement(opID, ownerEpoch, OpStepRollbackCompleted, facts, wall, now, rollbackGuard),
		operationStepInsertStatement(opID, ownerEpoch, OpStepFailed, facts, wall, now, rollbackGuard),
		Statement{
			SQL:    containerCreateRollbackSQL,
			Params: []interface{}{wall, now, hostName, name, opID, ownerEpoch},
			Guard:  rollbackGuard,
		},
	})
}

func normalizeCreateIdentity(op *OperationRecord, resourceID, resourceKind string, ownerEpoch int64) error {
	if op.ID == "" || resourceID == "" {
		return fmt.Errorf("%w: operation and resource ids must be non-empty", ErrOperationIdentityConflict)
	}
	if op.ResourceID != resourceID || op.ResourceKind != resourceKind ||
		OperationKind(op.OperationKind) != OpWorkloadCreate {
		return fmt.Errorf("%w: got kind=%q resource=%q operation_kind=%q",
			ErrOperationIdentityConflict, op.ResourceKind, op.ResourceID, op.OperationKind)
	}
	if op.VMOwnerEpoch != 0 && ownerEpoch != 0 && op.VMOwnerEpoch != ownerEpoch {
		return fmt.Errorf("%w: owner epoch mismatch", ErrOperationIdentityConflict)
	}
	if op.VMOwnerEpoch == 0 {
		op.VMOwnerEpoch = ownerEpoch
	}
	return nil
}

func validateCreateReservationBinding(raw, workloadHost string) error {
	rv, err := DecodeReservation(raw)
	if err != nil {
		return err
	}
	if rv.TargetHost != "" && rv.TargetHost != workloadHost {
		return fmt.Errorf("%w: reservation target host %q does not match workload host %q",
			ErrOperationIdentityConflict, rv.TargetHost, workloadHost)
	}
	if rv.SourceHost != "" {
		return fmt.Errorf("%w: create reservation cannot bind source host %q",
			ErrOperationIdentityConflict, rv.SourceHost)
	}
	return nil
}

func operationInTx(ctx context.Context, tx *sql.Tx, id string) (*OperationRecord, error) {
	var op OperationRecord
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT id, method, principal, project, resource_kind, resource_id,
		        operation_kind, request_hash, idempotency_key, reservation_json,
		        desired_ref, vm_owner_epoch, created_at, updated_at, deleted_at
		 FROM operations WHERE id = ?`, id).
		Scan(&op.ID, &op.Method, &op.Principal, &op.Project, &op.ResourceKind,
			&op.ResourceID, &op.OperationKind, &op.RequestHash, &op.IdempotencyKey,
			&op.ReservationJSON, &op.DesiredRef, &op.VMOwnerEpoch, &op.CreatedAt,
			&op.UpdatedAt, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if deleted.Valid {
		op.DeletedAt = deleted.String
	}
	return &op, nil
}

func compareOperationClaim(existing, requested OperationRecord) error {
	if existing.RequestHash != requested.RequestHash {
		return ErrOperationHashConflict
	}
	if !sameOperationClaim(existing, requested) {
		return ErrOperationIdentityConflict
	}
	return nil
}

// canonicalOperationClaim is the single canonicalization boundary for immutable
// operation identity. Keep sameOperationClaim and the replicated guard
// fingerprint on this exact representation so they cannot drift.
type canonicalOperationClaim struct {
	ID              string `json:"id"`
	Method          string `json:"method"`
	Principal       string `json:"principal"`
	Project         string `json:"project"`
	ResourceKind    string `json:"resource_kind"`
	ResourceID      string `json:"resource_id"`
	OperationKind   string `json:"operation_kind"`
	RequestHash     string `json:"request_hash"`
	IdempotencyKey  string `json:"idempotency_key"`
	ReservationJSON string `json:"reservation_json"`
	DesiredRef      string `json:"desired_ref"`
	VMOwnerEpoch    int64  `json:"vm_owner_epoch"`
}

func canonicalizeOperationClaim(op OperationRecord) canonicalOperationClaim {
	return canonicalOperationClaim{
		ID: op.ID, Method: op.Method, Principal: op.Principal,
		Project: projectOrDefault(op.Project), ResourceKind: op.ResourceKind,
		ResourceID: op.ResourceID, OperationKind: op.OperationKind,
		RequestHash: op.RequestHash, IdempotencyKey: op.IdempotencyKey,
		ReservationJSON: op.ReservationJSON, DesiredRef: op.DesiredRef,
		VMOwnerEpoch: op.VMOwnerEpoch,
	}
}

// sameOperationClaim compares the complete immutable request identity of an
// operation header. Storage timestamps and the GC tombstone are metadata, not
// claim identity. Project is canonicalized exactly as begin/idempotency does.
func sameOperationClaim(a, b OperationRecord) bool {
	return canonicalizeOperationClaim(a) == canonicalizeOperationClaim(b)
}

func operationClaimHash(op OperationRecord) string {
	encoded, err := json.Marshal(canonicalizeOperationClaim(op))
	if err != nil {
		panic("marshal canonical operation claim: " + err.Error())
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (c *Client) liveOperationClaimHash(ctx context.Context, opID string) (string, bool, error) {
	op, err := GetOperation(ctx, c, opID)
	if err != nil || op == nil {
		return "", false, err
	}
	return operationClaimHash(*op), true, nil
}

func compareReservedStepInTx(ctx context.Context, tx *sql.Tx, opID string, ownerEpoch int64, requestedFacts string) error {
	var existingFacts string
	err := tx.QueryRowContext(ctx,
		`SELECT facts FROM operation_steps
		 WHERE operation_id = ? AND owner_epoch = ? AND step_name = ? AND deleted_at IS NULL`,
		opID, ownerEpoch, OpStepReserved).Scan(&existingFacts)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrOperationStepConflict
	}
	if err != nil {
		return err
	}
	if existingFacts != requestedFacts {
		return ErrOperationStepConflict
	}
	return nil
}

func compareVMCreateRetryInTx(ctx context.Context, tx *sql.Tx, requested VMRecord) error {
	var stored VMRecord
	var template int
	err := tx.QueryRowContext(ctx,
		`SELECT name, stack_name, host_name, spec, state_detail, cpu_actual,
		        mem_actual, project, is_template, vm_owner_epoch, spec_generation
		 FROM vms WHERE name = ?`, requested.Name).
		Scan(&stored.Name, &stored.StackName, &stored.HostName, &stored.Spec,
			&stored.StateDetail, &stored.CPUActual, &stored.MemActual,
			&stored.Project, &template, &stored.OwnerEpoch, &stored.SpecGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrOperationIdentityConflict
	}
	if err != nil {
		return err
	}
	stored.IsTemplate = template != 0
	if stored.Name != requested.Name ||
		stored.StackName != requested.StackName ||
		stored.HostName != requested.HostName ||
		stored.Spec != requested.Spec ||
		stored.StateDetail != requested.StateDetail ||
		stored.CPUActual != requested.CPUActual ||
		stored.MemActual != requested.MemActual ||
		projectOrDefault(stored.Project) != projectOrDefault(requested.Project) ||
		stored.IsTemplate != requested.IsTemplate ||
		stored.OwnerEpoch != requested.OwnerEpoch ||
		stored.SpecGeneration != requested.SpecGeneration {
		return ErrOperationIdentityConflict
	}
	return nil
}

func compareContainerCreateRetryInTx(ctx context.Context, tx *sql.Tx, requested ContainerRecord, requestedLabels string) error {
	var stored ContainerRecord
	var storedLabels string
	var template int
	err := tx.QueryRowContext(ctx,
		`SELECT host_name, name, image, cpu_limit, memory_mib, labels,
		        restart_policy, state_detail, project, is_template,
		        on_host_failure, create_spec, relocate_token, owner_epoch,
		        spec_generation
		 FROM containers WHERE host_name = ? AND name = ?`,
		requested.HostName, requested.Name).
		Scan(&stored.HostName, &stored.Name, &stored.Image, &stored.CPULimit,
			&stored.MemMiB, &storedLabels, &stored.RestartPolicy,
			&stored.StateDetail, &stored.Project, &template,
			&stored.OnHostFailure, &stored.CreateSpec, &stored.RelocateToken,
			&stored.OwnerEpoch, &stored.SpecGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrOperationIdentityConflict
	}
	if err != nil {
		return err
	}
	stored.IsTemplate = template != 0
	if stored.HostName != requested.HostName ||
		stored.Name != requested.Name ||
		stored.Image != requested.Image ||
		stored.CPULimit != requested.CPULimit ||
		stored.MemMiB != requested.MemMiB ||
		storedLabels != requestedLabels ||
		stored.RestartPolicy != requested.RestartPolicy ||
		stored.StateDetail != requested.StateDetail ||
		projectOrDefault(stored.Project) != projectOrDefault(requested.Project) ||
		stored.IsTemplate != requested.IsTemplate ||
		stored.OnHostFailure != requested.OnHostFailure ||
		stored.CreateSpec != requested.CreateSpec ||
		stored.RelocateToken != requested.RelocateToken ||
		stored.OwnerEpoch != requested.OwnerEpoch ||
		stored.SpecGeneration != requested.SpecGeneration {
		return ErrOperationIdentityConflict
	}
	return nil
}

func containerCreateDesiredRef(hostName, name string) string {
	return fmt.Sprintf("container/%d:%s/%d:%s", len(hostName), hostName, len(name), name)
}

func parseContainerCreateDesiredRef(ref string) (hostName, name string, ok bool) {
	const prefix = "container/"
	if !strings.HasPrefix(ref, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(ref, prefix)
	read := func(s string) (value, tail string, valid bool) {
		colon := strings.IndexByte(s, ':')
		if colon <= 0 {
			return "", "", false
		}
		n, err := strconv.Atoi(s[:colon])
		if err != nil || n < 0 || len(s[colon+1:]) < n {
			return "", "", false
		}
		value = s[colon+1 : colon+1+n]
		return value, s[colon+1+n:], true
	}
	hostName, rest, ok = read(rest)
	if !ok || !strings.HasPrefix(rest, "/") {
		return "", "", false
	}
	name, rest, ok = read(strings.TrimPrefix(rest, "/"))
	return hostName, name, ok && rest == ""
}

func validateReservationProject(raw, operationProject string) error {
	rv, err := DecodeReservation(raw)
	if err != nil {
		return fmt.Errorf("decode reservation: %w", err)
	}
	if raw == "" || rv == (ReservationVector{}) {
		return nil
	}
	// A pre-project operation header cannot prove a binding. Preserve those
	// genuinely legacy rows; every modern nonempty project is exact.
	if operationProject == "" {
		return nil
	}
	if rv.Project != operationProject {
		return fmt.Errorf("%w: reservation project %q does not match operation project %q",
			ErrOperationIdentityConflict, rv.Project, operationProject)
	}
	return nil
}

func operationInsertStatement(op OperationRecord, wall, now string, guard *MutationGuard) Statement {
	return Statement{
		SQL: `INSERT INTO operations (` + operationCols + `)
		     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		Params: []interface{}{
			op.ID, op.Method, op.Principal, op.Project, op.ResourceKind, op.ResourceID,
			op.OperationKind, op.RequestHash, op.IdempotencyKey, op.ReservationJSON,
			op.DesiredRef, op.VMOwnerEpoch, wall, now,
		},
		Guard: guard,
	}
}

func operationStepInsertStatement(opID string, ownerEpoch int64, step, facts, wall, now string, guard *MutationGuard) Statement {
	return Statement{
		SQL: `INSERT INTO operation_steps
		     (operation_id, owner_epoch, step_name, facts, created_at, updated_at, deleted_at)
		     VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		Params: []interface{}{opID, ownerEpoch, step, facts, wall, now},
		Guard:  guard,
	}
}

func encodeContainerLabels(labels map[string]string) (string, error) {
	if len(labels) == 0 {
		return "", nil
	}
	b, err := json.Marshal(labels)
	return string(b), err
}

func vmCreateHardwareStatements(vmName string, ifaces []InterfaceRecord, disks []DiskRecord, nics []NICRecord, intents []PCIIntentRecord, now string, guard *MutationGuard) ([]Statement, error) {
	stmts := make([]Statement, 0, len(ifaces)+len(disks)+len(nics)+len(intents))
	ifaceKeys := make(map[string]struct{}, len(ifaces))
	for _, iface := range ifaces {
		if _, duplicate := ifaceKeys[iface.NetworkName]; duplicate {
			return nil, fmt.Errorf("duplicate VM interface network %q", iface.NetworkName)
		}
		ifaceKeys[iface.NetworkName] = struct{}{}
		sgs, err := encodeSGs(iface.SecurityGroups)
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, Statement{
			SQL: `INSERT INTO vm_interfaces
			 (vm_name, network_name, ordinal, mac, ip, tap_device, security_groups, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
			 ON CONFLICT(vm_name, network_name) DO UPDATE SET
			   ordinal = excluded.ordinal,
			   mac = excluded.mac,
			   ip = excluded.ip,
			   tap_device = excluded.tap_device,
			   security_groups = excluded.security_groups,
			   updated_at = excluded.updated_at,
			   deleted_at = NULL`,
			Params: []interface{}{
				vmName, iface.NetworkName, iface.Ordinal, iface.MAC, iface.IP,
				iface.TapDevice, sgs, now,
			},
			Guard: guard,
		})
	}
	diskKeys := make(map[string]struct{}, len(disks))
	for _, disk := range disks {
		if _, duplicate := diskKeys[disk.DiskName]; duplicate {
			return nil, fmt.Errorf("duplicate VM disk %q", disk.DiskName)
		}
		diskKeys[disk.DiskName] = struct{}{}
		deviceKind := disk.DeviceKind
		if deviceKind == "" {
			deviceKind = "disk"
		}
		stmts = append(stmts, Statement{
			SQL: `INSERT INTO vm_disks
			 (vm_name, disk_name, host_name, path, size_bytes, backing_image,
			  storage_type, storage_volume, target_dev, backing_disk, bus,
			  device_kind, delete_with_vm, controller_model, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
			 ON CONFLICT(vm_name, disk_name) DO UPDATE SET
			   host_name = excluded.host_name,
			   path = excluded.path,
			   size_bytes = excluded.size_bytes,
			   backing_image = excluded.backing_image,
			   storage_type = excluded.storage_type,
			   storage_volume = excluded.storage_volume,
			   target_dev = excluded.target_dev,
			   backing_disk = excluded.backing_disk,
			   bus = excluded.bus,
			   device_kind = excluded.device_kind,
			   delete_with_vm = excluded.delete_with_vm,
			   controller_model = excluded.controller_model,
			   updated_at = excluded.updated_at,
			   deleted_at = NULL`,
			Params: []interface{}{
				vmName, disk.DiskName, disk.HostName, disk.Path, disk.SizeBytes,
				disk.BackingImage, disk.StorageType, disk.StorageVolume,
				disk.TargetDev, nullIfEmpty(disk.BackingDisk), nullIfEmpty(disk.Bus),
				deviceKind, boolToInt(disk.DeleteWithVM),
				nullIfEmpty(disk.ControllerModel), now,
			},
			Guard: guard,
		})
	}
	nicKeys := make(map[string]struct{}, len(nics))
	for _, nic := range nics {
		if _, duplicate := nicKeys[nic.ID]; duplicate {
			return nil, fmt.Errorf("duplicate VM NIC %q", nic.ID)
		}
		nicKeys[nic.ID] = struct{}{}
		model := nic.Model
		if model == "" {
			model = "virtio"
		}
		stmts = append(stmts, Statement{
			SQL: `INSERT OR REPLACE INTO vm_nics
			 (vm_name, id, network_name, model, mac, ordinal, ip, tap_device,
			  security_groups, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			Params: []interface{}{
				vmName, nic.ID, nic.NetworkName, model, nic.MAC, nic.Ordinal,
				nullIfEmpty(nic.IP), nullIfEmpty(nic.TapDevice),
				nullIfEmpty(nic.SecurityGroups), now,
			},
			Guard: guard,
		})
	}
	intentKeys := make(map[string]struct{}, len(intents))
	for _, in := range intents {
		if _, duplicate := intentKeys[in.DeviceID]; duplicate {
			return nil, fmt.Errorf("duplicate VM PCI intent %q", in.DeviceID)
		}
		intentKeys[in.DeviceID] = struct{}{}
		var exclusive interface{}
		if in.ExclusiveKey != nil {
			exclusive = *in.ExclusiveKey
		}
		stmts = append(stmts, Statement{
			SQL: `INSERT OR REPLACE INTO vm_pci_intent
			 (vm_name, device_id, host_name, selector_kind, selector_payload,
			  exclusive_key, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
			Params: []interface{}{
				vmName, in.DeviceID, in.HostName, in.SelectorKind,
				in.SelectorPayload, exclusive, now,
			},
			Guard: guard,
		})
	}
	return stmts, nil
}
