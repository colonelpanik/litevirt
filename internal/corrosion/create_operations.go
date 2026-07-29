package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	reservedFacts, err := reservationStepFacts(op.ReservationFacts, op.Project)
	if err != nil {
		return false, err
	}
	provisionalGuard, err := vmCreateMutationGuard(op.ID, op.VMOwnerEpoch, vm, false)
	if err != nil {
		return false, err
	}
	claimedGuard := *provisionalGuard
	claimedGuard.RequireOperation = true
	now, wall := c.NowTS(), nowRFC3339()
	guard := func(tx *sql.Tx) (bool, error) {
		existing, err := operationInTx(ctx, tx, op.ID)
		if err != nil {
			return false, err
		}
		if existing != nil {
			if err := compareOperationClaim(*existing, op); err != nil {
				return false, err
			}
			return false, compareReservedStepInTx(ctx, tx, op.ID, op.VMOwnerEpoch, reservedFacts)
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM vms WHERE name = ?`, vm.Name).Scan(&n); err != nil {
			return false, err
		}
		return n == 0, nil
	}
	stmts := []Statement{
		{
			SQL: `INSERT INTO vms (name, stack_name, host_name, spec, state, state_detail,
				cpu_actual, mem_actual, project, is_template, vm_owner_epoch,
				spec_generation, active_operation_id, created_at, updated_at)
			 VALUES (?, ?, ?, ?, 'creating', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{
				vm.Name, vm.StackName, vm.HostName, vm.Spec, vm.StateDetail,
				vm.CPUActual, vm.MemActual, vm.Project, boolToInt(vm.IsTemplate),
				vm.OwnerEpoch, vm.SpecGeneration, op.ID, wall, now,
			},
		},
		operationInsertStatement(op, wall, now, provisionalGuard),
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
	now, wall := c.NowTS(), nowRFC3339()
	commitGuard, err := vmCreateMutationGuard(opID, ownerEpoch, vm, true)
	if err != nil {
		return false, err
	}
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
			SQL: `UPDATE vms SET state = 'running', state_detail = ?,
				cpu_actual = ?, mem_actual = ?,
				hardware_adoption_state = 'adopted', hardware_adoption_error = NULL,
				active_operation_id = '', updated_at = ?
			 WHERE name = ? AND state = 'creating' AND active_operation_id = ?
			   AND vm_owner_epoch = ? AND spec_generation = ? AND deleted_at IS NULL`,
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
	now, wall := c.NowTS(), nowRFC3339()
	rollbackGuard := vmRollbackMutationGuard(name, opID, ownerEpoch)
	guard := func(tx *sql.Tx) (bool, error) {
		return c.mutationGuardMatches(ctx, tx, rollbackGuard)
	}
	return c.ExecuteBatchGuarded(ctx, guard, []Statement{
		operationStepInsertStatement(opID, ownerEpoch, OpStepRollbackCompleted, facts, wall, now, rollbackGuard),
		operationStepInsertStatement(opID, ownerEpoch, OpStepFailed, facts, wall, now, rollbackGuard),
		Statement{
			SQL: `UPDATE vms SET active_operation_id = '', deleted_at = ?, updated_at = ?
			 WHERE name = ? AND state = 'creating' AND active_operation_id = ?
			   AND vm_owner_epoch = ? AND deleted_at IS NULL`,
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
	claimedGuard := *provisionalGuard
	claimedGuard.RequireOperation = true
	now, wall := c.NowTS(), nowRFC3339()
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
			return false, compareContainerCreateRetryInTx(ctx, tx, op.ID, ct)
		}
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM containers WHERE host_name = ? AND name = ?`,
			ct.HostName, ct.Name).Scan(&n); err != nil {
			return false, err
		}
		return n == 0, nil
	}
	return c.ExecuteBatchGuarded(ctx, guard, []Statement{
		{
			SQL: `INSERT INTO containers
			 (host_name, name, state, image, cpu_limit, memory_mib, labels,
			  restart_policy, state_detail, project, is_template, on_host_failure,
			  create_spec, relocate_token, owner_epoch, spec_generation,
			  active_operation_id, created_at, updated_at)
			 VALUES (?, ?, 'creating', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{
				ct.HostName, ct.Name, ct.Image, ct.CPULimit, ct.MemMiB, labels,
				ct.RestartPolicy, ct.StateDetail, ct.Project, boolToInt(ct.IsTemplate),
				ct.OnHostFailure, ct.CreateSpec, ct.RelocateToken, ct.OwnerEpoch,
				ct.SpecGeneration, op.ID, wall, now,
			},
		},
		operationInsertStatement(op, wall, now, provisionalGuard),
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepPlanned, "", wall, now, &claimedGuard),
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepReserved, reservedFacts, wall, now, &claimedGuard),
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepDesiredPersisted, "", wall, now, &claimedGuard),
	})
}

// CommitContainerCreateOperation atomically persists the container's complete
// managed-interface set and commits its provisional row.
func (c *Client) CommitContainerCreateOperation(ctx context.Context, opID string, ownerEpoch int64, ct ContainerRecord, ifaces []ContainerInterfaceRecord) (bool, error) {
	commitGuard, err := containerCreateMutationGuard(opID, ownerEpoch, ct, true)
	if err != nil {
		return false, err
	}
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
			SQL: `INSERT OR REPLACE INTO container_interfaces
			 (host_name, ct_name, network_name, ordinal, mac, ip, veth_device, security_groups, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
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
			SQL: `UPDATE containers SET state = 'running', state_detail = ?,
				active_operation_id = '', updated_at = ?
			 WHERE host_name = ? AND name = ? AND state = 'creating'
			   AND active_operation_id = ? AND owner_epoch = ? AND spec_generation = ?
			   AND deleted_at IS NULL`,
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
	now, wall := c.NowTS(), nowRFC3339()
	rollbackGuard := containerRollbackMutationGuard(hostName, name, opID, ownerEpoch)
	guard := func(tx *sql.Tx) (bool, error) {
		return c.mutationGuardMatches(ctx, tx, rollbackGuard)
	}
	return c.ExecuteBatchGuarded(ctx, guard, []Statement{
		operationStepInsertStatement(opID, ownerEpoch, OpStepRollbackCompleted, facts, wall, now, rollbackGuard),
		operationStepInsertStatement(opID, ownerEpoch, OpStepFailed, facts, wall, now, rollbackGuard),
		Statement{
			SQL: `UPDATE containers SET active_operation_id = '', deleted_at = ?, updated_at = ?
			 WHERE host_name = ? AND name = ? AND state = 'creating'
			   AND active_operation_id = ? AND owner_epoch = ? AND deleted_at IS NULL`,
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
	if existing.Method != requested.Method || existing.Principal != requested.Principal ||
		projectOrDefault(existing.Project) != projectOrDefault(requested.Project) ||
		existing.ResourceKind != requested.ResourceKind ||
		existing.ResourceID != requested.ResourceID ||
		existing.OperationKind != requested.OperationKind ||
		existing.IdempotencyKey != requested.IdempotencyKey ||
		existing.ReservationJSON != requested.ReservationJSON ||
		existing.DesiredRef != requested.DesiredRef ||
		existing.VMOwnerEpoch != requested.VMOwnerEpoch {
		return ErrOperationIdentityConflict
	}
	return nil
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

func compareContainerCreateRetryInTx(ctx context.Context, tx *sql.Tx, opID string, requested ContainerRecord) error {
	var hostName, name string
	err := tx.QueryRowContext(ctx,
		`SELECT host_name, name FROM containers
		 WHERE active_operation_id = ? AND deleted_at IS NULL LIMIT 1`, opID).
		Scan(&hostName, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if hostName != requested.HostName || name != requested.Name {
		return ErrOperationIdentityConflict
	}
	return nil
}

func containerCreateDesiredRef(hostName, name string) string {
	return fmt.Sprintf("container/%d:%s/%d:%s", len(hostName), hostName, len(name), name)
}

func validateReservationProject(raw, operationProject string) error {
	rv, err := DecodeReservation(raw)
	if err != nil {
		return fmt.Errorf("decode reservation: %w", err)
	}
	if rv.Project != "" && projectOrDefault(rv.Project) != projectOrDefault(operationProject) {
		return fmt.Errorf("%w: reservation project %q does not match operation project %q",
			ErrOperationIdentityConflict, rv.Project, operationProject)
	}
	if (rv.ProjectCPU != 0 || rv.ProjectMemMiB != 0) && rv.Project == "" &&
		projectOrDefault(operationProject) != DefaultProject {
		return fmt.Errorf("%w: project reservation is missing its non-default project",
			ErrOperationIdentityConflict)
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
	for _, iface := range ifaces {
		sgs, err := encodeSGs(iface.SecurityGroups)
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, Statement{
			SQL: `INSERT INTO vm_interfaces
			 (vm_name, network_name, ordinal, mac, ip, tap_device, security_groups, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{
				vmName, iface.NetworkName, iface.Ordinal, iface.MAC, iface.IP,
				iface.TapDevice, sgs, now,
			},
			Guard: guard,
		})
	}
	for _, disk := range disks {
		deviceKind := disk.DeviceKind
		if deviceKind == "" {
			deviceKind = "disk"
		}
		stmts = append(stmts, Statement{
			SQL: `INSERT INTO vm_disks
			 (vm_name, disk_name, host_name, path, size_bytes, backing_image,
			  storage_type, storage_volume, target_dev, backing_disk, bus,
			  device_kind, delete_with_vm, controller_model, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
	for _, nic := range nics {
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
	for _, in := range intents {
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
