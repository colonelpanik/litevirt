package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	workloadCreateGuardV1      = "workload_create_v1"
	workloadCreateBeginGuardV1 = "workload_create_begin_v1"
)

// MutationGuard carries the local create-operation transaction predicate over
// replication. It is deliberately structured rather than arbitrary SQL: every
// receiver evaluates one fixed, audited predicate and unknown protocols fail
// closed.
type MutationGuard struct {
	Protocol            string `json:"protocol"`
	ResourceKind        string `json:"resource_kind"`
	ResourceID          string `json:"resource_id"`
	HostName            string `json:"host_name,omitempty"`
	OperationID         string `json:"operation_id"`
	OwnerEpoch          int64  `json:"owner_epoch"`
	SpecGeneration      int64  `json:"spec_generation,omitempty"`
	CheckSpecGeneration bool   `json:"check_spec_generation,omitempty"`
	IdentityHash        string `json:"identity_hash,omitempty"`
	RequireOperation    bool   `json:"require_operation,omitempty"`
}

func vmCreateMutationGuard(opID string, ownerEpoch int64, vm VMRecord, requireOperation bool) (*MutationGuard, error) {
	return &MutationGuard{
		Protocol: workloadCreateGuardV1, ResourceKind: "vm", ResourceID: vm.Name,
		HostName: vm.HostName, OperationID: opID, OwnerEpoch: ownerEpoch,
		SpecGeneration: vm.SpecGeneration, CheckSpecGeneration: true,
		IdentityHash: vmCreateIdentityHash(vm), RequireOperation: requireOperation,
	}, nil
}

func vmCreateBeginMutationGuard(opID string, ownerEpoch int64, vm VMRecord) *MutationGuard {
	return &MutationGuard{
		Protocol: workloadCreateBeginGuardV1, ResourceKind: "vm", ResourceID: vm.Name,
		HostName: vm.HostName, OperationID: opID, OwnerEpoch: ownerEpoch,
		SpecGeneration: vm.SpecGeneration, CheckSpecGeneration: true,
		IdentityHash: vmCreateIdentityHash(vm),
	}
}

func containerCreateMutationGuard(opID string, ownerEpoch int64, ct ContainerRecord, requireOperation bool) (*MutationGuard, error) {
	labels, err := encodeContainerLabels(ct.Labels)
	if err != nil {
		return nil, err
	}
	return &MutationGuard{
		Protocol: workloadCreateGuardV1, ResourceKind: "container", ResourceID: ct.Name,
		HostName: ct.HostName, OperationID: opID, OwnerEpoch: ownerEpoch,
		SpecGeneration: ct.SpecGeneration, CheckSpecGeneration: true,
		IdentityHash: containerCreateIdentityHash(ct, labels), RequireOperation: requireOperation,
	}, nil
}

func containerCreateBeginMutationGuard(opID string, ownerEpoch int64, ct ContainerRecord, labels string) *MutationGuard {
	return &MutationGuard{
		Protocol: workloadCreateBeginGuardV1, ResourceKind: "container", ResourceID: ct.Name,
		HostName: ct.HostName, OperationID: opID, OwnerEpoch: ownerEpoch,
		SpecGeneration: ct.SpecGeneration, CheckSpecGeneration: true,
		IdentityHash: containerCreateIdentityHash(ct, labels),
	}
}

func vmRollbackMutationGuard(name, opID string, ownerEpoch int64) *MutationGuard {
	return &MutationGuard{
		Protocol: workloadCreateGuardV1, ResourceKind: "vm", ResourceID: name,
		OperationID: opID, OwnerEpoch: ownerEpoch, RequireOperation: true,
	}
}

func containerRollbackMutationGuard(hostName, name, opID string, ownerEpoch int64) *MutationGuard {
	return &MutationGuard{
		Protocol: workloadCreateGuardV1, ResourceKind: "container", ResourceID: name,
		HostName: hostName, OperationID: opID, OwnerEpoch: ownerEpoch, RequireOperation: true,
	}
}

func (c *Client) mutationGuardMatches(ctx context.Context, tx *sql.Tx, guard *MutationGuard) (bool, error) {
	if guard == nil {
		return true, nil
	}
	if guard.OperationID == "" || guard.ResourceID == "" {
		return false, fmt.Errorf("invalid mutation guard protocol or identity")
	}
	if guard.Protocol == workloadCreateBeginGuardV1 {
		return createBeginGuardMatches(ctx, tx, guard)
	}
	if guard.Protocol != workloadCreateGuardV1 {
		return false, fmt.Errorf("invalid mutation guard protocol or identity")
	}

	var workloadProject, workloadHost string
	switch guard.ResourceKind {
	case "vm":
		var stackName, spec, state, active string
		var isTemplate int
		var ownerEpoch, generation int64
		err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(stack_name, ''), host_name, spec, state,
			        COALESCE(project, '_default'), COALESCE(is_template, 0),
			        vm_owner_epoch, spec_generation, active_operation_id
			 FROM vms WHERE name = ? AND deleted_at IS NULL`, guard.ResourceID).
			Scan(&stackName, &workloadHost, &spec, &state, &workloadProject,
				&isTemplate, &ownerEpoch, &generation, &active)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if state != "creating" || active != guard.OperationID || ownerEpoch != guard.OwnerEpoch ||
			guard.HostName != "" && workloadHost != guard.HostName ||
			guard.CheckSpecGeneration && generation != guard.SpecGeneration {
			return false, nil
		}
		if guard.IdentityHash != "" {
			row := VMRecord{
				Name: guard.ResourceID, StackName: stackName, HostName: workloadHost,
				Spec: spec, Project: workloadProject, IsTemplate: isTemplate != 0,
			}
			if vmCreateIdentityHash(row) != guard.IdentityHash {
				return false, nil
			}
		}
	case "container":
		var image, labels, restartPolicy, state, project, onHostFailure, createSpec, relocateToken, active string
		var cpu, mem, isTemplate int
		var ownerEpoch, generation int64
		err := tx.QueryRowContext(ctx,
			`SELECT image, cpu_limit, memory_mib, COALESCE(labels, ''),
			        COALESCE(restart_policy, ''), state, COALESCE(project, '_default'),
			        COALESCE(is_template, 0), COALESCE(on_host_failure, ''),
			        COALESCE(create_spec, ''), COALESCE(relocate_token, ''),
			        owner_epoch, spec_generation, active_operation_id
			 FROM containers WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
			guard.HostName, guard.ResourceID).
			Scan(&image, &cpu, &mem, &labels, &restartPolicy, &state, &project,
				&isTemplate, &onHostFailure, &createSpec, &relocateToken,
				&ownerEpoch, &generation, &active)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		workloadHost, workloadProject = guard.HostName, project
		if state != "creating" || active != guard.OperationID || ownerEpoch != guard.OwnerEpoch ||
			guard.CheckSpecGeneration && generation != guard.SpecGeneration {
			return false, nil
		}
		if guard.IdentityHash != "" {
			row := ContainerRecord{
				HostName: guard.HostName, Name: guard.ResourceID, Image: image,
				CPULimit: cpu, MemMiB: mem, RestartPolicy: restartPolicy,
				Project: project, IsTemplate: isTemplate != 0,
				OnHostFailure: onHostFailure, CreateSpec: createSpec, RelocateToken: relocateToken,
			}
			if containerCreateIdentityHash(row, labels) != guard.IdentityHash {
				return false, nil
			}
		}
	default:
		return false, fmt.Errorf("invalid mutation guard resource kind %q", guard.ResourceKind)
	}

	if !guard.RequireOperation {
		return true, nil
	}
	var opProject, resourceKind, resourceID, operationKind, reservationJSON, desiredRef string
	var opOwnerEpoch int64
	err := tx.QueryRowContext(ctx,
		`SELECT project, resource_kind, resource_id, operation_kind,
		        reservation_json, desired_ref, vm_owner_epoch
		 FROM operations WHERE id = ? AND deleted_at IS NULL`, guard.OperationID).
		Scan(&opProject, &resourceKind, &resourceID, &operationKind,
			&reservationJSON, &desiredRef, &opOwnerEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if guard.ResourceKind == "container" &&
		desiredRef != containerCreateDesiredRef(workloadHost, guard.ResourceID) {
		return false, nil
	}
	if resourceKind != guard.ResourceKind || resourceID != guard.ResourceID ||
		OperationKind(operationKind) != OpWorkloadCreate ||
		projectOrDefault(opProject) != projectOrDefault(workloadProject) ||
		opOwnerEpoch != guard.OwnerEpoch {
		return false, nil
	}
	reservation, err := DecodeReservation(reservationJSON)
	if err != nil {
		return false, fmt.Errorf("guard reservation: %w", err)
	}
	if reservation.TargetHost != "" && reservation.TargetHost != workloadHost {
		return false, nil
	}
	if reservation.Project != "" && projectOrDefault(reservation.Project) != projectOrDefault(workloadProject) {
		return false, nil
	}
	return true, nil
}

// createBeginGuardMatches authorizes the one statement that establishes a
// provisional workload row. A receiver may install a fresh identity, or
// resurrect a tombstone only when BOTH ABA axes advance. Any live row,
// including another provisional create, is an unconditional refusal.
func createBeginGuardMatches(ctx context.Context, tx *sql.Tx, guard *MutationGuard) (bool, error) {
	if guard.RequireOperation || !guard.CheckSpecGeneration {
		return false, fmt.Errorf("invalid create-begin mutation guard")
	}
	var ownerEpoch, generation int64
	var deletedAt sql.NullString
	var err error
	switch guard.ResourceKind {
	case "vm":
		err = tx.QueryRowContext(ctx,
			`SELECT vm_owner_epoch, spec_generation, deleted_at FROM vms WHERE name = ?`,
			guard.ResourceID).Scan(&ownerEpoch, &generation, &deletedAt)
	case "container":
		if guard.HostName == "" {
			return false, fmt.Errorf("invalid container create-begin mutation guard")
		}
		err = tx.QueryRowContext(ctx,
			`SELECT owner_epoch, spec_generation, deleted_at
			 FROM containers WHERE host_name = ? AND name = ?`,
			guard.HostName, guard.ResourceID).Scan(&ownerEpoch, &generation, &deletedAt)
	default:
		return false, fmt.Errorf("invalid mutation guard resource kind %q", guard.ResourceKind)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return deletedAt.Valid &&
		guard.OwnerEpoch > ownerEpoch &&
		guard.SpecGeneration > generation, nil
}

func vmCreateIdentityHash(vm VMRecord) string {
	return hashIdentity(
		vm.Name, vm.StackName, vm.HostName, vm.Spec, projectOrDefault(vm.Project),
		fmt.Sprintf("%t", vm.IsTemplate),
	)
}

func containerCreateIdentityHash(ct ContainerRecord, labelsJSON string) string {
	return hashIdentity(
		ct.HostName, ct.Name, ct.Image, fmt.Sprintf("%d", ct.CPULimit),
		fmt.Sprintf("%d", ct.MemMiB), labelsJSON, ct.RestartPolicy,
		projectOrDefault(ct.Project), fmt.Sprintf("%t", ct.IsTemplate),
		ct.OnHostFailure, ct.CreateSpec, ct.RelocateToken,
	)
}

func hashIdentity(fields ...string) string {
	h := sha256.New()
	for _, field := range fields {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return hex.EncodeToString(h.Sum(nil))
}
