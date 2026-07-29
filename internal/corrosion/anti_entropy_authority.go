package corrosion

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
)

// mergeAuthorityManifest binds legacy child rows (which have no owner columns)
// to the workload and operation identities shipped in the same anti-entropy
// payload. Missing or malformed identity is a keep-local decision.
type mergeAuthorityManifest struct {
	vms        map[string]workloadMergeAuthority
	containers map[string]workloadMergeAuthority
	operations map[string]operationMergeAuthority
}

type workloadMergeAuthority struct {
	kind, name, host, project, state, activeOperationID string
	ownerEpoch, generation                              int64
	identityHash                                        string
	deleted, valid                                      bool
}

type operationMergeAuthority struct {
	OperationRecord
	valid bool
}

type mergeAuthorityDecision uint8

const (
	mergeAuthorityNormal mergeAuthorityDecision = iota
	mergeAuthorityKeepLocal
	mergeAuthorityApplyIncoming
	mergeAuthorityApplyIncomingAndSweep
)

var vmAuthorityChildTables = map[string]bool{
	"vm_interfaces":       true,
	"vm_disks":            true,
	"vm_nics":             true,
	"vm_pci_intent":       true,
	"vm_pci_realizations": true,
}

// authorityOrderedMergeTables derives one immutable manifest before any row is
// applied, then orders parents before their dependants. Stable sorting preserves
// the sender's order within each dependency tier.
func authorityOrderedMergeTables(payload *syncPayload) []syncTable {
	manifest := buildMergeAuthorityManifest(payload)
	tables := append([]syncTable(nil), payload.Tables...)
	for i := range tables {
		tables[i].authority = manifest
	}
	sort.SliceStable(tables, func(i, j int) bool {
		return mergeDependencyRank(tables[i].Name) < mergeDependencyRank(tables[j].Name)
	})
	return tables
}

func mergeDependencyRank(table string) int {
	switch table {
	case "vms", "containers":
		return 0
	case "operations":
		return 1
	case "vm_interfaces", "vm_disks", "vm_nics", "vm_pci_intent",
		"vm_pci_realizations", "container_interfaces", "operation_steps":
		return 3
	default:
		return 2
	}
}

func buildMergeAuthorityManifest(payload *syncPayload) *mergeAuthorityManifest {
	m := &mergeAuthorityManifest{
		vms:        make(map[string]workloadMergeAuthority),
		containers: make(map[string]workloadMergeAuthority),
		operations: make(map[string]operationMergeAuthority),
	}
	for _, table := range payload.Tables {
		for _, row := range table.Rows {
			if len(row) != len(table.Columns) {
				continue
			}
			switch table.Name {
			case "vms":
				a, ok := vmAuthorityFromDump(table.Columns, row)
				if ok {
					recordWorkloadAuthority(m.vms, a.name, a)
				}
			case "containers":
				a, ok := containerAuthorityFromDump(table.Columns, row)
				if ok {
					recordWorkloadAuthority(m.containers, containerCreateDesiredRef(a.host, a.name), a)
				}
			case "operations":
				a, ok := operationAuthorityFromDump(table.Columns, row)
				if ok {
					if _, duplicate := m.operations[a.ID]; duplicate {
						a.valid = false
					}
					m.operations[a.ID] = a
				}
			}
		}
	}
	return m
}

func recordWorkloadAuthority(dst map[string]workloadMergeAuthority, key string, a workloadMergeAuthority) {
	if _, duplicate := dst[key]; duplicate {
		a.valid = false
	}
	dst[key] = a
}

func vmAuthorityFromDump(cols []string, row []interface{}) (workloadMergeAuthority, bool) {
	required := []string{
		"name", "stack_name", "host_name", "spec", "state", "project",
		"is_template", "vm_owner_epoch", "spec_generation",
		"active_operation_id", "deleted_at",
	}
	idx, ok := requiredColumnIndexes(cols, required)
	if !ok {
		return workloadMergeAuthority{}, false
	}
	vm := VMRecord{
		Name:       coerceString(row[idx["name"]]),
		StackName:  coerceString(row[idx["stack_name"]]),
		HostName:   coerceString(row[idx["host_name"]]),
		Spec:       coerceString(row[idx["spec"]]),
		Project:    coerceString(row[idx["project"]]),
		IsTemplate: coerceInt64(row[idx["is_template"]]) != 0,
	}
	ownerEpoch, ownerOK := coerceInt64OK(row[idx["vm_owner_epoch"]])
	generation, generationOK := coerceInt64OK(row[idx["spec_generation"]])
	return workloadMergeAuthority{
		kind: "vm", name: vm.Name, host: vm.HostName,
		project:           projectOrDefault(vm.Project),
		state:             coerceString(row[idx["state"]]),
		activeOperationID: coerceString(row[idx["active_operation_id"]]),
		ownerEpoch:        ownerEpoch,
		generation:        generation,
		identityHash:      vmCreateIdentityHash(vm),
		deleted:           cellNonEmpty(row[idx["deleted_at"]]),
		valid:             vm.Name != "" && vm.HostName != "" && ownerOK && generationOK,
	}, true
}

func containerAuthorityFromDump(cols []string, row []interface{}) (workloadMergeAuthority, bool) {
	required := []string{
		"host_name", "name", "image", "cpu_limit", "memory_mib", "labels",
		"restart_policy", "state", "project", "is_template", "on_host_failure",
		"create_spec", "relocate_token", "owner_epoch", "spec_generation",
		"active_operation_id", "deleted_at",
	}
	idx, ok := requiredColumnIndexes(cols, required)
	if !ok {
		return workloadMergeAuthority{}, false
	}
	labels := coerceString(row[idx["labels"]])
	ct := ContainerRecord{
		HostName:      coerceString(row[idx["host_name"]]),
		Name:          coerceString(row[idx["name"]]),
		Image:         coerceString(row[idx["image"]]),
		CPULimit:      int(coerceInt64(row[idx["cpu_limit"]])),
		MemMiB:        int(coerceInt64(row[idx["memory_mib"]])),
		RestartPolicy: coerceString(row[idx["restart_policy"]]),
		Project:       coerceString(row[idx["project"]]),
		IsTemplate:    coerceInt64(row[idx["is_template"]]) != 0,
		OnHostFailure: coerceString(row[idx["on_host_failure"]]),
		CreateSpec:    coerceString(row[idx["create_spec"]]),
		RelocateToken: coerceString(row[idx["relocate_token"]]),
	}
	ownerEpoch, ownerOK := coerceInt64OK(row[idx["owner_epoch"]])
	generation, generationOK := coerceInt64OK(row[idx["spec_generation"]])
	return workloadMergeAuthority{
		kind: "container", name: ct.Name, host: ct.HostName,
		project:           projectOrDefault(ct.Project),
		state:             coerceString(row[idx["state"]]),
		activeOperationID: coerceString(row[idx["active_operation_id"]]),
		ownerEpoch:        ownerEpoch,
		generation:        generation,
		identityHash:      containerCreateIdentityHash(ct, labels),
		deleted:           cellNonEmpty(row[idx["deleted_at"]]),
		valid:             ct.Name != "" && ct.HostName != "" && ownerOK && generationOK,
	}, true
}

func operationAuthorityFromDump(cols []string, row []interface{}) (operationMergeAuthority, bool) {
	required := []string{
		"id", "method", "principal", "project", "resource_kind", "resource_id",
		"operation_kind", "request_hash", "idempotency_key",
		"reservation_json", "desired_ref", "vm_owner_epoch", "deleted_at",
	}
	idx, ok := requiredColumnIndexes(cols, required)
	if !ok {
		return operationMergeAuthority{}, false
	}
	ownerEpoch, ownerOK := coerceInt64OK(row[idx["vm_owner_epoch"]])
	a := operationMergeAuthority{
		OperationRecord: OperationRecord{
			ID:              coerceString(row[idx["id"]]),
			Method:          coerceString(row[idx["method"]]),
			Principal:       coerceString(row[idx["principal"]]),
			Project:         projectOrDefault(coerceString(row[idx["project"]])),
			ResourceKind:    coerceString(row[idx["resource_kind"]]),
			ResourceID:      coerceString(row[idx["resource_id"]]),
			OperationKind:   coerceString(row[idx["operation_kind"]]),
			RequestHash:     coerceString(row[idx["request_hash"]]),
			IdempotencyKey:  coerceString(row[idx["idempotency_key"]]),
			ReservationJSON: coerceString(row[idx["reservation_json"]]),
			DesiredRef:      coerceString(row[idx["desired_ref"]]),
			VMOwnerEpoch:    ownerEpoch,
			DeletedAt:       coerceString(row[idx["deleted_at"]]),
		},
	}
	a.valid = a.ID != "" && a.ResourceID != "" && ownerOK
	return a, true
}

func requiredColumnIndexes(cols, required []string) (map[string]int, bool) {
	out := make(map[string]int, len(required))
	for _, name := range required {
		idx := indexOf(cols, name)
		if idx < 0 {
			return nil, false
		}
		out[name] = idx
	}
	return out, true
}

func coerceInt64(v interface{}) int64 {
	n, _ := coerceInt64OK(v)
	return n
}

func coerceInt64OK(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n ||
			n < math.MinInt64 || n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	default:
		i, err := strconv.ParseInt(coerceString(v), 10, 64)
		return i, err == nil
	}
}

func (c *Client) antiEntropyAuthorityDecision(tx *sql.Tx, table syncTable, row []interface{}) (mergeAuthorityDecision, error) {
	m := table.authority
	if m == nil {
		return mergeAuthorityNormal, nil
	}
	switch {
	case table.Name == "vms":
		idx := indexOf(table.Columns, "name")
		if idx < 0 {
			return mergeAuthorityKeepLocal, nil
		}
		a, ok := m.vms[coerceString(row[idx])]
		if !ok {
			// A pre-authority sender omits owner/generation columns entirely;
			// preserve its historical column-preserving LWW behavior.
			return mergeAuthorityNormal, nil
		}
		if !a.valid {
			return mergeAuthorityKeepLocal, nil
		}
		return workloadParentAuthorityDecision(tx, a)
	case table.Name == "containers":
		hostIdx, nameIdx := indexOf(table.Columns, "host_name"), indexOf(table.Columns, "name")
		if hostIdx < 0 || nameIdx < 0 {
			return mergeAuthorityKeepLocal, nil
		}
		key := containerCreateDesiredRef(coerceString(row[hostIdx]), coerceString(row[nameIdx]))
		a, ok := m.containers[key]
		if !ok {
			return mergeAuthorityNormal, nil
		}
		if !a.valid {
			return mergeAuthorityKeepLocal, nil
		}
		return workloadParentAuthorityDecision(tx, a)
	case vmAuthorityChildTables[table.Name]:
		idx := indexOf(table.Columns, "vm_name")
		if idx < 0 {
			return mergeAuthorityKeepLocal, nil
		}
		a, ok := m.vms[coerceString(row[idx])]
		if !ok || !a.valid || provisionalWorkloadBarrier(a) ||
			a.deleted && !mergeRowIsDeleted(table, row) {
			return mergeAuthorityKeepLocal, nil
		}
		matches, err := localWorkloadMatchesMergeAuthority(tx, a)
		if !matches {
			return mergeAuthorityKeepLocal, err
		}
		return mergeAuthorityNormal, err
	case table.Name == "container_interfaces":
		hostIdx, nameIdx := indexOf(table.Columns, "host_name"), indexOf(table.Columns, "ct_name")
		if hostIdx < 0 || nameIdx < 0 {
			return mergeAuthorityKeepLocal, nil
		}
		key := containerCreateDesiredRef(coerceString(row[hostIdx]), coerceString(row[nameIdx]))
		a, ok := m.containers[key]
		if !ok || !a.valid || provisionalWorkloadBarrier(a) ||
			a.deleted && !mergeRowIsDeleted(table, row) {
			return mergeAuthorityKeepLocal, nil
		}
		matches, err := localWorkloadMatchesMergeAuthority(tx, a)
		if !matches {
			return mergeAuthorityKeepLocal, err
		}
		return mergeAuthorityNormal, err
	case table.Name == "operation_steps":
		keep, err := c.operationStepAuthorityKeepsLocal(tx, table, row, m)
		if keep {
			return mergeAuthorityKeepLocal, err
		}
		return mergeAuthorityNormal, err
	default:
		return mergeAuthorityNormal, nil
	}
}

func mergeRowIsDeleted(table syncTable, row []interface{}) bool {
	idx := indexOf(table.Columns, "deleted_at")
	return idx >= 0 && idx < len(row) && cellNonEmpty(row[idx])
}

func workloadParentAuthorityDecision(tx *sql.Tx, incoming workloadMergeAuthority) (mergeAuthorityDecision, error) {
	var localOwner, localGeneration int64
	var err error
	switch incoming.kind {
	case "vm":
		err = tx.QueryRow(`SELECT vm_owner_epoch, spec_generation FROM vms WHERE name = ?`,
			incoming.name).Scan(&localOwner, &localGeneration)
	case "container":
		err = tx.QueryRow(`SELECT owner_epoch, spec_generation FROM containers
			WHERE host_name = ? AND name = ?`, incoming.host, incoming.name).
			Scan(&localOwner, &localGeneration)
	default:
		return mergeAuthorityKeepLocal, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		if incoming.deleted {
			return mergeAuthorityApplyIncomingAndSweep, nil
		}
		return mergeAuthorityNormal, nil
	}
	if err != nil {
		return mergeAuthorityKeepLocal, err
	}
	switch {
	case localOwner == incoming.ownerEpoch && localGeneration == incoming.generation:
		if incoming.deleted {
			return mergeAuthorityApplyIncomingAndSweep, nil
		}
		return mergeAuthorityNormal, nil
	case incoming.ownerEpoch >= localOwner && incoming.generation >= localGeneration:
		if incoming.deleted {
			return mergeAuthorityApplyIncomingAndSweep, nil
		}
		return mergeAuthorityApplyIncoming, nil
	case localOwner >= incoming.ownerEpoch && localGeneration >= incoming.generation:
		return mergeAuthorityKeepLocal, nil
	default:
		// Crossed authority axes are not comparable. Fail closed rather than
		// allowing a timestamp to choose an ABA-sensitive workload identity.
		return mergeAuthorityKeepLocal, nil
	}
}

func antiEntropySweepDeletedWorkloadChildren(
	tx *sql.Tx, table syncTable, row []interface{}, deletedAt, now string,
) error {
	deletedIdx, updatedIdx := indexOf(table.Columns, "deleted_at"), indexOf(table.Columns, "updated_at")
	if deletedIdx < 0 || updatedIdx < 0 || deletedAt == "" || now == "" {
		return invalidf("authority sweep requires a deleted workload parent")
	}
	switch table.Name {
	case "vms":
		nameIdx := indexOf(table.Columns, "name")
		if nameIdx < 0 {
			return invalidf("VM authority sweep missing name")
		}
		for _, child := range []string{
			"vm_interfaces", "vm_disks", "vm_nics", "vm_pci_intent", "vm_pci_realizations",
		} {
			if _, err := tx.Exec(
				`UPDATE `+child+` SET deleted_at = ?, updated_at = ? WHERE vm_name = ?`,
				deletedAt, now, row[nameIdx],
			); err != nil {
				return fmt.Errorf("anti-entropy sweep %s: %w", child, err)
			}
		}
	case "containers":
		hostIdx, nameIdx := indexOf(table.Columns, "host_name"), indexOf(table.Columns, "name")
		if hostIdx < 0 || nameIdx < 0 {
			return invalidf("container authority sweep missing identity")
		}
		if _, err := tx.Exec(
			`UPDATE container_interfaces SET deleted_at = ?, updated_at = ?
			 WHERE host_name = ? AND ct_name = ?`,
			deletedAt, now, row[hostIdx], row[nameIdx],
		); err != nil {
			return fmt.Errorf("anti-entropy sweep container interfaces: %w", err)
		}
	default:
		return invalidf("authority sweep on unexpected table %s", table.Name)
	}
	return nil
}

func provisionalWorkloadBarrier(a workloadMergeAuthority) bool {
	return a.state == "creating" && a.activeOperationID != ""
}

func (c *Client) operationStepAuthorityKeepsLocal(tx *sql.Tx, table syncTable, row []interface{}, m *mergeAuthorityManifest) (bool, error) {
	idIdx, epochIdx := indexOf(table.Columns, "operation_id"), indexOf(table.Columns, "owner_epoch")
	if idIdx < 0 || epochIdx < 0 {
		return true, nil
	}
	id := coerceString(row[idIdx])
	incomingEpoch := coerceInt64(row[epochIdx])
	sourceOp, inManifest := m.operations[id]

	var local operationMergeAuthority
	err := tx.QueryRow(
		`SELECT id, method, principal, project, resource_kind, resource_id,
		        operation_kind, request_hash, idempotency_key, reservation_json,
		        desired_ref, vm_owner_epoch, COALESCE(deleted_at, '')
		 FROM operations WHERE id = ?`, id).
		Scan(&local.ID, &local.Method, &local.Principal, &local.Project,
			&local.ResourceKind, &local.ResourceID, &local.OperationKind,
			&local.RequestHash, &local.IdempotencyKey, &local.ReservationJSON,
			&local.DesiredRef, &local.VMOwnerEpoch, &local.DeletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("anti-entropy operation-step authority lookup: %w", err)
	}
	local.Project = projectOrDefault(local.Project)
	local.valid = local.ID != "" && local.ResourceID != ""

	// Non-create journals retain their existing immutable merge behavior.
	if local.OperationKind != string(OpWorkloadCreate) {
		return false, nil
	}
	if !inManifest || !sourceOp.valid || sourceOp.DeletedAt != "" || local.DeletedAt != "" ||
		incomingEpoch != sourceOp.VMOwnerEpoch ||
		!sameOperationMergeAuthority(local, sourceOp) {
		return true, nil
	}
	a, ok := sourceOperationWorkloadAuthority(sourceOp, m)
	if !ok || !a.valid {
		return true, nil
	}
	matches, err := localWorkloadMatchesMergeAuthority(tx, a)
	return !matches, err
}

func sameOperationMergeAuthority(a, b operationMergeAuthority) bool {
	return sameOperationClaim(a.OperationRecord, b.OperationRecord)
}

func sourceOperationWorkloadAuthority(op operationMergeAuthority, m *mergeAuthorityManifest) (workloadMergeAuthority, bool) {
	switch op.ResourceKind {
	case "vm":
		a, ok := m.vms[op.ResourceID]
		return a, ok && a.ownerEpoch == op.VMOwnerEpoch &&
			a.name == op.ResourceID && a.project == op.Project
	case "container":
		a, ok := m.containers[op.DesiredRef]
		return a, ok && a.ownerEpoch == op.VMOwnerEpoch &&
			a.name == op.ResourceID && a.project == op.Project &&
			op.DesiredRef == containerCreateDesiredRef(a.host, a.name)
	default:
		return workloadMergeAuthority{}, false
	}
}

func localWorkloadMatchesMergeAuthority(tx *sql.Tx, want workloadMergeAuthority) (bool, error) {
	switch want.kind {
	case "vm":
		var vm VMRecord
		var isTemplate int
		var deletedAt sql.NullString
		err := tx.QueryRow(
			`SELECT name, COALESCE(stack_name, ''), host_name, spec, state,
			        COALESCE(project, '_default'), COALESCE(is_template, 0),
			        vm_owner_epoch, spec_generation, active_operation_id, deleted_at
			 FROM vms WHERE name = ?`, want.name).
			Scan(&vm.Name, &vm.StackName, &vm.HostName, &vm.Spec, &vm.State,
				&vm.Project, &isTemplate, &vm.OwnerEpoch, &vm.SpecGeneration,
				&vm.ActiveOperationID, &deletedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		vm.IsTemplate = isTemplate != 0
		return vm.OwnerEpoch == want.ownerEpoch &&
			vm.SpecGeneration == want.generation &&
			vm.State == want.state &&
			vm.ActiveOperationID == want.activeOperationID &&
			(deletedAt.Valid && deletedAt.String != "") == want.deleted &&
			vmCreateIdentityHash(vm) == want.identityHash, nil
	case "container":
		var ct ContainerRecord
		var labels string
		var isTemplate int
		var deletedAt sql.NullString
		err := tx.QueryRow(
			`SELECT host_name, name, COALESCE(image, ''), cpu_limit, memory_mib, state,
			        COALESCE(labels, ''), COALESCE(restart_policy, ''),
			        COALESCE(project, '_default'), COALESCE(is_template, 0),
			        COALESCE(on_host_failure, ''), COALESCE(create_spec, ''),
			        COALESCE(relocate_token, ''), owner_epoch, spec_generation,
			        active_operation_id, deleted_at
			 FROM containers WHERE host_name = ? AND name = ?`, want.host, want.name).
			Scan(&ct.HostName, &ct.Name, &ct.Image, &ct.CPULimit, &ct.MemMiB,
				&ct.State, &labels, &ct.RestartPolicy, &ct.Project, &isTemplate,
				&ct.OnHostFailure, &ct.CreateSpec, &ct.RelocateToken,
				&ct.OwnerEpoch, &ct.SpecGeneration, &ct.ActiveOperationID, &deletedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		ct.IsTemplate = isTemplate != 0
		return ct.OwnerEpoch == want.ownerEpoch &&
			ct.SpecGeneration == want.generation &&
			ct.State == want.state &&
			ct.ActiveOperationID == want.activeOperationID &&
			(deletedAt.Valid && deletedAt.String != "") == want.deleted &&
			containerCreateIdentityHash(ct, labels) == want.identityHash, nil
	default:
		return false, nil
	}
}
