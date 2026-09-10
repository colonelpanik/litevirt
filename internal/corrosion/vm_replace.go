package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// Giving a replacement VM the name a REPLACED VM still holds — `lv cutover` — is
// the one VM transition that cannot be built out of the pre-existing replicated
// statement shapes.
//
// `vms.name` is the PRIMARY KEY and DeleteVM soft-deletes, so the replaced VM's
// tombstone still occupies the key. Clearing it with a retention DELETE fails on a
// receiver: the delete is applied unconditionally while the write meant to replace
// the row is only LWW-gated, so a delayed replay erases a tombstone and puts
// nothing in its place. Moving it aside instead splits the handover into two
// independently gated statements, and a receiver can commit one and skip the
// other — leaving no row at the name, or moving a still-live VM aside when its own
// newer ownership made the sender's delete decline there. And none of it addresses
// the merge rules, which decide a both-live conflict at the contested name on
// owner/generation authority alone: a stale higher-authority copy of the replaced
// VM overwrites its replacement wherever the tombstone ended up.
//
// So the transition is ONE receiver decision. Every statement in the batch carries
// the same workload_replace_v1 guard, over both VMs' incarnations AND authority,
// and the receiver either applies all of them or none. The target row is written
// by a dedicated upsert that
//
//   - PRESERVES the replacement's incarnation (created_at), so a delayed tombstone
//     of the replaced VM names an OLDER incarnation and cannot kill the
//     replacement — a delete is terminal only for its own incarnation; and
//   - ADVANCES authority beyond BOTH inputs, so a stale copy of either VM loses
//     the owner/generation comparison the anti-entropy merge actually makes.
//
// Both are re-stated as SQL predicates on the upsert itself, so the shape fails
// closed even reached without its guard — the same belt-and-braces the
// create-begin resurrection uses.
//
// This is new receiver behavior, which no historical-ledger entry can retrofit
// onto an older peer, so the shapes are capability-gated on vm_replace_v1 and
// `lv cutover` refuses until it is latched cluster-wide.

// capVMReplaceV1 is the capability token gating every shape in this file.
const capVMReplaceV1 = capabilities.VMReplaceV1

const (
	// vmReplaceTargetSQL installs the replacement AT the contested name.
	//
	// created_at is the REPLACEMENT's (its incarnation travels with it, rather than
	// the row inheriting the replaced VM's identity), and the authority columns are
	// bound strictly above both inputs. The ON CONFLICT predicate repeats that
	// ordering: it fires only on a TOMBSTONE, or on a live row that is already this
	// same replace's result, and only when both authority axes genuinely advance —
	// so a live target with newer ownership, or one belonging to a different
	// incarnation, is a no-op rather than an overwrite.
	vmReplaceTargetSQL = `INSERT INTO vms (name, stack_name, host_name, spec, state, state_detail,
				cpu_actual, mem_actual, project, is_template, vm_owner_epoch,
				spec_generation, active_operation_id, created_at, updated_at,
				deleted_at, pending_action_id, hardware_adoption_state,
				hardware_adoption_error)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, NULL, '', ?, NULL)
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
			 WHERE excluded.vm_owner_epoch > vms.vm_owner_epoch
			   AND excluded.spec_generation > vms.spec_generation
			   AND (vms.deleted_at IS NOT NULL OR vms.created_at = excluded.created_at)`

	// The child rows the replacement brings to the contested name. Each is a
	// FULL-ROW upsert at its own primary key, applied verbatim under the shared
	// guard rather than per-row LWW-gated: a child write the receiver skipped on
	// its own clock would leave the name holding some of the replacement's disks
	// and not others, which is precisely the partial application the single
	// receiver decision exists to prevent.
	vmReplaceInterfaceSQL = `INSERT INTO vm_interfaces
			 (vm_name, network_name, ordinal, mac, ip, tap_device, security_groups, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
			 ON CONFLICT(vm_name, network_name) DO UPDATE SET
			   ordinal = excluded.ordinal,
			   mac = excluded.mac,
			   ip = excluded.ip,
			   tap_device = excluded.tap_device,
			   security_groups = excluded.security_groups,
			   updated_at = excluded.updated_at,
			   deleted_at = excluded.deleted_at`

	vmReplaceDiskSQL = `INSERT INTO vm_disks
			 (vm_name, disk_name, host_name, path, size_bytes, backing_image,
			  storage_type, storage_volume, target_dev, backing_disk,
			  bus, device_kind, delete_with_vm, controller_model, updated_at, deleted_at)
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
			   deleted_at = excluded.deleted_at`

	vmReplaceNICSQL = `INSERT INTO vm_nics
			 (vm_name, id, network_name, model, mac, ordinal, ip, tap_device, security_groups, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
			 ON CONFLICT(vm_name, id) DO UPDATE SET
			   network_name = excluded.network_name,
			   model = excluded.model,
			   mac = excluded.mac,
			   ordinal = excluded.ordinal,
			   ip = excluded.ip,
			   tap_device = excluded.tap_device,
			   security_groups = excluded.security_groups,
			   updated_at = excluded.updated_at,
			   deleted_at = excluded.deleted_at`

	vmReplacePCIIntentSQL = `INSERT INTO vm_pci_intent
			 (vm_name, device_id, host_name, selector_kind, selector_payload, exclusive_key, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
			 ON CONFLICT(vm_name, device_id) DO UPDATE SET
			   host_name = excluded.host_name,
			   selector_kind = excluded.selector_kind,
			   selector_payload = excluded.selector_payload,
			   exclusive_key = excluded.exclusive_key,
			   updated_at = excluded.updated_at,
			   deleted_at = excluded.deleted_at`

	// vmReplaceLeaseSQL moves the replacement's IPAM leases onto the new name.
	// ip_allocations keys on (network, ip), so vm_name is a plain column here and
	// this shape is shared with the ordinary rename rather than replace-specific.
	vmReplaceLeaseSQL = `UPDATE ip_allocations SET vm_name = ?, updated_at = ? WHERE vm_name = ?`

	vmReplacePCIRealizationSQL = `INSERT INTO vm_pci_realizations
			 (vm_name, device_id, member_id, host_name, resolved_address, xml_alias, ordinal, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
			 ON CONFLICT(vm_name, device_id, member_id) DO UPDATE SET
			   host_name = excluded.host_name,
			   resolved_address = excluded.resolved_address,
			   xml_alias = excluded.xml_alias,
			   ordinal = excluded.ordinal,
			   updated_at = excluded.updated_at,
			   deleted_at = excluded.deleted_at`
)

// ErrVMReplaceSourceUnsafe means the replacement is not in a state that may be
// handed a new name — it is missing, already tombstoned, or has an operation in
// flight whose barrier this transition would break.
var ErrVMReplaceSourceUnsafe = errors.New("corrosion: replacement VM cannot take another name")

// ErrVMReplaceTargetUnsafe means the name being taken is held by something this
// transition must not overwrite: a LIVE VM (only DeleteVM may decide a workload
// can be tombstoned), or a tombstone whose authority this replace cannot exceed.
var ErrVMReplaceTargetUnsafe = errors.New("corrosion: VM name cannot be taken by a replacement")

// vmReplaceAuthority is the authority a replace writes, and the two rows it was
// derived from. Strictly above BOTH, so neither input's stale copy can win the
// owner/generation comparison the anti-entropy merge makes at the contested name.
type vmReplaceAuthority struct {
	epoch, generation             int64
	sourceEpoch, sourceGeneration int64
	targetEpoch, targetGeneration int64
}

func vmReplaceAuthorityFor(source, target *VMRecord) vmReplaceAuthority {
	a := vmReplaceAuthority{
		sourceEpoch: source.OwnerEpoch, sourceGeneration: source.SpecGeneration,
	}
	if target != nil {
		a.targetEpoch, a.targetGeneration = target.OwnerEpoch, target.SpecGeneration
	}
	a.epoch = max64(a.sourceEpoch, a.targetEpoch) + 1
	a.generation = max64(a.sourceGeneration, a.targetGeneration) + 1
	return a
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// vmReplaceMutationGuard is the ONE predicate every statement in the batch
// carries. It binds the source's exact incarnation and authority, the target's
// (or its absence), and the authority this batch writes — so a receiver reaches a
// single decision for the whole transition instead of gating each statement on
// its own clock.
func vmReplaceMutationGuard(source VMRecord, target *VMRecord, name string, a vmReplaceAuthority) *MutationGuard {
	g := &MutationGuard{
		Protocol: workloadReplaceGuardV1, ResourceKind: "vm",
		ResourceID: source.Name, TargetResourceID: name, HostName: source.HostName,
		OwnerEpoch: source.OwnerEpoch, SpecGeneration: source.SpecGeneration,
		CheckSpecGeneration: true,
		IdentityHash:        vmCreateIdentityHash(source),
		Incarnation:         source.CreatedAt,
		NewOwnerEpoch:       a.epoch, NewSpecGeneration: a.generation,
	}
	if target != nil {
		g.TargetIncarnation = target.CreatedAt
		g.TargetOwnerEpoch, g.TargetSpecGeneration = target.OwnerEpoch, target.SpecGeneration
	}
	return g
}

// ReplaceVM gives `replacement` the name `name`, which a TOMBSTONED VM may still
// hold, as a single guarded transition. It is the database half of `lv cutover`.
//
// The caller must already have tombstoned the VM being replaced — only DeleteVM
// may decide that, and this refuses a live occupant rather than deciding it here.
//
// Statement order is what keeps the guard's predicate true for the whole batch:
// the target row and its children are written first, and the replacement's own
// rows are retired LAST, so the source stays live — and therefore matches the
// guard — right up to the final statement, exactly as the container owner re-key
// does.
func ReplaceVM(ctx context.Context, c *Client, replacement, name string) error {
	source, err := GetVM(ctx, c, replacement)
	if err != nil {
		return err
	}
	if source == nil {
		return fmt.Errorf("%w: %q is not a live VM", ErrVMReplaceSourceUnsafe, replacement)
	}
	if source.ActiveOperationID != "" {
		return fmt.Errorf("%w: %q has operation %s in flight",
			ErrVMReplaceSourceUnsafe, replacement, source.ActiveOperationID)
	}
	if live, lErr := GetVM(ctx, c, name); lErr != nil {
		return lErr
	} else if live != nil {
		return fmt.Errorf("%w: %q is a live VM — it must be tombstoned first", ErrVMReplaceTargetUnsafe, name)
	}
	target, err := getVMRowIncludingDeleted(ctx, c, name)
	if err != nil {
		return err
	}

	authority := vmReplaceAuthorityFor(source, target)
	guard := vmReplaceMutationGuard(*source, target, name, authority)
	now := c.NowTS()

	stmts, err := vmReplaceStatements(ctx, c, *source, name, authority, guard, now)
	if err != nil {
		return err
	}
	return c.ExecuteBatch(ctx, stmts)
}

// vmReplaceStatements builds the batch. Every statement carries the same guard.
func vmReplaceStatements(
	ctx context.Context, c *Client, source VMRecord, name string,
	a vmReplaceAuthority, guard *MutationGuard, now string,
) ([]Statement, error) {
	// The spec's own "name" field is patched: it is what later XML and
	// firmware-path derivation read, so leaving the replacement's temporary name
	// in there would point them at the wrong VM (G1).
	spec := source.Spec
	if spec != "" {
		var m map[string]interface{}
		if json.Unmarshal([]byte(spec), &m) == nil {
			m["name"] = name
			if b, mErr := json.Marshal(m); mErr == nil {
				spec = string(b)
			}
		}
	}
	adoptionState, _, adoptionErr := GetHardwareAdoptionState(ctx, c, source.Name)
	if adoptionErr != nil {
		return nil, adoptionErr
	}
	if adoptionState == "" {
		adoptionState = "pending"
	}

	stmts := []Statement{{
		SQL: vmReplaceTargetSQL,
		Params: []interface{}{
			name, source.StackName, source.HostName, spec, source.State, source.StateDetail,
			source.CPUActual, source.MemActual, projectOrDefault(source.Project),
			boolToInt(source.IsTemplate), a.epoch, a.generation,
			source.CreatedAt, now, adoptionState,
		},
		Guard: guard,
	}}

	ifaces, err := GetVMInterfaces(ctx, c, source.Name)
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		sgs, sErr := encodeSGs(iface.SecurityGroups)
		if sErr != nil {
			return nil, sErr
		}
		stmts = append(stmts, Statement{
			SQL: vmReplaceInterfaceSQL,
			Params: []interface{}{
				name, iface.NetworkName, iface.Ordinal, iface.MAC,
				nullIfEmpty(iface.IP), nullIfEmpty(iface.TapDevice), nullIfEmpty(sgs), now,
			},
			Guard: guard,
		})
	}

	disks, err := GetVMDisks(ctx, c, source.Name)
	if err != nil {
		return nil, err
	}
	for _, d := range disks {
		kind := d.DeviceKind
		if kind == "" {
			kind = "disk"
		}
		stmts = append(stmts, Statement{
			SQL: vmReplaceDiskSQL,
			Params: []interface{}{
				name, d.DiskName, d.HostName, d.Path, d.SizeBytes, d.BackingImage,
				d.StorageType, d.StorageVolume, d.TargetDev, d.BackingDisk,
				d.Bus, kind, boolToInt(d.DeleteWithVM), d.ControllerModel, now,
			},
			Guard: guard,
		})
	}

	// vm_nics keys on (vm_name, id) and its id is DeterministicNICID(vm_name, mac)
	// — DERIVED from the name — so the replacement's NICs are RE-DERIVED at the new
	// name. Two VMs can hold the same MAC, in which case the re-derived id is
	// exactly the replaced VM's tombstoned one; the upsert displaces it at that key,
	// which is why this needs no collision special case.
	nics, err := GetVMNICsRaw(ctx, c, "vm_nics", source.Name)
	if err != nil {
		return nil, err
	}
	for _, n := range nics {
		if n.DeletedAt != "" {
			continue // GetVMNICsRaw is the shared live+tombstoned reader
		}
		model := n.Model
		if model == "" {
			model = "virtio"
		}
		stmts = append(stmts, Statement{
			SQL: vmReplaceNICSQL,
			Params: []interface{}{
				name, DeterministicNICID(name, n.MAC), n.NetworkName, model, n.MAC, n.Ordinal,
				nullIfEmpty(n.IP), nullIfEmpty(n.TapDevice), nullIfEmpty(n.SecurityGroups), now,
			},
			Guard: guard,
		})
	}

	// vm_pci_intent.device_id and vm_pci_realizations' device_id/member_id are
	// name-INDEPENDENT by design (DeterministicPCIIntentID takes no vmName), so they
	// are PRESERVED — which is what lets the hardware-adoption audit's unconditional
	// re-derive converge onto the same row instead of forking a duplicate.
	intents, err := ListVMPCIIntents(ctx, c, source.Name)
	if err != nil {
		return nil, err
	}
	for _, in := range intents {
		var exclusive interface{}
		if in.ExclusiveKey != nil {
			exclusive = *in.ExclusiveKey
		}
		stmts = append(stmts, Statement{
			SQL: vmReplacePCIIntentSQL,
			Params: []interface{}{
				name, in.DeviceID, in.HostName, in.SelectorKind, in.SelectorPayload, exclusive, now,
			},
			Guard: guard,
		})
	}
	reals, err := ListVMPCIRealizations(ctx, c, source.Name)
	if err != nil {
		return nil, err
	}
	for _, r := range reals {
		stmts = append(stmts, Statement{
			SQL: vmReplacePCIRealizationSQL,
			Params: []interface{}{
				name, r.DeviceID, r.MemberID, r.HostName,
				nullIfEmpty(r.ResolvedAddress), nullIfEmpty(r.XMLAlias), r.Ordinal, now,
			},
			Guard: guard,
		})
	}

	// ip_allocations keys on (network, ip); vm_name is a NON-PK column, so this is a
	// bulk update whose per-row LWW expansion is safe on apply.
	stmts = append(stmts, Statement{
		SQL:    vmReplaceLeaseSQL,
		Params: []interface{}{name, now, source.Name},
		Guard:  guard,
	})

	// Retire the replacement's own rows. Children first, then the parent — which is
	// deliberately the LAST statement in the batch: it is the semantic commit
	// barrier, and keeping the source row live until then is what lets every
	// preceding statement re-evaluate the SAME guard and reach the same answer.
	// Written out rather than looped: every replicated statement has to be finite
	// static SQL at its own emission site, or the compatibility ledger cannot see it.
	wall := nowRFC3339()
	retire := []interface{}{wall, now, source.Name}
	stmts = append(stmts, Statement{SQL: vmInterfacesCreateCleanupSQL, Params: retire, Guard: guard})
	stmts = append(stmts, Statement{SQL: vmDisksCreateCleanupSQL, Params: retire, Guard: guard})
	stmts = append(stmts, Statement{SQL: vmNICsCreateCleanupSQL, Params: retire, Guard: guard})
	stmts = append(stmts, Statement{SQL: vmPCIIntentCreateCleanupSQL, Params: retire, Guard: guard})
	stmts = append(stmts, Statement{SQL: vmPCIRealCreateCleanupSQL, Params: retire, Guard: guard})
	stmts = append(stmts, Statement{
		SQL:    vmDeleteSQL,
		Params: []interface{}{wall, now, source.Name, source.OwnerEpoch, source.SpecGeneration},
		Guard:  guard,
	})
	return stmts, nil
}

// getVMRowIncludingDeleted reads the authority and incarnation of a vms row
// whether or not it is tombstoned. A replace has to bind the tombstone it is
// displacing, which the live-only and delete-only readers both hide.
func getVMRowIncludingDeleted(ctx context.Context, c *Client, name string) (*VMRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, COALESCE(stack_name, '') AS stack_name, host_name, spec,
		        COALESCE(project, '_default') AS project, COALESCE(is_template, 0) AS is_template,
		        vm_owner_epoch, spec_generation, created_at, COALESCE(deleted_at, '') AS deleted_at
		 FROM vms WHERE name = ?`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &VMRecord{
		Name: r.String("name"), StackName: r.String("stack_name"), HostName: r.String("host_name"),
		Spec: r.String("spec"), Project: r.String("project"), IsTemplate: r.Int("is_template") != 0,
		OwnerEpoch: r.Int64("vm_owner_epoch"), SpecGeneration: r.Int64("spec_generation"),
		CreatedAt: r.String("created_at"),
	}, nil
}

// workloadReplaceGuardMatches is the single receiver decision for a guarded VM
// name replacement. Every statement in the batch carries the same guard, so this
// predicate has to hold for all of them — which is why it accepts the target both
// before and after this batch's own writes, and why the source is required to be
// live (the batch retires it last).
func workloadReplaceGuardMatches(ctx context.Context, tx *sql.Tx, guard *MutationGuard) (bool, error) {
	if guard.ResourceKind != "vm" || guard.ResourceID == "" || guard.TargetResourceID == "" ||
		guard.ResourceID == guard.TargetResourceID || guard.Incarnation == "" ||
		guard.IdentityHash == "" || !guard.CheckSpecGeneration ||
		guard.OwnerEpoch < 0 || guard.SpecGeneration < 0 ||
		guard.TargetOwnerEpoch < 0 || guard.TargetSpecGeneration < 0 ||
		// The authority written MUST exceed both inputs. A sender that did not
		// advance it is emitting a transition a stale copy of either VM could still
		// win, so this is a protocol violation rather than a declined guard.
		guard.NewOwnerEpoch <= guard.OwnerEpoch || guard.NewOwnerEpoch <= guard.TargetOwnerEpoch ||
		guard.NewSpecGeneration <= guard.SpecGeneration ||
		guard.NewSpecGeneration <= guard.TargetSpecGeneration {
		return false, fmt.Errorf("invalid workload replace guard")
	}

	// SOURCE. The replacement must be exactly the row the sender validated and
	// still live. Absent or already tombstoned means this receiver either never had
	// it or has already applied the whole transition — decline, do not error: the
	// batch's own final statement is what tombstones it.
	var src VMRecord
	var isTemplate int
	var srcCreated string
	var srcDeleted sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT name, COALESCE(stack_name, ''), host_name, spec, COALESCE(project, '_default'),
		        COALESCE(is_template, 0), vm_owner_epoch, spec_generation, created_at, deleted_at
		 FROM vms WHERE name = ?`, guard.ResourceID).
		Scan(&src.Name, &src.StackName, &src.HostName, &src.Spec, &src.Project,
			&isTemplate, &src.OwnerEpoch, &src.SpecGeneration, &srcCreated, &srcDeleted)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	src.IsTemplate = isTemplate != 0
	if srcDeleted.Valid && srcDeleted.String != "" {
		return false, nil
	}
	if srcCreated != guard.Incarnation ||
		src.OwnerEpoch != guard.OwnerEpoch || src.SpecGeneration != guard.SpecGeneration ||
		guard.HostName != "" && src.HostName != guard.HostName ||
		vmCreateIdentityHash(src) != guard.IdentityHash {
		return false, nil
	}

	// TARGET. Absent is safe. A tombstone is replaceable only when it is the exact
	// incarnation and authority the sender bound — a NEWER tombstone, or one from a
	// different incarnation, is an authority decision this batch must not undo. A
	// LIVE target is safe only when it is already this same replace's result, which
	// is both the mid-batch state (the target row is written first) and the
	// already-applied state a full-state sync can install before the WAL entry
	// arrives.
	var tgtEpoch, tgtGeneration int64
	var tgtCreated string
	var tgtDeleted sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT vm_owner_epoch, spec_generation, created_at, deleted_at FROM vms WHERE name = ?`,
		guard.TargetResourceID).Scan(&tgtEpoch, &tgtGeneration, &tgtCreated, &tgtDeleted)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if tgtDeleted.Valid && tgtDeleted.String != "" {
		return tgtCreated == guard.TargetIncarnation &&
			tgtEpoch == guard.TargetOwnerEpoch &&
			tgtGeneration == guard.TargetSpecGeneration, nil
	}
	return tgtCreated == guard.Incarnation &&
		tgtEpoch == guard.NewOwnerEpoch &&
		tgtGeneration == guard.NewSpecGeneration, nil
}
