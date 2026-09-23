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

	// The replacement's OWN rows, retired one key at a time.
	//
	// Row-scoped, not bulk by vm_name, and applied under the shared guard rather
	// than per-row last-writer-wins. Bulk-by-name statements are dispatched through
	// ordinary per-row LWW on a receiver, so a peer with a newer clock on one of
	// them could commit the parent transition and leave that child live — the
	// replacement still owning disks under a name the transition retired. Full-PK
	// identity is also what lets the receiver clamp updated_at to max(incoming,
	// local), so applying verbatim cannot REGRESS its clock on the row.
	//
	// `deleted_at IS NULL` makes each one naturally idempotent: a re-apply leaves
	// an existing tombstone's own stamp alone.
	vmReplaceRetireInterfaceSQL = `UPDATE vm_interfaces SET deleted_at = ?, updated_at = ?
		 WHERE vm_name = ? AND network_name = ? AND deleted_at IS NULL`
	vmReplaceRetireDiskSQL = `UPDATE vm_disks SET deleted_at = ?, updated_at = ?
		 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`
	vmReplaceRetireNICSQL = `UPDATE vm_nics SET deleted_at = ?, updated_at = ?
		 WHERE vm_name = ? AND id = ? AND deleted_at IS NULL`
	vmReplaceRetirePCIIntentSQL = `UPDATE vm_pci_intent SET deleted_at = ?, updated_at = ?
		 WHERE vm_name = ? AND device_id = ? AND deleted_at IS NULL`
	vmReplaceRetirePCIRealSQL = `UPDATE vm_pci_realizations SET deleted_at = ?, updated_at = ?
		 WHERE vm_name = ? AND device_id = ? AND member_id = ? AND deleted_at IS NULL`

	// vmReplaceCleanupAuthSQL is the operation_steps insert that authorizes the
	// destruction — the same shape every other journaled operation appends with,
	// so it carries no new wire liability of its own. It is named here because the
	// batch envelope validator requires exactly one of it.
	vmReplaceCleanupAuthSQL = `INSERT INTO operation_steps
		     (operation_id, owner_epoch, step_name, facts, created_at, updated_at, deleted_at)
		     VALUES (?, ?, ?, ?, ?, ?, NULL)`

	// vmReplaceLeaseSQL moves ONE of the replacement's IPAM leases onto the new
	// name, keyed on the allocation's own primary key AND its current owner.
	//
	// The bulk-by-vm_name form would be dispatched through per-row LWW on a
	// receiver, which is how a lease ends up still owned by a name the transition
	// retired. But keying on (network, ip) alone is worse: a receiver that released
	// that address and reallocated it to an unrelated VM would have the lease
	// STOLEN by a delayed cutover — same key, different tenant, its MAC left
	// behind. The owner predicate makes such a row unmatchable, and the guard's
	// lease digest declines the whole transition rather than silently skipping it.
	vmReplaceLeaseSQL = `UPDATE ip_allocations SET vm_name = ?, updated_at = ?
		 WHERE network = ? AND ip = ? AND vm_name = ?
		   AND owner_kind = 'vm' AND owner_host = '' AND deleted_at IS NULL`

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

// vmReplaceRetirementFingerprints is the closed set of shapes that may retire one
// of the replacement's own keys inside a guarded replace envelope.
var vmReplaceRetirementFingerprints = map[string]bool{
	mustStatementFingerprint(vmReplaceRetireInterfaceSQL): true,
	mustStatementFingerprint(vmReplaceRetireDiskSQL):      true,
	mustStatementFingerprint(vmReplaceRetireNICSQL):       true,
	mustStatementFingerprint(vmReplaceRetirePCIIntentSQL): true,
	mustStatementFingerprint(vmReplaceRetirePCIRealSQL):   true,
}

// replaceInterleaveHook is the seam described in ReplaceVM. Set it only from a
// test, and clear it afterwards.
var replaceInterleaveHook func()

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

// vmReplaceLeaseDigest fingerprints the IPAM allocations held by EITHER name, by
// key and MAC, so a receiver can tell "the same leases the sender saw" from "that
// address was released and handed to someone else".
//
// Both names, deliberately. The batch moves each allocation from the temporary
// name to the contested one, so a digest over the source alone changes as the
// batch applies — and the guard is re-evaluated for every statement in it. Over
// the union it is INVARIANT across the transition, while an address that left
// both names (released and reallocated to an unrelated VM, which is the case
// worth declining for) still drops out of it.
func vmReplaceLeaseDigest(ctx context.Context, c *Client, replacement, name string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT network, ip, COALESCE(mac, '') AS mac FROM ip_allocations
		 WHERE vm_name IN (?, ?) AND owner_kind = 'vm' AND owner_host = ''
		   AND deleted_at IS NULL ORDER BY network, ip`, replacement, name)
	if err != nil {
		return "", err
	}
	fields := make([]string, 0, len(rows)*3)
	for _, r := range rows {
		fields = append(fields, r.String("network"), r.String("ip"), r.String("mac"))
	}
	return hashIdentity(fields...), nil
}

// vmReplaceLeaseDigestInTx is the receiver-side recomputation, inside the apply
// transaction.
func vmReplaceLeaseDigestInTx(ctx context.Context, tx *sql.Tx, replacement, name string) (string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT network, ip, COALESCE(mac, '') FROM ip_allocations
		 WHERE vm_name IN (?, ?) AND owner_kind = 'vm' AND owner_host = ''
		   AND deleted_at IS NULL ORDER BY network, ip`, replacement, name)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var fields []string
	for rows.Next() {
		var network, ip, mac string
		if err := rows.Scan(&network, &ip, &mac); err != nil {
			return "", err
		}
		fields = append(fields, network, ip, mac)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return hashIdentity(fields...), nil
}

// vmReplaceMutationGuard is the ONE predicate every statement in the batch
// carries. It binds the source's exact incarnation and authority, the target's
// (or its absence), and the authority this batch writes — so a receiver reaches a
// single decision for the whole transition instead of gating each statement on
// its own clock.
func vmReplaceMutationGuard(source VMRecord, target *VMRecord, name, opID, leaseDigest string, a vmReplaceAuthority) *MutationGuard {
	g := &MutationGuard{
		Protocol: workloadReplaceGuardV1, ResourceKind: "vm", OperationID: opID,
		ResourceID: source.Name, TargetResourceID: name, HostName: source.HostName,
		OwnerEpoch: source.OwnerEpoch, SpecGeneration: source.SpecGeneration,
		CheckSpecGeneration: true,
		IdentityHash:        vmCreateIdentityHash(source),
		Incarnation:         source.CreatedAt,
		LeaseDigest:         leaseDigest,
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
// prepared names the PrepareVMReplace operation whose cleanup this batch
// authorizes. It is not optional: the batch writes that authorization, and a
// transition that committed without it would displace the manifest's rows with
// nothing left to say what the replaced VM owned.
func ReplaceVM(ctx context.Context, c *Client, replacement, name string, prepared VMReplacePrepared) error {
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

	if prepared.OperationID == "" {
		return fmt.Errorf("corrosion: VM replace requires a prepared cleanup operation")
	}
	if source.OwnerEpoch != prepared.OwnerEpoch {
		return fmt.Errorf("%w: %q moved to owner epoch %d since its cleanup was journaled at %d",
			ErrVMReplaceSourceUnsafe, replacement, source.OwnerEpoch, prepared.OwnerEpoch)
	}
	leaseDigest, err := vmReplaceLeaseDigest(ctx, c, replacement, name)
	if err != nil {
		return err
	}
	authority := vmReplaceAuthorityFor(source, target)
	guard := vmReplaceMutationGuard(*source, target, name, prepared.OperationID, leaseDigest, authority)
	now := c.NowTS()

	stmts, err := vmReplaceStatements(ctx, c, *source, name, authority, guard, now)
	if err != nil {
		return err
	}
	// A TEST-ONLY seam, run after the batch is built and before it is written.
	// Producing that interleaving is the only way to exercise what the
	// write-transaction guard exists to catch, and it cannot be arranged from
	// outside: the reads, the build and the write are adjacent here. Production
	// leaves it nil.
	if replaceInterleaveHook != nil {
		replaceInterleaveHook()
	}
	// GUARDED, not a plain batch. ExecuteBatch executes each statement and
	// evaluates no guard at all, so the reads above would be a bare
	// time-of-check-to-time-of-use window: an ownership transfer landing between
	// them and the write would let a stale target upsert — and the cleanup
	// authorization travelling with it — commit while the source retirement CAS
	// changed no rows, leaving both names live and destruction authorized.
	//
	// ExecuteBatchGuarded re-evaluates the SAME predicate inside the write
	// transaction, for every statement, so the local writer reaches the identical
	// decision a receiver does.
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		return workloadReplaceGuardMatches(ctx, tx, guard)
	}, stmts)
	if err != nil {
		return err
	}
	if !applied {
		return fmt.Errorf("%w: %q or %q moved while the transition was being built",
			ErrVMReplaceSourceUnsafe, replacement, name)
	}
	// The transition and the retirement are the two statements that must actually
	// have taken effect. A matched guard implies both, so this is a post-condition
	// rather than a race check — and cheap insurance against a future statement
	// reordering that would otherwise authorize a cleanup for a transition that
	// never happened.
	return verifyVMReplaceApplied(ctx, c, replacement, name, authority)
}

// verifyVMReplaceApplied re-reads both names and refuses to call the transition
// done unless the contested name holds the replacement at the authority the batch
// wrote and the temporary name is retired.
func verifyVMReplaceApplied(
	ctx context.Context, c *Client, replacement, name string, a vmReplaceAuthority,
) error {
	took, err := GetVM(ctx, c, name)
	if err != nil {
		return err
	}
	if took == nil || took.OwnerEpoch != a.epoch || took.SpecGeneration != a.generation {
		return fmt.Errorf("corrosion: replacement did not take %q (row=%+v, want epoch %d generation %d)",
			name, took, a.epoch, a.generation)
	}
	if stillLive, lErr := GetVM(ctx, c, replacement); lErr != nil {
		return lErr
	} else if stillLive != nil {
		return fmt.Errorf("corrosion: %q is still live after it took the name %q", replacement, name)
	}
	return nil
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
	// Every key the replacement holds, so each can be retired by its own primary
	// key below. Tombstoned keys are included and harmless: the retirement
	// statements carry `deleted_at IS NULL`, so re-retiring one is a no-op that
	// leaves its existing stamp alone.
	sourceChildren, err := vmChildKeys(ctx, c, source.Name)
	if err != nil {
		return nil, err
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

	// Move each of the replacement's IPAM leases by its OWN primary key. The
	// bulk-by-vm_name form is dispatched through per-row LWW on a receiver, which
	// is how a lease ends up still assigned to the name the transition retired.
	leases, err := c.Query(ctx,
		`SELECT network, ip FROM ip_allocations
		 WHERE vm_name = ? AND owner_kind = 'vm' AND owner_host = '' AND deleted_at IS NULL`,
		source.Name)
	if err != nil {
		return nil, err
	}
	for _, l := range leases {
		stmts = append(stmts, Statement{
			SQL:    vmReplaceLeaseSQL,
			Params: []interface{}{name, now, l.String("network"), l.String("ip"), source.Name},
			Guard:  guard,
		})
	}

	// Retire the replacement's own rows. Children first, then the parent — which is
	// deliberately the LAST statement in the batch: it is the semantic commit
	// barrier, and keeping the source row live until then is what lets every
	// preceding statement re-evaluate the SAME guard and reach the same answer.
	//
	// Row-scoped for the same reason as the leases, and written out per table
	// because every replicated statement has to be finite static SQL at its own
	// emission site or the compatibility ledger cannot see it.
	wall := nowRFC3339()
	for _, k := range sourceChildren {
		switch k.table {
		case "vm_interfaces":
			stmts = append(stmts, Statement{SQL: vmReplaceRetireInterfaceSQL,
				Params: []interface{}{wall, now, source.Name, k.key}, Guard: guard})
		case "vm_disks":
			stmts = append(stmts, Statement{SQL: vmReplaceRetireDiskSQL,
				Params: []interface{}{wall, now, source.Name, k.key}, Guard: guard})
		case "vm_nics":
			stmts = append(stmts, Statement{SQL: vmReplaceRetireNICSQL,
				Params: []interface{}{wall, now, source.Name, k.key}, Guard: guard})
		case "vm_pci_intent":
			stmts = append(stmts, Statement{SQL: vmReplaceRetirePCIIntentSQL,
				Params: []interface{}{wall, now, source.Name, k.key}, Guard: guard})
		case "vm_pci_realizations":
			stmts = append(stmts, Statement{SQL: vmReplaceRetirePCIRealSQL,
				Params: []interface{}{wall, now, source.Name, k.deviceID, k.memberID}, Guard: guard})
		default:
			return nil, fmt.Errorf("corrosion: replace has no retirement for child table %q", k.table)
		}
	}
	// The step that AUTHORIZES the destruction, in the same batch as the
	// transition that makes it necessary. Atomic with it by construction: a
	// receiver — or a crashed sender's own database — can never hold this step
	// without the transition, or the transition without this step. A prepared
	// operation on its own authorizes nothing.
	//
	// Its FACTS carry the runtime intent the cutover is committing to — the
	// replacement's accepted state as of this transition, which is what the
	// handoff has to restore afterwards. It cannot come from the manifest: a
	// manifest is taken before the first attempt's teardown and then adopted
	// verbatim by every retry, so an operator who starts the replacement between
	// two attempts would have that start reverted by a snapshot older than their
	// decision. It cannot come from the row either, because a reconciler pass
	// syncs an unfinished handoff's shut-off domain to "stopped" and reading that
	// back erases the start still owed. Written HERE it is neither: it is what was
	// accepted at the moment the transition committed, and it is as durable as the
	// authorization beside it.
	stmts = append(stmts, operationStepInsertStatement(
		guard.OperationID, source.OwnerEpoch, OpStepDesiredPersisted, source.State, wall, now, guard))
	stmts = append(stmts, Statement{
		SQL:    vmDeleteSQL,
		Params: []interface{}{wall, now, source.Name, source.OwnerEpoch, source.SpecGeneration},
		Guard:  guard,
	})
	return stmts, nil
}

// GetVMIncludingDeleted reads a vms row whether or not it is tombstoned.
//
// Both ordinary readers hide something that matters here: GetVM hides a
// tombstone, and GetDeletedVM hides a live row. A caller reasoning about who owns
// a NAME needs neither hidden — a tombstone is still evidence of which
// incarnation last held it, and a VM deleted with its disks retained still owns
// the artifacts keyed by that name.
func GetVMIncludingDeleted(ctx context.Context, c *Client, name string) (*VMRecord, error) {
	return getVMRowIncludingDeleted(ctx, c, name)
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
		guard.OperationID == "" ||
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

	// LEASES. The batch moves each of the replacement's allocations onto the
	// contested name. If this receiver's set differs — an address released and
	// reallocated to an unrelated VM is the dangerous case — the transition is
	// declined WHOLE rather than applied with that statement quietly matching
	// nothing, because the divergence means the sender and this node disagree about
	// what the replacement owns.
	localLeases, err := vmReplaceLeaseDigestInTx(ctx, tx, guard.ResourceID, guard.TargetResourceID)
	if err != nil {
		return false, err
	}
	if localLeases != guard.LeaseDigest {
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

// ── the cleanup journal ─────────────────────────────────────────────────────
//
// The replacement transition and the destruction of what the replaced VM owned
// cannot be one commit: the destruction is filesystem and storage-driver work
// that must follow the transition (a failure before it must destroy nothing),
// and the transition itself DISPLACES the rows that say what to destroy — the
// replaced VM's parent row and any child row whose key the replacement claims.
//
// So a crash in between would otherwise leak the replaced VM's volumes forever,
// with nothing left in the database naming them. The journal closes that window:
//
//  1. PrepareVMReplace records the manifest while those rows are still intact,
//     as a PLANNED operation that authorizes nothing.
//  2. ReplaceVM writes the desired_persisted step in the SAME batch as the
//     transition, so the authorization cannot be observed without it.
//  3. The owner frees what the manifest lists, then CompleteVMReplace.
//
// A restart resumes from (3) — never from (1) or (2), and never by reading the
// reused name, which now belongs to the replacement.

// VMReplaceManifest is the immutable record of what the REPLACED VM owned, taken
// before the transition displaces it. Everything the cleanup needs is here:
// reading it back is the only supported way to free those resources, because the
// name they were recorded under now belongs to the replacement.
type VMReplaceManifest struct {
	// ReplacedVM is the contested name — whose resources these were, NOT whose
	// they are now.
	ReplacedVM string `json:"replaced_vm"`
	// Replacement is the temporary name the replacement held. The cleanup passes
	// it as the owning name for the shared-path check, because it owns no live row
	// afterwards, which makes every live reference count as another VM's.
	Replacement string `json:"replacement"`
	HostName    string `json:"host_name"`
	// ReplacementUUID is the domain UUID recorded in the replacement's spec. The
	// runtime handoff acts on libvirt BY NAME, and the temporary name is free and
	// reusable the moment the transition commits — so every runtime action checks
	// this first, or a delayed recovery undefines whatever VM happens to hold that
	// name and installs its identity at the contested one.
	ReplacementUUID string `json:"replacement_uuid,omitempty"`
	// ReplacementIncarnation is the replacement's created_at. It is in the
	// operation's deterministic identity because the NAMES are not unique over
	// time: a second deployment reuses both of them, and an id built from names
	// alone collides with the first deployment's completed header — which is a
	// hash conflict raised after the current VM has already been torn down.
	ReplacementIncarnation string `json:"replacement_incarnation"`
	// FirmwareUUID keys the replaced VM's swtpm tree. Its NVRAM is name-keyed and
	// so is covered by ReplacedVM.
	FirmwareUUID string `json:"firmware_uuid,omitempty"`
	// Disks are the replaced VM's recorded disk rows, driver-dispatched at cleanup
	// so a non-default-pool volume is freed where it actually lives.
	Disks []DiskRecord `json:"disks,omitempty"`
	// Paths are whole-file artifacts keyed by the replaced VM's name (its
	// cloud-init ISO), which the transition does not describe.
	Paths []string `json:"paths,omitempty"`
	// Leases are the replaced VM's IPAM addresses, to be given back AFTER the
	// transition. They are captured here because the transition moves the
	// REPLACEMENT's leases onto the contested name: afterwards both VMs' addresses
	// answer to one owner name, and only the address itself — with the MAC that
	// held it — still says which was whose.
	Leases []VMReplaceLease `json:"leases,omitempty"`
	// ReplacementSpec and ReplacementState are the runtime-handoff inputs: the
	// libvirt domain and firmware still answer to the temporary name after the
	// transition commits, and moving them is the other half of a cutover. A
	// restart cannot re-derive them from the database — the replacement's row is
	// tombstoned under its temporary name and the reused name now holds the
	// transitioned record — so they are captured here alongside the manifest.
	ReplacementSpec  string `json:"replacement_spec,omitempty"`
	ReplacementState string `json:"replacement_state,omitempty"`
}

// VMReplaceLease is one address the replaced VM held, identified well enough to
// prove — after the transition — that it is still the same allocation.
type VMReplaceLease struct {
	Network string `json:"network"`
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	// NetBoxIPID is the external object backing this address, captured because
	// the local lease row is what normally carries it — and a release whose LOCAL
	// half landed and whose REMOTE half failed has already destroyed that row. The
	// retry has no other way to finish, which is how an address ends up allocated
	// in the external IPAM for good.
	NetBoxIPID int `json:"netbox_ip_id,omitempty"`
	// Identity is the external IPAM identity this address was claimed under —
	// cluster fingerprint, the replaced VM's incarnation uuid, and this MAC. It is
	// what makes the retry above OWNERSHIP-CHECKED rather than blind: the object
	// id alone is a name, not a claim, and an address released and re-allocated to
	// something else keeps the id while the identity moves. The retry may delete
	// the object only while the object still answers to THIS identity.
	Identity string `json:"identity,omitempty"`
}

// VMReplacePrepared is the handle PrepareVMReplace returns: the journaled
// operation whose cleanup the transition must authorize, at the exact owner epoch
// the manifest was recorded under. ReplaceVM refuses a mismatch rather than
// authorizing under a different epoch, which would leave the authorization where
// no resume can find it.
type VMReplacePrepared struct {
	OperationID string
	OwnerEpoch  int64
}

// VMReplaceCleanup is a committed replace with phases still outstanding.
//
// CleanupDone says the destruction has already run, which is not merely an
// optimisation: after it, the replacement's own firmware has moved onto the
// contested name, so re-running the name-keyed wipe would destroy the
// replacement's state instead of the replaced VM's.
type VMReplaceCleanup struct {
	OperationID string
	OwnerEpoch  int64
	Manifest    VMReplaceManifest
	CleanupDone bool
	RuntimeDone bool
	// ReleaseDone records that the replaced VM's addresses were given back.
	ReleaseDone bool
	// StopDone records that the replacement's domain was confirmed inactive, so a
	// retry does not re-stop a domain it has already redefined and restarted.
	StopDone bool
	// Handoff is the recorded domain definition, present once the runtime phase has
	// durably journaled it. Empty means it has not been captured yet.
	Handoff VMReplaceHandoff
	// AcceptedState is the runtime intent recorded ATOMICALLY with the transition:
	// the replacement's accepted state at the moment the cutover committed. It is
	// what the runtime handoff restores, in preference to the manifest's snapshot —
	// the manifest is taken before the first attempt and adopted verbatim by every
	// retry, so a start accepted between two attempts is not in it.
	//
	// Empty only for an operation journaled by a build that did not record it; the
	// handoff falls back to the manifest there.
	AcceptedState string
}

// Outstanding reports whether any phase still has to run.
func (c VMReplaceCleanup) Outstanding() bool {
	return !c.ReleaseDone || !c.CleanupDone || !c.RuntimeDone
}

// VMReplaceHandoff is the replacement's exact domain definition, recorded DURABLY
// before anything undefines it. A redefine that fails transiently otherwise
// leaves neither name defined and the XML only in a local variable, which no
// later recovery can recover.
type VMReplaceHandoff struct {
	XML  string `json:"xml"`
	UUID string `json:"uuid"`
}

// vmReplaceMethod names the operation in its deterministic id.
const vmReplaceMethod = "CutoverVM"

// PrepareVMReplace journals the cleanup manifest as a PLANNED operation and
// returns its id together with the manifest the caller must actually use. It has
// to be called while the replaced VM's rows are still intact — that is the only
// moment a manifest can be TAKEN.
//
// A planned operation authorizes NOTHING. It is safe to leave one behind: the
// resources it names are still owned by a VM that still exists.
//
// The id is deterministic over the replacement's incarnation, so a retry of the
// same cutover reuses the same operation — and the returned manifest is then the
// one that retry's PREDECESSOR journaled, not the one it just built. The caller
// has to use what comes back: after its own earlier attempt tombstoned the
// replaced VM, several of the manifest's inputs can no longer be re-derived.
func PrepareVMReplace(ctx context.Context, c *Client, m VMReplaceManifest, ownerEpoch int64) (VMReplacePrepared, VMReplaceManifest, error) {
	var none VMReplacePrepared
	if m.ReplacedVM == "" || m.Replacement == "" || m.HostName == "" {
		return none, m, fmt.Errorf("corrosion: incomplete VM replace manifest")
	}
	body, err := json.Marshal(m)
	if err != nil {
		return none, m, err
	}
	if m.ReplacementIncarnation == "" {
		return none, m, fmt.Errorf("corrosion: VM replace manifest has no replacement incarnation")
	}
	// The incarnation, not just the names: both names are reused by the next
	// deployment, and a completed header sticks around until the retention sweep.
	// Two deployments of the same pair must be two operations; two ATTEMPTS at one
	// deployment must be the same one.
	id := DeterministicOperationID(vmReplaceMethod, m.HostName, "", m.ReplacedVM,
		m.Replacement+"@"+m.ReplacementIncarnation)
	// A retry of the SAME attempt adopts the manifest that was journaled while the
	// replaced VM's rows were still intact, rather than re-deriving one now.
	//
	// The caller cannot rebuild an equivalent manifest once its own earlier attempt
	// has tombstoned the rows it reads: the NIC rows a lease capture walks are
	// live-only, so a retry after the teardown produces an EMPTY lease list. Hashing
	// that against the stored body would refuse every subsequent attempt, and the
	// operation is not yet resumable on its own — it is still `planned`, which
	// authorizes nothing, so nothing else would ever finish it either.
	//
	// The stored manifest is the authority precisely because it is the earlier one.
	if existing, gErr := GetOperation(ctx, c, id); gErr != nil {
		return none, m, gErr
	} else if existing != nil {
		stored, aErr := adoptVMReplaceManifest(*existing, m, ownerEpoch)
		if aErr != nil {
			return none, m, aErr
		}
		if err := AppendOperationStep(ctx, c, OperationStepRecord{
			OperationID: id, OwnerEpoch: existing.VMOwnerEpoch, StepName: OpStepPlanned,
		}); err != nil {
			return none, m, err
		}
		return VMReplacePrepared{OperationID: id, OwnerEpoch: existing.VMOwnerEpoch}, stored, nil
	}
	op := OperationRecord{
		ID: id, Method: vmReplaceMethod, Principal: m.HostName,
		ResourceKind: "vm", ResourceID: m.ReplacedVM,
		OperationKind: string(OpVMReplace),
		// The manifest IS the request: a retry that produced a different one would
		// be describing different resources, which ClaimOrFindOperation refuses
		// rather than silently adopting.
		RequestHash:     hashIdentity(string(body)),
		IdempotencyKey:  m.Replacement + "@" + m.ReplacementIncarnation,
		ReservationJSON: string(body), DesiredRef: m.ReplacedVM, VMOwnerEpoch: ownerEpoch,
	}
	if _, _, err := ClaimOrFindOperation(ctx, c, op); err != nil {
		return none, m, err
	}
	if err := AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: id, OwnerEpoch: ownerEpoch, StepName: OpStepPlanned,
	}); err != nil {
		return none, m, err
	}
	return VMReplacePrepared{OperationID: id, OwnerEpoch: ownerEpoch}, m, nil
}

// adoptVMReplaceManifest validates an already-journaled replace header against
// the attempt now asking to continue it, and returns the manifest that attempt
// must use.
//
// What is checked is what the deterministic id does NOT already pin: the
// AUTHORITY the header was recorded under. Every cleanup phase is keyed on
// (operation, owner epoch), so continuing at a different epoch would write the
// authorization where no resume can read it back — and an epoch that moved at all
// means the replacement's ownership moved to another node, whose attempt this one
// may not adopt. Refusing leaves the header planned, which authorizes nothing.
//
// The identity fields are re-checked too. They are inputs to the id, so a
// disagreement is a hash collision or a hand-edited row rather than an ordinary
// race — but this is the function that hands a caller the resource list it is
// about to destroy from, and it must not hand over a list belonging to a
// different pair.
func adoptVMReplaceManifest(existing OperationRecord, fresh VMReplaceManifest, ownerEpoch int64) (VMReplaceManifest, error) {
	var stored VMReplaceManifest
	if err := json.Unmarshal([]byte(existing.ReservationJSON), &stored); err != nil {
		return fresh, fmt.Errorf("corrosion: decode the journaled VM replace manifest: %w", err)
	}
	if existing.VMOwnerEpoch != ownerEpoch {
		return fresh, fmt.Errorf(
			"corrosion: the journaled VM replace is at owner epoch %d, this attempt is at %d",
			existing.VMOwnerEpoch, ownerEpoch)
	}
	if stored.ReplacedVM != fresh.ReplacedVM || stored.Replacement != fresh.Replacement ||
		stored.HostName != fresh.HostName || stored.ReplacementIncarnation != fresh.ReplacementIncarnation {
		return fresh, fmt.Errorf(
			"corrosion: the journaled VM replace describes %q<-%q@%s on %q, this attempt describes %q<-%q@%s on %q",
			stored.ReplacedVM, stored.Replacement, stored.ReplacementIncarnation, stored.HostName,
			fresh.ReplacedVM, fresh.Replacement, fresh.ReplacementIncarnation, fresh.HostName)
	}
	return stored, nil
}

// VMReplaceAcceptedState reads back the runtime intent the transition committed —
// the facts on the `desired_persisted` step, written in the same batch as the
// transition itself.
//
// The handler reads it through the journal rather than keeping the value it just
// sent, so the live path and the restart path answer the question from the same
// durable place. An empty string means an operation journaled before this was
// recorded, and the caller falls back to the manifest.
func VMReplaceAcceptedState(ctx context.Context, c *Client, operationID string, ownerEpoch int64) (string, error) {
	steps, err := ListOperationSteps(ctx, c, operationID, ownerEpoch)
	if err != nil {
		return "", err
	}
	for _, st := range steps {
		if st.StepName == OpStepDesiredPersisted {
			return st.Facts, nil
		}
	}
	return "", nil
}

// ListVMReplaceCleanups returns every replace on hostName whose transition
// COMMITTED and whose cleanup has not been recorded as done — the work a
// restarted daemon has to finish.
//
// A planned-only operation is deliberately excluded: its transition never landed,
// so the resources its manifest names are still owned by a live VM.
func ListVMReplaceCleanups(ctx context.Context, c *Client, hostName string) ([]VMReplaceCleanup, error) {
	rows, err := c.Query(ctx,
		`SELECT `+operationCols+` FROM operations
		 WHERE operation_kind = ? AND deleted_at IS NULL ORDER BY created_at`,
		string(OpVMReplace))
	if err != nil {
		return nil, err
	}
	var out []VMReplaceCleanup
	for _, r := range rows {
		op := scanOperation(r)
		state, _, sErr := OperationCurrentState(ctx, c, op.ID, op.VMOwnerEpoch, OpVMReplace)
		if sErr != nil {
			return nil, sErr
		}
		// planned authorizes nothing — its transition never landed, so the
		// resources its manifest names are still owned by a live VM. A terminal
		// operation is finished.
		if state == OpStepPlanned || IsOperationTerminal(state) {
			continue
		}
		var m VMReplaceManifest
		if json.Unmarshal([]byte(op.ReservationJSON), &m) != nil || m.HostName != hostName {
			continue
		}
		steps, stErr := ListOperationSteps(ctx, c, op.ID, op.VMOwnerEpoch)
		if stErr != nil {
			return nil, stErr
		}
		pending := VMReplaceCleanup{OperationID: op.ID, OwnerEpoch: op.VMOwnerEpoch, Manifest: m}
		for _, st := range steps {
			switch st.StepName {
			case OpStepReleased:
				pending.ReleaseDone = true
			case OpStepConfigApplied:
				pending.CleanupDone = true
			case OpStepJournaled:
				_ = json.Unmarshal([]byte(st.Facts), &pending.Handoff)
			case OpStepStopped:
				pending.StopDone = true
			case OpStepRedefined:
				pending.RuntimeDone = true
			case OpStepDesiredPersisted:
				pending.AcceptedState = st.Facts
			}
		}
		if !pending.Outstanding() {
			continue
		}
		out = append(out, pending)
	}
	return out, nil
}

// RecordVMReplacePhase records that one phase of a committed replace has run.
//
// Appended ONLY after that phase actually succeeded: the step is what stops a
// restart from doing it again, so writing it early would either strand the
// resources the journal exists to free, or — for the cleanup phase — let a later
// resume wipe firmware that by then belongs to the replacement.
func RecordVMReplacePhase(ctx context.Context, c *Client, operationID string, ownerEpoch int64, step string) error {
	if step != OpStepReleased && step != OpStepConfigApplied && step != OpStepStopped &&
		step != OpStepRedefined && step != OpStepCompleted {
		return fmt.Errorf("corrosion: %q is not a VM replace phase", step)
	}
	return AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: operationID, OwnerEpoch: ownerEpoch, StepName: step,
	})
}

// VMReplaceHandoffPending reports whether vmName on hostName is the contested
// name of a cutover whose RUNTIME HANDOFF has not finished.
//
// The reconciler asks before syncing a VM it finds shut off: an unfinished
// handoff is precisely a VM whose domain has not been installed under this name
// yet, so reconciling it to "stopped" would erase the running intent the retry
// needs and finish the operation with the VM down.
func VMReplaceHandoffPending(ctx context.Context, c *Client, hostName, vmName string) (bool, error) {
	pending, err := ListVMReplaceCleanups(ctx, c, hostName)
	if err != nil {
		return false, err
	}
	for _, p := range pending {
		if p.Manifest.ReplacedVM == vmName && !p.RuntimeDone {
			return true, nil
		}
	}
	return false, nil
}

// RecordVMReplaceHandoff durably records the replacement's domain definition, so
// the runtime phase can be finished after ANY interruption — including one that
// leaves the domain undefined under both names. It must be called BEFORE the
// undefine, which is the only point at which the definition is still readable.
//
// Re-recording the same definition is a no-op; recording a DIFFERENT one for the
// same operation is refused, because that would mean a second domain answered to
// the temporary name.
func RecordVMReplaceHandoff(
	ctx context.Context, c *Client, operationID string, ownerEpoch int64, h VMReplaceHandoff,
) error {
	body, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: operationID, OwnerEpoch: ownerEpoch,
		StepName: OpStepJournaled, Facts: string(body),
	})
}
