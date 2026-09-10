package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// MirrorEvidence is what the local replicated database can PROVE it holds a
// record of — TOMBSTONES INCLUDED.
//
// It exists for one consumer and one question: the NetBox inventory mirror
// asking whether it may delete a remote object. That question cannot be answered
// from the live tables, because they answer the same "not here" for two states
// that must be told apart:
//
//   - the workload was DESTROYED. litevirt soft-deletes, so the row is still
//     there with a `deleted_at` on it, and a VM delete tombstones its
//     `vm_interfaces` and `vm_nics` rows in the same batch.
//   - the row has NOT REPLICATED YET. A node rebuilt after a database loss, or
//     one that has just joined, hydrates row by row; a row that has not arrived
//     leaves NOTHING behind, tombstone included.
//
// So these reads deliberately carry NO `deleted_at` predicate — the one place in
// this package where that is intended rather than a bug. The absence of a filter
// IS the evidence: a record of any kind means the cluster has told this node
// about the object, and no record at all means it has not.
//
// A RECORD IS NOT AUTOMATICALLY A PERMISSION, which is the distinction the VM
// half of this type gets wrong if it unions its records: knowing an incarnation
// exists is a record too, and so is having MIRRORED one. So the VM question
// reports WHICH record it holds (VMRemovalRecord) and leaves the policy to its
// caller, while the NIC and address questions — where every record the local
// database can hold really does say the thing is gone — stay predicates.
//
// The reads are per SWEEP, not per candidate: the mirror diffs the whole fleet
// on a 15-minute cadence, and a query per candidate would turn one pass into
// thousands of round trips against the same five tables.
//
// It is evidence of a RECORD, never of intent. Nothing here says the object
// should be deleted; the diff decides that. This only says whether the local
// database is in a position to have an opinion.
type MirrorEvidence struct {
	nicKeys map[string]bool
	addrIDs map[int]bool

	// The INCARNATION-level records, keyed on the uuid and on the identity that
	// carries it rather than on any name. See VMRemoval, which is their only
	// reader and states why a name cannot answer its question — and why the
	// live and the tombstoned `vms` row are kept APART rather than unioned.
	liveVMUUIDs map[string]bool
	// liveWorkloadVMUUIDs is the subset of liveVMUUIDs whose live row is NOT a
	// template. Held as the non-template set rather than as the template one so
	// that a uuid carried by two live rows — one template, one not — reads as
	// LIVE and withholds: the permissive branch must need every live row to
	// agree, not just one.
	liveWorkloadVMUUIDs map[string]bool
	retiredVMUUIDs      map[string]bool
	mirroredVMs         map[string]bool
}

// VMRemovalRecord is what the local database holds about ONE INCARNATION, in
// the four states that decide whether the mirror may remove that incarnation's
// NetBox object.
//
// FOUR STATES AND NOT A BOOLEAN, because the question a removal has to answer is
// not "can this node name the thing?" but "can this node conclude the mirror
// must no longer represent it?" — and those two came apart here once already. A
// predicate that unioned every record it held answered the first question and
// was read as the second: it accepted a MAPPING row, which proves an incarnation
// was MIRRORED and says nothing whatever about whether it stopped existing.
// Identifying the victim precisely is not permission to delete it.
//
// So the records are reported APART and the caller applies the policy. See
// MirrorEvidence.VMRemoval for what each state is derived from, and
// netboxsync's vmRemovalProven for the one policy both removals apply to them.
type VMRemovalRecord int

const (
	// VMRemovalNoRecord: this node holds NOTHING about this incarnation — no
	// `vms` row of any kind, no mapping row. The unhydrated case, and the one
	// state that has always withheld.
	VMRemovalNoRecord VMRemovalRecord = iota
	// VMRemovalRetired: a TOMBSTONED `vms` row carrying this uuid. litevirt
	// soft-deletes, so this is the record a destroyed incarnation leaves, and it
	// is a justified conclusion of absence on its own.
	VMRemovalRetired
	// VMRemovalLive: a LIVE `vms` row carrying this uuid. The incarnation
	// EXISTS. Nothing may remove its object.
	VMRemovalLive
	// VMRemovalLiveTemplate: a LIVE `vms` row carrying this uuid whose
	// `is_template` is set. The incarnation exists and the mirror deliberately
	// does not represent it — a template is a disk image, never a running
	// machine, and desiredState skips it — so its object is one the mirror must
	// no longer hold. The one state where a live row still authorizes a removal,
	// and it is reported separately rather than folded into VMRemovalLive so
	// that a live row some FUTURE reason drops from the desired set fails closed
	// instead of inheriting this one's permission.
	VMRemovalLiveTemplate
	// VMRemovalMirroredOnly: no `vms` row of any kind, but the mirror's own
	// `netbox_objects` mapping row for this exact identity. INCARNATION-SPECIFIC
	// IDENTIFICATION AND NOTHING MORE — it proves this node's mirror created that
	// object for that incarnation, not that the incarnation is gone. Replication
	// is per TABLE, so this is exactly what a node holds for an incarnation whose
	// `vms` row has not arrived and whose VM may be alive on a peer. It
	// authorizes nothing by itself; the caller has to corroborate its inventory
	// read against the cluster first.
	VMRemovalMirroredOnly
)

// VMRemoval reports which record — if any — the local database holds about the
// ONE INCARNATION this identity names.
//
// WHY A NAME CANNOT ANSWER THIS, for either removal that asks. The mirror's
// vm/replace frees a reused VM name for the create or the rename about to take
// it, so the identity being removed is by construction NOT the identity of the
// VM taking the name: a name-keyed question is answered by the row of the
// BENEFICIARY, the premise proves itself, and any VM under that name authorizes
// replacing an object whose incarnation this node has never held. The ordinary
// vm/delete had the same defect from the other direction — a tombstone under the
// name proved a removal for whichever incarnation NetBox happened to hold there,
// so a re-created-then-deleted VM's tombstone authorized deleting the object of a
// DIFFERENT incarnation that may be alive on a peer.
//
// THE RECORDS, and each is incarnation-keyed so that no row of a different VM
// sharing the name can satisfy it:
//
//   - the `vms` row carrying this uuid, CLASSIFIED live or tombstoned rather
//     than unioned. RenameVM MOVES that row rather than removing it, and patches
//     only the spec's `name`, so a rename-then-delete leaves the uuid exactly
//     where this looks — which is what makes the freed-name rename provable
//     without asking about the stale name NetBox still holds.
//   - the `netbox_objects` mapping row under this exact identity, reported ONLY
//     when no `vms` row carries the uuid. The mirror's own createVM/updateVM
//     writes it, its delete tombstones it, and NOTHING prunes it — so it
//     survives the one path that takes the `vms` uuid away:
//     InsertVMWithHardware's same-name re-create purge, which drops the previous
//     incarnation's tombstone. That purge is precisely the
//     delete-then-recreate-under-the-same-name case the replace exists for, so
//     without this record the commonest proven replacement would be withheld
//     forever and the original permanent collision stall would be back. What it
//     is NOT is evidence of absence — see VMRemovalMirroredOnly.
//
// A LIVE ROW WINS over a tombstone carrying the same uuid. Two rows can carry
// one uuid (a spec copied onto a second name), and "one of them is still live"
// is the answer that withholds.
//
// An empty identity or uuid is never evidence.
func (e MirrorEvidence) VMRemoval(identity, vmUUID string) VMRemovalRecord {
	if identity == "" || vmUUID == "" {
		return VMRemovalNoRecord
	}
	switch {
	case e.liveVMUUIDs[vmUUID]:
		if e.liveWorkloadVMUUIDs[vmUUID] {
			return VMRemovalLive
		}
		return VMRemovalLiveTemplate
	case e.retiredVMUUIDs[vmUUID]:
		return VMRemovalRetired
	case e.mirroredVMs[identity]:
		return VMRemovalMirroredOnly
	default:
		return VMRemovalNoRecord
	}
}

// KnowsNIC reports whether the local database holds an interface row of ANY kind
// for this (VM, MAC).
//
// Both NIC tables count. `vm_interfaces` is the legacy row and `vm_nics` the v42
// hardware_v2 one; a detach tombstones whichever exist, and which of them a given
// cluster carries depends on a latch. Evidence of a record is not a question of
// precedence — the merged view decides what a NIC IS, this decides only whether
// the cluster has ever mentioned one.
//
// `vm_nics` IS LOAD-BEARING, not belt-and-braces. On the commonest hotplug
// sequence it is the only row left: `vm_interfaces` keys on
// (vm_name, network_name) and InsertInterface is an INSERT OR REPLACE, so
// re-attaching on the SAME network — with the freshly randomised MAC an attach
// always gets — overwrites the detached NIC's row in place, MAC and tombstone
// together. `vm_nics` keys on (vm_name, id) with the id derived from the MAC, so
// the two incarnations are different rows and the old one's tombstone survives.
// Drop that table from the union and every re-attached NIC permanently strands
// its old NetBox interface: the delete is withheld on every sweep from then on.
// Pinned by TestDetachedMACStaysProvableAfterReattach.
//
// That mitigation covers the LOCAL write path only, and one more path overwrites
// a MAC in place: buildMergeUpsertSQL assigns every sender-supplied non-PK
// column, and `vm_interfaces` keys on (vm_name, network_name), so a merged peer
// row replaces the local `mac` outright. `vm_nics` keys on (vm_name, id) with the
// id derived from the MAC, so the merge lands the peer's NIC as a SEPARATE row
// and cannot overwrite another MAC's — but anti-entropy repairs per TABLE, so
// during the window where `vm_interfaces` has merged and `vm_nics` has not,
// neither table names the displaced MAC. It fails the same direction as
// everything else here: the mirror withholds that interface's delete until the
// `vm_nics` merge closes the window.
//
// KNOWN GAP, bounded: InsertVMWithHardware's same-name re-create purge is keyed
// on `vm_name` ALONE, so re-creating a VM under a name that was used before
// drops the previous incarnation's interface tombstones — and its MACs were
// freshly randomised, so this evidence goes with them. It cannot lose an object:
// the parent VM delete is proven by NAME, which the purge leaves live, and a
// NetBox VM delete cascades its interfaces away anyway. What it costs is noise —
// delete-then-recreate-under-the-same-name can log a withheld interface delete
// that resolves itself on the next sweep, on the gauge an operator alerts on.
//
// An empty VM name or MAC is never evidence.
func (e MirrorEvidence) KnowsNIC(vmName, mac string) bool {
	if vmName == "" || mac == "" {
		return false
	}
	return e.nicKeys[nicEvidenceKey(vmName, mac)]
}

// KnowsAddress reports whether the local `ip_allocations` table holds a lease
// row of ANY kind — live or tombstoned — that references this NetBox address
// object.
//
// It is what authorizes the mirror's `clear`, which unassigns an address from an
// interface. A clear is bounded where a delete is not, but it is reached by the
// SAME unhydrated read: `ip_allocations` empty resolves every NIC to address 0,
// which reads as "this NIC holds no address" and routes every litevirt-owned
// address in the cluster into the clear branch. Anti-entropy repairs per table,
// so "`vms` repaired, `ip_allocations` not yet" is a state the repair mechanism
// itself produces.
//
// It is NOT complete, and the tempting argument for why it would be does not
// hold. Nothing hard-deletes an `ip_allocations` row — ReleaseLease tombstones it
// and RETAINS netbox_ip_id — but the read below filters `WHERE netbox_ip_id IS
// NOT NULL`, so losing the COLUMN VALUE loses the evidence exactly as a hard
// delete would, and two paths do that by UPDATE:
//
//   - network's NetBox allocator resurrects a tombstoned lease with an upsert
//     keyed on (network, ip) that assigns `netbox_ip_id = excluded.netbox_ip_id`.
//     Re-claiming a released address therefore overwrites the PRIOR object's id
//     with the new one's. The producible permanent case: the compensating
//     ReleaseIP after a failed persist does not go through, an explicit re-claim
//     of the same address mints a fresh object, and the old litevirt-owned object
//     — still assigned to a surviving interface — becomes unclearable for good.
//   - buildMergeUpsertSQL (anti-entropy merge) assigns every sender-supplied
//     non-PK column, so a strictly-newer peer row carrying a NULL `netbox_ip_id`
//     nulls the local value.
//
// What saves the caller is the DIRECTION, not completeness: a missing id yields
// "not proven", and the mirror's answer to that is to withhold the clear. The
// cost is a withheld clear — an address NetBox keeps advertising — never an
// unproven one. Leak over collision, the same direction as every other
// fail-closed decision here. A withheld clear that never resolves is an object
// for an operator to unassign in NetBox by hand.
//
// (DiscardReplicatedStateForReseed truncates the table, and the merge behind it
// restores the rows; the window in between costs withheld clears the same way.)
//
// Address 0 is never evidence: it is what a builtin, non-NetBox lease reads back
// as, and what an unresolved lookup returns.
func (e MirrorEvidence) KnowsAddress(id int) bool {
	return id != 0 && e.addrIDs[id]
}

// nicEvidenceKey keys one interface record. Lower-cased because NetBox echoes
// MACs upper-cased and litevirt records them either way; NUL-separated so no
// (name, MAC) pair can be spelled two ways.
func nicEvidenceKey(vmName, mac string) string {
	return vmName + "\x00" + strings.ToLower(mac)
}

// mirrorRefKindVM is the `netbox_objects.litevirt_kind` the inventory mirror
// records a virtual_machine under.
//
// A literal, matching internal/netboxsync's own and the re-key's, for the reason
// stated at those: it is a REPLICATED COLUMN VALUE, so a rename of a shared
// constant would change what one build writes and not what an older peer reads.
const mirrorRefKindVM = "vm"

// specVMUUID is the incarnation uuid inside a stored VM spec, or "" when the
// spec is absent, unparseable, or carries none.
//
// A one-field decode rather than the whole spec: this package is deliberately
// pb-free (see RenameVM, which patches the same JSON through a generic map), and
// the uuid is the only field any evidence question is about.
func specVMUUID(spec string) string {
	if spec == "" {
		return ""
	}
	var s struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal([]byte(spec), &s); err != nil {
		return ""
	}
	return s.UUID
}

// ReadMirrorEvidence collects the record evidence in one pass over the five
// tables that carry it.
//
// Every read failure is RETURNED. This is the evidence a delete rests on, so a
// swallowed error would turn "the local history could not be read" into "the
// local history holds nothing" — which reads as no proof for anything and would
// silently disable the delete half, or, read the other way round, would be
// exactly the fail-open the caller must not have.
func ReadMirrorEvidence(ctx context.Context, c *Client) (MirrorEvidence, error) {
	out := MirrorEvidence{
		nicKeys:             map[string]bool{},
		addrIDs:             map[int]bool{},
		liveVMUUIDs:         map[string]bool{},
		liveWorkloadVMUUIDs: map[string]bool{},
		retiredVMUUIDs:      map[string]bool{},
		mirroredVMs:         map[string]bool{},
	}

	// EVERY incarnation record from ONE scan. Two queries over the same table
	// would be two chances for one of them to grow a `deleted_at` predicate the
	// other does not have, and the absence of that predicate is the evidence.
	//
	// `deleted_at` IS SELECTED and is still not a predicate. It is read to
	// CLASSIFY the row — live, or the tombstone a destroyed incarnation leaves —
	// which is the difference between "it exists" and "it stopped existing", and
	// the whole reason two of the four states above are separate. Filtering on
	// it would throw away exactly the rows that authorize a removal; unioning
	// the two states, as this once did, throws away the only rows that forbid
	// one.
	rows, err := c.Query(ctx,
		`SELECT spec, COALESCE(deleted_at, '') AS deleted_at,
		        COALESCE(is_template, 0) AS is_template
		   FROM vms`)
	if err != nil {
		return MirrorEvidence{}, fmt.Errorf("read local VM records: %w", err)
	}
	for _, r := range rows {
		// A spec that will not parse, or one with no uuid, contributes NOTHING
		// rather than an empty key: an unreadable record is not evidence about
		// any incarnation, and a blank entry would be evidence about all of them.
		uuid := specVMUUID(r.String("spec"))
		if uuid == "" {
			continue
		}
		if r.String("deleted_at") != "" {
			out.retiredVMUUIDs[uuid] = true
			continue
		}
		out.liveVMUUIDs[uuid] = true
		if r.Int("is_template") == 0 {
			out.liveWorkloadVMUUIDs[uuid] = true
		}
	}

	// The mirror's own identity map, TOMBSTONES INCLUDED and for the same reason
	// every other read here omits the predicate — see VMRemoval, which is the
	// only reader and states why this record is load-bearing rather than a
	// duplicate of the `vms` uuid above, and why on its own it is
	// identification and not evidence of absence.
	//
	// Scoped to the VM kind. A VM identity is its NIC identity with an empty MAC
	// component, so the two kinds share a key space and an unscoped read would
	// admit interface mappings into a set only VM questions are asked of.
	rows, err = c.Query(ctx,
		`SELECT litevirt_key FROM netbox_objects WHERE litevirt_kind = ?`, mirrorRefKindVM)
	if err != nil {
		return MirrorEvidence{}, fmt.Errorf("read local NetBox object mappings: %w", err)
	}
	for _, r := range rows {
		if key := r.String("litevirt_key"); key != "" {
			out.mirroredVMs[key] = true
		}
	}

	for _, q := range []string{
		`SELECT vm_name, mac FROM vm_interfaces`,
		`SELECT vm_name, mac FROM vm_nics`,
	} {
		rows, err := c.Query(ctx, q)
		if err != nil {
			return MirrorEvidence{}, fmt.Errorf("read local NIC records: %w", err)
		}
		for _, r := range rows {
			vmName, mac := r.String("vm_name"), r.String("mac")
			if vmName == "" || mac == "" {
				continue
			}
			out.nicKeys[nicEvidenceKey(vmName, mac)] = true
		}
	}

	// NO `deleted_at` predicate here either, and for the same reason: a released
	// lease keeps its netbox_ip_id, so the tombstone IS the proof that the
	// address the mirror wants to unassign is genuinely unclaimed. Filtering to
	// live rows would make every correct clear unprovable.
	//
	// The `netbox_ip_id IS NOT NULL` predicate is what makes this evidence
	// INCOMPLETE rather than merely conservative: two UPDATE paths can clear the
	// column and take the proof with it. See KnowsAddress — both cost a withheld
	// clear, which is the safe direction.
	rows, err = c.Query(ctx,
		`SELECT netbox_ip_id FROM ip_allocations WHERE netbox_ip_id IS NOT NULL`)
	if err != nil {
		return MirrorEvidence{}, fmt.Errorf("read local NetBox lease records: %w", err)
	}
	for _, r := range rows {
		if id := r.Int("netbox_ip_id"); id != 0 {
			out.addrIDs[id] = true
		}
	}
	return out, nil
}
