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
// The reads are per SWEEP, not per candidate: the mirror diffs the whole fleet
// on a 15-minute cadence, and a query per candidate would turn one pass into
// thousands of round trips against the same five tables.
//
// It is evidence of a RECORD, never of intent. Nothing here says the object
// should be deleted; the diff decides that. This only says whether the local
// database is in a position to have an opinion.
type MirrorEvidence struct {
	vmNames map[string]bool
	nicKeys map[string]bool
	addrIDs map[int]bool

	// The two INCARNATION-level records, keyed on the uuid and on the identity
	// that carries it rather than on any name. See KnowsIncarnation, which is
	// their only reader and states why a name cannot answer its question.
	vmUUIDs     map[string]bool
	mirroredVMs map[string]bool
}

// KnowsVM reports whether the local database holds a `vms` row of ANY kind for
// this name.
//
// IT ANSWERS FOR AN ORDINARY DELETE AND FOR NOTHING ELSE. A name is a slot, not
// an identity, so this cannot say which INCARNATION the cluster accounted for —
// and there is one removal where that difference decides the answer. See
// KnowsIncarnation, which the mirror's vm/replace asks instead, and which exists
// because the beneficiary of a replace is itself a row under the very name this
// would be asked about.
//
// Keyed on the NAME rather than the spec's incarnation uuid, and for an ordinary
// delete that is the stronger choice. The create path drops a VM's tombstones
// when a VM of the SAME NAME is created again (the `full-state-delete-ok`
// statements in InsertVMWithHardware), so a uuid-keyed lookup over `vms` ALONE
// would lose its evidence on every re-create and leave the old incarnation's
// NetBox object un-reapable forever. The name survives that: a name the local
// database holds a row for is a name the cluster has accounted for, whichever
// incarnation currently owns it — and the old incarnation's object is genuinely
// obsolete either way. (KnowsIncarnation needs the incarnation regardless, and
// pairs the uuid with the mirror's own identity map, which that purge does not
// touch — see there.)
//
// WHAT ACTUALLY TAKES A ROW AWAY FROM A NAME is three paths, not one — the
// create-path cleanup above, DiscardReplicatedStateForReseed's outright
// truncation of `vms`/`vm_interfaces`/`vm_nics`, and RenameVM, which UPDATEs
// `vms.name` (`vm_name` in the child tables, where the rename MOVES the evidence
// to the new name rather than removing it) and so leaves nothing at the old name.
// See HasVMRecords for why each is safe. The common property, and the only one
// this type relies on, is that absent evidence means the caller WITHHOLDS its
// removal: a path that takes evidence away can cost a withheld delete, never an
// unproven one.
//
// An empty name is never evidence.
func (e MirrorEvidence) KnowsVM(name string) bool {
	return name != "" && e.vmNames[name]
}

// KnowsIncarnation reports whether the local database holds a record — live or
// tombstoned — of the ONE INCARNATION this identity names.
//
// WHY A NAME CANNOT ANSWER THIS. It is asked by the mirror's vm/replace, the
// removal that frees a reused VM name for the create or the rename about to take
// it. The identity of the object being removed is not the identity of the VM
// taking the name — that is the entire point of the action — so a name-keyed
// question is answered by the row of the VM the replace is being performed FOR.
// The premise then proves itself: any VM under that name, related or not,
// authorizes replacing an object whose incarnation this node has never held. A
// name standing in for an identity, at the one place the mirror is irreversible.
//
// TWO RECORDS, EITHER OF WHICH IS THE INCARNATION ITSELF:
//
//   - a `vms` row of ANY kind whose spec carries this uuid. Present here and
//     absent from the desired set means the cluster told this node about the
//     incarnation and it is no longer live — tombstoned, or turned into a
//     template the mirror does not represent. RenameVM MOVES that row rather
//     than removing it, and patches only the spec's `name`, so a
//     rename-then-delete leaves the uuid exactly where this looks. That is what
//     makes the freed-name rename provable without asking about the stale name
//     NetBox still holds.
//   - a `netbox_objects` mapping row of ANY kind under this exact identity. The
//     mirror's own createVM/updateVM writes it, its delete tombstones it, and
//     NOTHING prunes it — so it survives the one path that takes the `vms` uuid
//     away: InsertVMWithHardware's same-name re-create purge, which drops the
//     previous incarnation's tombstone. That purge is precisely the
//     delete-then-recreate-under-the-same-name case the replace was built for, so
//     without this second record the commonest proven replacement would be
//     withheld forever and the original permanent collision stall would be back.
//
// Both are INCARNATION-keyed, which is the property that matters: neither can be
// satisfied by a different VM that happens to hold the same name.
//
// WHAT IT DOES NOT CLOSE, stated because the direction is what makes it safe
// rather than completeness. Replication is per TABLE, so a node can hold the
// mapping row for an incarnation whose `vms` row has not arrived; the premise is
// then satisfiable for an object whose VM is alive elsewhere. That window is
// bounded by ONE named incarnation this node's own mirror is recorded as having
// created, where the name-keyed question was satisfied by any row at all — and it
// fails the safe way whenever the node holds neither record: the replacement is
// withheld, the create or rename collides, and the mirror stalls for that one VM
// rather than removing an object it cannot account for.
//
// An empty identity or uuid is never evidence.
func (e MirrorEvidence) KnowsIncarnation(identity, vmUUID string) bool {
	if identity == "" || vmUUID == "" {
		return false
	}
	return e.vmUUIDs[vmUUID] || e.mirroredVMs[identity]
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
		vmNames:     map[string]bool{},
		nicKeys:     map[string]bool{},
		addrIDs:     map[int]bool{},
		vmUUIDs:     map[string]bool{},
		mirroredVMs: map[string]bool{},
	}

	// The name AND the incarnation, from ONE scan. Two queries over the same
	// table would be two chances for one of them to grow a `deleted_at`
	// predicate the other does not have, and the absence of that predicate is
	// the evidence.
	rows, err := c.Query(ctx, `SELECT name, spec FROM vms`)
	if err != nil {
		return MirrorEvidence{}, fmt.Errorf("read local VM records: %w", err)
	}
	for _, r := range rows {
		if name := r.String("name"); name != "" {
			out.vmNames[name] = true
		}
		// A spec that will not parse, or one with no uuid, contributes NOTHING
		// rather than an empty key: an unreadable record is not evidence about
		// any incarnation, and a blank entry would be evidence about all of them.
		if uuid := specVMUUID(r.String("spec")); uuid != "" {
			out.vmUUIDs[uuid] = true
		}
	}

	// The mirror's own identity map, TOMBSTONES INCLUDED and for the same reason
	// every other read here omits the predicate — see KnowsIncarnation, which is
	// the only reader and states why this second record is load-bearing rather
	// than a duplicate of the `vms` uuid above.
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
