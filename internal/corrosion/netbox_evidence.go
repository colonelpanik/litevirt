package corrosion

import (
	"context"
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
// on a 15-minute cadence, and a query per delete candidate would turn one pass
// into thousands of round trips against the same three tables.
//
// It is evidence of a RECORD, never of intent. Nothing here says the object
// should be deleted; the diff decides that. This only says whether the local
// database is in a position to have an opinion.
type MirrorEvidence struct {
	vmNames map[string]bool
	nicKeys map[string]bool
}

// KnowsVM reports whether the local database holds a `vms` row of ANY kind for
// this name.
//
// Keyed on the NAME rather than the spec's incarnation uuid, and that is the
// stronger choice. `DeleteVM` removes a VM's tombstones when a VM of the SAME
// NAME is created again (see the cleanup statements on the create path), so a
// uuid-keyed lookup would lose its evidence on every re-create and leave the old
// incarnation's NetBox object un-reapable forever. The name survives that: a
// name the local database holds a row for is a name the cluster has accounted
// for, whichever incarnation currently owns it — and the old incarnation's object
// is genuinely obsolete either way.
//
// An empty name is never evidence.
func (e MirrorEvidence) KnowsVM(name string) bool {
	return name != "" && e.vmNames[name]
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
// An empty VM name or MAC is never evidence.
func (e MirrorEvidence) KnowsNIC(vmName, mac string) bool {
	if vmName == "" || mac == "" {
		return false
	}
	return e.nicKeys[nicEvidenceKey(vmName, mac)]
}

// nicEvidenceKey keys one interface record. Lower-cased because NetBox echoes
// MACs upper-cased and litevirt records them either way; NUL-separated so no
// (name, MAC) pair can be spelled two ways.
func nicEvidenceKey(vmName, mac string) string {
	return vmName + "\x00" + strings.ToLower(mac)
}

// ReadMirrorEvidence collects the record evidence in one pass over the three
// tables that carry it.
//
// Every read failure is RETURNED. This is the evidence a delete rests on, so a
// swallowed error would turn "the local history could not be read" into "the
// local history holds nothing" — which reads as no proof for anything and would
// silently disable the delete half, or, read the other way round, would be
// exactly the fail-open the caller must not have.
func ReadMirrorEvidence(ctx context.Context, c *Client) (MirrorEvidence, error) {
	out := MirrorEvidence{
		vmNames: map[string]bool{},
		nicKeys: map[string]bool{},
	}

	rows, err := c.Query(ctx, `SELECT name FROM vms`)
	if err != nil {
		return MirrorEvidence{}, fmt.Errorf("read local VM records: %w", err)
	}
	for _, r := range rows {
		if name := r.String("name"); name != "" {
			out.vmNames[name] = true
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
	return out, nil
}
