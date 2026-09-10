package netboxsync

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

func TestApplySearchesBeforeCreating(t *testing.T) {
	nb := &stubVirt{
		// The object EXISTS in NetBox but has no local mapping — the exact state
		// left by a timeout after creation but before the identity-map write.
		byIdentity: map[string][]int{vmIdent("uuid-1"): {11}},
	}
	r := newTestReconciler(t, nb)

	id := netbox.Identity(fp, "uuid-1", "")
	err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: id}},
		indexDesired([]DesiredVM{{Name: "vm-1", UUID: "uuid-1"}}, fp),
		fp,
	)
	if err != nil {
		t.Fatal(err)
	}
	if nb.createCalls != 0 {
		t.Fatal("must adopt the existing object, not create a duplicate")
	}
	if ref := mustGetRef(t, r, "vm", id); ref.NetBoxID != 11 {
		t.Fatalf("must record the adopted id, got %+v", ref)
	}
}

func TestApplyDeleteUsesTheActionsObjectID(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	id := netbox.Identity(fp, "uuid-gone", "")

	// A delete action carries its NetBoxID: an identity alone cannot be deleted,
	// and re-resolving it here would be a second round trip that could observe
	// different state than the diff did.
	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "delete", Key: id, NetBoxID: 11}},
		indexDesired(nil, fp), fp,
	); err != nil {
		t.Fatal(err)
	}
	if len(nb.deleted) != 1 || nb.deleted[0] != 11 {
		t.Fatalf("want VM 11 deleted, got %v", nb.deleted)
	}
	if ref, _ := getRef(r, "vm", id); ref != nil {
		t.Fatal("the identity mapping must be tombstoned with the object")
	}
}

// ── vm/replace: the applier's own, independent proof ────────────────────────

// TestApplyReplaceRemovesTheSupersededObjectAndRetiresItsMapping is the positive
// case. The identity is absent from the desired set and carries this cluster's
// fingerprint, which is the whole proof — and the mapping is retired here
// because Diff emits no separate delete for a replaced identity, so nothing else
// would ever prune it.
func TestApplyReplaceRemovesTheSupersededObjectAndRetiresItsMapping(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	old := netbox.Identity(fp, "uuid-old", "")
	if err := r.recordRef(context.Background(), "vm", old, netboxKindVM, 11); err != nil {
		t.Fatalf("seed the superseded mapping: %v", err)
	}

	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: opReplace, Key: old, NetBoxID: 11, FreesName: "vm-1"}},
		indexDesired([]DesiredVM{{Name: "vm-1", UUID: "uuid-new"}}, fp), fp,
	); err != nil {
		t.Fatal(err)
	}
	if len(nb.deleted) != 1 || nb.deleted[0] != 11 {
		t.Fatalf("want the superseded object 11 removed, got %v", nb.deleted)
	}
	if ref, _ := getRef(r, "vm", old); ref != nil {
		t.Fatal("the superseded identity's mapping must be retired with its object; nothing " +
			"else prunes it, and a stranded row is how a re-created object adopts a dead id")
	}
}

// TestApplyReplaceRefusesAnIdentityInTheDesiredSet re-proves the first refusal
// where the delete is actually issued.
//
// Diff already refuses this, so reaching the applier with such an action means
// something upstream is wrong — and the answer to that is to STOP, loudly, not
// to trust the flag. A create that cannot be made is a stalled mirror the next
// sweep can still fix; a mirrored VM deleted out of NetBox is gone.
func TestApplyReplaceRefusesAnIdentityInTheDesiredSet(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	live := netbox.Identity(fp, "uuid-live", "")

	err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: opReplace, Key: live, NetBoxID: 11, FreesName: "vm-1"}},
		// The very identity the action would remove is DESIRED.
		indexDesired([]DesiredVM{{Name: "vm-2", UUID: "uuid-live"}}, fp), fp,
	)
	if err == nil {
		t.Fatal("the applier removed an object whose identity IS in the desired set — a live " +
			"VM of this cluster — to free a name")
	}
	if len(nb.deleted) != 0 {
		t.Fatalf("nothing may be deleted on a refused replacement, got %v", nb.deleted)
	}
}

// TestApplyReplaceRefusesAForeignIdentity re-proves the second refusal: another
// installation's object is untouchable at any cost.
func TestApplyReplaceRefusesAForeignIdentity(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	foreign := netbox.Identity("another-installation", "uuid-old", "")

	err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: opReplace, Key: foreign, NetBoxID: 11, FreesName: "vm-1"}},
		indexDesired([]DesiredVM{{Name: "vm-1", UUID: "uuid-new"}}, fp), fp,
	)
	if err == nil {
		t.Fatal("the applier removed an object carrying ANOTHER installation's fingerprint")
	}
	if len(nb.deleted) != 0 {
		t.Fatalf("nothing may be deleted on a refused replacement, got %v", nb.deleted)
	}
}

func TestApplyDeletesADetachedInterface(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	id := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:01")

	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "delete", Key: id, NetBoxID: 21}},
		indexDesired(nil, fp), fp,
	); err != nil {
		t.Fatal(err)
	}
	// Without DeleteInterface, a hotplug detach never converges in NetBox.
	if len(nb.deletedInterfaces) != 1 || nb.deletedInterfaces[0] != 21 {
		t.Fatalf("want interface 21 deleted, got %v", nb.deletedInterfaces)
	}
	if ref, _ := getRef(r, "nic", id); ref != nil {
		t.Fatal("the identity mapping must be tombstoned with the interface")
	}
}

// TestApplyDeleteTombstonesRefWhenObjectAlreadyGone pins that a 404 counts as
// success. Aborting on it strands the netbox_objects row PERMANENTLY: the next
// sweep sees no such object in actual state, so it emits no delete, and nothing
// else prunes a mapping.
func TestApplyDeleteTombstonesRefWhenObjectAlreadyGone(t *testing.T) {
	for _, tc := range []struct {
		kind       string
		netboxKind string
		netboxID   int
		mac        string
	}{
		{kind: kindVM, netboxKind: netboxKindVM, netboxID: 11},
		{kind: kindNIC, netboxKind: netboxKindNIC, netboxID: 21, mac: "52:54:00:aa:bb:01"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			nb := &stubVirt{deleteErr: &netbox.APIError{Status: 404, Body: "Not found."}}
			r := newTestReconciler(t, nb)
			key := netbox.Identity(fp, "uuid-1", tc.mac)
			if err := r.recordRef(context.Background(), tc.kind, key, tc.netboxKind, tc.netboxID); err != nil {
				t.Fatal(err)
			}

			if err := r.apply(context.Background(),
				[]Action{{Kind: tc.kind, Op: "delete", Key: key, NetBoxID: tc.netboxID}},
				indexDesired(nil, fp), fp,
			); err != nil {
				t.Fatalf("an object that is already gone IS the desired end state: %v", err)
			}
			if ref, _ := getRef(r, tc.kind, key); ref != nil {
				t.Fatalf("the mapping must be tombstoned anyway, or nothing ever prunes it: %+v", *ref)
			}
		})
	}
}

// TestApplyDeleteKeepsTheRefWhenTheDeleteFails is the other half: only a proven
// absence may tombstone. A 500 or a transport failure may have left the object
// standing, and dropping the mapping there orphans it beyond any later sweep.
func TestApplyDeleteKeepsTheRefWhenTheDeleteFails(t *testing.T) {
	for name, delErr := range map[string]error{
		"server":    &netbox.APIError{Status: 500, Body: "boom"},
		"transport": errors.New("connection refused"),
	} {
		t.Run(name, func(t *testing.T) {
			nb := &stubVirt{deleteErr: delErr}
			r := newTestReconciler(t, nb)
			key := netbox.Identity(fp, "uuid-1", "")
			if err := r.recordRef(context.Background(), kindVM, key, netboxKindVM, 11); err != nil {
				t.Fatal(err)
			}

			if err := r.apply(context.Background(),
				[]Action{{Kind: "vm", Op: "delete", Key: key, NetBoxID: 11}},
				indexDesired(nil, fp), fp,
			); err == nil {
				t.Fatal("an unproven delete must be reported, not tombstoned")
			}
			if ref, _ := getRef(r, kindVM, key); ref == nil {
				t.Fatal("the mapping must survive a delete that may not have happened")
			}
		})
	}
}

func TestApplyDeduplicatesKeepingOldest(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{vmIdent("uuid-1"): {13, 11, 12}}}
	r := newTestReconciler(t, nb)

	id := netbox.Identity(fp, "uuid-1", "")
	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: id}},
		indexDesired([]DesiredVM{{Name: "vm-1", UUID: "uuid-1"}}, fp),
		fp,
	); err != nil {
		t.Fatal(err)
	}
	// NetBox offers no idempotency key, so a transient duplicate is possible.
	// The sweep is authoritative: keep the oldest, delete the rest.
	if len(nb.deleted) != 2 {
		t.Fatalf("want 2 duplicates deleted, got %v", nb.deleted)
	}
	if ref := mustGetRef(t, r, "vm", id); ref.NetBoxID != 11 {
		t.Fatalf("must keep the OLDEST object, got %+v", ref)
	}
	// Every duplicate is counted, so an operator sees the condition rather than
	// only its silent repair.
	if got := dupesCounted(t, r); got != 2 {
		t.Fatalf("litevirt_netbox_duplicate_objects_total incremented %d times, want 2", got)
	}
}

func TestVMCreateDoesNotCreateNICs(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	id := netbox.Identity(fp, "uuid-1", "")

	// Phase 2 owns every interface and Diff already emits a nic/create for each
	// one. Creating them here too would double the work and split interface
	// ownership across two phases, so a bug in either path would be masked by
	// the other.
	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: id}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1",
			NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc", IP: "10.0.5.100", NetBoxIPID: 41}},
		}}, fp),
		fp,
	); err != nil {
		t.Fatal(err)
	}
	if nb.createCalls != 1 {
		t.Fatalf("want the VM created once, got %d", nb.createCalls)
	}
	if len(nb.createdInterfaces) != 0 {
		t.Fatalf("vm/create must never create interfaces, got %+v", nb.createdInterfaces)
	}
	if len(nb.ipAssignments) != 0 {
		t.Fatalf("vm/create must never assign addresses, got %+v", nb.ipAssignments)
	}
}

func TestNICCreateAssignsItsAddress(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)

	// Driven by nic/create, NOT vm/create: phase 0 creates only the VM, and Diff
	// emits no separate assign for a NIC that does not exist yet. Without an
	// assignment here a new NIC stays unassigned until a later sweep.
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")
	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: nicID, ParentNetBoxID: 11}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1",
			NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc", IP: "10.0.5.100", NetBoxIPID: 41}},
		}}, fp),
		fp,
	); err != nil {
		t.Fatal(err)
	}
	if len(nb.createdInterfaces) != 1 || nb.createdInterfaces[0].VMID != 11 {
		t.Fatalf("interface must be created under the parent VM, got %+v", nb.createdInterfaces)
	}
	if len(nb.ipAssignments) != 1 {
		t.Fatalf("want exactly one assignment, got %v", nb.ipAssignments)
	}
	if got := nb.ipAssignments[0]; got.IPID != 41 || got.IfaceID != nb.createdInterfaces[0].ID {
		t.Fatalf("assignment = %+v, want IP 41 on the new interface", got)
	}
}

func TestNICCreateAdoptsAnExistingInterfaceThenAssigns(t *testing.T) {
	// The interface already exists in NetBox — a create whose identity-map write
	// was lost. Adopting must not mint a second interface, and the address must
	// still land on the adopted one.
	nb := &stubVirt{
		interfacesByIdentity: map[string][]int{
			netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc"): {21},
		},
	}
	r := newTestReconciler(t, nb)
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")

	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: nicID, ParentNetBoxID: 11}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1",
			NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc", NetBoxIPID: 41}},
		}}, fp),
		fp,
	); err != nil {
		t.Fatal(err)
	}
	if len(nb.createdInterfaces) != 0 {
		t.Fatalf("an existing interface must be adopted, not duplicated: %+v", nb.createdInterfaces)
	}
	if len(nb.ipAssignments) != 1 || nb.ipAssignments[0].IfaceID != 21 || nb.ipAssignments[0].IPID != 41 {
		t.Fatalf("want address 41 assigned to the adopted interface 21, got %v", nb.ipAssignments)
	}
	if ref := mustGetRef(t, r, "nic", nicID); ref.NetBoxID != 21 {
		t.Fatalf("the adopted id must be recorded, got %+v", ref)
	}
}

func TestNICCreateUsesActualParentWhenMappingIsLost(t *testing.T) {
	// The VM exists in NetBox but its netbox_objects row is gone, so Diff emits
	// no VM action and phase 0 records nothing. Phase ordering alone cannot
	// establish the parent; ParentNetBoxID from actual state can.
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")

	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: nicID, ParentNetBoxID: 11}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1",
			NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc"}},
		}}, fp),
		fp,
	); err != nil {
		t.Fatalf("a missing parent mapping must not fail the NIC create: %v", err)
	}
	if nb.createCalls != 0 {
		t.Fatal("the existing VM must not be duplicated")
	}
	if len(nb.createdInterfaces) != 1 || nb.createdInterfaces[0].VMID != 11 {
		t.Fatalf("want the interface created under VM 11, got %+v", nb.createdInterfaces)
	}
}

// TestNICCreateFallsBackToTheRecordedParent pins the OTHER half of the parent
// resolution: a NIC whose VM was created earlier in this sweep carries no
// ParentNetBoxID, because Diff read an actual state in which the VM did not
// exist. The netbox_objects row phase 0 wrote is the only link.
func TestNICCreateFallsBackToTheRecordedParent(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	vmID := netbox.Identity(fp, "uuid-1", "")
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")
	idx := indexDesired([]DesiredVM{{
		Name: "vm-1", UUID: "uuid-1",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc"}},
	}}, fp)

	// Phase 0, then phase 2 — the ordering the production runner uses.
	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: vmID}}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: nicID}}, idx, fp); err != nil {
		t.Fatal(err)
	}
	created := mustGetRef(t, r, "vm", vmID).NetBoxID
	if len(nb.createdInterfaces) != 1 || nb.createdInterfaces[0].VMID != created {
		t.Fatalf("want the interface under the VM created this sweep (%d), got %+v", created, nb.createdInterfaces)
	}
}

// TestNICCreateRefusesWithNoResolvableParent pins that an unparented interface
// is never minted. NetBox would reject it anyway, but a create issued with
// virtual_machine 0 turns a recoverable "the mapping is lost" into an API error
// that says nothing about why.
func TestNICCreateRefusesWithNoResolvableParent(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")

	err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: nicID}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1",
			NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc"}},
		}}, fp),
		fp,
	)
	if err == nil {
		t.Fatal("want an error when no parent can be resolved")
	}
	if len(nb.createdInterfaces) != 0 {
		t.Fatalf("no interface may be created without a parent, got %+v", nb.createdInterfaces)
	}
}

// TestVMUpdateAndNICUpdateTargetTheActionsObject pins that both updates PATCH
// the id the diff resolved, and that the VM body carries the mirrored fields.
func TestVMUpdateAndNICUpdateTargetTheActionsObject(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	vmID := netbox.Identity(fp, "uuid-1", "")
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")

	if err := r.apply(context.Background(), []Action{
		{Kind: "vm", Op: "update", Key: vmID, NetBoxID: 11},
		{Kind: "nic", Op: "update", Key: nicID, NetBoxID: 21, ParentNetBoxID: 11},
	}, indexDesired([]DesiredVM{{
		Name: "vm-1", UUID: "uuid-1", Status: "active", VCPUs: 2, MemoryMB: 2048,
		DiskMB: 20, DeviceID: 9,
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc"}},
	}}, fp), fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.updatedVMs) != 1 || nb.updatedVMs[0].ID != 11 {
		t.Fatalf("want VM 11 patched, got %+v", nb.updatedVMs)
	}
	got := nb.updatedVMs[0].VM
	if got.Name != "vm-1" || got.VCPUs != 2 || got.MemoryMB != 2048 ||
		got.DiskMB != 20 || got.Status != "active" || got.DeviceID != 9 || got.Identity != vmID {
		t.Fatalf("the update must carry every mirrored field, got %+v", got)
	}
	if len(nb.updatedIfaces) != 1 || nb.updatedIfaces[0].ID != 21 ||
		nb.updatedIfaces[0].Iface.Name != "eth0" {
		t.Fatalf("want interface 21 patched with the desired name, got %+v", nb.updatedIfaces)
	}
}

// TestAssignAndClearUseTheAddressID pins the two one-address actions. Clear
// takes the ADDRESS id — an interface id cannot detach anything — and Diff only
// ever carries a litevirt-owned address here.
func TestAssignAndClearUseTheAddressID(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")

	if err := r.apply(context.Background(), []Action{
		{Kind: "nic", Op: "assign", Key: nicID, NetBoxID: 21, IPID: 41},
	}, indexDesired(nil, fp), fp); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(context.Background(), []Action{
		{Kind: "nic", Op: "clear", Key: nicID, NetBoxID: 21, IPID: 42},
	}, indexDesired(nil, fp), fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.ipAssignments) != 1 || nb.ipAssignments[0] != (ipAssignment{IPID: 41, IfaceID: 21}) {
		t.Fatalf("want address 41 assigned to interface 21, got %+v", nb.ipAssignments)
	}
	if len(nb.cleared) != 1 || nb.cleared[0] != 42 {
		t.Fatalf("want address 42 cleared, got %v", nb.cleared)
	}
}

// TestVMCreateSurvivesAnUnresolvableHostLink pins that the DCIM link is
// best-effort in BOTH directions: a lookup failure and a host that is simply
// not modelled must both leave a working mirror rather than failing the sweep.
func TestVMCreateSurvivesAnUnresolvableHostLink(t *testing.T) {
	nb := &stubVirt{deviceErr: errors.New("netbox: HTTP 500")}
	r := newTestReconciler(t, nb)

	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: netbox.Identity(fp, "uuid-1", "")}},
		indexDesired([]DesiredVM{{Name: "vm-1", UUID: "uuid-1", Host: "host-a"}}, fp),
		fp,
	); err != nil {
		t.Fatalf("an unresolvable host link must not fail the mirror: %v", err)
	}
	if len(nb.created) != 1 || nb.created[0].DeviceID != 0 {
		t.Fatalf("want the VM created with no device link, got %+v", nb.created)
	}
}

// TestVMUpdateWritesTheDiffsDeviceIDNotAReResolvedOne pins the update path
// against a perpetual-update loop.
//
// The diff compared DesiredVM.DeviceID. If the applier re-resolves the host
// instead, a host deliberately no longer modelled as a DCIM device gets its link
// RE-ADDED by the very update that was emitted to clear it — and the next sweep
// diffs it again, forever. Any transient disagreement between the two
// resolutions does the same.
func TestVMUpdateWritesTheDiffsDeviceIDNotAReResolvedOne(t *testing.T) {
	// The host WOULD resolve, which is the whole point: a re-resolving applier
	// finds 9 here, while the diff decided on 0.
	nb := &stubVirt{devices: map[string]int{"host-a": 9}}
	r := newTestReconciler(t, nb)
	vmKey := netbox.Identity(fp, "uuid-1", "")

	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "update", Key: vmKey, NetBoxID: 11}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1", Status: "active", Host: "host-a", DeviceID: 0,
		}}, fp), fp,
	); err != nil {
		t.Fatal(err)
	}
	if len(nb.updatedVMs) != 1 {
		t.Fatalf("want one VM patched, got %+v", nb.updatedVMs)
	}
	if got := nb.updatedVMs[0].VM.DeviceID; got != 0 {
		t.Fatalf("the update must carry the diff's device id 0, got %d", got)
	}
	if len(nb.deviceLookups) != 0 {
		t.Fatalf("the update path must not re-resolve the link, looked up %v", nb.deviceLookups)
	}
	// What NetBox actually receives: an explicit null. An omitted key is a no-op
	// on a PATCH, which leaves the stale link standing.
	body := vmWireBody(t, nb.updatedVMs[0].VM)
	if v, ok := body["device"]; !ok || v != nil {
		t.Fatalf("device must be sent as an explicit null, got %v (present=%v)", v, ok)
	}
}

// TestVMCreateStillResolvesTheDeviceLink pins the other side of that split. A
// first mirror has no prior link to preserve and desiredState may not have
// resolved one yet, so the CREATE path keeps the fallback lookup.
func TestVMCreateStillResolvesTheDeviceLink(t *testing.T) {
	nb := &stubVirt{devices: map[string]int{"host-a": 9}}
	r := newTestReconciler(t, nb)

	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: netbox.Identity(fp, "uuid-1", "")}},
		indexDesired([]DesiredVM{{Name: "vm-1", UUID: "uuid-1", Host: "host-a"}}, fp), fp,
	); err != nil {
		t.Fatal(err)
	}
	if len(nb.created) != 1 || nb.created[0].DeviceID != 9 {
		t.Fatalf("create must resolve host-a to device 9, got %+v", nb.created)
	}
}

// TestApplyAppliesEveryActionInABatch exercises the worker pool: a batch is
// applied concurrently, so every action must still land exactly once.
func TestApplyAppliesEveryActionInABatch(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)

	var desired []DesiredVM
	var actions []Action
	for _, u := range []string{"u1", "u2", "u3", "u4", "u5", "u6"} {
		desired = append(desired, DesiredVM{Name: "vm-" + u, UUID: u})
		actions = append(actions, Action{Kind: "vm", Op: "create", Key: netbox.Identity(fp, u, "")})
	}
	if err := r.apply(context.Background(), actions, indexDesired(desired, fp), fp); err != nil {
		t.Fatal(err)
	}
	if nb.createCalls != len(actions) {
		t.Fatalf("want %d VMs created, got %d", len(actions), nb.createCalls)
	}
	for _, d := range desired {
		if ref := mustGetRef(t, r, "vm", netbox.Identity(fp, d.UUID, "")); ref.NetBoxID == 0 {
			t.Fatalf("no mapping recorded for %s", d.UUID)
		}
	}
}

// TestApplyReportsAFailedActionWithoutSkippingTheRest pins that one failure
// does not silently abandon a batch's other actions, which are independent.
func TestApplyReportsAFailedActionWithoutSkippingTheRest(t *testing.T) {
	nb := &stubVirt{createErr: map[string]error{netbox.Identity(fp, "u1", ""): errors.New("boom")}}
	r := newTestReconciler(t, nb)

	err := r.apply(context.Background(), []Action{
		{Kind: "vm", Op: "create", Key: netbox.Identity(fp, "u1", "")},
		{Kind: "vm", Op: "create", Key: netbox.Identity(fp, "u2", "")},
	}, indexDesired([]DesiredVM{
		{Name: "vm-1", UUID: "u1"}, {Name: "vm-2", UUID: "u2"},
	}, fp), fp)
	if err == nil {
		t.Fatal("a failed action must be reported")
	}
	if ref, _ := getRef(r, "vm", netbox.Identity(fp, "u2", "")); ref == nil {
		t.Fatal("the other action in the batch must still have been applied")
	}
}

// --- helpers ---------------------------------------------------------------

// newTestReconciler builds a reconciler over a real in-memory corrosion DB, so
// every identity mapping goes through the production SQL rather than a map.
func newTestReconciler(t *testing.T, nb netboxWriter) *Reconciler {
	t.Helper()
	return &Reconciler{
		nb: nb, db: newMirrorDB(t), clusterID: 5, metrics: &countingMetrics{},
		// Supplied EXPLICITLY. An unwired lease reads as "not the leader" (the
		// fail-closed direction), so applyPhases would write nothing at all and
		// every ordering assertion would pass vacuously. The capability
		// predicate is fail-closed for the same reason and supplied for the
		// same one.
		holdsLease: func(context.Context) bool { return true },
		latched:    func(context.Context) bool { return true },
	}
}

// newMirrorDB is a schema-initialised corrosion handle scoped to one test.
func newMirrorDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

// vmWireBody returns the body the PRODUCTION client puts on the wire for the VM
// the applier handed it, captured off a real UpdateVM. Reconstructing the body
// here would assert on a copy of the rule instead of on the rule.
func vmWireBody(t *testing.T, vm netbox.VirtualMachine) map[string]any {
	t.Helper()
	var got map[string]any
	c := netboxClientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode PATCH body: %v", err)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	if err := c.UpdateVM(context.Background(), 11, vm); err != nil {
		t.Fatal(err)
	}
	return got
}

func getRef(r *Reconciler, kind, key string) (*corrosion.ObjectRef, error) {
	return corrosion.GetObjectRef(context.Background(), r.db, kind, key)
}

func mustGetRef(t *testing.T, r *Reconciler, kind, key string) corrosion.ObjectRef {
	t.Helper()
	ref, err := getRef(r, kind, key)
	if err != nil {
		t.Fatal(err)
	}
	if ref == nil {
		t.Fatalf("no %s mapping recorded for %s", kind, key)
	}
	return *ref
}

func dupesCounted(t *testing.T, r *Reconciler) int {
	t.Helper()
	m, ok := r.metrics.(*countingMetrics)
	if !ok {
		t.Fatalf("metrics sink is %T, want *countingMetrics", r.metrics)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dupes
}

// countingMetrics is the test sink. The production one is process-global
// Prometheus state, which cannot be asserted on per test.
//
// Objects are keyed "<netbox kind>/<op>" — the two label values joined — so a
// scenario asserting on the pair fails if either label is dropped, rather than
// silently summing two operations into one number.
type countingMetrics struct {
	mu       sync.Mutex
	dupes    int
	objects_ map[string]int
	sweeps_  map[string]int
	success  time.Time
}

func (m *countingMetrics) IncDuplicateObject() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dupes++
}

func (m *countingMetrics) IncMirrorObject(kind, op string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objects_ == nil {
		m.objects_ = map[string]int{}
	}
	m.objects_[kind+"/"+op]++
}

func (m *countingMetrics) IncMirrorSweep(result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sweeps_ == nil {
		m.sweeps_ = map[string]int{}
	}
	m.sweeps_[result]++
}

func (m *countingMetrics) SetMirrorLastSuccess(t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.success = t
}

// objects and sweeps return copies: apply runs a worker pool, so a caller
// ranging over the live map would race the sink.
func (m *countingMetrics) objects() map[string]int { return copyCounts(&m.mu, m.objects_) }
func (m *countingMetrics) sweeps() map[string]int  { return copyCounts(&m.mu, m.sweeps_) }

func (m *countingMetrics) lastSuccess() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.success
}

func copyCounts(mu *sync.Mutex, in map[string]int) map[string]int {
	mu.Lock()
	defer mu.Unlock()
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type updatedVM struct {
	ID int
	VM netbox.VirtualMachine
}

type updatedIface struct {
	ID    int
	Iface netbox.VMInterface
}

type ipAssignment struct {
	IPID    int
	IfaceID int
}

// stubVirt is an in-memory NetBox. It is mutex-guarded because apply runs a
// worker pool.
type stubVirt struct {
	mu sync.Mutex

	// byIdentity and interfacesByIdentity are what a search finds — the state a
	// create whose identity-map write was lost leaves behind.
	byIdentity           map[string][]int
	interfacesByIdentity map[string][]int
	devices              map[string]int
	deviceErr            error

	// dropMACOnCreate models a NetBox whose vminterface serializer does not know
	// mac_address: DRF ignores an unknown write field silently, so the object
	// comes back 201 with no MAC at all. upperCaseMACEcho models what a real
	// NetBox does — echo it UPPER-cased.
	dropMACOnCreate  bool
	upperCaseMACEcho bool

	createErr map[string]error
	deleteErr error

	// enforceNames turns on NetBox's one-VM-name-per-cluster rule for creates
	// and renames alike. See nameConflictLocked.
	enforceNames bool

	// The NetBox-side state a sweep reads back, served by the collection half
	// below. Empty by default, so every existing scenario is untouched.
	listVMs    []netbox.VirtualMachine
	listIfaces []netbox.VMInterface
	listIPs    []netbox.IPAddress

	// sweeps counts EnsureCluster calls — one per sweep, whether or not the
	// sweep goes on to write anything. See Sweeps.
	sweeps int

	createCalls       int
	created           []netbox.VirtualMachine
	updatedVMs        []updatedVM
	deleted           []int
	createdInterfaces []netbox.VMInterface
	updatedIfaces     []updatedIface
	deletedInterfaces []int
	ipAssignments     []ipAssignment
	cleared           []int
	deviceLookups     []string

	nextID int
}

// nextObjectID mints ids well above the fixtures' hand-picked ones, so a test
// asserting on a created object's id cannot accidentally match a fixture.
func (s *stubVirt) nextObjectID() int {
	s.nextID++
	return 100 + s.nextID
}

func (s *stubVirt) FindVMByIdentity(_ context.Context, identity string) ([]netbox.VirtualMachine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []netbox.VirtualMachine
	for _, id := range s.byIdentity[identity] {
		out = append(out, netbox.VirtualMachine{ID: id, Identity: identity})
	}
	return out, nil
}

func (s *stubVirt) CreateVM(_ context.Context, vm netbox.VirtualMachine) (netbox.VirtualMachine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.createErr[vm.Identity]; err != nil {
		return netbox.VirtualMachine{}, err
	}
	if err := s.nameConflictLocked(vm.Name, 0); err != nil {
		return netbox.VirtualMachine{}, err
	}
	s.createCalls++
	vm.ID = s.nextObjectID()
	s.created = append(s.created, vm)
	return vm, nil
}

func (s *stubVirt) UpdateVM(_ context.Context, id int, vm netbox.VirtualMachine) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nameConflictLocked(vm.Name, id); err != nil {
		return err
	}
	s.updatedVMs = append(s.updatedVMs, updatedVM{ID: id, VM: vm})
	return nil
}

// nameConflictLocked models NetBox's one-VM-name-per-cluster rule, which is a
// constraint on the NAME and therefore refuses a rename exactly as it refuses a
// create.
//
// Off unless enforceNames is set, so every existing scenario is untouched. `self`
// is the object being patched, which of course may keep its own name.
//
// IT READS THE EFFECTIVE NAME, not the one the collection read served. Two things
// free a name inside a pass — a delete and a RENAME — and a fake that only knew
// about the delete would refuse the second half of every scenario where one
// object moves out of the way of another. That is exactly what the cycle-breaker
// does, so without this a correct park would still fail the pass that made it.
//
// A 400 with the `name` field named, which is what NetBox actually answers —
// the annotation that explains a withheld replacement keys off the status and
// the field, not the sentence.
func (s *stubVirt) nameConflictLocked(name string, self int) error {
	if !s.enforceNames || name == "" {
		return nil
	}
	for _, v := range s.listVMs {
		if v.ID == self || s.deletedLocked(v.ID) {
			continue
		}
		if s.effectiveNameLocked(v) == name {
			return &netbox.APIError{
				Status: 400,
				Body:   `{"name":["A virtual machine with this name already exists in this cluster."]}`,
			}
		}
	}
	return nil
}

// effectiveNameLocked is the name an object holds NOW: the last patch's, or the
// one the collection read served if this pass has not patched it.
func (s *stubVirt) effectiveNameLocked(v netbox.VirtualMachine) string {
	name := v.Name
	for _, u := range s.updatedVMs {
		if u.ID == v.ID {
			name = u.VM.Name
		}
	}
	return name
}

func (s *stubVirt) deletedLocked(id int) bool {
	for _, d := range s.deleted {
		if d == id {
			return true
		}
	}
	return false
}

// updatedName is the name the LAST patch of this object wrote, or "" when the
// sweep never patched it. It reads under the lock, so a scenario driving
// concurrent passes can call it.
func (s *stubVirt) updatedName(id int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out string
	for _, u := range s.updatedVMs {
		if u.ID == id {
			out = u.VM.Name
		}
	}
	return out
}

func (s *stubVirt) DeleteVM(_ context.Context, id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, id)
	return nil
}

func (s *stubVirt) FindInterfaceByIdentity(_ context.Context, identity string) ([]netbox.VMInterface, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []netbox.VMInterface
	for _, id := range s.interfacesByIdentity[identity] {
		out = append(out, netbox.VMInterface{ID: id, Identity: identity})
	}
	return out, nil
}

func (s *stubVirt) CreateInterface(_ context.Context, i netbox.VMInterface) (netbox.VMInterface, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i.ID = s.nextObjectID()
	s.createdInterfaces = append(s.createdInterfaces, i)
	echoed := i
	switch {
	case s.dropMACOnCreate:
		echoed.MAC = ""
	case s.upperCaseMACEcho:
		echoed.MAC = strings.ToUpper(i.MAC)
	}
	return echoed, nil
}

func (s *stubVirt) UpdateInterface(_ context.Context, id int, i netbox.VMInterface) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updatedIfaces = append(s.updatedIfaces, updatedIface{ID: id, Iface: i})
	return nil
}

func (s *stubVirt) DeleteInterface(_ context.Context, id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deletedInterfaces = append(s.deletedInterfaces, id)
	return nil
}

func (s *stubVirt) AssignIPToInterface(_ context.Context, ipID, ifaceID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipAssignments = append(s.ipAssignments, ipAssignment{IPID: ipID, IfaceID: ifaceID})
	return nil
}

func (s *stubVirt) ClearIPAssignment(_ context.Context, ipID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleared = append(s.cleared, ipID)
	return nil
}

func (s *stubVirt) FindDeviceByName(_ context.Context, name string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceLookups = append(s.deviceLookups, name)
	if s.deviceErr != nil {
		return 0, s.deviceErr
	}
	return s.devices[name], nil
}

// The collection half of the interface. The applier never reads through it —
// Reconciler.actualState does — but it is one interface so a fake cannot
// satisfy the writes while a second, drifting path serves the reads.
//
// It answers from listVMs/listIfaces/listIPs, which are empty unless a scenario
// fills them. A sweep-level scenario has to be able to put objects on the NetBox
// side that litevirt does NOT hold — that is the only shape a delete is computed
// from, so without it every "did this sweep delete anything?" assertion would be
// vacuous.
func (s *stubVirt) ListVMsByCluster(context.Context, int) ([]netbox.VirtualMachine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]netbox.VirtualMachine(nil), s.listVMs...), nil
}

func (s *stubVirt) ListInterfacesByCluster(context.Context, int) ([]netbox.VMInterface, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]netbox.VMInterface(nil), s.listIfaces...), nil
}

func (s *stubVirt) ListOwnedIPsForInterfaces(context.Context, []int) ([]netbox.IPAddress, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]netbox.IPAddress(nil), s.listIPs...), nil
}

// The cluster half. Fixed ids: the applier is handed a resolved clusterID, so
// nothing here decides anything — Sync resolves it through these, and the fleet
// exercises that against a real NetBox surface.
func (s *stubVirt) EnsureClusterType(context.Context, string) (int, error) { return 1, nil }

func (s *stubVirt) EnsureCluster(context.Context, string, int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweeps++
	return 5, nil
}

// Sweeps is how many times a sweep got as far as resolving its cluster.
//
// Every sweep resolves the cluster before it reads either side of the diff, and
// nothing else does, so this counts SWEEPS — including the ones that go on to
// find no work and write nothing. A scenario asserting "no sweep ran" cannot use
// the write counters for that: a sweep over converged state issues no writes
// either, and the two would be indistinguishable.
func (s *stubVirt) Sweeps() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweeps
}
