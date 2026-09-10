package netboxsync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/netbox"
)

const fp = "abc123"

func vmIdent(uuid string) string  { return netbox.Identity(fp, uuid, "") }
func nicIdent(u, m string) string { return netbox.Identity(fp, u, m) }

// TestDiffSkipsAVMWhoseNameACoTenantHolds pins the pre-create name guard.
//
// NetBox allows one VM name per cluster and enforces it across identities, so a
// create for a name a co-tenant installation (or an operator, by hand) already
// holds is a 400 — and one 400 fails the whole sweep, every pass, for as long as
// both VMs exist. The action has to be withheld rather than issued and mourned.
func TestDiffSkipsAVMWhoseNameACoTenantHolds(t *testing.T) {
	actual := Actual{
		VMs:            map[string]netbox.VirtualMachine{},
		ForeignVMNames: map[string]bool{"vm-1": true},
	}
	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2,
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc"}},
	}}, actual, fp)
	if len(got) != 0 {
		t.Fatalf("got %+v, want no action for a VM whose name this cluster cannot claim", got)
	}
}

// TestDiffNeverReapsACollidedVMsOwnObjects is the dangerous half of that skip.
//
// A rename ONTO a taken name reaches the same guard while this cluster's own
// objects for that VM are already standing. Skipping the VM without first
// marking its identities as seen takes them out of the desired set, and the
// delete half then reaps them — turning a name collision into a deletion, which
// is worse than not mirroring at all.
func TestDiffNeverReapsACollidedVMsOwnObjects(t *testing.T) {
	const mac = "52:54:00:aa:bb:cc"
	actual := Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-old", Identity: vmIdent("u1")},
		},
		NICs: map[string]netbox.VMInterface{
			nicIdent("u1", mac): {ID: 21, VMID: 11, Name: "eth0", MAC: mac,
				Identity: nicIdent("u1", mac)},
		},
		// The VM was renamed onto a name a co-tenant holds.
		ForeignVMNames: map[string]bool{"vm-new": true},
	}
	got := Diff([]DesiredVM{{
		Name: "vm-new", UUID: "u1", VCPUs: 2,
		NICs: []DesiredNIC{{Name: "eth0", MAC: mac}},
	}}, actual, fp)

	for _, a := range got {
		if a.Op == "delete" {
			t.Fatalf("a name collision emitted %+v — this cluster's own objects must survive it", a)
		}
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want no action at all", got)
	}
}

func TestDiffCreatesMissingVM(t *testing.T) {
	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u1", VCPUs: 2}}, Actual{}, fp)
	if len(got) != 1 || got[0].Op != "create" || got[0].Key != vmIdent("u1") {
		t.Fatalf("got %+v", got)
	}
}

// TestDiffEmitsNothingWhenIdenticalUsingDecodedActual builds the actual state by
// DECODING a NetBox payload rather than constructing the struct by hand.
//
// Constructing it by hand hides the bug that matters: if vmJSON.toVM fails to
// populate a field vmDiffers compares, every VM looks changed on every sweep and
// write-on-change never fires. A hand-built fixture would pass regardless.
func TestDiffEmitsNothingWhenIdenticalUsingDecodedActual(t *testing.T) {
	actual := decodeActualFixture(t, `{"results":[{"id":11,"name":"vm-1","vcpus":2,`+
		`"memory":2048,"disk":20,"status":{"value":"active"},"cluster":{"id":5},`+
		`"device":{"id":9},"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048,
		DiskMB: 20, Status: "active", DeviceID: 9,
	}}, actual, fp)

	if len(got) != 0 {
		t.Fatalf("identical state must emit no actions, got %+v", got)
	}
}

func TestDiffUpdatesOnDeviceChange(t *testing.T) {
	// A migration moves the host link but not the address. Without DeviceID in
	// vmDiffers, migration never converges in NetBox.
	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u1", DeviceID: 10, Status: "active"}},
		Actual{VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-1", DeviceID: 9, Status: "active"},
		}}, fp)
	if len(got) != 1 || got[0].Op != "update" {
		t.Fatalf("got %+v", got)
	}
}

func TestDiffCreatesAndDeletesNICs(t *testing.T) {
	// The actual VM MATCHES the desired one in every mirrored field, so the whole
	// action set is attributable to the NICs. With a mismatched actual VM the
	// count below would still pass while an unnoticed vm/update rode along, and
	// the test would no longer pin only what its name claims.
	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:01"}},
	}}, Actual{
		VMs:  map[string]netbox.VirtualMachine{vmIdent("u1"): {ID: 11, Name: "vm-1", Status: "active"}},
		NICs: map[string]netbox.VMInterface{nicIdent("u1", "52:54:00:aa:bb:02"): {ID: 21}},
	}, fp)

	var creates, deletes int
	for _, a := range got {
		if a.Kind != "nic" {
			continue
		}
		switch a.Op {
		case "create":
			creates++
		case "delete":
			deletes++
		}
	}
	// Hotplug attach and detach cannot converge without both.
	if creates != 1 || deletes != 1 {
		t.Fatalf("want one NIC create and one delete, got %+v", got)
	}
	if len(got) != 2 {
		t.Fatalf("the matching VM must contribute no action of its own, got %+v", got)
	}
}

func TestDiffUpdatesNICOnRenameUsingDecodedActual(t *testing.T) {
	// An interface identity is derived from the MAC, so a NIC rename keeps the
	// SAME object — exactly the case that must be updated rather than recreated.
	// NIC names are VM-derived, so a VM rename routinely renames every interface
	// under it while their identities stay put. Without the nic/update branch
	// NetBox keeps the old name forever and nothing else ever carries the new one
	// across.
	//
	// Actual state is DECODED from the real interface payload BuildActual
	// consumes: a hand-built netbox.VMInterface would pass even if ifaceJSON.toIface
	// stopped populating Name, which is the same field nicDiffers compares.
	const mac = "52:54:00:aa:bb:01"
	actual := decodeActualWithIPs(t,
		`{"results":[{"id":11,"name":"new-name","vcpus":2,"memory":2048,"disk":20,`+
			`"status":{"value":"active"},"cluster":{"id":5},`+
			`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`,
		// Stored under the OLD VM-derived name, same MAC and so the same identity.
		`{"results":[{"id":21,"name":"old-name-eth0","mac_address":"52:54:00:AA:BB:01",`+
			`"virtual_machine":{"id":11},`+
			`"custom_fields":{"litevirt_identity":"`+nicIdent("u1", mac)+`"}}],"next":""}`,
		`{"results":[],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "new-name", UUID: "u1", VCPUs: 2, MemoryMB: 2048, DiskMB: 20, Status: "active",
		NICs: []DesiredNIC{{Name: "new-name-eth0", MAC: mac}},
	}}, actual, fp)

	if len(got) != 1 {
		t.Fatalf("a NIC rename must emit exactly one action, got %+v", got)
	}
	a := got[0]
	if a.Kind != "nic" || a.Op != "update" {
		t.Fatalf("want a nic/update, got %+v", a)
	}
	if a.Key != nicIdent("u1", mac) {
		t.Fatalf("nic/update must carry the MAC-derived identity, got %+v", a)
	}
	if a.NetBoxID != 21 || a.ParentNetBoxID != 11 {
		t.Fatalf("nic/update must target iface 21 under VM 11, got %+v", a)
	}
	// A rename must not FORK the interface. Keying on the MAC-derived identity is
	// the whole reason it cannot: a name-keyed diff would miss the existing object,
	// create a second one, and delete the first as unseen on the same pass.
	for _, x := range got {
		if x.Kind == "nic" && (x.Op == "create" || x.Op == "delete") {
			t.Fatalf("a rename must not create or delete an interface: %+v", x)
		}
	}
}

func TestDiffClearsEveryOwnedAddressWhenNoneDesired(t *testing.T) {
	// The NIC's address did not come from a bound network (NetBoxIPID 0), but the
	// interface still holds litevirt-owned addresses from an earlier binding.
	// EVERY one of them must be released and nothing assigned: skipping the clear
	// loop when nothing is desired would strand those addresses in NetBox forever,
	// and the IPAM view would keep showing a VM holding an address it no longer has.
	const mac = "52:54:00:aa:bb:01"
	actual := decodeActualWithIPs(t,
		`{"results":[{"id":11,"name":"vm-1","vcpus":2,"memory":2048,"disk":20,`+
			`"status":{"value":"active"},"cluster":{"id":5},`+
			`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`,
		`{"results":[{"id":21,"name":"eth0","mac_address":"52:54:00:aa:bb:01",`+
			`"virtual_machine":{"id":11},`+
			`"custom_fields":{"litevirt_identity":"`+nicIdent("u1", mac)+`"}}],"next":""}`,
		// Two litevirt-owned addresses on the ONE interface, returned newest first
		// so the sort below is doing real work.
		`{"results":[`+
			`{"id":43,"address":"10.0.5.101/24","assigned_object_id":21,`+
			`"custom_fields":{"litevirt_identity":"`+nicIdent("u1", mac)+`"}},`+
			`{"id":41,"address":"10.0.5.100/24","assigned_object_id":21,`+
			`"custom_fields":{"litevirt_identity":"`+nicIdent("u1", mac)+`"}}`+
			`],"next":""}`)

	if len(actual.OwnedIPsByIface[21]) != 2 {
		t.Fatalf("fixture must present two owned addresses, got %+v", actual.OwnedIPsByIface[21])
	}

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048, DiskMB: 20, Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: mac, NetBoxIPID: 0}},
	}}, actual, fp)

	var clears []Action
	for _, a := range got {
		if a.Op == "assign" {
			t.Fatalf("nothing is desired, so nothing may be assigned: %+v", a)
		}
		if a.Op == "clear" {
			clears = append(clears, a)
		}
	}
	if len(clears) != 2 || len(got) != 2 {
		t.Fatalf("want exactly two clears and nothing else, got %+v", got)
	}
	// Sorted by address id, so identical state yields an identical list whatever
	// order the API returned.
	if clears[0].IPID != 41 || clears[1].IPID != 43 {
		t.Fatalf("clears must be sorted by address id, got %+v", clears)
	}
	for _, a := range clears {
		if a.Kind != "nic" || a.Key != nicIdent("u1", mac) || a.NetBoxID != 21 || a.ParentNetBoxID != 11 {
			t.Fatalf("clear must target iface 21 under VM 11 by identity, got %+v", a)
		}
	}
}

func TestDiffUpdatesOnRenameUsingDecodedActual(t *testing.T) {
	// Identity-keying keeps the object across a rename, so nothing creates a new
	// one — but without Name in vmDiffers, NetBox keeps the OLD name forever.
	actual := decodeActualFixture(t, `{"results":[{"id":11,"name":"old-name","vcpus":2,`+
		`"memory":2048,"disk":20,"status":{"value":"active"},"cluster":{"id":5},`+
		`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "new-name", UUID: "u1", VCPUs: 2, MemoryMB: 2048, DiskMB: 20, Status: "active",
	}}, actual, fp)

	if len(got) != 1 || got[0].Op != "update" || got[0].NetBoxID != 11 {
		t.Fatalf("a rename must emit one update carrying the object id, got %+v", got)
	}
}

func TestDiffClearsAStaleDeviceLinkUsingDecodedActual(t *testing.T) {
	actual := decodeActualFixture(t, `{"results":[{"id":11,"name":"vm-1","vcpus":2,`+
		`"memory":2048,"disk":20,"status":{"value":"active"},"cluster":{"id":5},`+
		`"device":{"id":9},"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`)

	// The host is no longer modelled as a DCIM device.
	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048,
		DiskMB: 20, Status: "active", DeviceID: 0,
	}}, actual, fp)

	if len(got) != 1 || got[0].Op != "update" {
		t.Fatalf("want one update to clear the device link, got %+v", got)
	}
	// The applier must send an explicit null; a body that omits the key leaves
	// device 9 in place and this same update repeats every sweep forever.
	body := vmBodyForTest(t, DesiredVM{Name: "vm-1", DeviceID: 0})
	if v, ok := body["device"]; !ok || v != nil {
		t.Fatalf("device must be sent as an explicit null, got %v (present=%v)", v, ok)
	}
}

// ── the superseded incarnation of a reused name ─────────────────────────────

// supersededActual is one of THIS cluster's objects holding `name` under `uuid`,
// which is the shape every scenario below varies one property of.
func supersededActual(name, uuid string) Actual {
	return Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent(uuid): {ID: 11, Name: name, Identity: vmIdent(uuid)},
		},
		NICs:            map[string]netbox.VMInterface{},
		ForeignVMNames:  map[string]bool{},
		OwnedIPsByIface: map[int][]netbox.IPAddress{},
	}
}

func replaceActions(actions []Action) []Action {
	var out []Action
	for _, a := range actions {
		if a.Op == opReplace {
			out = append(out, a)
		}
	}
	return out
}

// TestDiffReplacesASupersededIncarnationOfAReusedName is the positive case: our
// object, holding the name, under a UUID the cluster no longer has.
func TestDiffReplacesASupersededIncarnationOfAReusedName(t *testing.T) {
	// "u-old" was deleted; "u-new" is the same name recreated.
	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u-new", VCPUs: 2}},
		supersededActual("vm-1", "u-old"), fp)

	rep := replaceActions(got)
	if len(rep) != 1 {
		t.Fatalf("got %+v, want exactly one vm/replace freeing the reused name", got)
	}
	if rep[0].Key != vmIdent("u-old") || rep[0].NetBoxID != 11 {
		t.Errorf("the replace must name the superseded object, got %+v", rep[0])
	}
	if rep[0].FreesName != "vm-1" {
		t.Errorf("FreesName = %q, want the name being freed", rep[0].FreesName)
	}
	// STRICTLY EARLIER THAN THE CREATE, stated as an inequality on the phases:
	// a create cannot use a name another object still holds.
	if Phase(rep[0]) >= Phase(Action{Kind: "vm", Op: "create"}) {
		t.Errorf("the replace runs in phase %d and the create in phase %d; freeing the name "+
			"must happen strictly first", Phase(rep[0]), Phase(Action{Kind: "vm", Op: "create"}))
	}
	// And exactly ONE removal is emitted for that object: the delete half must
	// not also claim it.
	for _, a := range got {
		if a.Op == "delete" && a.Key == vmIdent("u-old") {
			t.Errorf("the superseded object has two owners — a replace AND a delete: %+v", got)
		}
	}
}

// TestDiffNeverReplacesAnIdentityInTheDesiredSet is the first refusal, and the
// one that matters most: an identity in the desired set is a LIVE VM.
//
// Here two desired VMs briefly disagree about a name — one renamed onto a name
// the other still holds — so the occupant IS in the desired set. Freeing a name
// may never remove a mirrored VM: the collision is lived with, and the sweep
// converges once the rename lands.
func TestDiffNeverReplacesAnIdentityInTheDesiredSet(t *testing.T) {
	got := Diff([]DesiredVM{
		{Name: "vm-1", UUID: "u-new", VCPUs: 2},
		// Still desired, and still named vm-1 in NetBox.
		{Name: "vm-2", UUID: "u-live", VCPUs: 2},
	}, supersededActual("vm-1", "u-live"), fp)

	if rep := replaceActions(got); len(rep) != 0 {
		t.Fatalf("a LIVE VM's object was scheduled for replacement to free a name: %+v", rep)
	}
}

// TestDiffNeverReplacesAForeignIdentity is the second refusal. An object under
// another installation's fingerprint is untouchable at any cost — the name
// collision it causes is reported and lived with, never resolved by deleting
// somebody else's inventory.
//
// The object is placed in actual.VMs deliberately, which is a state BuildActual
// does not produce (it files a foreign object's name under ForeignVMNames). That
// is the point: this pins the guard in Diff rather than relying on the
// collection filter upstream, so a mis-scoped read cannot become a deletion.
func TestDiffNeverReplacesAForeignIdentity(t *testing.T) {
	actual := supersededActual("vm-1", "u-old")
	foreign := netbox.Identity("another-installation", "u-old", "")
	actual.VMs = map[string]netbox.VirtualMachine{
		foreign: {ID: 11, Name: "vm-1", Identity: foreign},
	}

	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u-new", VCPUs: 2}}, actual, fp)
	if rep := replaceActions(got); len(rep) != 0 {
		t.Fatalf("an object under another installation's fingerprint was scheduled for "+
			"replacement: %+v", rep)
	}
}

// TestDiffDoesNotReplaceWhenTheNameIsFree is the negative control: without it a
// Diff that emitted a replace unconditionally would satisfy the positive case.
func TestDiffDoesNotReplaceWhenTheNameIsFree(t *testing.T) {
	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u-new", VCPUs: 2}},
		supersededActual("vm-other", "u-old"), fp)
	if rep := replaceActions(got); len(rep) != 0 {
		t.Fatalf("nothing holds the name vm-1, so no replacement is warranted: %+v", rep)
	}
}

// ── the same proof ahead of a name-changing UPDATE ──────────────────────────
//
// NetBox's one-VM-name-per-cluster rule constrains the NAME, so a PATCH that
// moves an object onto a taken name is the same 400 a create gets. The scenario
// is ordinary: rename a VM away, delete it, and rename a second VM into the name
// it vacated, all inside one sweep interval. The survivor then needs an UPDATE,
// which the create-only version of the proof never covered — three consecutive
// sweeps returned 400 before reaching the deletion that would clear it.
//
// renameCollisionActual is the state such a pass reads: our SUPERSEDED object
// still holding the name (its rename was never mirrored, and its UUID is gone
// from the desired set), and the SURVIVOR still under its old name.
func renameCollisionActual(name, supersededUUID, survivorUUID string) Actual {
	return Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent(supersededUUID): {ID: 11, Name: name, Identity: vmIdent(supersededUUID)},
			vmIdent(survivorUUID): {
				ID: 12, Name: "survivor", Identity: vmIdent(survivorUUID), VCPUs: 2,
			},
		},
		NICs:            map[string]netbox.VMInterface{},
		ForeignVMNames:  map[string]bool{},
		OwnedIPsByIface: map[int][]netbox.IPAddress{},
	}
}

// TestDiffReplacesASupersededIncarnationHoldingANameARenameNeeds is the positive
// case for the update half.
func TestDiffReplacesASupersededIncarnationHoldingANameARenameNeeds(t *testing.T) {
	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u-live", VCPUs: 2}},
		renameCollisionActual("vm-1", "u-old", "u-live"), fp)

	rep := replaceActions(got)
	if len(rep) != 1 {
		t.Fatalf("got %+v, want exactly one vm/replace freeing the renamed-into name", got)
	}
	if rep[0].Key != vmIdent("u-old") || rep[0].NetBoxID != 11 {
		t.Errorf("the replace must name the superseded object, got %+v", rep[0])
	}
	if rep[0].FreesName != "vm-1" {
		t.Errorf("FreesName = %q, want the name being freed", rep[0].FreesName)
	}
	// The survivor needs an UPDATE, not a create — that is what makes this a
	// different path from the reused-name create.
	var upsert Action
	for _, a := range got {
		if a.Kind == "vm" && a.Op == "update" {
			upsert = a
		}
	}
	if upsert.Key != vmIdent("u-live") || upsert.NetBoxID != 12 {
		t.Fatalf("want an update moving the survivor onto the freed name, got %+v", got)
	}
	// STRICTLY EARLIER, as an inequality on the phases: a rename cannot use a
	// name another object still holds any more than a create can.
	if Phase(rep[0]) >= Phase(upsert) {
		t.Errorf("the replace runs in phase %d and the update in phase %d; freeing the name "+
			"must happen strictly first", Phase(rep[0]), Phase(upsert))
	}
	for _, a := range got {
		if a.Op == "delete" && a.Key == vmIdent("u-old") {
			t.Errorf("the superseded object has two owners — a replace AND a delete: %+v", got)
		}
	}
}

// TestDiffNeverReplacesADesiredIdentityToFreeANameForARename is the first
// withholding gate on the new path: two VMs swapping names.
//
// The occupant of the name the first VM wants is the SECOND desired VM, which is
// live. The collision is lived with — the sweep converges once one of the two
// renames lands — and no mirrored VM is destroyed to mirror another.
func TestDiffNeverReplacesADesiredIdentityToFreeANameForARename(t *testing.T) {
	actual := renameCollisionActual("vm-1", "u-other", "u-live")
	got := Diff([]DesiredVM{
		{Name: "vm-1", UUID: "u-live", VCPUs: 2},
		// Still desired, and still the object named vm-1 in NetBox.
		{Name: "vm-2", UUID: "u-other", VCPUs: 2},
	}, actual, fp)

	if rep := replaceActions(got); len(rep) != 0 {
		t.Fatalf("a LIVE VM's object was scheduled for replacement to free a name for a "+
			"rename: %+v", rep)
	}
}

// TestDiffNeverReplacesAForeignIdentityToFreeANameForARename is the second gate.
// The object is planted in actual.VMs, a state BuildActual does not produce, so
// this pins the guard in Diff rather than the collection filter above it.
func TestDiffNeverReplacesAForeignIdentityToFreeANameForARename(t *testing.T) {
	actual := renameCollisionActual("vm-1", "u-old", "u-live")
	foreign := netbox.Identity("another-installation", "u-old", "")
	delete(actual.VMs, vmIdent("u-old"))
	actual.VMs[foreign] = netbox.VirtualMachine{ID: 11, Name: "vm-1", Identity: foreign}

	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u-live", VCPUs: 2}}, actual, fp)
	if rep := replaceActions(got); len(rep) != 0 {
		t.Fatalf("an object under another installation's fingerprint was scheduled for "+
			"replacement to free a name for a rename: %+v", rep)
	}
}

// TestDiffConsidersNoReplacementForAnUpdateThatKeepsItsName is the negative
// control for the gating condition. An update that only moves a CPU count
// cannot collide with anything, so an unconditional proof there would be a
// removal considered over an operation that can never need one.
func TestDiffConsidersNoReplacementForAnUpdateThatKeepsItsName(t *testing.T) {
	actual := Actual{
		VMs: map[string]netbox.VirtualMachine{
			// Same NAME as the desired VM below, different CPU count.
			vmIdent("u-live"): {ID: 12, Name: "vm-1", Identity: vmIdent("u-live"), VCPUs: 1},
			// And a superseded object of ours sitting under a DIFFERENT name,
			// so a proof run over the wrong name would find something.
			vmIdent("u-old"): {ID: 11, Name: "vm-old", Identity: vmIdent("u-old")},
		},
		NICs:            map[string]netbox.VMInterface{},
		ForeignVMNames:  map[string]bool{},
		OwnedIPsByIface: map[int][]netbox.IPAddress{},
	}
	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u-live", VCPUs: 4}}, actual, fp)
	if rep := replaceActions(got); len(rep) != 0 {
		t.Fatalf("an update that keeps its name needs no name freed: %+v", rep)
	}
}

// TestDiffLetsAReplaceOwnTheInterfacesItCascades pins the other half of "one
// removal, one owner".
//
// A vm/replace runs in the FIRST phase and DeleteVM cascades every vminterface
// under it, so a separate nic/delete for one of those children would be asking
// NetBox to remove an object that is already gone. That is the INVERSE of an
// ordinary VM delete, where the parent goes last and detaching the children
// first is the documented ordering.
//
// It is not merely redundant. A nic delete carries its own, weaker evidence
// question — keyed on the owning VM's NetBox NAME — and a replaced object is
// exactly where that name can be stale (rename-then-delete). The withheld
// delete that produces escalates to withholding every destructive action in the
// pass, the proven replace included, which puts the mirror back in the permanent
// collision stall the replace exists to end.
func TestDiffLetsAReplaceOwnTheInterfacesItCascades(t *testing.T) {
	actual := renameCollisionActual("vm-1", "u-old", "u-live")
	actual.NICs = map[string]netbox.VMInterface{
		// The superseded object's interface: not in the desired set, parented on
		// the object the replace removes.
		nicIdent("u-old", "52:54:00:aa:bb:cc"): {
			ID: 21, VMID: 11, Name: "eth0", MAC: "52:54:00:AA:BB:CC",
			Identity: nicIdent("u-old", "52:54:00:aa:bb:cc"),
		},
		// An unrelated orphan, parented on an object nothing is replacing: its
		// delete must still be emitted, or this test would pass with the nic
		// delete half removed altogether.
		nicIdent("u-gone", "52:54:00:dd:ee:ff"): {
			ID: 22, VMID: 99, Name: "eth0", MAC: "52:54:00:DD:EE:FF",
			Identity: nicIdent("u-gone", "52:54:00:dd:ee:ff"),
		},
	}

	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u-live", VCPUs: 2}}, actual, fp)

	var nicDeletes []int
	for _, a := range got {
		if a.Kind == "nic" && a.Op == "delete" {
			nicDeletes = append(nicDeletes, a.NetBoxID)
		}
	}
	sort.Ints(nicDeletes)
	if want := []int{22}; !reflect.DeepEqual(nicDeletes, want) {
		t.Fatalf("nic deletes = %v, want %v — the replace cascades interface 21 away, and "+
			"asking for it separately is a second owner for one removal", nicDeletes, want)
	}
}

// ── the rename cycle ────────────────────────────────────────────────────────

// nameSwapActual is two of our own objects holding each other's desired name.
func nameSwapActual() Actual {
	return Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent("u-a"): {ID: 11, Name: "vm-1", Identity: vmIdent("u-a"), VCPUs: 2},
			vmIdent("u-b"): {ID: 12, Name: "vm-2", Identity: vmIdent("u-b"), VCPUs: 2},
		},
		NICs:            map[string]netbox.VMInterface{},
		ForeignVMNames:  map[string]bool{},
		OwnedIPsByIface: map[int][]netbox.IPAddress{},
	}
}

// swappedDesired is the same two VMs after each has taken the other's name.
func swappedDesired() []DesiredVM {
	return []DesiredVM{
		{Name: "vm-2", UUID: "u-a", VCPUs: 2},
		{Name: "vm-1", UUID: "u-b", VCPUs: 2},
	}
}

func parkActions(actions []Action) []Action {
	var out []Action
	for _, a := range actions {
		if a.Op == opPark {
			out = append(out, a)
		}
	}
	return out
}

// TestDiffBreaksARenameCycleWithOneParkAndNoRemoval.
//
// A name swap is a permutation, so it has no safe starting point: each object's
// occupant is the other, both identities are in the desired set, and the
// replacement refuses both — a live VM may never be removed to free a name. What
// the diff does instead is move ONE member onto a temporary name it owns, which
// leaves the other member's rename unblocked.
func TestDiffBreaksARenameCycleWithOneParkAndNoRemoval(t *testing.T) {
	got := Diff(swappedDesired(), nameSwapActual(), fp)

	parks := parkActions(got)
	if len(parks) != 1 {
		t.Fatalf("got %+v, want exactly one vm/park: a cycle needs one name outside it, and "+
			"parking both members frees nothing", got)
	}
	// The LOWEST identity, so a condition lasting several sweeps parks the same
	// object rather than a different one each pass.
	if parks[0].Key != vmIdent("u-a") || parks[0].NetBoxID != 11 {
		t.Errorf("the park must name the lowest identity in the cycle, got %+v", parks[0])
	}
	if parks[0].FreesName != "vm-1" {
		t.Errorf("FreesName = %q, want the name the park vacates", parks[0].FreesName)
	}
	// NOTHING IS REMOVED, and nothing is replaced: both identities are live.
	for _, a := range got {
		if a.Op == "delete" || a.Op == opReplace {
			t.Fatalf("a rename cycle produced %+v — a collision between two live VMs may never "+
				"be resolved by removing either of them", a)
		}
	}
	// The OTHER member's rename goes this pass, onto the name the park frees.
	var updates []string
	for _, a := range got {
		if a.Kind == "vm" && a.Op == "update" {
			updates = append(updates, a.Key)
		}
	}
	if !reflect.DeepEqual(updates, []string{vmIdent("u-b")}) {
		t.Fatalf("vm updates = %v, want only the member the park unblocked: the parked object's "+
			"own name is still held, and writing it would be the 400 all over again", updates)
	}
}

// TestDiffDoesNotParkWhenTheTemporaryNameIsTaken is the fail-closed half.
//
// NetBox's rule is per name whoever holds it, so a park onto a taken name is the
// identical refusal it exists to avoid. Refusing to plan it leaves the cycle
// exactly as it was — which the sweep reports — rather than trading a stall for
// a failed pass.
func TestDiffDoesNotParkWhenTheTemporaryNameIsTaken(t *testing.T) {
	actual := nameSwapActual()
	// A co-tenant's object already holds the name the park would use for the
	// lowest identity in the cycle.
	actual.ForeignVMNames[parkedName(vmIdent("u-a"))] = true

	got := Diff(swappedDesired(), actual, fp)

	if parks := parkActions(got); len(parks) != 0 {
		t.Fatalf("planned %+v onto a name this NetBox cluster already holds", parks)
	}
	for _, a := range got {
		if a.Kind == "vm" && (a.Op == "update" || a.Op == "create") {
			t.Fatalf("emitted %+v into an unbroken cycle; every such write is a 400 that fails "+
				"the whole pass", a)
		}
	}
}

// TestDiffKeepsACycledVMsObjectsInTheDesiredSet is the property whose absence
// would turn a name collision into a deletion.
//
// A VM whose upsert is deferred — parked or blocked — emits no NIC actions this
// pass, so if it were also left out of the seen sets the delete half would reap
// the objects of a VM that is very much alive.
func TestDiffKeepsACycledVMsObjectsInTheDesiredSet(t *testing.T) {
	actual := nameSwapActual()
	actual.NICs = map[string]netbox.VMInterface{
		nicIdent("u-a", "52:54:00:aa:00:01"): {
			ID: 21, VMID: 11, Name: "eth0", MAC: "52:54:00:AA:00:01",
			Identity: nicIdent("u-a", "52:54:00:aa:00:01"),
		},
		nicIdent("u-b", "52:54:00:aa:00:02"): {
			ID: 22, VMID: 12, Name: "eth0", MAC: "52:54:00:AA:00:02",
			Identity: nicIdent("u-b", "52:54:00:aa:00:02"),
		},
	}
	desired := swappedDesired()
	desired[0].NICs = []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:00:01"}}
	desired[1].NICs = []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:00:02"}}

	got := Diff(desired, actual, fp)

	for _, a := range got {
		if a.Op == "delete" {
			t.Fatalf("a deferred rename produced %+v: a VM waiting for its name is still in the "+
				"desired set, objects and interfaces both", a)
		}
	}
}

// TestDiffDefersARenameChainWithoutFailingThePass.
//
// A CHAIN is not a cycle and needs no park: its head is unblocked, so it drains
// one link per sweep. What it must not do is emit the blocked link's write, which
// is a 400 that fails the whole pass — including work the pass had already done —
// over a wait of one interval.
func TestDiffDefersARenameChainWithoutFailingThePass(t *testing.T) {
	actual := nameSwapActual()
	// u-b wants a free name, so only u-a is waiting: a chain, not a cycle.
	desired := []DesiredVM{
		{Name: "vm-2", UUID: "u-a", VCPUs: 2},
		{Name: "vm-3", UUID: "u-b", VCPUs: 2},
	}

	got := Diff(desired, actual, fp)

	if parks := parkActions(got); len(parks) != 0 {
		t.Fatalf("a chain needs no name outside it, got %+v", parks)
	}
	var updates []string
	for _, a := range got {
		if a.Kind == "vm" && a.Op == "update" {
			updates = append(updates, a.Key)
		}
	}
	if !reflect.DeepEqual(updates, []string{vmIdent("u-b")}) {
		t.Fatalf("vm updates = %v, want only the chain's head", updates)
	}
}

// TestUnconvergedRenamesNamesEveryVMStillWaiting is the reporting predicate.
//
// A parked member has NOT converged — its object sits under a temporary name —
// and neither has a blocked one. Both must be reported, or a pass that made
// progress would stamp the staleness gauge an operator alerts on.
func TestUnconvergedRenamesNamesEveryVMStillWaiting(t *testing.T) {
	desired, actual := swappedDesired(), nameSwapActual()
	actions := Diff(desired, actual, fp)

	got := unconvergedRenames(desired, actual, actions, fp)
	if !reflect.DeepEqual(got, []string{"vm-2"}) {
		t.Fatalf("unconverged renames = %v, want the parked member's desired name: the other "+
			"member's rename landed this pass", got)
	}
	// And a pass with nothing outstanding reports nothing, or the gauge would
	// never be stamped again.
	settled := []DesiredVM{{Name: "vm-1", UUID: "u-a", VCPUs: 2}}
	settledActual := Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent("u-a"): {ID: 11, Name: "vm-1", Identity: vmIdent("u-a"), VCPUs: 2},
		},
		NICs: map[string]netbox.VMInterface{}, ForeignVMNames: map[string]bool{},
		OwnedIPsByIface: map[int][]netbox.IPAddress{},
	}
	if got := unconvergedRenames(settled, settledActual, nil, fp); len(got) != 0 {
		t.Fatalf("a converged pass reported %v as waiting", got)
	}
}

// TestUnconvergedRenamesReportsADeferredCreateToo.
//
// A blocked CREATE has no NetBox object at all, so a predicate that compared the
// desired name against an existing object's would skip it entirely — and the pass
// would stamp the success gauge over a VM it wrote nothing for. The producible
// shape: a live VM is renaming away from a name a brand-new VM has taken.
func TestUnconvergedRenamesReportsADeferredCreateToo(t *testing.T) {
	actual := Actual{
		// Only the incumbent is mirrored; it still holds vm-1 and is moving off it.
		VMs: map[string]netbox.VirtualMachine{
			vmIdent("u-a"): {ID: 11, Name: "vm-1", Identity: vmIdent("u-a"), VCPUs: 2},
		},
		NICs: map[string]netbox.VMInterface{}, ForeignVMNames: map[string]bool{},
		OwnedIPsByIface: map[int][]netbox.IPAddress{},
	}
	desired := []DesiredVM{
		{Name: "vm-9", UUID: "u-a", VCPUs: 2},   // renaming away, unblocked
		{Name: "vm-1", UUID: "u-new", VCPUs: 2}, // a create onto the name it vacates
	}

	actions := Diff(desired, actual, fp)

	for _, a := range actions {
		if a.Kind == "vm" && a.Op == "create" {
			t.Fatalf("emitted %+v while a live VM still holds the name; that is the 400 all "+
				"over again", a)
		}
	}
	if got := unconvergedRenames(desired, actual, actions, fp); !reflect.DeepEqual(got, []string{"vm-1"}) {
		t.Fatalf("unconverged = %v, want the deferred CREATE's name: a VM with no NetBox object "+
			"yet is exactly the one a name-comparison would miss", got)
	}
}

func TestPhasesOrderParentsBeforeChildren(t *testing.T) {
	actions := []Action{
		{Kind: "vm", Op: "delete", Key: "vm-gone"},
		{Kind: "nic", Op: "delete", Key: "nic-gone"},
		{Kind: "nic", Op: "create", Key: "nic-new"},
		{Kind: "nic", Op: "clear", Key: "nic-stale", IPID: 41},
		{Kind: "vm", Op: "create", Key: "vm-new"},
		{Kind: "vm", Op: opReplace, Key: "vm-superseded", NetBoxID: 11},
	}
	got := Phases(actions)

	for _, tc := range []struct {
		phase int
		key   string
		what  string
	}{
		{PhaseVMSupersede, "vm-superseded", "freeing a reused name"},
		{PhaseVMUpsert, "vm-new", "VM creates/updates"},
		{PhaseIPClear, "nic-stale", "IP clears"},
		{PhaseNICUpsert, "nic-new", "NIC create/update/assign"},
		{PhaseNICDelete, "nic-gone", "NIC deletes"},
		{PhaseVMDelete, "vm-gone", "VM deletes"},
	} {
		if len(got[tc.phase]) != 1 || got[tc.phase][0].Key != tc.key {
			t.Errorf("phase %d must be %s, got %+v", tc.phase, tc.what, got[tc.phase])
		}
	}
}

// TestPhasesPutTheRenameCycleParkAheadOfTheUpserts.
//
// A park frees a name a rename in the upsert phase needs, so it has to run in
// the FIRST phase for the identical reason the replace does — the actions inside
// one phase run in parallel, so anything but a phase boundary is a race. Falling
// through to the default bucket would put it LAST, after the very write it exists
// to unblock.
func TestPhasesPutTheRenameCycleParkAheadOfTheUpserts(t *testing.T) {
	got := Phases([]Action{
		{Kind: "vm", Op: "update", Key: "vm-renaming", NetBoxID: 12},
		{Kind: "vm", Op: opPark, Key: "vm-parked", NetBoxID: 11},
	})

	if len(got[PhaseVMSupersede]) != 1 || got[PhaseVMSupersede][0].Op != opPark {
		t.Fatalf("the first phase must hold the park, got %+v", got[PhaseVMSupersede])
	}
	if len(got[PhaseVMDelete]) != 0 {
		t.Fatalf("the park fell through to the last phase, behind the upsert it unblocks: %+v",
			got[PhaseVMDelete])
	}
}

func TestClearIsStrictlyBeforeEveryAssignment(t *testing.T) {
	// Ordering stated as an INEQUALITY on phase numbers, not as an observation
	// about a particular list. An assertion that merely checked which bucket
	// each action landed in would still pass if someone renumbered the phases
	// while collapsing two of them together.
	clear := Action{Kind: "nic", Op: "clear", IPID: 41}
	assign := Action{Kind: "nic", Op: "assign", IPID: 41}
	create := Action{Kind: "nic", Op: "create"}

	if !(Phase(clear) < Phase(assign)) {
		t.Errorf("clear must precede assign: %d vs %d", Phase(clear), Phase(assign))
	}
	// nic/create assigns its own address, so it counts as an assignment too.
	if !(Phase(clear) < Phase(create)) {
		t.Errorf("clear must precede nic/create: %d vs %d", Phase(clear), Phase(create))
	}
}

func TestDiffDetectsAssignmentDriftUsingDecodedActual(t *testing.T) {
	// The address was detached in NetBox after creation. Assignment happens only
	// on the create path, so without an assign action the sweep never repairs it.
	//
	// Actual state is DECODED from the real IP-address payload that BuildActual
	// consumes. Hand-setting an assignment field would prove nothing about
	// whether production collection can see the drift at all — the same gap that
	// made the earlier write-on-change test vacuous.
	actual := decodeActualWithIPs(t,
		`{"results":[{"id":11,"name":"vm-1","vcpus":2,"memory":2048,"disk":20,`+
			`"status":{"value":"active"},"cluster":{"id":5},`+
			`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`,
		`{"results":[{"id":21,"name":"eth0","mac_address":"52:54:00:aa:bb:01",`+
			`"virtual_machine":{"id":11},`+
			`"custom_fields":{"litevirt_identity":"`+nicIdent("u1", "52:54:00:aa:bb:01")+`"}}],"next":""}`,
		// The address exists but is assigned to NOTHING — the drift.
		`{"results":[{"id":41,"address":"10.0.5.100/24","assigned_object_id":null,`+
			`"custom_fields":{"litevirt_identity":"`+nicIdent("u1", "52:54:00:aa:bb:01")+`"}}],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048, DiskMB: 20, Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:01", NetBoxIPID: 41}},
	}}, actual, fp)

	var assign *Action
	for i := range got {
		if got[i].Op == "assign" {
			assign = &got[i]
		}
	}
	if assign == nil {
		t.Fatalf("want an assign action to repair the drift, got %+v", got)
	}
	if assign.NetBoxID != 21 || assign.IPID != 41 {
		t.Fatalf("assign must target iface 21 with address 41, got %+v", *assign)
	}
	// Nothing was assigned before, so there is nothing to clear.
	for _, a := range got {
		if a.Op == "clear" {
			t.Fatalf("no clear expected when the interface held nothing: %+v", a)
		}
	}
}

func TestDiffNeverClearsAnOperatorOwnedAddress(t *testing.T) {
	// DECODED, not hand-built. An empty OwnedIPsByIface would only prove that an
	// empty map yields no clear — it would say nothing about whether BuildActual
	// actually excludes an operator-owned address it decoded.
	actual := decodeActualWithIPs(t,
		`{"results":[{"id":11,"name":"vm-1","status":{"value":"active"},"cluster":{"id":5},`+
			`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`,
		`{"results":[{"id":21,"name":"eth0","mac_address":"52:54:00:aa:bb:01",`+
			`"virtual_machine":{"id":11},`+
			`"custom_fields":{"litevirt_identity":"`+nicIdent("u1", "52:54:00:aa:bb:01")+`"}}],"next":""}`,
		// Assigned to OUR interface, but with no litevirt identity: an operator's.
		`{"results":[{"id":77,"address":"10.0.5.77/24","assigned_object_id":21,`+
			`"custom_fields":{}}],"next":""}`)

	if len(actual.OwnedIPsByIface[21]) != 0 {
		t.Fatalf("BuildActual must not admit an operator-owned address, got %+v", actual.OwnedIPsByIface[21])
	}
	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:01", NetBoxIPID: 41}},
	}}, actual, fp)

	for _, a := range got {
		if a.Op == "clear" {
			t.Fatalf("an operator-owned address must never be cleared: %+v", a)
		}
	}
}

func TestDiffAssignmentIsOrderIndependent(t *testing.T) {
	// A NetBox interface can hold several addresses. Picking ips[0] made the
	// action set depend on API ordering: [desired, stale] looked correct and
	// left the stale one forever, [stale, desired] emitted a needless clear.
	desired := []DesiredVM{{
		Name: "vm-1", UUID: "u1", Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:01", NetBoxIPID: 41}},
	}}
	base := func(ips []netbox.IPAddress) Actual {
		return Actual{
			VMs:             map[string]netbox.VirtualMachine{vmIdent("u1"): {ID: 11, Name: "vm-1", Status: "active"}},
			NICs:            map[string]netbox.VMInterface{nicIdent("u1", "52:54:00:aa:bb:01"): {ID: 21, Name: "eth0", MAC: "52:54:00:aa:bb:01"}},
			OwnedIPsByIface: map[int][]netbox.IPAddress{21: ips},
		}
	}
	forward := Diff(desired, base([]netbox.IPAddress{{ID: 41}, {ID: 42}}), fp)
	reverse := Diff(desired, base([]netbox.IPAddress{{ID: 42}, {ID: 41}}), fp)

	summarise := func(as []Action) []string {
		var out []string
		for _, a := range as {
			if a.Op == "assign" || a.Op == "clear" {
				out = append(out, fmt.Sprintf("%s:%d", a.Op, a.IPID))
			}
		}
		return out
	}
	f, rv := summarise(forward), summarise(reverse)
	if !reflect.DeepEqual(f, rv) {
		t.Fatalf("action set depends on API ordering: %v vs %v", f, rv)
	}
	// The desired address is already present, so only the stale one is cleared.
	if len(f) != 1 || f[0] != "clear:42" {
		t.Fatalf("want exactly clear:42, got %v", f)
	}
}

func TestDiffNeverDeletesAnotherClustersVM(t *testing.T) {
	// Same VM NAME, different cluster fingerprint. A name-keyed diff would emit
	// a delete here and destroy the other cluster's inventory.
	other := netbox.Identity("otherfp", "u9", "")
	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u1", Status: "active"}},
		Actual{VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-1", Status: "active"},
			other:         {ID: 99, Name: "vm-1"},
		}}, fp)

	for _, a := range got {
		if a.Op == "delete" && a.Key == other {
			t.Fatal("diff deleted another cluster's VM")
		}
		// Identity-keying is also what makes OUR lookup hit at all. Keyed by
		// name, the desired VM would miss its own actual object — both entries
		// are named vm-1 — and the sweep would re-create it and then delete it
		// as unseen on the very same pass.
		if a.Key == vmIdent("u1") {
			t.Fatalf("our VM already matches its actual object, so no action is due: %+v", a)
		}
	}
}

func TestActualStateDiscardsForeignIdentities(t *testing.T) {
	// The first of two independent guards: BuildActual must not even ADMIT
	// another cluster's objects. Diff's fingerprint filter is the second.
	actual := decodeActualFixture(t, `{"results":[`+
		`{"id":11,"name":"vm-1","status":{"value":"active"},"cluster":{"id":5},`+
		`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}},`+
		`{"id":99,"name":"vm-1","status":{"value":"active"},"cluster":{"id":5},`+
		`"custom_fields":{"litevirt_identity":"`+netbox.Identity("otherfp", "u9", "")+`"}}`+
		`],"next":""}`)

	if len(actual.VMs) != 1 {
		t.Fatalf("BuildActual must discard foreign identities, got %d: %+v", len(actual.VMs), actual.VMs)
	}
	if _, ok := actual.VMs[vmIdent("u1")]; !ok {
		t.Fatalf("BuildActual kept the wrong VM: %+v", actual.VMs)
	}
}

func TestDiffDerivesParentFromActualWhenMappingIsLost(t *testing.T) {
	// The VM already exists in NetBox and matches, so Diff emits NO vm action —
	// nothing this sweep records its NetBox id. If the local netbox_objects row
	// was also lost, phase ordering gives the applier nothing to look up and a
	// nic/create has no parent to be created under. Reading the parent from
	// ACTUAL state is the only thing that closes that hole.
	actual := decodeActualWithIPs(t,
		`{"results":[{"id":11,"name":"vm-1","vcpus":2,"memory":2048,"disk":20,`+
			`"status":{"value":"active"},"cluster":{"id":5},`+
			`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`,
		// No interfaces at all: the NIC must be created.
		`{"results":[],"next":""}`,
		`{"results":[],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048, DiskMB: 20, Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:01"}},
	}}, actual, fp)

	if len(got) != 1 || got[0].Kind != "nic" || got[0].Op != "create" {
		t.Fatalf("want exactly one nic/create, got %+v", got)
	}
	if got[0].ParentNetBoxID != 11 {
		t.Fatalf("nic/create must carry the owning VM's NetBox id from actual state, got %+v", got[0])
	}
}

// --- helpers ---------------------------------------------------------------

// decodeActualFixture builds Actual from a VM-list payload alone.
func decodeActualFixture(t *testing.T, vmsJSON string) Actual {
	t.Helper()
	return decodeActualWithIPs(t, vmsJSON, `{"results":[],"next":""}`, `{"results":[],"next":""}`)
}

// decodeActualWithIPs builds Actual from the three payloads BuildActual reads,
// using the production decoders rather than hand-built structs.
func decodeActualWithIPs(t *testing.T, vmsJSON, ifacesJSON, ipsJSON string) Actual {
	t.Helper()
	c := netboxClientServing(t, map[string]string{
		"/api/virtualization/virtual-machines/": vmsJSON,
		"/api/virtualization/interfaces/":       ifacesJSON,
		"/api/ipam/ip-addresses/":               ipsJSON,
	})
	actual, err := BuildActual(context.Background(), c, 5, fp)
	if err != nil {
		t.Fatal(err)
	}
	return actual
}

// allowedQuery lists, per endpoint, the query parameters a real NetBox
// implements.
//
// A fake that ignored an unrecognised parameter would let a query like
// virtual_machine_cluster_id — which NetBox does not implement — pass here while
// silently losing its scope against a real server, handing the sweep every
// litevirt object in the install. The same rule applies to the fleet fake.
var allowedQuery = map[string]map[string]bool{
	"/api/virtualization/virtual-machines/": {"cluster_id": true, "limit": true, "offset": true},
	"/api/virtualization/interfaces/":       {"cluster_id": true, "limit": true, "offset": true},
	"/api/ipam/ip-addresses/": {
		"vminterface_id": true, "limit": true, "offset": true,
		"cf_" + netbox.IdentityField + "__n": true,
	},
}

// netboxClientServing starts an httptest server routing by path and returns a
// REAL *netbox.Client, so every fixture is decoded by the production decoders.
// It rejects an unrecognised query parameter with a 400 naming the ones it knows.
func netboxClientServing(t *testing.T, byPath map[string]string) *netbox.Client {
	t.Helper()
	return netboxClientFor(t, func(w http.ResponseWriter, r *http.Request) {
		body, ok := byPath[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		allowed := allowedQuery[r.URL.Path]
		for k := range r.URL.Query() {
			if !allowed[k] {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, `{"detail":"unknown query parameter %q; recognised: %v"}`,
					k, sortedKeys(allowed))
				return
			}
		}
		_, _ = w.Write([]byte(body))
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// netboxClientFor wires a real client to an arbitrary handler.
func netboxClientFor(t *testing.T, h http.HandlerFunc) *netbox.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := netbox.New(netbox.Config{BaseURL: srv.URL, TokenPath: tok, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// vmBodyForTest returns the write body the PRODUCTION client sends for a VM,
// captured off the wire from a real UpdateVM rather than reconstructed here.
// Reconstructing it would assert on a copy of the rule instead of on the rule.
func vmBodyForTest(t *testing.T, d DesiredVM) map[string]any {
	t.Helper()
	var got map[string]any
	c := netboxClientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode PATCH body: %v", err)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	if err := c.UpdateVM(context.Background(), 11, netbox.VirtualMachine{
		Name: d.Name, VCPUs: netbox.VCPUs(d.VCPUs), MemoryMB: d.MemoryMB,
		DiskMB: d.DiskMB, Status: d.Status, DeviceID: d.DeviceID,
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

// TestDiffEmitsNothingForADecimalVCPUsThatEqualsTheDesiredCount is the other
// half of the decimal-vcpus fix, and the half a decode-only test cannot reach.
//
// NetBox stores `vcpus` as a decimal and returns the two-vCPU guest above as
// `2.0`. litevirt's desired value is the integer 2. If the diff compared those
// through anything but a numeric widening — an int on one side, a rounded decode
// on the other — the VM would look changed on every sweep and the mirror would
// PATCH it forever, which is precisely what write-on-change exists to prevent.
func TestDiffEmitsNothingForADecimalVCPUsThatEqualsTheDesiredCount(t *testing.T) {
	actual := decodeActualFixture(t, `{"results":[{"id":11,"name":"vm-1","vcpus":2.0,`+
		`"memory":2048,"disk":20,"status":{"value":"active"},"cluster":{"id":5},`+
		`"device":{"id":9},"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048,
		DiskMB: 20, Status: "active", DeviceID: 9,
	}}, actual, fp)

	if len(got) != 0 {
		t.Fatalf("a decimal 2.0 must equal a desired 2, got %+v", got)
	}
}

// TestDiffConvergesAGenuinelyFractionalVCPUs is the control that keeps the
// comparison honest.
//
// NetBox's field permits 2.5 and litevirt's count is a whole number, so a
// fractional value is drift and must be patched back — the outcome a decoder
// that ROUNDED to an int would silently lose, by making 2.5 compare equal to a
// desired 2 and leaving the fraction in NetBox for good.
func TestDiffConvergesAGenuinelyFractionalVCPUs(t *testing.T) {
	actual := decodeActualFixture(t, `{"results":[{"id":11,"name":"vm-1","vcpus":2.5,`+
		`"memory":2048,"disk":20,"status":{"value":"active"},"cluster":{"id":5},`+
		`"device":{"id":9},"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048,
		DiskMB: 20, Status: "active", DeviceID: 9,
	}}, actual, fp)

	if len(got) != 1 || got[0].Op != "update" {
		t.Fatalf("a fractional vcpus must converge to the desired integer, got %+v", got)
	}
}
