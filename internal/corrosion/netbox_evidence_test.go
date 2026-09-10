package corrosion

import (
	"context"
	"testing"
)

// Why the NIC evidence union reads BOTH interface tables.
//
// KnowsNIC asks whether the local database holds a record of a (VM, MAC) — the
// proof the NetBox mirror needs before it may retire that interface object. It
// reads `vm_interfaces` and `vm_nics`, and the second one is not belt-and-braces
// for the first: on the commonest hotplug sequence it is the ONLY row left.
//
// `vm_interfaces` keys on (vm_name, network_name) and InsertInterface is an
// INSERT OR REPLACE, so re-attaching on the same network — which gets a freshly
// randomised MAC — overwrites the detached NIC's row in place, MAC and tombstone
// together. `vm_nics` keys on (vm_name, id) with the id derived from the MAC, so
// the two incarnations occupy different rows and the old one's tombstone
// survives.
//
// Drop `vm_nics` from the union and an ordinary detach-then-re-attach makes the
// old MAC unprovable, which permanently strands its NetBox interface: every
// sweep withholds the delete and the mirror never converges again.

// The MACs one detach-and-re-attach cycle on a single network uses.
const (
	evidenceMACFirst  = "52:54:00:e0:00:01"
	evidenceMACSecond = "52:54:00:e0:00:02"
)

// reattachedNIC drives the real sequence: a VM created with one NIC on one
// network, that NIC detached, then a new NIC attached on the SAME network with a
// different MAC — through the production write paths, because the overwrite this
// pins is a property of those statements' primary keys.
func reattachedNIC(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()

	nicID := DeterministicNICID("vm-1", evidenceMACFirst)
	if err := InsertVMWithHardware(ctx, c,
		VMRecord{Name: "vm-1", HostName: "host-a", State: "running", Spec: `{"uuid":"uuid-1"}`},
		[]InterfaceRecord{{VMName: "vm-1", NetworkName: "net-a", Ordinal: 0, MAC: evidenceMACFirst}},
		nil,
		[]NICRecord{{VMName: "vm-1", ID: nicID, NetworkName: "net-a", MAC: evidenceMACFirst}},
		nil, true); err != nil {
		t.Fatalf("InsertVMWithHardware: %v", err)
	}

	// Detach: both NIC tables are tombstoned, which is what a hot-detach does.
	if err := SoftDeleteInterfaceByMAC(ctx, c, "vm-1", evidenceMACFirst); err != nil {
		t.Fatalf("SoftDeleteInterfaceByMAC: %v", err)
	}
	if err := TombstoneNIC(ctx, c, "vm-1", nicID); err != nil {
		t.Fatalf("TombstoneNIC: %v", err)
	}

	// Re-attach on the SAME network with a fresh MAC, exactly as the hotplug
	// attach path does.
	if err := InsertInterface(ctx, c, InterfaceRecord{
		VMName: "vm-1", NetworkName: "net-a", Ordinal: 0, MAC: evidenceMACSecond,
	}); err != nil {
		t.Fatalf("InsertInterface: %v", err)
	}
	if err := UpsertNIC(ctx, c, NICRecord{
		VMName: "vm-1", ID: DeterministicNICID("vm-1", evidenceMACSecond),
		NetworkName: "net-a", MAC: evidenceMACSecond,
	}); err != nil {
		t.Fatalf("UpsertNIC: %v", err)
	}
}

// TestReattachOverwritesTheLegacyInterfaceTombstone is the precondition, and
// without it the assertion below proves nothing: it establishes that
// `vm_interfaces` really has forgotten the first MAC.
func TestReattachOverwritesTheLegacyInterfaceTombstone(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	reattachedNIC(t, c)

	rows, err := c.Query(ctx, `SELECT mac FROM vm_interfaces WHERE vm_name = 'vm-1'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("vm_interfaces holds %d rows for one (vm, network); INSERT OR REPLACE keys on "+
			"(vm_name, network_name), so there can only be one", len(rows))
	}
	if got := rows[0].String("mac"); got != evidenceMACSecond {
		t.Fatalf("vm_interfaces MAC = %q, want the re-attached one — this test's premise is that "+
			"the re-attach overwrote the detached NIC's row", got)
	}
}

// TestDetachedMACStaysProvableAfterReattach is the property the mirror's delete
// half depends on, and the mutation that catches `vm_nics` being dropped from
// the evidence union.
func TestDetachedMACStaysProvableAfterReattach(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	reattachedNIC(t, c)

	known, err := ReadMirrorEvidence(ctx, c)
	if err != nil {
		t.Fatalf("ReadMirrorEvidence: %v", err)
	}
	if !known.KnowsNIC("vm-1", evidenceMACFirst) {
		t.Fatal("the DETACHED MAC is no longer provable after a re-attach on the same network. " +
			"`vm_interfaces` overwrote its row, so only the `vm_nics` tombstone carries the " +
			"evidence — remove that table from the union and every re-attached NIC strands its " +
			"old NetBox interface forever")
	}
	if !known.KnowsNIC("vm-1", evidenceMACSecond) {
		t.Fatal("the live NIC must be provable too")
	}
	// The negative control: an evidence set that answered yes to everything
	// would satisfy both assertions above and authorize every delete.
	if known.KnowsNIC("vm-1", "52:54:00:e0:00:09") {
		t.Fatal("a MAC this cluster has never recorded must not be provable")
	}
}

// TestBridgedNICIDsStayMACDerived is the TRIPWIRE under the mitigation above,
// and the assertion it makes is the one the test before it cannot.
//
// TestDetachedMACStaysProvableAfterReattach hand-derives both `vm_nics` ids with
// DeterministicNICID, so it asserts the CONSEQUENCE of the id being MAC-derived
// while baking that premise into its own fixture. Re-key production ids on
// something a re-attach PRESERVES — (vm_name, network_name), or the ordinal — and
// it stays green while the mitigation collapses underneath it: the re-attach
// would resolve to the same `vm_nics` key, and UpsertNIC is an INSERT OR REPLACE
// that clears deleted_at, so it would resurrect the row in place and take the old
// MAC's tombstone with it, exactly as `vm_interfaces` already does.
//
// This test therefore names DeterministicNICID nowhere and takes every id from
// production. It drives the legacy→v42 bridge, which derives the id itself
// (GetVMNICsRaw's `vm_interfaces` projection), over the same detach-and-re-attach
// on ONE network — same network name, same ordinal, fresh MAC, which is the only
// field that changes. Two rows out means the derivation still separates the two
// incarnations; one row out means it does not.
//
// It guards a derivation twelve production construction sites share and none of
// them checks, and it is a fair proxy for all of them: they mint the id the same
// way, from (vm name, MAC), so the property is the helper's, not the call site's.
func TestBridgedNICIDsStayMACDerived(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	// A legacy-only NIC — what an old peer writes mid-rolling-upgrade — bridged
	// into vm_nics, which is where the id gets derived.
	if err := InsertInterface(ctx, c, InterfaceRecord{
		VMName: "vm-1", NetworkName: "net-a", Ordinal: 0, MAC: evidenceMACFirst,
	}); err != nil {
		t.Fatalf("InsertInterface(first): %v", err)
	}
	if err := BridgeVMNICs(ctx, c, "vm-1"); err != nil {
		t.Fatalf("BridgeVMNICs(first): %v", err)
	}
	if rows := nicRows(t, c); len(rows) != 1 {
		t.Fatalf("the bridge produced %d vm_nics rows for one legacy NIC, want 1: %v", len(rows), rows)
	}

	// Detach, and let the bridge carry the tombstone across.
	if err := SoftDeleteInterfaceByMAC(ctx, c, "vm-1", evidenceMACFirst); err != nil {
		t.Fatalf("SoftDeleteInterfaceByMAC: %v", err)
	}
	if err := BridgeVMNICs(ctx, c, "vm-1"); err != nil {
		t.Fatalf("BridgeVMNICs(detach): %v", err)
	}

	// Re-attach on the SAME network and ordinal with the fresh MAC an attach
	// always gets. This overwrites the legacy row in place — see the test above
	// — so from here only vm_nics can carry the old MAC.
	if err := InsertInterface(ctx, c, InterfaceRecord{
		VMName: "vm-1", NetworkName: "net-a", Ordinal: 0, MAC: evidenceMACSecond,
	}); err != nil {
		t.Fatalf("InsertInterface(second): %v", err)
	}
	if err := BridgeVMNICs(ctx, c, "vm-1"); err != nil {
		t.Fatalf("BridgeVMNICs(reattach): %v", err)
	}

	rows := nicRows(t, c)
	if len(rows) != 2 {
		t.Fatalf("vm_nics holds %d rows after a detach-and-re-attach on one network, want 2: %v.\n"+
			"One row means the two incarnations shared an id, so UpsertNIC resurrected the "+
			"tombstone in place. `vm_nics.id` MUST stay derived from the MAC (DeterministicNICID): "+
			"an id keyed on anything a re-attach preserves — the network name, the ordinal — "+
			"collapses the only evidence a detached NIC leaves, and the NetBox mirror then "+
			"withholds that interface's delete on every sweep forever", len(rows), rows)
	}
	byMAC := map[string]nicRow{}
	for _, r := range rows {
		byMAC[r.mac] = r
	}
	old, oldOK := byMAC[evidenceMACFirst]
	live, liveOK := byMAC[evidenceMACSecond]
	if !oldOK || !liveOK {
		t.Fatalf("want one row per MAC, got %v", rows)
	}
	if old.id == live.id {
		t.Fatalf("both incarnations derived id %q — the id is not MAC-derived", old.id)
	}
	if old.deletedAt == "" {
		t.Fatalf("the detached NIC's row is live: %v", old)
	}
	if live.deletedAt != "" {
		t.Fatalf("the re-attached NIC's row is tombstoned: %v", live)
	}

	// And the point of all of it: the detached MAC is still provable, so the
	// mirror may retire its NetBox interface.
	known, err := ReadMirrorEvidence(ctx, c)
	if err != nil {
		t.Fatalf("ReadMirrorEvidence: %v", err)
	}
	if !known.KnowsNIC("vm-1", evidenceMACFirst) {
		t.Fatal("the detached MAC is unprovable after a bridged re-attach")
	}
}

// nicRow is one raw `vm_nics` row, read straight from the table so the ids under
// test are production's and not the caller's.
type nicRow struct {
	id, mac, deletedAt string
}

func nicRows(t *testing.T, c *Client) []nicRow {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT id, mac, COALESCE(deleted_at, '') AS deleted_at
		   FROM vm_nics WHERE vm_name = 'vm-1' ORDER BY id`)
	if err != nil {
		t.Fatalf("read vm_nics: %v", err)
	}
	out := make([]nicRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, nicRow{
			id: r.String("id"), mac: r.String("mac"), deletedAt: r.String("deleted_at"),
		})
	}
	return out
}

// TestKnowsAddressNeedsALeaseRecord pins the clear half's evidence: a lease row
// of ANY kind naming a NetBox address proves it, and nothing else does.
//
// The tombstoned row is the important half — that is what a released lease
// leaves, and it is what makes a genuinely stale NetBox assignment provable
// rather than permanently withheld.
func TestKnowsAddressNeedsALeaseRecord(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if err := c.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES ('net-a', '10.0.9.1', ?, 'vm-1', 'vm', 'host-a', 41, 7, ?, ?)`,
		evidenceMACFirst, c.NowWall(), c.NowTS()); err != nil {
		t.Fatalf("seed live lease: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at, deleted_at)
		 VALUES ('net-a', '10.0.9.2', ?, 'vm-1', 'vm', 'host-a', 42, 7, ?, ?, ?)`,
		evidenceMACFirst, c.NowWall(), c.NowTS(), c.NowWall()); err != nil {
		t.Fatalf("seed released lease: %v", err)
	}
	// A builtin allocation has no NetBox object, so its row must contribute no
	// address evidence at all.
	if err := c.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES ('net-b', '10.0.9.3', ?, 'vm-2', 'vm', 'host-a', ?, ?)`,
		evidenceMACSecond, c.NowWall(), c.NowTS()); err != nil {
		t.Fatalf("seed builtin lease: %v", err)
	}

	known, err := ReadMirrorEvidence(ctx, c)
	if err != nil {
		t.Fatalf("ReadMirrorEvidence: %v", err)
	}
	if !known.KnowsAddress(41) {
		t.Fatal("a live lease must prove its own address")
	}
	if !known.KnowsAddress(42) {
		t.Fatal("a RELEASED lease keeps its netbox_ip_id, and that tombstone is the only thing " +
			"that makes a genuinely stale NetBox assignment clearable")
	}
	if known.KnowsAddress(43) {
		t.Fatal("an address no lease row names must not be provable")
	}
	if known.KnowsAddress(0) {
		t.Fatal("address 0 is what a builtin lease and an unresolved lookup read back as; it " +
			"can never be evidence")
	}
}

// ── the VM half: WHICH record, not whether there is one ─────────────────────

// TestVMRemovalTellsTheFourRecordsApart is the classification the mirror's
// removal policy rests on, and every state here decides a different answer.
//
// The predicate this replaced returned one boolean for all of them, which is
// what let a MAPPING row — "this node's mirror created that object" — stand in
// for "that incarnation stopped existing". Keeping the records apart is the
// whole mechanism: the policy lives in netboxsync, and it can only be right if
// what it is given distinguishes a tombstone from a live row from a mapping row.
func TestVMRemovalTellsTheFourRecordsApart(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	// A live workload, a template, and a destroyed incarnation — three VMs so
	// no single-row fixture can conflate two of the states.
	for _, vm := range []struct{ name, uuid string }{
		{"vm-live", "uuid-live"},
		{"vm-template", "uuid-template"},
		{"vm-gone", "uuid-gone"},
	} {
		if err := InsertVM(ctx, c, VMRecord{
			Name: vm.name, HostName: "host-a", State: "running",
			Spec: `{"uuid":"` + vm.uuid + `"}`,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm.name, err)
		}
	}
	if err := SetVMTemplate(ctx, c, "vm-template", true); err != nil {
		t.Fatalf("SetVMTemplate: %v", err)
	}
	if err := DeleteVM(ctx, c, "vm-gone"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	// The mirror's own mapping row for an incarnation NO `vms` row mentions:
	// what a node holds when `netbox_objects` has replicated and `vms` has not,
	// and what survives the same-name re-create purge.
	if err := PutObjectRef(ctx, c, ObjectRef{
		LitevirtKind: mirrorRefKindVM, LitevirtKey: "lv:fp:uuid-mirrored:",
		NetBoxKind: "virtual_machine", NetBoxID: 12,
	}); err != nil {
		t.Fatalf("PutObjectRef: %v", err)
	}

	known, err := ReadMirrorEvidence(ctx, c)
	if err != nil {
		t.Fatalf("ReadMirrorEvidence: %v", err)
	}

	for _, tc := range []struct {
		what     string
		identity string
		uuid     string
		want     VMRemovalRecord
		why      string
	}{
		{"a live workload's own incarnation", "lv:fp:uuid-live:", "uuid-live",
			VMRemovalLive,
			"a live row says the incarnation EXISTS, which is the one answer that must " +
				"never authorize removing its object"},
		{"an incarnation this cluster turned into a template", "lv:fp:uuid-template:",
			"uuid-template", VMRemovalLiveTemplate,
			"a template's row is live and the mirror does not represent it, so its object " +
				"is one to retire — reported apart from a plain live row so a FUTURE reason " +
				"for leaving the desired set cannot inherit this permission"},
		{"a destroyed incarnation", "lv:fp:uuid-gone:", "uuid-gone", VMRemovalRetired,
			"litevirt soft-deletes, so the tombstone is what a destroyed incarnation leaves " +
				"and it justifies absence on its own"},
		{"an incarnation only the mapping row names", "lv:fp:uuid-mirrored:", "uuid-mirrored",
			VMRemovalMirroredOnly,
			"the mapping row identifies the incarnation and says NOTHING about whether it " +
				"stopped existing; it must be distinguishable so the caller can require " +
				"corroboration before concluding an absence from it"},
		{"an incarnation this node has never held", "lv:fp:uuid-unknown:", "uuid-unknown",
			VMRemovalNoRecord,
			"an unhydrated node holds no record, and that has always withheld"},
		{"an empty identity", "", "uuid-live", VMRemovalNoRecord,
			"an empty identity is never evidence"},
		{"an empty uuid", "lv:fp::", "", VMRemovalNoRecord,
			"an empty uuid is never evidence"},
	} {
		if got := known.VMRemoval(tc.identity, tc.uuid); got != tc.want {
			t.Errorf("VMRemoval for %s = %d, want %d: %s", tc.what, got, tc.want, tc.why)
		}
	}
}

// TestALiveRowOutranksATombstoneCarryingTheSameUUID pins the precedence, which
// only shows up when one uuid is on two rows — a spec copied onto a second name.
//
// The permissive branch must need EVERY live row to agree; "one of them is still
// live" is the answer that withholds.
func TestALiveRowOutranksATombstoneCarryingTheSameUUID(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	for _, name := range []string{"vm-a", "vm-b"} {
		if err := InsertVM(ctx, c, VMRecord{
			Name: name, HostName: "host-a", State: "running",
			Spec: `{"uuid":"uuid-shared"}`,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", name, err)
		}
	}
	// One destroyed, one still running, both carrying the same uuid.
	if err := DeleteVM(ctx, c, "vm-a"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	known, err := ReadMirrorEvidence(ctx, c)
	if err != nil {
		t.Fatalf("ReadMirrorEvidence: %v", err)
	}
	if got := known.VMRemoval("lv:fp:uuid-shared:", "uuid-shared"); got != VMRemovalLive {
		t.Fatalf("VMRemoval = %d, want VMRemovalLive (%d): a tombstone beside a LIVE row "+
			"carrying the same uuid must not read as an absence", got, VMRemovalLive)
	}

	// …and the same precedence for the template flag: a live non-template row
	// beside a live template one is a workload, not a template.
	if err := SetVMTemplate(ctx, c, "vm-a", true); err != nil {
		t.Fatalf("SetVMTemplate: %v", err)
	}
	if err := InsertVM(ctx, c, VMRecord{
		Name: "vm-a", HostName: "host-a", State: "running",
		Spec: `{"uuid":"uuid-shared"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM(revive): %v", err)
	}
	if err := SetVMTemplate(ctx, c, "vm-a", true); err != nil {
		t.Fatalf("SetVMTemplate(revive): %v", err)
	}
	known, err = ReadMirrorEvidence(ctx, c)
	if err != nil {
		t.Fatalf("ReadMirrorEvidence: %v", err)
	}
	if got := known.VMRemoval("lv:fp:uuid-shared:", "uuid-shared"); got != VMRemovalLive {
		t.Fatalf("VMRemoval = %d, want VMRemovalLive (%d): one live row is a template and "+
			"the other is a running workload, so the uuid is a workload's", got, VMRemovalLive)
	}
}
