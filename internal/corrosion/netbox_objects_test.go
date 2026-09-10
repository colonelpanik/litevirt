package corrosion

import (
	"context"
	"testing"
)

func TestObjectRefRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	// Keyed by IDENTITY, matching Action.Key — a name key would not resolve
	// against identity-keyed actions, and two clusters can share a VM name.
	const id = "lv:abc123:uuid-1:"
	if err := PutObjectRef(ctx, c, ObjectRef{
		LitevirtKind: "vm", LitevirtKey: id,
		NetBoxKind: "virtual_machine", NetBoxID: 11,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := GetObjectRef(ctx, c, "vm", id)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.NetBoxID != 11 {
		t.Fatalf("got %+v", got)
	}
	if got.LitevirtKind != "vm" || got.LitevirtKey != id || got.NetBoxKind != "virtual_machine" {
		t.Fatalf("round-trip lost a field: %+v", got)
	}

	// A retry of the same create re-records the SAME row rather than adding a
	// second one — that is what makes the mirror idempotent.
	if err := PutObjectRef(ctx, c, ObjectRef{
		LitevirtKind: "vm", LitevirtKey: id,
		NetBoxKind: "virtual_machine", NetBoxID: 12,
	}); err != nil {
		t.Fatal(err)
	}
	all, err := ListObjectRefs(ctx, c, "vm")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("want exactly 1 row for one identity, got %d: %+v", len(all), all)
	}
	if all[0].NetBoxID != 12 {
		t.Fatalf("upsert did not update netbox_id: %+v", all[0])
	}
}

func TestInterfaceRefKeyedOnMACSurvivesRename(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	// Keyed on the FULL identity — fingerprint + VM uuid + MAC — matching
	// Action.Key. A bare MAC would collide across clusters sharing one NetBox,
	// and would not resolve against identity-keyed actions.
	//
	// The MAC component is what survives a rename: DeterministicNICID is derived
	// from the VM name and RenameVM re-derives it, so keying on that would fork
	// a duplicate interface every rename.
	const nicID = "lv:abc123:uuid-1:52:54:00:aa:bb:cc"
	if err := PutObjectRef(ctx, c, ObjectRef{
		LitevirtKind: "nic", LitevirtKey: nicID,
		NetBoxKind: "vminterface", NetBoxID: 21,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := GetObjectRef(ctx, c, "nic", nicID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.NetBoxID != 21 {
		t.Fatal("interface mapping must survive a rename")
	}
}

func TestDeleteObjectRefTombstonesAndPutRevives(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	const id = "lv:abc123:uuid-1:"
	if err := PutObjectRef(ctx, c, ObjectRef{
		LitevirtKind: "vm", LitevirtKey: id,
		NetBoxKind: "virtual_machine", NetBoxID: 11,
	}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteObjectRef(ctx, c, "vm", id); err != nil {
		t.Fatal(err)
	}
	got, err := GetObjectRef(ctx, c, "vm", id)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("a tombstoned mapping must read back as absent, got %+v", got)
	}

	// The tombstone is a soft delete, not a hard one: the row is still there
	// holding its PK, so a hard-delete implementation would let the reclaim
	// below insert a duplicate instead of reviving.
	rows, err := c.Query(ctx,
		`SELECT deleted_at FROM netbox_objects WHERE litevirt_kind = ? AND litevirt_key = ?`,
		"vm", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("delete must tombstone, not hard-delete; got %d rows", len(rows))
	}
	if rows[0].String("deleted_at") == "" {
		t.Fatal("deleted_at not stamped")
	}

	// Re-creating the object reuses the row and clears the tombstone.
	if err := PutObjectRef(ctx, c, ObjectRef{
		LitevirtKind: "vm", LitevirtKey: id,
		NetBoxKind: "virtual_machine", NetBoxID: 99,
	}); err != nil {
		t.Fatal(err)
	}
	got, err = GetObjectRef(ctx, c, "vm", id)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.NetBoxID != 99 {
		t.Fatalf("re-created object must reuse its row: %+v", got)
	}
	all, err := ListObjectRefs(ctx, c, "vm")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("revive must not fork a second row, got %d", len(all))
	}
}

func TestListObjectRefsScopesToKindAndSkipsTombstones(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	put := func(kind, key, nbKind string, nbID int) {
		t.Helper()
		if err := PutObjectRef(ctx, c, ObjectRef{
			LitevirtKind: kind, LitevirtKey: key, NetBoxKind: nbKind, NetBoxID: nbID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("vm", "lv:abc123:uuid-1:", "virtual_machine", 11)
	put("vm", "lv:abc123:uuid-2:", "virtual_machine", 12)
	put("nic", "lv:abc123:uuid-1:52:54:00:aa:bb:cc", "vminterface", 21)

	// The same VM uuid appears under both kinds; a list that ignored the kind
	// would hand the VM syncer an interface mapping.
	vms, err := ListObjectRefs(ctx, c, "vm")
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 2 {
		t.Fatalf("want 2 vm refs, got %d: %+v", len(vms), vms)
	}
	for _, r := range vms {
		if r.LitevirtKind != "vm" {
			t.Fatalf("list leaked a %q ref into the vm listing: %+v", r.LitevirtKind, r)
		}
	}

	if err := DeleteObjectRef(ctx, c, "vm", "lv:abc123:uuid-2:"); err != nil {
		t.Fatal(err)
	}
	vms, err = ListObjectRefs(ctx, c, "vm")
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 1 || vms[0].LitevirtKey != "lv:abc123:uuid-1:" {
		t.Fatalf("tombstoned ref must not be listed: %+v", vms)
	}

	nics, err := ListObjectRefs(ctx, c, "nic")
	if err != nil {
		t.Fatal(err)
	}
	if len(nics) != 1 || nics[0].NetBoxID != 21 {
		t.Fatalf("want the single nic ref, got %+v", nics)
	}
}
