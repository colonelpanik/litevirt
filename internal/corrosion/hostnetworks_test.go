package corrosion

import (
	"context"
	"errors"
	"testing"
)

func TestHostNetworkLifecycle(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	// Reject the garbage early: unknown kind, VLAN without its link/id.
	if err := UpsertHostNetwork(ctx, c, HostNetworkRecord{HostName: "h1", Name: "x", Kind: "tunnel"}); err == nil {
		t.Fatal("an unknown kind must be refused")
	}
	if err := UpsertHostNetwork(ctx, c, HostNetworkRecord{HostName: "h1", Name: "v", Kind: "vlan"}); err == nil {
		t.Fatal("a vlan without vlan_link/vlan_id must be refused")
	}
	if err := UpsertHostNetwork(ctx, c, HostNetworkRecord{
		HostName: "h1", Name: "b", Kind: "bridge", Addressing: "{not json",
	}); err == nil {
		t.Fatal("unparseable addressing JSON must be refused")
	}

	// A fresh intent starts desired at generation 0.
	if err := UpsertHostNetwork(ctx, c, HostNetworkRecord{
		HostName: "h1", Name: "vmbr0", Kind: "bridge",
		Members:    []string{"eth1"},
		Addressing: `{"dhcp4":true}`,
		MTU:        1500,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	rec, err := GetHostNetwork(ctx, c, "h1", "vmbr0")
	if err != nil || rec == nil {
		t.Fatalf("get: rec=%v err=%v", rec, err)
	}
	if rec.State != HostNetworkDesired || rec.Generation != 0 || len(rec.Members) != 1 || rec.Members[0] != "eth1" {
		t.Fatalf("fresh intent: %+v", rec)
	}
	created := rec.CreatedAt

	// Apply protocol: applying → applied mints the generation.
	if err := SetHostNetworkState(ctx, c, "h1", "vmbr0", HostNetworkApplying, ""); err != nil {
		t.Fatalf("applying: %v", err)
	}
	if err := MarkHostNetworkApplied(ctx, c, "h1", "vmbr0"); err != nil {
		t.Fatalf("applied: %v", err)
	}
	rec, _ = GetHostNetwork(ctx, c, "h1", "vmbr0")
	if rec.State != HostNetworkApplied || rec.Generation != 1 {
		t.Fatalf("after confirmed apply: state=%q generation=%d", rec.State, rec.Generation)
	}

	// An EDIT resets the lifecycle to desired but keeps identity + apply count:
	// "edited since last apply" must be distinguishable from "never applied".
	if err := UpsertHostNetwork(ctx, c, HostNetworkRecord{
		HostName: "h1", Name: "vmbr0", Kind: "bridge",
		Members: []string{"eth1", "eth2"}, MTU: 9000,
	}); err != nil {
		t.Fatalf("edit: %v", err)
	}
	rec, _ = GetHostNetwork(ctx, c, "h1", "vmbr0")
	if rec.State != HostNetworkDesired {
		t.Fatalf("an edit must reset state to desired, got %q", rec.State)
	}
	if rec.Generation != 1 {
		t.Fatalf("an edit must NOT reset the apply count, got generation=%d", rec.Generation)
	}
	if rec.CreatedAt != created {
		t.Fatalf("an edit must not re-stamp created_at: %q → %q", created, rec.CreatedAt)
	}
	if rec.MTU != 9000 || len(rec.Members) != 2 {
		t.Fatalf("edit did not land: %+v", rec)
	}

	// Rollback records its cause.
	if err := SetHostNetworkState(ctx, c, "h1", "vmbr0", HostNetworkRolledBack, "gateway unreachable"); err != nil {
		t.Fatalf("rolled_back: %v", err)
	}
	rec, _ = GetHostNetwork(ctx, c, "h1", "vmbr0")
	if rec.State != HostNetworkRolledBack || rec.LastError != "gateway unreachable" {
		t.Fatalf("rollback: %+v", rec)
	}

	// Soft delete: gone from reads, strict about a second delete.
	if err := DeleteHostNetwork(ctx, c, "h1", "vmbr0"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if rec, _ := GetHostNetwork(ctx, c, "h1", "vmbr0"); rec != nil {
		t.Fatalf("deleted intent still readable: %+v", rec)
	}
	if err := DeleteHostNetwork(ctx, c, "h1", "vmbr0"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("second delete: err=%v, want ErrNoRowsAffected", err)
	}
	// State writers are strict too — an apply outcome must never be recorded
	// against a row that vanished.
	if err := MarkHostNetworkApplied(ctx, c, "h1", "vmbr0"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("applied on tombstone: err=%v, want ErrNoRowsAffected", err)
	}

	// Re-creating the same name revives the row as a fresh desired intent.
	if err := UpsertHostNetwork(ctx, c, HostNetworkRecord{HostName: "h1", Name: "vmbr0", Kind: "bridge"}); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	rec, _ = GetHostNetwork(ctx, c, "h1", "vmbr0")
	if rec == nil || rec.State != HostNetworkDesired {
		t.Fatalf("recreate: %+v", rec)
	}
}

func TestListHostNetworksScoping(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	for _, r := range []HostNetworkRecord{
		{HostName: "h1", Name: "vmbr0", Kind: "bridge"},
		{HostName: "h1", Name: "bond0", Kind: "bond", Members: []string{"eth1", "eth2"}, BondMode: "802.3ad", LACPRate: "fast", HashPolicy: "layer3+4"},
		{HostName: "h2", Name: "vlan40", Kind: "vlan", VLANID: 40, VLANLink: "eth0"},
	} {
		if err := UpsertHostNetwork(ctx, c, r); err != nil {
			t.Fatalf("upsert %s/%s: %v", r.HostName, r.Name, err)
		}
	}
	all, err := ListHostNetworks(ctx, c, "")
	if err != nil || len(all) != 3 {
		t.Fatalf("cluster-wide list: n=%d err=%v", len(all), err)
	}
	h1, err := ListHostNetworks(ctx, c, "h1")
	if err != nil || len(h1) != 2 {
		t.Fatalf("host list: n=%d err=%v", len(h1), err)
	}
	// The bond's renderer-owned fields round-trip.
	var bond *HostNetworkRecord
	for i := range h1 {
		if h1[i].Name == "bond0" {
			bond = &h1[i]
		}
	}
	if bond == nil || bond.BondMode != "802.3ad" || bond.LACPRate != "fast" ||
		bond.HashPolicy != "layer3+4" || len(bond.Members) != 2 {
		t.Fatalf("bond round-trip: %+v", bond)
	}
}
