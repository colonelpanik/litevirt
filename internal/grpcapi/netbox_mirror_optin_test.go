package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// The inventory mirror is OPT-IN, and the opt-in is a capability token rather
// than a config read.
//
// NetBox is two integrations behind one config block. The IPAM half claims
// `ip_address` objects carrying this cluster's identity; the INVENTORY half
// creates `virtual_machine` and `vminterface` objects and assigns the addresses
// to them. An installation that wants NetBox as its address authority does not
// necessarily want litevirt rewriting its VM inventory, so the mirror runs only
// when asked for — and "asked for" has to mean asked for CLUSTER-WIDE, because
// the sweep runs on whichever node holds the `netbox` lease. A node mirroring
// while its peers do not is a cluster whose inventory appears and disappears
// with leadership.
//
// So the gate is `netbox_mirror_v1`, advertised only while this node's
// `netbox.mirror_inventory` flag is set: the latch then requires config
// uniformity, not just a uniform build, exactly as netbox_ipam_v1's does. The
// flag stays the reversible kill switch, because a latch is monotone and
// durable.

// TestAdvertisedCapabilities_NetBoxMirrorConditional pins the advertisement
// half, which is the whole reason a token beats a config read.
//
// Both directions matter. Advertised while the flag is off and the cluster can
// latch across a node that will never mirror — the uniformity the latch is
// supposed to prove would be a lie. Missing from tokenEnabled and the latch is
// never DRIVEN at all, so the token can never form and the mirror is dead in
// production while every other test here stays green.
func TestAdvertisedCapabilities_NetBoxMirrorConditional(t *testing.T) {
	off := testServer(t) // enfNetBoxMirror defaults false
	if hasCap(off.advertisedCapabilities(), capabilities.NetBoxMirrorV1) {
		t.Fatal("netbox_mirror_v1 must NOT be advertised when the mirror is config-off")
	}
	if off.tokenEnabled(capabilities.NetBoxMirrorV1) {
		t.Fatal("tokenEnabled(netbox_mirror_v1) must be false when config-off (latch not driven)")
	}
	// The IPAM token is independent: pure-IPAM is the DEFAULT shape, so enabling
	// NetBox must still advertise netbox_ipam_v1 with the mirror off.
	off.SetNetBoxIPAM(true)
	if !hasCap(off.advertisedCapabilities(), capabilities.NetBoxIPAMV1) {
		t.Fatal("netbox_ipam_v1 must still be advertised with the mirror off — pure IPAM is the default")
	}
	if hasCap(off.advertisedCapabilities(), capabilities.NetBoxMirrorV1) {
		t.Fatal("enabling the IPAM half must not advertise the mirror token")
	}

	on := testServer(t)
	on.SetNetBoxMirrorInventory(true)
	if !hasCap(on.advertisedCapabilities(), capabilities.NetBoxMirrorV1) {
		t.Fatal("netbox_mirror_v1 must be advertised when config-on")
	}
	if !on.tokenEnabled(capabilities.NetBoxMirrorV1) {
		t.Fatal("tokenEnabled(netbox_mirror_v1) must be true when config-on (drives the latch)")
	}

	// Filtering must never mutate the shared build-static Supported() slice.
	if !hasCap(capabilities.Supported(), capabilities.NetBoxMirrorV1) {
		t.Fatal("advertisedCapabilities filtering corrupted the shared Supported() slice")
	}
}

// TestMirrorDeclinesWithoutTheInventoryOptIn is the flag half of the gate.
//
// A fully latched cluster — both tokens durable — must still mirror NOTHING on a
// node whose `netbox.mirror_inventory` is off. That is what makes the flag a
// kill switch after the latch has formed: a latch is monotone and durable and
// can never be withdrawn, so if the flag did not gate the DECISION as well as
// the advertisement, turning the mirror off again would be impossible.
//
// The lease is the observable. SyncOnce acquires the `netbox` leader lease
// before anything else, and that acquire is itself a replicated write, so a gate
// that refused after it would already have written.
func TestMirrorDeclinesWithoutTheInventoryOptIn(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{})
	s.SetNetBoxMirrorInventory(false)
	s.SetGate(fakeServerGate{enforced: true}) // every token latched, durably
	ctx := context.Background()

	if s.StartNetBoxMirror(ctx, 0) {
		t.Fatal("StartNetBoxMirror must decline on a node that has not opted into mirroring")
	}
	if err := s.RunNetBoxMirrorOnce(ctx); err != nil {
		t.Fatalf("an opted-out pass must decline quietly, not error: %v", err)
	}
	if got := mirrorLeaseHolder(t, s); got != "" {
		t.Fatalf("an opted-out node took the netbox leader lease (holder %q)", got)
	}
	// The second producer. Every VM delete, rename and migration calls this, and
	// it writes `netbox_sync_queue` — a table that only exists to feed the mirror.
	s.enqueueMirrorSync(ctx, "vm-1", mirrorOpUpsert)
	if got := queuedMirrorItems(t, s); got != 0 {
		t.Fatalf("an opted-out node wrote %d netbox_sync_queue row(s)", got)
	}

	// The positive control: with the opt-in on, the SAME fixture mirrors. Without
	// it every assertion above is satisfied by a mirror broken for some other
	// reason.
	s.SetNetBoxMirrorInventory(true)
	if !s.StartNetBoxMirror(ctx, 0) {
		t.Fatal("StartNetBoxMirror must run on an opted-in, configured node")
	}
	_ = s.RunNetBoxMirrorOnce(ctx)
	if got := mirrorLeaseHolder(t, s); got != s.hostName {
		t.Fatalf("an opted-in latched node must take the lease, holder = %q want %q", got, s.hostName)
	}
	s.enqueueMirrorSync(ctx, "vm-1", mirrorOpUpsert)
	if got := queuedMirrorItems(t, s); got != 1 {
		t.Fatalf("an opted-in node must record the latency shortcut, got %d row(s)", got)
	}
}

// TestMirrorDeclinesWithoutItsOwnLatch pins the CLUSTER-WIDE half.
//
// The flag alone is not enough and must not be: one node opted in ahead of its
// peers is precisely the flapping inventory this token exists to prevent. The
// IPAM latch is held here so the refusal can only be the mirror token's.
func TestMirrorDeclinesWithoutItsOwnLatch(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{})
	s.SetNetBoxMirrorInventory(true)
	s.SetGate(fakeServerGate{
		enforced: true,
		durablyLatchedTok: map[string]bool{
			capabilities.NetBoxIPAMV1:   true,
			capabilities.NetBoxMirrorV1: false,
		},
	})
	ctx := context.Background()

	if err := s.RunNetBoxMirrorOnce(ctx); err != nil {
		t.Fatalf("a pass without the mirror latch must decline quietly: %v", err)
	}
	if got := mirrorLeaseHolder(t, s); got != "" {
		t.Fatalf("a node whose peers have not opted in took the lease (holder %q)", got)
	}
	s.enqueueMirrorSync(ctx, "vm-1", mirrorOpUpsert)
	if got := queuedMirrorItems(t, s); got != 0 {
		t.Fatalf("%d queue row(s) written before netbox_mirror_v1 latched", got)
	}
}

// TestMirrorStillRequiresTheIPAMLatch pins the OTHER token, which the mirror
// does not stop needing.
//
// The mirror writes `netbox_objects` and `netbox_sync_queue`, and a build that
// predates them carries neither table in either of its ledgers — a statement the
// LWW apply path cannot place BACK-PRESSURES that peer's whole stream rather
// than failing those rows. netbox_ipam_v1 is the token that says every peer
// carries the v51 tables, so the mirror needs it whatever its own opt-in says.
func TestMirrorStillRequiresTheIPAMLatch(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{})
	s.SetNetBoxMirrorInventory(true)
	s.SetGate(fakeServerGate{
		enforced: true,
		durablyLatchedTok: map[string]bool{
			capabilities.NetBoxIPAMV1:   false,
			capabilities.NetBoxMirrorV1: true,
		},
	})
	ctx := context.Background()

	if err := s.RunNetBoxMirrorOnce(ctx); err != nil {
		t.Fatalf("a pass without the IPAM latch must decline quietly: %v", err)
	}
	if got := mirrorLeaseHolder(t, s); got != "" {
		t.Fatalf("a node without netbox_ipam_v1 took the lease (holder %q)", got)
	}
	s.enqueueMirrorSync(ctx, "vm-1", mirrorOpUpsert)
	if got := queuedMirrorItems(t, s); got != 0 {
		t.Fatalf("%d queue row(s) written before netbox_ipam_v1 latched", got)
	}
}

// TestMirrorOptInDoesNotGateTheIPAMHalf is the coherence claim Section A rests
// on: with mirroring off, NetBox is still a working IPAM.
//
// The orphan sweeper is the part that could plausibly have depended on the
// mirror, because reclamation is about addresses the inventory no longer names.
// It does not: its proof is the per-host negative fan-out, and the maintenance
// loop asks only for a NetBox client. An opted-out node must therefore still run
// revalidation and the sweep.
func TestMirrorOptInDoesNotGateTheIPAMHalf(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{})
	s.SetNetBoxMirrorInventory(false)
	s.SetGate(fakeServerGate{enforced: true})
	ctx := context.Background()

	if !s.StartNetBoxMaintenance(ctx, 0) {
		t.Fatal("an opted-out node must still run NetBox maintenance — IPAM does not depend on the mirror")
	}
	if err := s.RunNetBoxMaintenanceOnce(ctx); err != nil {
		t.Fatalf("maintenance on an opted-out node: %v", err)
	}
	// The sweep is leader-gated, and taking that lease is the proof it ran at
	// all: an opt-out that had leaked into the IPAM half would have declined
	// before the acquire, exactly as the mirror does above.
	if got := mirrorLeaseHolder(t, s); got != s.hostName {
		t.Fatalf("the orphan sweep did not run on an opted-out node (lease holder %q)", got)
	}
}
