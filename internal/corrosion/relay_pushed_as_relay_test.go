package corrosion

import (
	"context"
	"testing"
)

// A relay disagreement must not silently stop replication.
//
// Relay eligibility is derived from hosts.state, which is REPLICATED and
// therefore converges asynchronously. Two nodes can hold different rows for the
// same host at the same instant — a member whose hosts row has not arrived yet,
// or one that is 'draining' here and still 'active' there — so they compute
// different relay sets. That is not a bug that can be designed out at the
// eligibility layer: any rule over asynchronously-replicated state can be
// disagreed about.
//
// What CAN be fixed is the consequence. Fan-out is gated on the receiver's own
// r.isRelay, so a node that is pushed to as a relay by a peer that believes it
// is one, while it does not, applies those mutations locally and forwards
// NOTHING. The sender's backlog gauges stay green because the push itself
// succeeded; the mutations simply never reach the leaves behind that relay
// until anti-entropy catches up.
//
// So the sender's belief is carried on the push and honoured. Over-relaying is
// harmless: a forwarded entry keeps its ORIGINAL origin and hlc, and
// filterUnseen dedups on exactly that pair, so a peer that has already seen it
// skips it and no loop can form.
func TestApplyRemoteMutations_RecordsForFanOutWhenPushedToAsARelay(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	r := NewReplicator(c, "", RelayConfig{})

	// This node does NOT believe it is a relay. That is the whole point: the
	// sender does, and the two have diverged.
	r.mu.Lock()
	r.isRelay = false
	r.mu.Unlock()

	const hlc = "2000000000000-0000-n2"
	stmt := Statement{
		SQL:    "INSERT OR REPLACE INTO crl_versions (host, version, updated_at)\n\t\t\t\t VALUES (?, ?, ?)",
		Params: []interface{}{"host-a", float64(7), hlc},
	}
	entries := replayEntry(t, "origin-node", hlc, stmt)

	if _, err := r.ApplyRemoteMutationsFrom(ctx, entries, true); err != nil {
		t.Fatalf("apply: %v", err)
	}

	rows, err := c.Query(ctx, `SELECT origin, hlc FROM mutation_log WHERE hlc = ?`, hlc)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("mutation_log rows = %d, want 1: a node pushed to as a relay recorded nothing "+
			"for fan-out, so every leaf behind it stops receiving while the sender's backlog reads healthy",
			len(rows))
	}
	// The ORIGINAL origin, not this node's name — that pair is what dedups the
	// forward downstream, and rewriting it is what would allow a loop.
	if got := rows[0].String("origin"); got != "origin-node" {
		t.Errorf("forwarded origin = %q, want %q; rewriting the origin breaks the (origin,hlc) "+
			"dedup that makes over-relaying safe", got, "origin-node")
	}
}

// The control, and the compatibility guarantee.
//
// The claim travels in a new proto field, so a peer on a released build sends
// the zero value. That must reproduce today's behaviour exactly: no claim and
// no local belief means no fan-out record.
func TestApplyRemoteMutations_NoRelayClaimAndNoBeliefRecordsNothing(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	r := NewReplicator(c, "", RelayConfig{})

	r.mu.Lock()
	r.isRelay = false
	r.mu.Unlock()

	const hlc = "2000000000001-0000-n2"
	stmt := Statement{
		SQL:    "INSERT OR REPLACE INTO crl_versions (host, version, updated_at)\n\t\t\t\t VALUES (?, ?, ?)",
		Params: []interface{}{"host-b", float64(8), hlc},
	}
	if _, err := r.ApplyRemoteMutationsFrom(ctx, replayEntry(t, "origin-node", hlc, stmt), false); err != nil {
		t.Fatalf("apply: %v", err)
	}

	rows, err := c.Query(ctx, `SELECT hlc FROM mutation_log WHERE hlc = ?`, hlc)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("mutation_log rows = %d, want 0; an unclaimed push must not be fanned out, "+
			"or a released peer's every push turns this node into a relay", len(rows))
	}
}

// The sender half, tested through the function that actually feeds the wire.
//
// A first version of this test asserted on RelaySet.IsRelay and passed with
// peerIsRelay replaced by `return true` — vacuous, because it never called the
// function under test. This one does, so a constant-returning peerIsRelay
// fails: sending the claim to every peer would make every receiver a relay.
func TestPeerIsRelay_ComesFromThisNodesElection(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	// Before any election there is no relay set, and a claim must not be
	// invented: nil means "no opinion", which has to read as false.
	if r.peerIsRelay("node-b") {
		t.Error("peerIsRelay = true with no relay set; an unelected topology must claim nothing")
	}

	members := []PeerInfo{{Name: "node-a"}, {Name: "node-b"}, {Name: "node-c"}, {Name: "node-d"}}
	// BaseRelays 1 leaves both cases reachable in a four-node set; the default 3
	// would elect three of four and make the negative case one name wide.
	rs := ComputeRelays(members, "node-a", RelayConfig{BaseRelays: 1}, nil)
	r.mu.Lock()
	r.relaySet = rs
	r.mu.Unlock()

	var elected, leaf string
	for _, m := range members {
		if rs.IsRelay(m.Name) && elected == "" {
			elected = m.Name
		}
		if !rs.IsRelay(m.Name) && leaf == "" {
			leaf = m.Name
		}
	}
	if elected == "" || leaf == "" {
		t.Fatalf("fixture cannot distinguish the cases: elected=%q leaf=%q", elected, leaf)
	}

	if !r.peerIsRelay(elected) {
		t.Errorf("peerIsRelay(%q) = false for an elected relay; the claim never goes out and "+
			"the receiver falls back to its own possibly-diverged belief", elected)
	}
	if r.peerIsRelay(leaf) {
		t.Errorf("peerIsRelay(%q) = true for a leaf; claiming relay status of every peer would "+
			"turn the whole cluster into relays", leaf)
	}
}
