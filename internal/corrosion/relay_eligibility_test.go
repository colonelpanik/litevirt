package corrosion

import (
	"context"
	"testing"
)

func peers(names ...string) []PeerInfo {
	out := make([]PeerInfo, 0, len(names))
	for _, n := range names {
		out = append(out, PeerInfo{Name: n, Addr: n + ":8080"})
	}
	return out
}

func relayNames(rs *RelaySet) map[string]bool {
	m := map[string]bool{}
	for _, r := range rs.Relays() {
		m[r] = true
	}
	return m
}

// Relays were the first R nodes by sorted hostname, full stop. Nothing about
// whether those nodes could actually be reached entered the decision, so two
// hosts named early in the alphabet that are offline or fenced took the whole
// cluster's relay duty with them and every leaf assigned to them lost
// replication.
//
// Eligibility has to come from REPLICATED state, not from each node's own
// view: the relay set is only useful if every node computes the same one. A
// leaf pushing to a relay that does not believe it is a relay forwards
// nothing.
func TestComputeRelays_PrefersEligibleNodes(t *testing.T) {
	members := peers("node-b", "node-c", "node-d", "node-e")
	// node-a (self) and node-b sort first but are not eligible.
	eligible := map[string]bool{"node-c": true, "node-d": true, "node-e": true}

	rs := ComputeRelays(members, "node-a", RelayConfig{BaseRelays: 2, NodesPerRelay: 50}, eligible)

	got := relayNames(rs)
	if got["node-a"] || got["node-b"] {
		t.Fatalf("relays = %v, want no ineligible node elected (node-a/node-b are offline)", rs.Relays())
	}
	if len(rs.Relays()) != 3 {
		t.Fatalf("relays = %v, want 3 (BaseRelays 2 + ceil(5/50))", rs.Relays())
	}
}

// Every node must compute the SAME relay set from the same inputs, whichever
// node is asking. A relay set that depends on who is looking is not a
// topology, it is a disagreement.
func TestComputeRelays_IsIdenticalFromEveryVantagePoint(t *testing.T) {
	all := []string{"node-a", "node-b", "node-c", "node-d", "node-e"}
	eligible := map[string]bool{"node-c": true, "node-d": true, "node-e": true}
	cfg := RelayConfig{BaseRelays: 2, NodesPerRelay: 50}

	var first []string
	for _, self := range all {
		others := make([]string, 0, len(all)-1)
		for _, n := range all {
			if n != self {
				others = append(others, n)
			}
		}
		rs := ComputeRelays(peers(others...), self, cfg, eligible)
		if first == nil {
			first = rs.Relays()
			continue
		}
		if len(rs.Relays()) != len(first) {
			t.Fatalf("from %s relays = %v, but from %s = %v", self, rs.Relays(), all[0], first)
		}
		for i := range first {
			if rs.Relays()[i] != first[i] {
				t.Fatalf("from %s relays = %v, but from %s = %v", self, rs.Relays(), all[0], first)
			}
		}
	}
}

// An ineligible node is still a LEAF — it must keep receiving replication.
// Only the relay ROLE is withheld; excluding it from the topology entirely
// would stop replicating to a host that is merely draining.
func TestComputeRelays_IneligibleNodesAreStillLeaves(t *testing.T) {
	members := peers("node-b", "node-c", "node-d", "node-e")
	eligible := map[string]bool{"node-c": true, "node-d": true, "node-e": true}

	rs := ComputeRelays(members, "node-a", RelayConfig{BaseRelays: 1, NodesPerRelay: 50}, eligible)

	if rs.IsRelay("node-b") {
		t.Fatal("node-b is ineligible and must not be a relay")
	}
	if pair := rs.AssignedRelays("node-b"); pair[0] == "" {
		t.Fatal("node-b must still be assigned a relay — an ineligible node is a leaf, not an outcast")
	}
}

// If the replicated state says NOBODY is eligible, the cluster must still
// replicate. A bad or transient state that elected zero relays would be a
// cluster-wide outage caused by a column.
func TestComputeRelays_NoEligibleNodesFallsBackRatherThanElectingNone(t *testing.T) {
	members := peers("node-b", "node-c", "node-d")

	rs := ComputeRelays(members, "node-a", RelayConfig{BaseRelays: 2, NodesPerRelay: 50},
		map[string]bool{})

	if len(rs.Relays()) == 0 {
		t.Fatal("no relays elected when no node is eligible; replication stops cluster-wide")
	}
}

// A nil eligibility map means "no information", which must behave exactly as
// before — the existing caller in self_upgrade passes nothing.
func TestComputeRelays_NilEligibilityIsUnchangedBehaviour(t *testing.T) {
	members := peers("node-b", "node-c", "node-d")
	cfg := RelayConfig{BaseRelays: 2, NodesPerRelay: 50}

	rs := ComputeRelays(members, "node-a", cfg, nil)

	// Sorted order, first R.
	want := []string{"node-a", "node-b", "node-c"}
	if len(rs.Relays()) != len(want) {
		t.Fatalf("relays = %v, want %v", rs.Relays(), want)
	}
	for i := range want {
		if rs.Relays()[i] != want[i] {
			t.Fatalf("relays = %v, want %v", rs.Relays(), want)
		}
	}
}

// When FEWER nodes are eligible than the cluster needs relays, the shortfall
// is filled from the ineligible ones rather than electing a smaller set.
//
// This is the path the all-ineligible test cannot reach: an EMPTY map means
// "no information" and short-circuits, so only a non-empty map that is too
// small exercises the fill. Dropping ineligible names instead of appending
// them silently shrinks R, and a cluster that needs 3 relays running on 1 is a
// bottleneck and a single point of failure.
func TestComputeRelays_ShortfallIsFilledNotShrunk(t *testing.T) {
	members := peers("node-b", "node-c", "node-d", "node-e")
	// 5 nodes, R = 2 + ceil(5/50) = 3, but only ONE eligible.
	eligible := map[string]bool{"node-e": true}

	rs := ComputeRelays(members, "node-a", RelayConfig{BaseRelays: 2, NodesPerRelay: 50}, eligible)

	if len(rs.Relays()) != 3 {
		t.Fatalf("relays = %v (%d), want 3 — the shortfall must be filled from ineligible "+
			"nodes, not silently reduce the relay count", rs.Relays(), len(rs.Relays()))
	}
	if !rs.IsRelay("node-e") {
		t.Errorf("relays = %v, want the one eligible node (node-e) among them", rs.Relays())
	}
	// A length check alone does not catch the real failure here. relayOrder is
	// built with spare capacity, so slicing past its length yields "" entries
	// that still COUNT as three relays while routing their leaves nowhere.
	for i, r := range rs.Relays() {
		if r == "" {
			t.Fatalf("relays[%d] is empty (%v) — the selection sliced into spare capacity", i, rs.Relays())
		}
	}
}

// relayEligibleStates decides which hosts.state values may carry relay duty.
// A host that is fenced or offline is exactly the one whose election broke
// replication, so admitting it defeats the fix.
func TestRelayEligibleHosts_OnlyActiveNonWitnessHosts(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer c.Close()
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	for _, h := range []HostRecord{
		{Name: "act", Address: "10.0.0.1", State: "active"},
		{Name: "off", Address: "10.0.0.2", State: "offline"},
		{Name: "fen", Address: "10.0.0.3", State: "fenced"},
		{Name: "drn", Address: "10.0.0.4", State: "draining"},
		{Name: "mnt", Address: "10.0.0.5", State: "maintenance"},
		{Name: "upg", Address: "10.0.0.6", State: "upgrading"},
		// An ACTIVE witness. It passes the state test and must still be
		// refused: a witness hosts no workloads and exists to break ties, so
		// handing it the cluster's replication fan-out inverts its purpose.
		{Name: "wit", Address: "10.0.0.7", State: "active", Role: "witness"},
	} {
		if err := InsertHost(ctx, c, h); err != nil {
			t.Fatalf("InsertHost(%s): %v", h.Name, err)
		}
	}

	got := RelayEligibleHosts(ctx, c)

	if !got["act"] {
		t.Error("an active host must be relay-eligible")
	}
	for _, bad := range []string{"off", "fen", "drn", "mnt", "upg", "wit"} {
		if got[bad] {
			t.Errorf("host in state %q was marked relay-eligible; electing it routes its "+
				"leaves' replication into a hole", bad)
		}
	}
	if len(got) != 1 {
		t.Errorf("eligible = %v, want only the active host", got)
	}
}
