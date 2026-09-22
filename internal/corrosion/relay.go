package corrosion

import (
	"context"
	"log/slog"
	"sort"
	"time"
)

// RelayConfig holds tunables for the Crescent relay protocol.
type RelayConfig struct {
	BaseRelays      int           // minimum relay count (default 3)
	NodesPerRelay   int           // add 1 relay per this many nodes (default 50)
	FallbackTimeout time.Duration // leaf fallback activation threshold (default 15s)
}

func (c RelayConfig) withDefaults() RelayConfig {
	if c.BaseRelays <= 0 {
		c.BaseRelays = 3
	}
	if c.NodesPerRelay <= 0 {
		c.NodesPerRelay = 50
	}
	if c.FallbackTimeout <= 0 {
		c.FallbackTimeout = 15 * time.Second
	}
	return c
}

// RelaySet represents the current set of elected relays and leaf-to-relay assignments.
type RelaySet struct {
	relays          []string             // sorted relay hostnames
	set             map[string]bool      // O(1) relay lookup
	leafAssignments map[string][2]string // leaf → [primary, backup] relay
	relayLeaves     map[string][]string  // relay → assigned leaves
}

// relayEligibleStates are the hosts.state values fit to carry relay duty.
//
// Only `active` qualifies. A host that is offline, fenced, draining,
// upgrading or in maintenance is either unreachable or on its way out, and
// electing it a relay routes its leaves' replication into a hole. The value is
// read from replicated state, so every node reaches the same verdict.
var relayEligibleStates = map[string]bool{"active": true}

// RelayEligibleHosts reads the hosts table for the set fit to relay.
//
// A read error yields nil, which ComputeRelays treats as "no information" and
// falls back to the original sorted-hostname selection — degraded, but never
// an empty relay set.
//
// Witnesses are excluded: they host no workloads and exist to break ties, so
// handing them the cluster's replication fan-out is the opposite of their
// purpose.
func RelayEligibleHosts(ctx context.Context, c *Client) map[string]bool {
	hosts, err := ListHosts(ctx, c)
	if err != nil {
		slog.Warn("relay: read host states for eligibility; falling back to name order", "error", err)
		return nil
	}
	out := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if h.IsWitness() {
			continue
		}
		if relayEligibleStates[h.State] {
			out[h.Name] = true
		}
	}
	return out
}

// ComputeRelays deterministically selects relays from the memberlist and assigns
// leaves to relays. All nodes compute the same result from the same member list.
//
// R = min(N, BaseRelays + ceil(N / NodesPerRelay))
// Relays: the first R nodes by sorted hostname, ELIGIBLE ones first.
// Leaf assignment: primary = relays[leafIndex % R], backup = relays[(leafIndex+1) % R].
//
// relayEligible names the hosts fit to carry relay duty. Selection used to be
// sorted hostname alone, so two hosts early in the alphabet that were offline
// or fenced took the cluster's relay duty with them and every leaf assigned to
// them stopped replicating.
//
// It must come from REPLICATED state — hosts.state, which every node has
// converged on — and never from a node's own reachability opinion. The relay
// set is only useful if every node computes the SAME one: a leaf pushing to a
// relay that does not itself believe it is a relay forwards nothing, so a
// topology that differs by who is asking is not a topology but a
// disagreement. That is also why memberlist liveness is not used here; it is
// each node's local view, and it describes the gossip port rather than the
// replication one.
//
// A nil map means "no information" and reproduces the original ordering
// exactly, which is what the self-upgrade caller wants.
//
// Ineligibility withholds the relay ROLE only. An ineligible node stays a
// LEAF and keeps receiving replication — a draining host still needs its data,
// and dropping it from the topology would be a worse bug than the one this
// fixes.
func ComputeRelays(members []PeerInfo, selfName string, cfg RelayConfig, relayEligible map[string]bool) *RelaySet {
	cfg = cfg.withDefaults()

	// Build sorted list of all member names (including self).
	names := make([]string, 0, len(members)+1)
	nameSet := make(map[string]bool, len(members)+1)
	for _, m := range members {
		if !nameSet[m.Name] {
			names = append(names, m.Name)
			nameSet[m.Name] = true
		}
	}
	if !nameSet[selfName] {
		names = append(names, selfName)
	}
	sort.Strings(names)

	N := len(names)
	R := cfg.BaseRelays + (N+cfg.NodesPerRelay-1)/cfg.NodesPerRelay
	if R > N {
		R = N
	}

	// Eligible names first, then the rest, each half keeping sorted order. The
	// result is still a total order every node derives identically, so the
	// determinism the whole scheme rests on is unchanged.
	//
	// Ineligible names are APPENDED rather than dropped, which is what makes
	// the all-ineligible case safe: if the replicated state says no host is fit
	// — a transient during a rolling restart, or simply wrong — relays are
	// still elected and replication continues, degraded instead of stopped. A
	// column must not be able to cause a cluster-wide outage.
	relayOrder := names
	if len(relayEligible) > 0 {
		ordered := make([]string, 0, len(names))
		for _, n := range names {
			if relayEligible[n] {
				ordered = append(ordered, n)
			}
		}
		for _, n := range names {
			if !relayEligible[n] {
				ordered = append(ordered, n)
			}
		}
		relayOrder = ordered
	}

	// Clamp to what relayOrder actually HOLDS, not to what it can hold.
	// relayOrder is built with make([]string, 0, len(names)), so slicing past
	// its length silently reads spare capacity and yields relays named "" —
	// which would not panic, would not look wrong in a length check, and would
	// route every assigned leaf at nothing. It cannot trigger while the
	// ordering keeps all N names, which is exactly why it needs a guard rather
	// than an assumption.
	if R > len(relayOrder) {
		R = len(relayOrder)
	}

	// Relays are re-sorted so Relays() keeps its documented sorted order and
	// the leaf-assignment modulo stays stable; WHICH names are chosen is what
	// eligibility changes, not how they are ordered once chosen.
	chosen := append([]string(nil), relayOrder[:R]...)
	sort.Strings(chosen)

	rs := &RelaySet{
		relays:          chosen,
		set:             make(map[string]bool, R),
		leafAssignments: make(map[string][2]string),
		relayLeaves:     make(map[string][]string),
	}
	for _, r := range rs.relays {
		rs.set[r] = true
	}

	// Leaves are all non-relay nodes, in sorted order — including any node that
	// was ineligible for relay duty. It is a leaf, not an outcast.
	leaves := make([]string, 0, N-R)
	for _, n := range names {
		if !rs.set[n] {
			leaves = append(leaves, n)
		}
	}
	for i, leaf := range leaves {
		primary := rs.relays[i%R]
		backup := rs.relays[(i+1)%R]
		rs.leafAssignments[leaf] = [2]string{primary, backup}
		rs.relayLeaves[primary] = append(rs.relayLeaves[primary], leaf)
		if backup != primary {
			rs.relayLeaves[backup] = append(rs.relayLeaves[backup], leaf)
		}
	}

	return rs
}

// IsRelay returns whether the given hostname is an elected relay.
func (rs *RelaySet) IsRelay(hostname string) bool {
	return rs.set[hostname]
}

// Relays returns the sorted relay hostnames.
func (rs *RelaySet) Relays() []string {
	return rs.relays
}

// AssignedRelays returns the [primary, backup] relay pair for a leaf node.
// Returns zero value if the hostname is a relay or unknown.
func (rs *RelaySet) AssignedRelays(leaf string) [2]string {
	return rs.leafAssignments[leaf]
}

// AssignedLeaves returns which leaves a relay is responsible for fanning out to.
// Returns nil if the hostname is not a relay.
func (rs *RelaySet) AssignedLeaves(relay string) []string {
	return rs.relayLeaves[relay]
}

// TargetsFor returns the set of peer hostnames that a given node should
// maintain replication goroutines to.
//   - Relay: assigned leaves + all other relays
//   - Leaf: its 2 assigned relays
//   - Leaf in fallback: assigned relays + extraLeaves random non-relay peers
func (rs *RelaySet) TargetsFor(hostname string, fallback bool, extraLeaves []string) []string {
	if rs.IsRelay(hostname) {
		// Relay pushes to its assigned leaves + all other relays.
		var targets []string
		targets = append(targets, rs.relayLeaves[hostname]...)
		for _, r := range rs.relays {
			if r != hostname {
				targets = append(targets, r)
			}
		}
		return dedup(targets)
	}

	// Leaf pushes to its assigned relays.
	pair := rs.leafAssignments[hostname]
	targets := []string{pair[0], pair[1]}
	if fallback {
		targets = append(targets, extraLeaves...)
	}
	return dedup(targets)
}

func dedup(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
