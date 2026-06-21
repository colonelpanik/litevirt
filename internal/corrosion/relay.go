package corrosion

import (
	"sort"
	"time"
)

// RelayConfig holds tunables for the Crescent relay protocol.
type RelayConfig struct {
	BaseRelays    int           // minimum relay count (default 3)
	NodesPerRelay int           // add 1 relay per this many nodes (default 50)
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
	relays          []string           // sorted relay hostnames
	set             map[string]bool    // O(1) relay lookup
	leafAssignments map[string][2]string // leaf → [primary, backup] relay
	relayLeaves     map[string][]string  // relay → assigned leaves
}

// ComputeRelays deterministically selects relays from the memberlist and assigns
// leaves to relays. All nodes compute the same result from the same member list.
//
// R = min(N, BaseRelays + ceil(N / NodesPerRelay))
// Relays: first R nodes by sorted hostname.
// Leaf assignment: primary = relays[leafIndex % R], backup = relays[(leafIndex+1) % R].
func ComputeRelays(members []PeerInfo, selfName string, cfg RelayConfig) *RelaySet {
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
	R := cfg.BaseRelays + (N + cfg.NodesPerRelay - 1) / cfg.NodesPerRelay
	if R > N {
		R = N
	}

	rs := &RelaySet{
		relays:          names[:R],
		set:             make(map[string]bool, R),
		leafAssignments: make(map[string][2]string),
		relayLeaves:     make(map[string][]string),
	}
	for _, r := range rs.relays {
		rs.set[r] = true
	}

	// Leaves are all non-relay nodes, in sorted order.
	leaves := names[R:]
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
