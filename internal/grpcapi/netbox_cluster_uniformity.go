package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/netboxsync"
)

// The PER-HOST half of the `netbox.cluster_name` uniformity enforcement.
//
// WHAT THE BINDING PIN CANNOT SEE. netbox_cluster_pin.go compares this node's
// resolved name against the name the first bind recorded on the binding row.
// That catches a cluster-wide change away from the pin. It cannot catch anything
// on a cluster that mirrors inventory with NO BOUND NETWORK: there is no binding
// row, so there is no pin, so there is no enforcement — and that shape is where
// the hazard is undiluted, since mirroring is the only thing such a cluster does
// with NetBox (tests/fleet/netbox_rekey_mirror_only_test.go covers it).
//
// BOTH CHECKS STAY, because neither subsumes the other:
//
//   - this one catches LIVE DISAGREEMENT between nodes, which is what makes
//     inventory flap: the sweep runs on whichever node holds the `netbox` lease,
//     so two nodes resolving different names create objects under one cluster
//     and delete them under another as leadership moves;
//   - the pin catches a cluster-wide RE-HOME, where every live node agrees with
//     each other but not with the binding — which would silently move an
//     existing inventory into a different NetBox cluster and strand everything
//     already written under the old name.
//
// DECLARE, THEN COMPARE. The gate publishes this node's resolved name before it
// compares. That ordering is what makes the absence of a peer's row safe to pass
// over: a node that has not published has not run this gate, and a node that has
// not run this gate has not mirrored, so it cannot be flapping anything. Were
// publication somewhere else, a node could mirror in the window before its first
// publication and the comparison would be reasoning from an incomplete set while
// believing it was complete.
//
// ONLY LIVE HOSTS COUNT. A host that is down, in maintenance, fenced or
// decommissioned keeps its published row — nothing deletes a departed node's
// publication — and must not be able to stop mirroring forever by holding a
// stale value. The live set is the health checker's own predicate,
// health.VotingEligible over the replicated `hosts` rows: the same one the
// quorum denominator uses, not a fourth answer to "is this host live".
//
// NOT HealthyPeers, which the orphan sweeper uses for REACHABILITY. That answer
// additionally requires a successful probe this run, so it differs per node and
// is empty on a freshly started daemon — two nodes would disagree about who is
// live, and a node that had just restarted would count nobody and mirror freely.
// Host state is replicated, so every node computes the same set and a
// disagreement stops BOTH nodes rather than whichever one happened to have
// probed the other.
//
// THE ONE WINDOW IT DOES NOT CLOSE. A node compares against the rows that exist
// when it runs, so the FIRST pass after the latch forms can compare against a
// set that does not yet include a peer which has not had its own first pass. One
// pass can therefore mirror under a disagreement, after which every pass on
// every node refuses and says so. Requiring that every live host has published
// would close it and was rejected: the latch is monotone and durable, so a host
// joining later with `netbox.enabled` off would be live, would never publish,
// and would block mirroring permanently — a worse failure than one bounded,
// self-announcing pass.
//
// THE NAME, NOT A HASH. `hosts.capacity_policy_hash` — the precedent for a
// per-host published config fingerprint — hashes because an admission policy is
// a compound structure with no useful short rendering. A cluster name already IS
// a short human string, and the health condition below has to name both values
// and the host holding the other one: an operator cannot correct a disagreement
// they cannot read, and two differing hashes say only that something differs.

// errNetBoxClusterNotYetComparable means the comparison has not become possible
// yet, as distinct from having failed. It is returned before the latch that
// makes the publication safe to replicate exists, which on a young cluster is
// every pass — so callers skip it in silence rather than logging a warning
// fifteen minutes apart forever.
var errNetBoxClusterNotYetComparable = errors.New("netbox cluster-name uniformity is not yet comparable")

// netboxClusterDisagreement is one node's disagreement with its live peers.
type netboxClusterDisagreement struct {
	// Resolved is what THIS node's configuration resolves to.
	Resolved string
	// Others maps each differing published value to the live hosts publishing
	// it, sorted. A map rather than a first-mismatch, because with three nodes
	// and three values the operator needs all of them to know which one is the
	// odd one out.
	Others map[string][]string
}

// hosts is every live host holding a differing value, for the condition's
// evidence field (conditionEvidence.Hosts).
func (d netboxClusterDisagreement) hosts() []string {
	var out []string
	for _, hs := range d.Others {
		out = append(out, hs...)
	}
	sort.Strings(out)
	return out
}

// String is the operator-facing sentence, used in the log line and the health
// condition's evidence so both say the same thing.
func (d netboxClusterDisagreement) String() string {
	var parts []string
	for value, hs := range d.Others {
		parts = append(parts, fmt.Sprintf("%q on %s", value, strings.Join(hs, ", ")))
	}
	sort.Strings(parts)
	return fmt.Sprintf(
		"this node resolves NetBox cluster %q, but live peers resolve %s. netbox.cluster_name "+
			"must be identical on every node (or unset on every node): the mirror sweep runs on "+
			"whichever node holds the netbox leader lease, so a disagreement moves the whole "+
			"inventory between two virtualization.cluster objects as leadership moves, and leaves "+
			"the objects under the other name invisible to every later sweep. Correct "+
			"netbox.cluster_name on the node that is wrong and restart it. The inventory mirror "+
			"declines every pass until they agree",
		d.Resolved, strings.Join(parts, "; "))
}

// declareAndCompareNetBoxCluster publishes this node's resolved NetBox cluster
// name and reports whether any LIVE host published a different one.
//
// FAIL CLOSED on anything it cannot establish, and the error is returned
// separately from the disagreement so a caller can tell "we disagree" from "we
// could not tell". Both stop the mirror; only the first is worth naming in a
// health condition, because the second names no second value.
//
// A publication FAILURE is one of those things. Failing to publish leaves peers
// unable to see this node's opinion, and a node whose opinion nobody can see is
// exactly the node that must not go on to mirror on the strength of a comparison
// that therefore excludes it.
func (s *Server) declareAndCompareNetBoxCluster(ctx context.Context) (netboxClusterDisagreement, bool, error) {
	if s.db == nil {
		return netboxClusterDisagreement{}, false, fmt.Errorf("no cluster database")
	}
	// netbox_host_config is a v51 table, so a peer whose ledgers do not carry
	// the statement shape would back-pressure its ENTIRE replication stream on
	// receiving one. Every netbox_* write waits for this latch for that reason;
	// this one has to check it explicitly, because unlike a binding suspend it
	// is reachable on a cluster that has never bound anything.
	//
	// Not a fail-open hole: mirroring itself requires this latch (and the mirror
	// token's), so a disagreement cannot flap an inventory before it forms.
	if s.gate == nil || !s.gate.DurablyLatched(capabilities.NetBoxIPAMV1) {
		return netboxClusterDisagreement{}, false, fmt.Errorf("%w: %s is not durably latched",
			errNetBoxClusterNotYetComparable, capabilities.NetBoxIPAMV1)
	}
	resolved, err := netboxsync.ClusterName(ctx, s.db, s.netboxClusterName)
	if err != nil {
		return netboxClusterDisagreement{}, false, fmt.Errorf("resolve the NetBox cluster name: %w", err)
	}
	if err := corrosion.PublishNetBoxHostConfig(ctx, s.db, s.hostName, resolved); err != nil {
		return netboxClusterDisagreement{}, false, fmt.Errorf(
			"publish this node's NetBox cluster name so peers can compare against it: %w", err)
	}
	published, err := corrosion.ListNetBoxHostConfig(ctx, s.db)
	if err != nil {
		return netboxClusterDisagreement{}, false, err
	}

	live, err := s.liveHostsForNetBoxUniformity(ctx)
	if err != nil {
		return netboxClusterDisagreement{}, false, err
	}
	d := netboxClusterDisagreement{Resolved: resolved}
	for host, value := range published {
		if !live[host] || value == resolved {
			continue
		}
		// An EMPTY published value is passed over: the resolution never yields
		// an empty string, so an empty row is one written before this table
		// existed and records no opinion. Refusing on it would stop a mirror on
		// the strength of no evidence.
		if value == "" {
			continue
		}
		if d.Others == nil {
			d.Others = map[string][]string{}
		}
		d.Others[value] = append(d.Others[value], host)
	}
	for value := range d.Others {
		sort.Strings(d.Others[value])
	}
	return d, len(d.Others) > 0, nil
}

// liveHostsForNetBoxUniformity is the set whose published values count: every
// voting-eligible host, plus this node.
//
// Self is always in it, even if its own row is missing or its state reads
// offline. This node's resolved name is the value the comparison is made FROM,
// so excluding it would compare a set against a value not in it.
//
// FAIL CLOSED on an unreadable host table: it returns an error rather than an
// empty set, because "no live hosts" and "we could not tell who is live" must
// not produce the same answer — the first is a single-node cluster and the
// second is a node that may not compare anything.
func (s *Server) liveHostsForNetBoxUniformity(ctx context.Context) (map[string]bool, error) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("read the host table to decide which published values count: %w", err)
	}
	live := map[string]bool{s.hostName: true}
	for _, h := range hosts {
		if health.VotingEligible(h.State) {
			live[h.Name] = true
		}
	}
	return live, nil
}

// netboxClusterUniformityAgrees is the boolean gate the mirror's per-pass check
// uses. It collapses "disagrees" and "could not tell" into the same answer, for
// the same reason netboxClusterPinAgrees does: the mirror has nothing useful to
// do with the difference, since both mean this node may not write inventory this
// pass.
func (s *Server) netboxClusterUniformityAgrees(ctx context.Context) bool {
	d, bad, err := s.declareAndCompareNetBoxCluster(ctx)
	if errors.Is(err, errNetBoxClusterNotYetComparable) {
		// Unreachable through the mirror's gate, which already requires the
		// latch — kept because this function's contract is "may this node
		// mirror", and the answer while the latch is absent is no.
		return false
	}
	if err != nil {
		slog.Warn("netbox mirror: could not establish that netbox.cluster_name is uniform across "+
			"live hosts; declining this pass", "error", err)
		return false
	}
	if bad {
		slog.Warn("netbox mirror: declining this pass — netbox.cluster_name disagrees with a live "+
			"peer", "resolved", d.Resolved, "peers", d.hosts())
		return false
	}
	return true
}

// evaluateNetBoxClusterUniformity advances condNetBoxClusterNameDisagreement for
// THIS host.
//
// Per-node and scoped to this host's own subject, exactly like the pin's
// finding: every configured node runs revalidation, and a node that agrees with
// its peers must not clean-count a subject belonging to one that does not — it
// would resolve the other node's finding within two passes while the
// misconfiguration stood.
//
// Note that on a genuine disagreement EVERY node raises its own row, and that is
// correct rather than duplication: with two nodes holding two values, neither is
// authoritative, and a finding on only one of them would point the operator at
// whichever node happened to evaluate first.
func (s *Server) evaluateNetBoxClusterUniformity(ctx context.Context) {
	positive := map[string]string{}
	d, bad, err := s.declareAndCompareNetBoxCluster(ctx)
	if errors.Is(err, errNetBoxClusterNotYetComparable) {
		return
	}
	if err != nil {
		// Neither agreement nor disagreement. The mirror declines a pass it
		// cannot verify; raising a DISAGREEMENT here would name a second value
		// this node never read.
		slog.Warn("netbox health: could not compare netbox.cluster_name across live hosts",
			"error", err)
		return
	}
	if bad {
		positive[s.hostName] = d.String()
	}
	s.applyNetBoxConditionsScoped(ctx, condNetBoxClusterNameDisagreement, "host", positive,
		func(subject string) bool { return subject == s.hostName },
		d.hosts()...)
}
