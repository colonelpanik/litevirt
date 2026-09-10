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
// PUBLISH, THEN COMPARE — as two steps, not one. The publication used to happen
// INSIDE the comparison, which made a predicate that reads like a query into
// something with a write in it, called from two places. Worse, it justified
// passing over a peer with no published row at all: "a node that has not
// published has not run this gate, so it cannot be flapping anything". That
// reasoning is sound about the PEER and unsound about THIS node — on its own
// first pass a node published, compared against a set that did not yet include a
// peer with no pass of its own, and mirrored. One bounded pass under a
// disagreement it could not see, which is one pass in which the inventory is
// written under the wrong cluster.
//
// So an absent publication from a LIVE host now FAILS CLOSED: the pass declines
// and a health condition names the hosts whose value is missing. That wait is
// bounded for a host that is coming up — every configured node publishes on its
// own first pass — and a host that has LEFT is excluded by the same predicate
// that excludes a stale disagreeing value, as is a witness (for a reason that is
// NOT "a witness cannot mirror" — see liveHostsForNetBoxUniformity). It is NOT
// bounded for a live worker running with `netbox.enabled` off: nothing
// excludes that node, so it blocks until somebody acts, which is
// why the condition names the hosts it is waiting for. See WHAT IT STILL DOES
// NOT CLOSE below; the two paragraphs must not disagree, and they used to.
// Stopping the mirror costs stale inventory; mirroring under an unverified set
// costs objects written under the wrong cluster name, and this branch ranks a
// leak above a collision.
//
// ONLY LIVE HOSTS COUNT, MINUS WITNESSES. A host that is down, in maintenance,
// fenced or decommissioned keeps its published row — nothing deletes a departed
// node's publication — and must not be able to stop mirroring forever by
// holding a stale value. The live set is the health checker's own predicate,
// health.VotingEligible over the replicated `hosts` rows: the same one the
// quorum denominator uses, not a fourth answer to "is this host live".
// Witnesses are then subtracted, because VotingEligible deliberately includes
// them and a witness has no reason to be configured for NetBox at all. What
// makes subtracting them safe is NOT that a witness cannot mirror — it can —
// but that an excluded node still gates itself; the whole argument, and the one
// case it does not cover, is in liveHostsForNetBoxUniformity.
//
// NOT HealthyPeers, which the orphan sweeper uses for REACHABILITY. That answer
// additionally requires a successful probe this run, so it differs per node and
// is empty on a freshly started daemon — two nodes would disagree about who is
// live, and a node that had just restarted would count nobody and mirror freely.
// Host state is replicated, so every node computes the same set and a
// disagreement stops BOTH nodes rather than whichever one happened to have
// probed the other.
//
// WHAT IT STILL DOES NOT CLOSE. The wait is on LIVE hosts, and host state is
// replicated, so a node that has stopped without being demoted to offline yet is
// waited for until demotion catches up (minutes). That is the fail-closed
// direction and mirroring is a convergence loop, so nothing is lost but
// freshness. The case that BLOCKS PERMANENTLY — a live worker running with
// `netbox.enabled` off, which never publishes because it runs no NetBox pass —
// is why the condition names the hosts it is waiting for: the block is visible
// and has a remedy (configure NetBox there, or take the node out), rather than
// being a mirror that quietly stopped. Nothing in the predicate excludes such a
// node, and nothing should: an unconfigured worker can be given the config, and
// guessing that its silence is benign is the assumption that wrote an inventory
// under the wrong cluster name in the first place.
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

// netboxClusterDisagreement is what one comparison found: which live peers
// resolve a different name, and which have not said yet.
type netboxClusterDisagreement struct {
	// Resolved is what THIS node's configuration resolves to.
	Resolved string
	// Others maps each differing published value to the live hosts publishing
	// it, sorted. A map rather than a first-mismatch, because with three nodes
	// and three values the operator needs all of them to know which one is the
	// odd one out.
	Others map[string][]string
	// Silent is every LIVE host with no published value, sorted. Its own field
	// rather than a differing value of "", because the two are different
	// findings with different remedies: a disagreement names a value to correct,
	// and this names a node that has not spoken. Both stop the mirror.
	Silent []string
}

// bad reports whether this comparison stops the mirror. Either finding does.
func (d netboxClusterDisagreement) bad() bool {
	return len(d.Others) > 0 || len(d.Silent) > 0
}

// hosts is every live host this finding is ABOUT, for the condition's structured
// evidence field (conditionEvidence.Hosts).
func (d netboxClusterDisagreement) hosts() []string {
	var out []string
	for _, hs := range d.Others {
		out = append(out, hs...)
	}
	out = append(out, d.Silent...)
	sort.Strings(out)
	return out
}

// silentString is the operator-facing sentence for the SILENT half.
//
// Separate from String because it is a different fault: nothing is
// misconfigured, this node simply cannot establish uniformity yet. It has to
// name the hosts, because a mirror that has stopped and says only "declining"
// leaves an operator with nowhere to go — and the one shape that does not
// resolve on its own is a live node running with `netbox.enabled` off, which is
// only diagnosable from the name.
func (d netboxClusterDisagreement) silentString() string {
	return fmt.Sprintf(
		"this node resolves NetBox cluster %q, but %d live host(s) have published no resolved "+
			"name yet: %s. netbox.cluster_name has to be identical on every node, and a host "+
			"that has not published one cannot be compared against — so the inventory mirror "+
			"DECLINES every pass until it does, rather than mirroring against a set it cannot "+
			"prove is complete. Every node configured for NetBox publishes on its first "+
			"maintenance pass, so this normally clears itself within one interval. If it does "+
			"not, that host is not running NetBox at all (`netbox.enabled`): enable it there, or "+
			"remove the host from the cluster",
		d.Resolved, len(d.Silent), strings.Join(d.Silent, ", "))
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

// netboxClusterComparable is the precondition BOTH steps share: a database, and
// the latch that makes writing `netbox_host_config` safe.
//
// netbox_host_config is a v51 table, so a peer whose ledgers do not carry the
// statement shape would back-pressure its ENTIRE replication stream on receiving
// one. Every netbox_* write waits for this latch for that reason; this one has to
// check it explicitly, because unlike a binding suspend it is reachable on a
// cluster that has never bound anything.
//
// Not a fail-open hole: mirroring itself requires this latch (and the mirror
// token's), so a disagreement cannot flap an inventory before it forms.
func (s *Server) netboxClusterComparable() error {
	if s.db == nil {
		return fmt.Errorf("no cluster database")
	}
	if s.gate == nil || !s.gate.DurablyLatched(capabilities.NetBoxIPAMV1) {
		return fmt.Errorf("%w: %s is not durably latched",
			errNetBoxClusterNotYetComparable, capabilities.NetBoxIPAMV1)
	}
	return nil
}

// publishNetBoxClusterName declares this node's resolved NetBox cluster name so
// peers can compare against it. THE WRITE, on its own.
//
// It used to live inside the comparison. Separating it is not cosmetic: a
// predicate with a side effect cannot be reasoned about at its call sites, and
// this one has two — the mirror's per-pass gate and the health evaluator — which
// between them meant the publication happened as a consequence of asking a
// question.
//
// A publication FAILURE stops the caller. Failing to publish leaves peers unable
// to see this node's opinion, and a node whose opinion nobody can see is exactly
// the node that must not go on to mirror on the strength of a comparison that
// therefore excludes it.
func (s *Server) publishNetBoxClusterName(ctx context.Context) error {
	if err := s.netboxClusterComparable(); err != nil {
		return err
	}
	resolved, err := netboxsync.ClusterName(ctx, s.db, s.netboxClusterName)
	if err != nil {
		return fmt.Errorf("resolve the NetBox cluster name: %w", err)
	}
	if err := corrosion.PublishNetBoxHostConfig(ctx, s.db, s.hostName, resolved); err != nil {
		return fmt.Errorf(
			"publish this node's NetBox cluster name so peers can compare against it: %w", err)
	}
	return nil
}

// compareNetBoxClusterName reports what the LIVE hosts have published against
// what this node resolves. A PURE READ — it writes nothing.
//
// FAIL CLOSED on anything it cannot establish, and the error is returned
// separately from the finding so a caller can tell "we disagree" from "we could
// not tell". Both stop the mirror; only the first two are worth naming in a
// health condition, because a read failure names no second value.
//
// A LIVE HOST WITH NO PUBLICATION IS A FINDING, not something to pass over. It
// used to be passed over on the argument that a node which has not published has
// not run this gate and so cannot be flapping anything — true of the peer, and
// beside the point for this node, which would go on to mirror against a set it
// could not prove was complete. See the file header.
func (s *Server) compareNetBoxClusterName(ctx context.Context) (netboxClusterDisagreement, error) {
	if err := s.netboxClusterComparable(); err != nil {
		return netboxClusterDisagreement{}, err
	}
	resolved, err := netboxsync.ClusterName(ctx, s.db, s.netboxClusterName)
	if err != nil {
		return netboxClusterDisagreement{}, fmt.Errorf("resolve the NetBox cluster name: %w", err)
	}
	published, err := corrosion.ListNetBoxHostConfig(ctx, s.db)
	if err != nil {
		return netboxClusterDisagreement{}, err
	}
	live, err := s.liveHostsForNetBoxUniformity(ctx)
	if err != nil {
		return netboxClusterDisagreement{}, err
	}

	d := netboxClusterDisagreement{Resolved: resolved}
	for host := range live {
		if host == s.hostName {
			// This node's own value is what the comparison is made FROM, and it
			// is `resolved` — read from config, not from the row it just wrote.
			// Reading its own row back would make the answer depend on whether
			// the write had landed, which is a question about SQLite and not
			// about configuration.
			continue
		}
		// An EMPTY value is treated as UNPUBLISHED, not as a differing one. The
		// resolution never yields an empty string, so an empty row records no
		// opinion — and "no opinion" is exactly the state that must now fail
		// closed rather than be passed over.
		switch value := published[host]; {
		case value == "":
			d.Silent = append(d.Silent, host)
		case value != resolved:
			if d.Others == nil {
				d.Others = map[string][]string{}
			}
			d.Others[value] = append(d.Others[value], host)
		}
	}
	for value := range d.Others {
		sort.Strings(d.Others[value])
	}
	sort.Strings(d.Silent)
	return d, nil
}

// liveHostsForNetBoxUniformity is the set whose published values count: every
// voting-eligible host that could actually mirror, plus this node.
//
// Self is always in it, even if its own row is missing or its state reads
// offline. This node's resolved name is the value the comparison is made FROM,
// so excluding it would compare a set against a value not in it.
//
// WITNESSES ARE EXCLUDED, and this is the most plausible permanent wedge in the
// whole gate. A witness votes and never hosts a workload, so it has no reason to
// be configured for NetBox at all — but health.VotingEligible counts witnesses
// (it has to: the quorum denominator does), and the gate blocks until every live
// host has published. A witness would therefore stop mirroring FOREVER on a
// cluster whose configuration is entirely correct, with no remedy but
// configuring NetBox on a node that does not need it or removing the witness.
//
// WHY THAT IS SAFE, AND IT IS NOT "A WITNESS NEVER MIRRORS". Nothing stops one:
// StartNetBoxMirror gates on a NetBox client plus `netbox.mirror_inventory`,
// acquireNetBoxLease has no role check, and the reconciler mirrors the whole
// CLUSTER's inventory rather than this host's share of it — so a witness
// configured for NetBox takes the lease and writes like any other node. The
// exclusion is safe for a different reason: excusing a node from OTHER nodes'
// sets does not excuse it from its own. An excluded witness still runs this
// comparison, still counts every live host IT has not excluded, and declines
// itself the moment one disagrees or has not spoken. The node this gate has to
// stop is the node that would mirror under a name its peers do not share, and
// that node is still fully gated — by itself.
//
// WHICH IS WHY THE EXCLUSION IS ONE-WAY. That argument needs the excused node to
// have somebody left to be gated by, and two witnesses have nobody: with no live
// non-witness host, each would compute a live set of {self}, agree with itself
// and mirror, and the two would delete each other's objects on every handover.
// So a witness does not excuse another witness — the exclusion is what a node
// still being watched grants to a node nobody is watching. A node with no `hosts`
// row of its own reads as a non-witness, which is the answer that keeps the
// ordinary worker-plus-witness cluster out of the wedge; the cost is a flap
// window for a witness whose own row has not replicated yet, on a cluster that
// has two of them and no worker.
//
// The sweeper's RUNTIME-PROOF SET (runtimeProofParticipants) excludes
// `role='witness'` too, but on its own ground and not this one: a negative proof
// is about who might be RUNNING the workload holding an address, and a witness
// hosts none. That reason does not transfer here, so this one is stated in full
// rather than borrowed. Note what the sweeper does NOT exclude a witness from —
// its membership-discovery fan-out, which asks every host what it knows, and its
// inventory-corroboration set, which asks every host what rows it holds. A
// witness is excused from the SCAN and from nothing else.
//
// Self is never excluded, by state or by role: this node's resolved name is the
// value the comparison is made FROM, so a set that dropped it would be compared
// against a value not in it. Seeding `live` with s.hostName is what guarantees
// that, which is why the loop below needs no self-exemption of its own — a
// non-witness self cannot match the role check anyway, and a witness self
// excludes nobody.
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
	// Whether THIS node is a witness decides whether it may excuse one: a node
	// its peers have stopped watching owes the comparison to its fellows.
	selfIsWitness := false
	for _, h := range hosts {
		if h.Name == s.hostName {
			selfIsWitness = h.IsWitness()
			break
		}
	}
	live := map[string]bool{s.hostName: true}
	for _, h := range hosts {
		if h.IsWitness() && !selfIsWitness {
			// A witness has nothing to be uniform about, and it gates itself.
			continue
		}
		if health.VotingEligible(h.State) {
			live[h.Name] = true
		}
	}
	return live, nil
}

// netboxClusterUniformityAgrees is the boolean gate the mirror's per-pass check
// uses. It collapses "disagrees", "nobody has said yet" and "could not tell"
// into the same answer, for the same reason netboxClusterPinAgrees does: the
// mirror has nothing useful to do with the difference, since all three mean this
// node may not write inventory this pass.
//
// PUBLISH FIRST, then compare — as two calls, so the order is visible here
// rather than buried in a predicate. Publishing first is what makes the wait
// below terminate: every configured node reaching this gate declares itself, so
// the set the comparison needs fills in on its own.
func (s *Server) netboxClusterUniformityAgrees(ctx context.Context) bool {
	if err := s.publishNetBoxClusterName(ctx); err != nil {
		if errors.Is(err, errNetBoxClusterNotYetComparable) {
			// Unreachable through the mirror's gate, which already requires the
			// latch — kept because this function's contract is "may this node
			// mirror", and the answer while the latch is absent is no.
			return false
		}
		slog.Warn("netbox mirror: could not publish this node's resolved netbox.cluster_name; "+
			"declining this pass", "error", err)
		return false
	}
	d, err := s.compareNetBoxClusterName(ctx)
	if err != nil {
		slog.Warn("netbox mirror: could not establish that netbox.cluster_name is uniform across "+
			"live hosts; declining this pass", "error", err)
		return false
	}
	if len(d.Others) > 0 {
		slog.Warn("netbox mirror: declining this pass — netbox.cluster_name disagrees with a live "+
			"peer", "resolved", d.Resolved, "peers", d.hosts())
		return false
	}
	if len(d.Silent) > 0 {
		slog.Warn("netbox mirror: declining this pass — a live host has published no resolved "+
			"netbox.cluster_name, so uniformity cannot be established yet",
			"resolved", d.Resolved, "silent", d.Silent)
		return false
	}
	return true
}

// evaluateNetBoxClusterUniformity advances the TWO per-host findings this
// comparison can produce: an actual disagreement, and a live host that has not
// published at all.
//
// Two codes rather than one, because they are different faults with different
// remedies — one names a value to correct, the other names a node that has not
// spoken — and because they resolve independently: a cluster can settle the
// silence and still disagree.
//
// Per-node and scoped to this host's own subject, exactly like the pin's
// finding: every configured node runs revalidation, and a node that agrees with
// its peers must not clean-count a subject belonging to one that does not — it
// would resolve the other node's finding within two passes while the
// misconfiguration stood.
//
// It PUBLISHES first, so a configured node contributes its opinion whether or
// not it ever mirrors — which is what makes the other nodes' wait terminate. A
// publication failure raises nothing (it names no second value) but is logged:
// the mirror's own gate declines on it.
//
// Note that on a genuine disagreement EVERY node raises its own row, and that is
// correct rather than duplication: with two nodes holding two values, neither is
// authoritative, and a finding on only one of them would point the operator at
// whichever node happened to evaluate first.
func (s *Server) evaluateNetBoxClusterUniformity(ctx context.Context) {
	if err := s.publishNetBoxClusterName(ctx); err != nil {
		if !errors.Is(err, errNetBoxClusterNotYetComparable) {
			slog.Warn("netbox health: could not publish this node's resolved netbox.cluster_name",
				"error", err)
		}
		return
	}
	d, err := s.compareNetBoxClusterName(ctx)
	if err != nil {
		if !errors.Is(err, errNetBoxClusterNotYetComparable) {
			// Neither agreement nor disagreement. The mirror declines a pass it
			// cannot verify; raising a DISAGREEMENT here would name a second
			// value this node never read.
			slog.Warn("netbox health: could not compare netbox.cluster_name across live hosts",
				"error", err)
		}
		return
	}

	disagree := map[string]string{}
	if len(d.Others) > 0 {
		disagree[s.hostName] = d.String()
	}
	s.applyNetBoxConditionsScoped(ctx, condNetBoxClusterNameDisagreement, "host", disagree,
		func(subject string) bool { return subject == s.hostName },
		d.hosts()...)

	silent := map[string]string{}
	if len(d.Silent) > 0 {
		silent[s.hostName] = d.silentString()
	}
	s.applyNetBoxConditionsScoped(ctx, condNetBoxClusterNameUnpublished, "host", silent,
		func(subject string) bool { return subject == s.hostName },
		d.Silent...)
}
