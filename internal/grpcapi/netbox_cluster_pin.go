package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netboxsync"
)

// The `netbox.cluster_name` uniformity check.
//
// THE HAZARD. `netbox.cluster_name` names the NetBox `virtualization.cluster`
// this installation mirrors into. The mirror sweep runs on whichever node holds
// the `netbox` leader lease, so the value is a CLUSTER-WIDE fact even though it
// is read from each node's own config file: set it on some nodes only and
// whichever node leads decides that sweep. Objects get created under one cluster
// and deleted under another as leadership moves, and the ones left behind are
// invisible to every sweep resolving the other name — so nothing reaps them, and
// the inventory flaps for as long as the disagreement stands.
//
// WHY NOT A TOKEN. Every `enforcement.*` flag gets its uniformity from a
// capability latch, and this one cannot: a token is a NAME, advertised or not,
// and cannot carry the string two nodes must agree on. Advertising
// "netbox_cluster_name_configured" would prove that both nodes set the key, not
// that they set it to the same thing.
//
// WHY THE BINDING ROW. `netbox_bindings` already replicates and already holds
// the facts a binding validates against — observed_cidr, vrf_id,
// cluster_fingerprint — each pinned at bind time for the same reason: a value
// recomputed per node cannot disagree with anything, and a value pinned once can.
// So the first bind records the resolved name and every node compares its own
// resolution against it. No new cross-host publication mechanism, and no new
// place for a comparison to be forgotten.
//
// The alternative considered was a per-host published fingerprint, in the shape
// of `hosts.capacity_policy_hash`. It was not taken: nothing currently reads
// that column to detect disagreement, so it would mean building both the
// publication and the comparison, and the comparison would then have to decide
// what a DOWN host's stale published value means — a question the binding row
// never raises, because a pin is a fact about the cluster rather than about a
// peer that may or may not be reachable.
//
// WHAT IT DOES NOT COVER, AND WHAT DOES. A cluster running the inventory mirror
// with NO bound network has no binding row, so it has no pin and this check
// alone gives it no enforcement — and that shape is exactly where the hazard is
// undiluted, since the mirror is all such a cluster does. That gap is closed by
// the per-host publication in netbox_cluster_uniformity.go, which compares what
// each LIVE host published rather than what a binding recorded.
//
// Both checks stay. This one catches a cluster-wide RE-HOME, where every live
// node agrees with each other but not with the binding; the other catches LIVE
// DISAGREEMENT between nodes. Neither subsumes the other.

// netboxClusterMismatch is one node's disagreement with the cluster's pin.
type netboxClusterMismatch struct {
	// Resolved is what THIS node's configuration resolves to.
	Resolved string
	// Pinned is what the binding recorded at bind time.
	Pinned string
	// Network is the binding holding the pin, so an operator has something to
	// look at rather than a pair of strings.
	Network string
}

// String is the operator-facing sentence, used in the refusal, the log line and
// the health condition's evidence so all three say the same thing.
func (m netboxClusterMismatch) String() string {
	return fmt.Sprintf(
		"this node resolves NetBox cluster %q, but the binding for network %s is pinned to %q. "+
			"netbox.cluster_name must be identical on every node (or unset on every node): the "+
			"mirror sweep runs on whichever node holds the netbox leader lease, so a disagreement "+
			"moves the whole inventory between two virtualization.cluster objects as leadership "+
			"moves, and leaves the objects under the other name invisible to every later sweep. "+
			"Correct netbox.cluster_name on the node that is wrong and restart it",
		m.Resolved, m.Network, m.Pinned)
}

// netboxClusterPinDisagrees reports whether THIS node's resolved NetBox cluster
// name disagrees with any live binding's pin.
//
// FAIL CLOSED on anything it cannot establish. A resolution that errors, or a
// bindings read that fails, is not agreement — it is the absence of evidence,
// and the caller's decision (mirror, or re-key) rewrites shared inventory. The
// error is returned separately from the mismatch so a caller can tell "we
// disagree" from "we could not tell", and both stop the operation.
//
// An EMPTY pin is passed over. The resolution never yields an empty string — it
// is the override, the local cluster name, or the placeholder — so the only row
// that reads back empty is one written before the column existed, on a database
// created by an earlier build of this branch. Such a row recorded no opinion and
// therefore cannot disagree; refusing on it would take a mirror out of service
// on the strength of no evidence.
//
// FIRST mismatch, not all of them. Every binding of one cluster pins the same
// resolved name, so a second disagreement would be the same disagreement
// reported twice.
func (s *Server) netboxClusterPinDisagrees(ctx context.Context) (netboxClusterMismatch, bool, error) {
	if s.db == nil {
		return netboxClusterMismatch{}, false, fmt.Errorf("no cluster database")
	}
	resolved, err := netboxsync.ClusterName(ctx, s.db, s.netboxClusterName)
	if err != nil {
		return netboxClusterMismatch{}, false, fmt.Errorf("resolve the NetBox cluster name: %w", err)
	}
	bindings, err := corrosion.ListBindings(ctx, s.db)
	if err != nil {
		return netboxClusterMismatch{}, false, fmt.Errorf("list bindings: %w", err)
	}
	return firstClusterPinMismatch(resolved, bindings)
}

// firstClusterPinMismatch is the comparison itself, over rows already read.
//
// Split out so the callers that ALREADY hold the binding list — revalidation
// reads it to check drift — do not read it a second time, and so the rule is
// stated once. The error return is always nil; it exists to match
// netboxClusterPinDisagrees's shape at the call sites that share the reporting.
func firstClusterPinMismatch(resolved string, bindings []corrosion.BindingRecord) (netboxClusterMismatch, bool, error) {
	for _, b := range bindings {
		if b.NetBoxCluster == "" || b.NetBoxCluster == resolved {
			continue
		}
		return netboxClusterMismatch{
			Resolved: resolved, Pinned: b.NetBoxCluster, Network: b.Network,
		}, true, nil
	}
	return netboxClusterMismatch{}, false, nil
}

// netboxClusterPinAgrees is the boolean gate the mirror's per-pass check uses.
//
// It collapses "disagrees" and "could not tell" into the same answer, because
// the mirror has nothing useful to do with the difference: both mean this node
// may not write inventory this pass. The distinction is preserved where an
// operator is waiting on it — the re-key refusal — and in the log line here.
func (s *Server) netboxClusterPinAgrees(ctx context.Context) bool {
	m, bad, err := s.netboxClusterPinDisagrees(ctx)
	if err != nil {
		slog.Warn("netbox mirror: could not check netbox.cluster_name against the cluster's pin; "+
			"declining this pass", "error", err)
		return false
	}
	if bad {
		slog.Warn("netbox mirror: declining this pass — netbox.cluster_name disagrees with the "+
			"cluster's pinned value", "resolved", m.Resolved, "pinned", m.Pinned,
			"network", m.Network)
		return false
	}
	return true
}

// netboxMirrorPassAuthorized is the mirror's WHOLE per-pass gate: the opt-in and
// both latches, then the cluster-name pin.
//
// The pin check is here rather than inside netboxMirrorAuthorized because it
// takes a context and does two local reads, and netboxMirrorAuthorized is also
// what gates enqueueMirrorSync on every VM lifecycle operation. Queuing a row is
// not a NetBox write — the row is a latency hint the leader drains, and the
// leader is by definition a node that passed this check — so paying two queries
// per lifecycle call to suppress it would buy nothing.
//
// Ordered cheapest-first, and that ordering is load-bearing: a node that has not
// opted in must not run two queries per pass to discover it, and more
// importantly a cluster with no NetBox latch must reach the end of a pass having
// touched nothing at all.
func (s *Server) netboxMirrorPassAuthorized(ctx context.Context) bool {
	return s.netboxMirrorAuthorized() &&
		s.netboxClusterPinAgrees(ctx) &&
		s.netboxClusterUniformityAgrees(ctx)
}

// requireNetBoxClusterAgreement is the LOUD form, for an operator-initiated
// operation that resolves the same cluster object the mirror does.
//
// A re-key rewrites every identity under the resolved cluster. Run on a node
// whose configuration disagrees it would re-stamp objects in the wrong cluster —
// or create that cluster and strand the real inventory — and report success
// while doing it. So unlike a sweep, which has another tick coming and declines
// in silence, this refuses with both values named: the operator is the one who
// can fix it, and cannot without knowing which two values disagree.
func (s *Server) requireNetBoxClusterAgreement(ctx context.Context) error {
	m, bad, err := s.netboxClusterPinDisagrees(ctx)
	if err != nil {
		return fmt.Errorf("could not verify netbox.cluster_name against the cluster's pinned "+
			"value, so nothing was rewritten: %w", err)
	}
	if bad {
		return fmt.Errorf("%s", m)
	}
	return nil
}
