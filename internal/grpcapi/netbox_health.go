package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netboxsync"
	"github.com/litevirt/litevirt/internal/network"
)

// NetBox health findings.
//
// Two NetBox failures are SILENT to everything else litevirt reports. A
// suspended binding produces no error and disturbs no running workload — the
// first symptom is a create refusing, long after the fact. A sweep blocked on an
// unreachable host reclaims nothing and returns nothing, forever, while the
// address pool quietly fills with orphans. Both are counted (see
// internal/metrics/netbox.go), but a counter is only a finding if somebody is
// scraping it; these are durable health_conditions rows, so `lv health` says so.
//
// WHO WRITES: only the sweep pass, and the sweep runs under the `netbox` leader
// lease — so the cluster has one writer at a time, which is what the LWW row
// merge assumes. Nothing here runs on a node with no NetBox client.
//
// WHAT IS NOT HERE: a health_evaluator_status row. The maintenance cadence is
// 15 minutes by default and evaluatorScanTTL is 5, so a `netbox` evaluator row
// would report STALE almost all the time and pin every NetBox cluster at
// DEGRADED forever. Conditions stand on their own; coverage does not apply
// here anyway — both findings rest on rows this node reads directly, not on a
// fleet-wide absence proof.
const netboxEvaluator = "netbox"

const (
	// condNetBoxBindingSuspended: a bound prefix is refusing new allocations.
	// Subject is the NETWORK, because that is what an operator acts on.
	condNetBoxBindingSuspended = "netbox_binding_suspended"
	// condNetBoxSweepBlocked: reclamation has been impossible for several
	// consecutive passes because a host would not answer the proof.
	condNetBoxSweepBlocked = "netbox_sweep_blocked"
	// condNetBoxClusterNameMismatch: THIS node's netbox.cluster_name resolves to
	// a different NetBox cluster than the one the cluster's bindings are pinned
	// to, so this node refuses to mirror.
	//
	// Subject is the HOST, unlike the two above, and that is load-bearing. The
	// finding is about one node's configuration; every configured node evaluates
	// it for itself from its OWN config, which no peer can read. A finding keyed
	// on the network would have the agreeing nodes and the disagreeing one
	// writing one row under LWW, so the last writer would decide whether the
	// cluster has a problem.
	condNetBoxClusterNameMismatch = "netbox_cluster_name_mismatch"
	// condNetBoxClusterNameDisagreement: a LIVE PEER published a different
	// netbox.cluster_name than this node resolves, so this node refuses to
	// mirror. The other half of the same enforcement, and a separate code
	// because it catches a different fault and carries different evidence: the
	// mismatch above is this node against the cluster's PIN, which needs a bound
	// network to exist; this one is this node against its live peers, which is
	// the only check a mirror-only cluster has. Subject is the HOST, for the
	// reason above, and the evidence carries the peers holding the other value.
	condNetBoxClusterNameDisagreement = "netbox_cluster_name_disagreement"
	// condNetBoxClusterNameUnpublished: a LIVE host has published no resolved
	// `netbox.cluster_name` at all, so this node cannot establish that the
	// setting is uniform and declines to mirror.
	//
	// A separate code from the disagreement above because it is a different
	// fault with a different remedy: that one names a value to correct, this one
	// names a node that has not spoken. It is normally transient — every node
	// configured for NetBox publishes on its first maintenance pass — and the
	// one shape that does not clear itself is a live host running with
	// `netbox.enabled` off, which is only diagnosable from the host name the
	// evidence carries. Without the row, that state would be a mirror that had
	// silently stopped.
	condNetBoxClusterNameUnpublished = "netbox_cluster_name_unpublished"
	// condNetBoxDiscoveryUnclaimable: a guest on THIS host is using an address
	// on a bound network that NetBox will not grant it, so litevirt refused to
	// record it.
	//
	// The most serious of the five, and the one that had no `lv health` surface
	// at all — only an ERROR log and a counter, both of which have to be watched
	// or scraped to exist. reason=not_ours means NetBox holds that address for
	// something else, which is two things using one address: the collision the
	// whole feature exists to prevent, arriving from the one direction litevirt
	// cannot stop (a DHCP server it does not run).
	//
	// Subject is the HOST, like the two cluster-name findings and for the same
	// reason: the observation is this node's own runtime — which MAC is
	// answering where — and no peer can make it or contradict it. The VMs and
	// addresses are named in the evidence, which is what an operator acts on.
	condNetBoxDiscoveryUnclaimable = "netbox_discovery_unclaimable"
	// condNetBoxDHCPWouldRace: provisioning a bound network on THIS host would
	// start litevirt's own DHCP server over the bound prefix, so this host
	// refuses to provision it.
	//
	// The provision-time refusal is what closes the host-local half of the
	// hazard, and it has to stay: a bind is a cluster-wide decision and
	// "did litevirt have to create this bridge" is host-local runtime state no
	// row records. But the refusal DOES NOT FAIL THE PLACEMENT — every caller
	// logs it and creates the bridge itself — so on its own it speaks only in a
	// log line on one node, and goes quiet as soon as the bridge it warned about
	// exists. This finding is the same fact stated in advance and KEPT UP, on
	// the node it is about; see evaluateNetBoxDHCPConflicts for the second
	// predicate that stops it clearing itself.
	//
	// Subject is the HOST, for the same reason as its two neighbours: the input
	// is this node's own bridge state, which no peer can read.
	condNetBoxDHCPWouldRace = "netbox_dhcp_would_race"
)

// netboxSweepSubject is the single subject of condNetBoxSweepBlocked. The
// finding is about the SWEEP, which is cluster-wide and singular — naming the
// unreachable host instead would fork a condition per host and lose the "the
// sweeper has been stuck for three passes" fact that matters.
const netboxSweepSubject = "netbox"

// netboxSweepBlockedPasses is how many CONSECUTIVE passes must skip a
// reclamation for an unreachable host before the finding is raised.
//
// Three, not one: a host is briefly unreachable on every reboot and every
// daemon restart, and a finding that fires on those is noise an operator learns
// to ignore. Three consecutive passes (45 minutes at the default cadence) is a
// host that is not coming back on its own — and until it does, NOT ONE address
// can be reclaimed, because a negative proof that is not whole is not a proof.
const netboxSweepBlockedPasses = 3

// netboxCleanPasses is how many consecutive clean passes resolve a finding.
// Two, matching the durable-condition model elsewhere: one clean pass can be a
// probe racing a restart.
const netboxCleanPasses = 2

// beginSweepPass arms the per-pass skip record. Called once per sweep, after the
// leader lease is held.
func (s *Server) beginSweepPass() {
	s.nbSweepMu.Lock()
	defer s.nbSweepMu.Unlock()
	s.nbSweepUnreachable = false
}

// noteSweepSkip records ONE declined reclamation: the bounded metric label, and
// — for the health evaluator — whether this pass was blocked by a host that
// would not answer.
//
// The health evaluator cannot read the Prometheus counter (the sink is an
// interface the daemon injects, and a scrape is not available in-process), so
// the sweeper keeps the consecutive-pass state itself and the evaluator reads
// that. The streak is per-process on purpose: it is held by the lease holder,
// which is the only node sweeping, and a restart or a lease handover re-arms it
// — three fresh passes then re-raise the finding. Forgetting is the safe
// direction for a WARNING that says "this has been stuck a while".
func (s *Server) noteSweepSkip(reason string) {
	s.nbMetrics().IncSweepSkipped(reason)
	if reason != skipUnreachable {
		return
	}
	s.nbSweepMu.Lock()
	defer s.nbSweepMu.Unlock()
	s.nbSweepUnreachable = true
}

// closeSweepPass folds this pass into the consecutive-unreachable streak and
// returns the streak's new length.
func (s *Server) closeSweepPass() int {
	s.nbSweepMu.Lock()
	defer s.nbSweepMu.Unlock()
	if s.nbSweepUnreachable {
		s.nbUnreachableStreak++
	} else {
		s.nbUnreachableStreak = 0
	}
	s.nbSweepUnreachable = false
	return s.nbUnreachableStreak
}

// evaluateNetBoxHealth advances both NetBox findings against what this pass saw.
// unreachableStreak is closeSweepPass's answer.
func (s *Server) evaluateNetBoxHealth(ctx context.Context, unreachableStreak int) {
	if s.db == nil {
		return
	}

	suspended := map[string]string{}
	bindings, err := corrosion.ListBindings(ctx, s.db)
	if err != nil {
		// A read we could not do proves nothing about absence, so the whole
		// binding half of this pass is skipped rather than reported clean.
		slog.Warn("netbox health: list bindings", "error", err)
	} else {
		for _, b := range bindings {
			if !b.Suspended {
				continue
			}
			suspended[b.Network] = fmt.Sprintf(
				"NetBox binding for network %s (prefix %d) is suspended: %s. "+
					"Every new allocation on this network refuses until it is resumed.",
				b.Network, b.PrefixID, b.SuspendReason)
		}
		s.applyNetBoxConditions(ctx, condNetBoxBindingSuspended, "network", suspended)
	}

	blocked := map[string]string{}
	if unreachableStreak >= netboxSweepBlockedPasses {
		blocked[netboxSweepSubject] = fmt.Sprintf(
			"%d consecutive orphan sweeps declined every reclamation because a host would not "+
				"answer the absence proof. No NetBox address can be reclaimed until the whole "+
				"eligible host set answers again.", unreachableStreak)
	}
	s.applyNetBoxConditions(ctx, condNetBoxSweepBlocked, "cluster", blocked)
}

// evaluateNetBoxClusterPin advances condNetBoxClusterNameMismatch for THIS host
// against binding rows the caller has already read.
//
// Called from revalidation rather than from the sweep, and that is the point:
// the sweep runs under the `netbox` leader lease, so a finding raised there
// would only ever describe the leader's configuration — and the misconfigured
// node is precisely the one that may never lead. Revalidation runs on every
// configured node, so each one reports its own.
//
// Scoped to this host's subject on the way out as well as in. Every node
// evaluates this code, so a node that AGREES must not clean-count a peer's
// subject: it would resolve the disagreeing node's finding within two passes
// while the misconfiguration stood, which is worse than no finding at all
// because the row would appear and then vanish.
func (s *Server) evaluateNetBoxClusterPin(ctx context.Context, bindings []corrosion.BindingRecord) {
	positive := map[string]string{}
	resolved, err := netboxsync.ClusterName(ctx, s.db, s.netboxClusterName)
	if err != nil {
		// Neither agreement nor disagreement. The mirror declines a pass it
		// cannot verify (netboxClusterPinAgrees); raising a MISMATCH here would
		// name a value this node could not read.
		slog.Warn("netbox health: could not resolve this node's NetBox cluster name", "error", err)
		return
	}
	if m, bad, _ := firstClusterPinMismatch(resolved, bindings); bad {
		positive[s.hostName] = m.String()
	}
	s.applyNetBoxConditionsScoped(ctx, condNetBoxClusterNameMismatch, "host", positive,
		func(subject string) bool { return subject == s.hostName })
}

// evaluateNetBoxDiscoveryRefusals advances condNetBoxDiscoveryUnclaimable for
// THIS host from what the IP scanner has been refused since the last pass.
//
// Per-node and scoped to this host's own subject, for the reason the finding is
// host-subjected at all: the refusal is a statement about a guest running HERE,
// derived from this host's ARP cache and dnsmasq leases. A node that has
// refused nothing must not clean-count another node's subject — it has observed
// nothing about it, and silence is not a clean pass.
//
// The evidence lists EVERY refused VM in one row rather than one row per VM.
// The row is keyed on the host, so a per-VM subject would need a per-VM key and
// a per-VM clean-count, and the state it would clean-count from is per-process:
// a restart would leave rows for VMs nothing is observing any more. One row that
// names them all resolves as a unit, which matches the lifetime of the state
// behind it.
func (s *Server) evaluateNetBoxDiscoveryRefusals(ctx context.Context) {
	refused := s.discoveryRefusals()
	positive := map[string]string{}
	if len(refused) > 0 {
		names := make([]string, 0, len(refused))
		for vm := range refused {
			names = append(names, vm)
		}
		// Sorted, so the evidence of an unchanged fault is byte-identical from
		// pass to pass and does not restamp the row's LWW timestamp with a
		// reordering.
		sort.Strings(names)
		details := make([]string, 0, len(names))
		for _, vm := range names {
			details = append(details, refused[vm])
		}
		positive[s.hostName] = fmt.Sprintf(
			"%d guest(s) on this host are using addresses NetBox will not grant them, so "+
				"litevirt has not recorded those addresses: %s. reason=not_ours is the serious "+
				"one — NetBox holds that address for something else, which means two things are "+
				"using it. Nothing repairs this automatically: find what else holds the address "+
				"(in NetBox, or an external DHCP server on that subnet) and move one of them off",
			len(names), strings.Join(details, "; "))
	}
	s.applyNetBoxConditionsScoped(ctx, condNetBoxDiscoveryUnclaimable, "host", positive,
		func(subject string) bool { return subject == s.hostName })
}

// evaluateNetBoxDHCPConflicts advances condNetBoxDHCPWouldRace for THIS host,
// over the bound networks the caller has already read.
//
// It answers "would this host refuse to provision that network right now" by
// asking the SAME predicate provisioning asks — network.BoundNetworkDHCPRefusal
// — with this host's own bridge state. Not a model of the refusal: the refusal.
// A second copy of the rule is exactly what this file's neighbours in
// internal/network exist to avoid, and it is the mistake this branch has already
// shipped twice.
//
// IT IS DERIVABLE IN ADVANCE only because the refusal is idempotent: a refused
// provision creates no bridge, so the state read here is the state the provision
// would read. Before that fix the first attempt created the bridge and the
// second read it as pre-existing, so any evaluator would have reported the
// opposite of what the next provision did.
//
// TWO PREDICATES, ONE FINDING, because the misconfiguration has two states and
// the refusal can only speak for the first. The refusal does not fail the
// placement — every caller logs it and creates the bridge itself — and once the
// bridge exists the refusal correctly goes quiet, since a pre-existing bridge
// gets no DHCP server. That is what made this finding SELF-CLEARING: a warning
// appeared and resolved itself two passes later while a guest sat on an
// uplink-less, gateway-less bridge holding a NetBox address. So a bridge that
// exists here with no uplink — what a bridge litevirt auto-created for a
// placement looks like — keeps the finding up through
// network.BoundNetworkAutoBridgeFinding, and only the operator's actual
// remedies clear it: an uplinked infrastructure bridge, or a definition litevirt
// serves no DHCP for.
//
// Its blind spot, stated: it evaluates the OTHER host-local input
// (IsGatewayHost) as false, because a bound network for which that input matters
// — vxlan with a subnet — cannot exist. The bind refuses those cluster-wide, on
// the certain assignment, before any binding row is written. A binding row that
// predates that refusal would be missed here; a re-key or a resume of it hits
// the same check at the bind's own predicate.
//
// Per-node and scoped to this host's own subject, like its two neighbours: a
// host that CAN provision must not clean-count a subject belonging to one that
// cannot.
func (s *Server) evaluateNetBoxDHCPConflicts(ctx context.Context, bindings []corrosion.BindingRecord) {
	positive := map[string]string{}
	var reasons []string
	for _, b := range bindings {
		nr, err := corrosion.GetNetwork(ctx, s.db, b.Network)
		if err != nil {
			// Not evidence of anything. Skipping the binding is right in both
			// directions: it is not a positive finding, and it is not a clean
			// pass for one either — a pass that could not read is silence, and
			// the map below simply does not carry it.
			slog.Warn("netbox health: read network for the DHCP conflict check",
				"network", b.Network, "error", err)
			return
		}
		if nr == nil {
			// A binding whose network is gone. DeleteNetwork releases the
			// binding, so this is a transient the next pass resolves; nothing on
			// this host can provision a network that does not exist.
			continue
		}
		var def compose.NetworkDef
		if err := json.Unmarshal([]byte(nr.Config), &def); err != nil {
			slog.Warn("netbox health: decode network config for the DHCP conflict check",
				"network", b.Network, "error", err)
			return
		}
		// The binding row is the authority on what is bound, not the config
		// blob: the two are written together, but the refusal is about the
		// PREFIX and the row is what holds it.
		def.NetBoxPrefixID = b.PrefixID
		bridge := def.Interface
		if bridge == "" {
			bridge = b.Network
		}
		exists := s.bridgeExistsHere(bridge)
		if rerr := network.BoundNetworkDHCPRefusal(def,
			network.DHCPHostFacts{BridgePreExisted: exists},
			b.Network, bridge, s.hostName); rerr != nil {
			reasons = append(reasons, rerr.Error())
			continue
		}
		// The SECOND state of the same misconfiguration. The refusal above does
		// not fail the placement — the caller creates the bridge itself — and
		// once it exists the refusal is silent, because a pre-existing bridge
		// genuinely gets no DHCP server. Nothing was fixed, so the finding must
		// not clear: it re-states itself against what the bridge actually is.
		if aerr := network.BoundNetworkAutoBridgeFinding(def,
			exists, s.bridgeHasUplinkHere(bridge),
			b.Network, bridge, s.hostName); aerr != nil {
			reasons = append(reasons, aerr.Error())
		}
	}
	if len(reasons) > 0 {
		sort.Strings(reasons)
		positive[s.hostName] = strings.Join(reasons, " | ")
	}
	s.applyNetBoxConditionsScoped(ctx, condNetBoxDHCPWouldRace, "host", positive,
		func(subject string) bool { return subject == s.hostName })
}

// applyNetBoxConditions advances one condition CODE against this pass's positive
// subjects, over EVERY subject of that code.
//
// Correct for the two sweep-written findings and only for those: the sweep runs
// under the `netbox` leader lease, so the cluster has one writer at a time and a
// pass that saw no problem has the standing to say every subject is clean. A
// per-node finding does not — see applyNetBoxConditionsScoped.
func (s *Server) applyNetBoxConditions(ctx context.Context, code, subjectKind string, positive map[string]string) {
	s.applyNetBoxConditionsScoped(ctx, code, subjectKind, positive, func(string) bool { return true })
}

// applyNetBoxConditionsScoped is applyNetBoxConditions restricted to the
// subjects this pass has authority over: observe, confirm on the second
// consecutive pass, resolve after netboxCleanPasses consecutive clean ones.
//
// `owns` decides which EXISTING subjects a clean pass may clean-count. It cannot
// be inferred from `positive`, because an empty positive set is exactly the
// ambiguous case: for a leader-written finding it means "nothing is wrong
// anywhere", and for a per-host one it means only "nothing is wrong here".
//
// All four findings are WARNING severity, observed and confirmed alike. None is
// corruption — one refuses new work, one stops a garbage collector, two stop an
// inventory mirror — and severity critical is reserved here for a workload
// running in two places.
//
// `hosts` is the optional structured host list of conditionEvidence, for a
// finding that is ABOUT other hosts rather than only reported by this one: the
// live cluster-name disagreement names the peers holding the other value. It is
// variadic so the three findings that have no such list keep their call sites
// unchanged, and it applies to every subject of one call because a per-host
// finding writes exactly one subject.
func (s *Server) applyNetBoxConditionsScoped(ctx context.Context, code, subjectKind string, positive map[string]string, owns func(subject string) bool, hosts ...string) {
	now := time.Now().UTC().Format(time.RFC3339)

	active, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		slog.Warn("netbox health: list health conditions", "error", err)
		return
	}
	existing := map[string]corrosion.HealthCondition{}
	for _, h := range active {
		if h.Evaluator == netboxEvaluator && h.Code == code {
			existing[h.SubjectID] = h
		}
	}

	for subject, detail := range positive {
		row, ok := existing[subject]
		if !ok {
			row = corrosion.HealthCondition{
				Evaluator: netboxEvaluator, Code: code,
				SubjectKind: subjectKind, SubjectID: subject,
				Lifecycle: corrosion.ConditionObserved, Severity: corrosion.SeverityWarning,
				ObserveCount: 1, FirstSeen: now,
			}
			slog.Warn("netbox health: condition observed", "code", code, "subject", subject, "detail", detail)
		} else {
			row.ObserveCount++
			row.CleanCount = 0
			if row.Lifecycle != corrosion.ConditionConfirmed && row.ObserveCount >= 2 {
				row.Lifecycle = corrosion.ConditionConfirmed
				row.ConfirmedAt = now
				slog.Warn("netbox health: condition confirmed", "code", code, "subject", subject, "detail", detail)
			}
		}
		row.Severity = corrosion.SeverityWarning
		row.Evidence = encodeEvidence(detail, hosts)
		row.LastSeen = now
		row.ResolvedAt = ""
		row.Reporter = s.hostName
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Error("netbox health: persist condition", "code", code, "subject", subject, "error", err)
		}
	}

	for subject, row := range existing {
		if _, still := positive[subject]; still {
			continue
		}
		if !owns(subject) {
			// Another node's subject. This pass observed nothing about it, and
			// silence is not a clean pass.
			continue
		}
		row.CleanCount++
		row.ObserveCount = 0
		row.LastSeen = now
		row.Reporter = s.hostName
		if row.CleanCount >= netboxCleanPasses {
			row.Lifecycle = corrosion.ConditionResolved
			row.ResolvedAt = now
			slog.Info("netbox health: condition resolved", "code", code, "subject", subject)
		}
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Error("netbox health: persist condition", "code", code, "subject", subject, "error", err)
		}
	}
}
