package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netboxsync"
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
// All three findings are WARNING severity, observed and confirmed alike. None is
// corruption — one refuses new work, one stops a garbage collector, one stops an
// inventory mirror — and severity critical is reserved here for a workload
// running in two places.
func (s *Server) applyNetBoxConditionsScoped(ctx context.Context, code, subjectKind string, positive map[string]string, owns func(subject string) bool) {
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
		row.Evidence = encodeEvidence(detail, nil)
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
