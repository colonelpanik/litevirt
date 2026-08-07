package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/notify"
)

// Durable condition lifecycle — the detector's state layer.
//
// The debounce used to live in a per-leader in-memory map, which had exactly
// the failure modes cluster state must not have: a leadership handover re-armed
// the debounce and silently un-confirmed standing findings, a daemon restart
// erased them, and no other consumer (admission, operator health) could see
// what the detector knew. Findings are now health_conditions ROWS: observation
// counts, confirmation, and resolution survive leader changes and restarts, and
// admission reads the same rows the operator does.
//
// Lifecycle (the rules consumers rely on — see the split-brain design doc):
//
//   - the FIRST positive observation writes an OBSERVED row at warning severity;
//   - the second CONSECUTIVE positive scan CONFIRMS it — critical for the
//     corruption-class codes (vm/ct/vip dual-run, runtime-owner mismatch),
//     warning for coverage gaps and unresolved ties;
//   - positive evidence is recorded WITHOUT quorum: refusing to write down
//     corruption because the cluster is degraded would hide exactly the state
//     an operator needs most;
//   - RESOLUTION is stricter than observation: it requires two consecutive
//     clean scans with COMPLETE coverage (no unreachable, partial, or
//     unsupported peer) while the leader's decision gate is valid. An
//     incomplete scan can neither resolve nor reset the observation streak —
//     it proves nothing about absence;
//   - there is no operator force-clear: operators remove the cause, the
//     evaluator proves the resolution.

// dualRunEvaluator is this detector's evaluator name in health_conditions /
// health_evaluator_status.
const dualRunEvaluator = "dual_run"

// conditionCleanScans is how many consecutive complete clean scans resolve a
// condition. Two, matching the confirm side: one clean pass can be a probe
// races a restart; two complete passes apart is a real absence.
const conditionCleanScans = 2

// conditionIdentity maps a notification kind to the condition's durable
// identity (code, subject_kind). The notification Kind strings stay the
// operator-facing contract; the codes are the storage identity.
func conditionIdentity(kind string) (code, subjectKind string) {
	switch kind {
	case kindDualRunVM:
		return "vm_dual_run", "vm"
	case kindDualRunCT:
		return "ct_dual_run", "container"
	case kindDualRunVIP:
		return "vip_dual_run", "vip"
	case kindOwnerMismatch:
		return "runtime_owner_mismatch", "vm"
	case kindLWWUnresolved:
		return "lww_unresolved", "host"
	case kindDualRunCoverage:
		return "coverage_gap", "host"
	case kindEpochMismatch:
		return "owner_epoch_mismatch", "vm"
	default:
		return kind, "cluster"
	}
}

// notifyKindForCondition is the inverse: the stable notification Kind for a
// stored condition.
func notifyKindForCondition(code string) string {
	switch code {
	case "vm_dual_run":
		return kindDualRunVM
	case "ct_dual_run":
		return kindDualRunCT
	case "vip_dual_run":
		return kindDualRunVIP
	case "runtime_owner_mismatch":
		return kindOwnerMismatch
	case "lww_unresolved":
		return kindLWWUnresolved
	case "coverage_gap":
		return kindDualRunCoverage
	case "owner_epoch_mismatch":
		return kindEpochMismatch
	default:
		return code
	}
}

// confirmedSeverity is the severity a condition carries once CONFIRMED. The
// corruption-class codes are critical; coverage gaps and unresolved ties are
// degraded-state warnings unless they accompany positive corruption evidence
// (which then has its own critical condition row).
func confirmedSeverity(kind string) string {
	switch kind {
	case kindDualRunVM, kindDualRunCT, kindDualRunVIP, kindOwnerMismatch, kindEpochMismatch:
		return corrosion.SeverityCritical
	default:
		return corrosion.SeverityWarning
	}
}

// conditionEvidence is the canonical structured evidence stored per condition.
type conditionEvidence struct {
	Detail string   `json:"detail"`
	Hosts  []string `json:"hosts,omitempty"`
}

func encodeEvidence(detail string, hosts []string) string {
	b, err := json.Marshal(conditionEvidence{Detail: detail, Hosts: hosts})
	if err != nil {
		return `{"detail":"evidence encoding failed"}`
	}
	return string(b)
}

// resolveGateValid reports whether this node's decision gate permits RESOLVING
// conditions. Recording positive evidence never consults it; proving absence
// does — a leader without local quorum cannot promise the rest of the cluster
// is clean. A nil gate (single-node rigs, tests) is valid: there is no quorum
// to lose.
func (s *Server) resolveGateValid(ctx context.Context) bool {
	if s.gate == nil {
		return true
	}
	return s.gate.ExecutionGate(ctx).OK
}

// applyConditionLifecycle advances every dual_run condition against this pass's
// findings and writes the evaluator's scan status. current/details/hosts are
// this pass's positive findings; coverageComplete says whether ABSENCE proved
// anything this pass.
func (s *Server) applyConditionLifecycle(
	ctx context.Context,
	current map[finding]bool,
	details map[finding]string,
	evidenceHosts map[finding][]string,
	coverageComplete bool,
	coverageDetail string,
	probeFailed []string,
) {
	now := time.Now().UTC().Format(time.RFC3339)

	active, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		slog.Warn("dual-run detector: list health conditions", "error", err)
		return
	}
	byIdentity := map[finding]corrosion.HealthCondition{}
	for _, h := range active {
		if h.Evaluator != dualRunEvaluator {
			continue
		}
		byIdentity[finding{kind: notifyKindForCondition(h.Code), target: h.SubjectID}] = h
	}

	// Positive findings first: observe or confirm. Recorded without quorum.
	for f := range current {
		code, subjectKind := conditionIdentity(f.kind)
		row, exists := byIdentity[f]
		evidence := encodeEvidence(details[f], evidenceHosts[f])
		switch {
		case !exists:
			row = corrosion.HealthCondition{
				Evaluator: dualRunEvaluator, Code: code, SubjectKind: subjectKind, SubjectID: f.target,
				Lifecycle: corrosion.ConditionObserved, Severity: corrosion.SeverityWarning,
				Hosts: evidenceHosts[f], Evidence: evidence,
				ObserveCount: 1, CleanCount: 0,
				FirstSeen: now, LastSeen: now, Reporter: s.hostName,
			}
			s.publish("ha.condition.observed", f.kind+":"+f.target, details[f])
			s.notify(ctx, notify.Notification{
				Kind: f.kind, Severity: notify.SevWarn, Subject: f.target,
				Detail: "observed (unconfirmed): " + details[f],
			})
			slog.Info("dual-run detector: condition observed", "kind", f.kind, "target", f.target)
		case row.Lifecycle == corrosion.ConditionObserved:
			row.ObserveCount++
			row.CleanCount = 0
			row.LastSeen = now
			row.Hosts, row.Evidence, row.Reporter = evidenceHosts[f], evidence, s.hostName
			if row.ObserveCount >= dualRunDebounce {
				row.Lifecycle = corrosion.ConditionConfirmed
				row.Severity = confirmedSeverity(f.kind)
				row.ConfirmedAt = now
				s.publish("ha.dualrun", f.kind+":"+f.target, details[f])
				s.notify(ctx, notify.Notification{
					Kind: f.kind, Severity: dualRunSeverity(f.kind), Subject: f.target,
					Detail: details[f],
				})
				slog.Warn("dual-run detector: condition confirmed",
					"kind", f.kind, "target", f.target, "detail", details[f])
			}
		default: // already confirmed — refresh evidence, no re-page (set-transition only)
			row.ObserveCount++
			row.CleanCount = 0
			row.LastSeen = now
			row.Hosts, row.Evidence, row.Reporter = evidenceHosts[f], evidence, s.hostName
		}
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Error("dual-run detector: persist condition", "kind", f.kind, "target", f.target, "error", err)
		}
		byIdentity[f] = row
	}

	// Absent conditions: advance the clean streak — but ONLY under complete
	// coverage and a valid decision gate. An unreachable, partial, unsupported,
	// or quorum-less scan proves nothing about absence, so it neither resolves
	// nor resets anything.
	canResolve := coverageComplete && s.resolveGateValid(ctx)
	for f, row := range byIdentity {
		if current[f] {
			continue
		}
		if !canResolve {
			continue
		}
		row.CleanCount++
		row.ObserveCount = 0
		row.Reporter = s.hostName
		if row.CleanCount >= conditionCleanScans {
			row.Lifecycle = corrosion.ConditionResolved
			row.ResolvedAt = now
			s.publish("ha.dualrun.cleared", f.kind+":"+f.target, "")
			s.notify(ctx, notify.Notification{
				Kind: f.kind, Severity: notify.SevInfo, Subject: f.target,
				Detail: "resolved: two consecutive complete clean scans",
			})
			slog.Info("dual-run detector: condition resolved", "kind", f.kind, "target", f.target)
		}
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Error("dual-run detector: persist condition", "kind", f.kind, "target", f.target, "error", err)
		}
		byIdentity[f] = row
	}

	// Scan status: when it ran, what it could see. Consumers use this to tell
	// "clean" from "blind".
	coverage := corrosion.CoverageComplete
	if !coverageComplete {
		coverage = corrosion.CoveragePartial
	}
	if err := corrosion.UpsertHealthEvaluatorStatus(ctx, s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: dualRunEvaluator, LastScan: now, Coverage: coverage,
		Reporter: s.hostName, Detail: coverageDetail,
	}); err != nil {
		slog.Warn("dual-run detector: persist evaluator status", "error", err)
	}

	// Gauges rebuild from the CONFIRMED conditions (the durable state), so a
	// fresh leader's first pass restores the series instead of blanking it.
	confirmedNow := map[finding]bool{}
	for f, row := range byIdentity {
		if row.Lifecycle == corrosion.ConditionConfirmed {
			confirmedNow[f] = true
		}
	}
	s.dualRunMetrics.SetDetected(detectedLabels(confirmedNow))
	sort.Strings(probeFailed)
	s.dualRunMetrics.SetProbeFailed(probeFailed)
}

// detectedLabels maps the confirmed findings to the litevirt_dual_run_detected
// gauge labels, EXCLUDING coverage findings (those have their own probe_failed
// gauge).
func detectedLabels(confirmed map[finding]bool) []metrics.DualRunLabel {
	var labels []metrics.DualRunLabel
	for f := range confirmed {
		if f.kind == kindDualRunCoverage {
			continue
		}
		labels = append(labels, metrics.DualRunLabel{Kind: dualRunKindLabel(f.kind), Target: f.target})
	}
	return labels
}
