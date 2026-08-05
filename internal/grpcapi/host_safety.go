package grpcapi

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The host-safety admission policy — ONE entrypoint consulted by every
// operator-driven create, start, restore, migrate, placement, and
// resource-growth admission. It reads the same durable health conditions the
// operator sees, so "lv health says CRITICAL" and "admission refused" can
// never disagree:
//
//   - an ACTIVE ownership condition (vm/ct dual-run, runtime-owner mismatch,
//     owner-epoch mismatch) blocks capacity-growing admission to every
//     involved host, and blocks runtime-changing actions on the affected
//     workload wherever it is — an observed (not yet confirmed) condition
//     already blocks: growing into a possibly-corrupting host is not a risk
//     admission gets to take while the evaluator finishes confirming;
//   - an INCOMPLETE local runtime inventory blocks NEW workloads from landing
//     on this host. The check is a fresh LOCAL probe, never replicated
//     telemetry — the target host answers for itself;
//   - --allow-overcommit bypasses numeric headroom ONLY; it cannot bypass
//     either of the above (reserveWithoutCheck consults this gate too);
//   - VIP dual-run is deliberately NOT consulted here: it blocks VIP/LB
//     ownership changes (checkVIPSafety), not unrelated VM placement.

// ownershipConditionCodes are the condition codes that gate admission.
var ownershipConditionCodes = map[string]bool{
	"vm_dual_run":            true,
	"ct_dual_run":            true,
	"runtime_owner_mismatch": true,
	"owner_epoch_mismatch":   true,
}

// subjectKindForWorkload maps a workload kind to its condition subject_kind.
func subjectKindForWorkload(kind string) string {
	if kind == corrosion.WorkloadContainer {
		return "container"
	}
	return "vm"
}

// checkHostSafety is the admission gate. host is where capacity would grow;
// (workloadKind, workloadName) is the workload being acted on ("" for
// host-only decisions); newWorkload says a workload would BECOME RESIDENT on
// host (create, start, migrate-in, restore-in) — the case an incomplete local
// inventory must refuse.
func (s *Server) checkHostSafety(ctx context.Context, host, workloadKind, workloadName string, newWorkload bool) error {
	conditions, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		// Conservative under uncertainty: an unreadable safety state is not a
		// license to admit.
		return status.Errorf(codes.Unavailable, "cannot read health conditions before admitting: %v", err)
	}
	subjectKind := subjectKindForWorkload(workloadKind)
	for _, c := range conditions {
		if !ownershipConditionCodes[c.Code] {
			continue
		}
		// Runtime-changing action on the AFFECTED workload, wherever it is.
		if workloadName != "" && c.SubjectKind == subjectKind && c.SubjectID == workloadName {
			return status.Errorf(codes.FailedPrecondition,
				"refusing to act on %s %q: active %s ownership condition (%s, involving %s) — "+
					"resolve the condition first; see `lv health`",
				subjectKind, workloadName, c.Severity, c.Code, strings.Join(c.Hosts, ", "))
		}
		// Capacity-growing admission to an involved host.
		for _, h := range c.Hosts {
			if h == host {
				return status.Errorf(codes.FailedPrecondition,
					"refusing admission to host %q: it is involved in an active %s condition (%s on %s/%s) — "+
						"resolve the condition first; see `lv health`",
					host, c.Severity, c.Code, c.SubjectKind, c.SubjectID)
			}
		}
	}

	// A NEW workload may only land on a host whose own runtime inventory is
	// COMPLETE right now — and whose consumption is fully ATTRIBUTABLE. Local
	// truth, freshly probed: placement filters on the replicated observation,
	// but the final admission never trusts it. An UNCAPPED runtime-only
	// container is the attributability hole: it consumes unbounded resources
	// capacity accounting cannot charge, so the host's headroom is unknowable
	// and a pinned create must not slip past the placement filter.
	if newWorkload && host == s.hostName {
		inv := s.localInventoryCached(ctx)
		if !inv.Complete {
			return status.Errorf(codes.FailedPrecondition,
				"refusing new workload on host %q: its runtime inventory is incomplete (%s) — "+
					"a host that cannot account for what it runs cannot accept more",
				host, strings.Join(inv.Errors, "; "))
		}
		for _, w := range inv.Workloads {
			if !w.Uncapped {
				continue
			}
			known, kerr := s.workloadDBKnown(ctx, w.Kind, w.Name)
			if kerr != nil {
				return status.Errorf(codes.Unavailable,
					"cannot verify runtime workload %q before admitting: %v", w.Name, kerr)
			}
			if !known {
				return status.Errorf(codes.FailedPrecondition,
					"refusing new workload on host %q: uncapped runtime-only container %q makes its "+
						"capacity unattributable — remove or limit it first; see `lv health`",
					host, w.Name)
			}
		}
	}
	return nil
}

// remoteObservationMaxAge bounds how old a REPLICATED capacity observation may
// be before runtimeExtras stops trusting its figures. Generous next to the 60s
// sampler period; a host that has not published for this long is a staleness
// problem placement's own filter already surfaces.
const remoteObservationMaxAge = 5 * time.Minute

// runtimeExtras returns host's FINITE runtime-only load — consumption the
// database does not account for (rogue-but-bounded workloads, a runtime grown
// past its recorded spec) — so the final admission arithmetic can subtract it
// from DB-derived headroom. Without this, the authoritative host can OBSERVE a
// rogue eating half its memory (placement correctly avoids it) and still admit
// a pinned create against full database headroom.
//
// For the local host the figures come from the same freshly-probed inventory
// the safety gate uses — the replicated observation is never the input to a
// local decision. For a REMOTE host (the migrate path admits for its target on
// the source) the replicated observation is the only view there is; a missing
// or stale one degrades to zero, which is exactly the DB-only arithmetic this
// function improves on. Errors also degrade to zero rather than refusing: the
// UNCAPPED/incomplete cases — where degrading would be unsafe — are already
// refused outright by checkHostSafety before any arithmetic runs.
func (s *Server) runtimeExtras(ctx context.Context, host string) (cpu, memMiB int) {
	pos := func(v int) int {
		if v < 0 {
			return 0
		}
		return v
	}
	if host == s.hostName {
		inv := s.localInventoryCached(ctx)
		vms, verr := corrosion.ListVMs(ctx, s.db, "", host)
		cts, cerr := corrosion.ListContainers(ctx, s.db, host)
		if verr != nil || cerr != nil {
			return 0, 0
		}
		obs := computeCapacityObservation(host, inv, vms, cts)
		return pos(obs.ExtraCPU), pos(obs.ExtraMemMiB)
	}
	obs, ok, err := corrosion.GetHostCapacityObservation(ctx, s.db, host)
	if err != nil || !ok {
		return 0, 0
	}
	if at, perr := time.Parse(time.RFC3339, obs.SampledAt); perr != nil || time.Since(at) > remoteObservationMaxAge {
		return 0, 0
	}
	return pos(obs.ExtraCPU), pos(obs.ExtraMemMiB)
}

// workloadDBKnown reports whether a runtime workload has a live DB row on this
// host — the line between "accounted" and "rogue".
func (s *Server) workloadDBKnown(ctx context.Context, kind, name string) (bool, error) {
	if kind == corrosion.WorkloadContainer {
		ct, err := corrosion.GetContainer(ctx, s.db, s.hostName, name)
		return ct != nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, name)
	return vm != nil, err
}

// checkVIPSafety gates VIP/LB OWNERSHIP changes on active VIP dual-run
// conditions. Separate from checkHostSafety on purpose: a dual VIP holder
// must freeze VIP moves, not unrelated VM placement.
func (s *Server) checkVIPSafety(ctx context.Context, vip string) error {
	conditions, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot read health conditions before a VIP change: %v", err)
	}
	for _, c := range conditions {
		if c.Code == "vip_dual_run" && c.SubjectID == vip {
			return status.Errorf(codes.FailedPrecondition,
				"refusing VIP ownership change for %s: active %s dual-holder condition (on %s) — "+
					"resolve it first; see `lv health`",
				vip, c.Severity, strings.Join(c.Hosts, ", "))
		}
	}
	return nil
}

// localInventoryTTL bounds how stale the cached local inventory used by the
// admission gate may be. Short enough that a probe failure surfaces within a
// few admissions; long enough that a create burst does not hammer libvirt.
const localInventoryTTL = 10 * time.Second

func (s *Server) localInventoryCached(ctx context.Context) runtimeInventory {
	s.invCacheMu.Lock()
	defer s.invCacheMu.Unlock()
	if !s.invCacheAt.IsZero() && time.Since(s.invCacheAt) < localInventoryTTL {
		return s.invCache
	}
	inv := s.collectRuntimeInventory(ctx)
	s.invCache, s.invCacheAt = inv, time.Now()
	if !inv.Complete {
		slog.Warn("admission gate: local runtime inventory incomplete", "errors", inv.Errors)
	}
	return inv
}

// invalidateInventoryCache drops the cached inventory (tests, and callers that
// just changed runtime state).
func (s *Server) invalidateInventoryCache() {
	s.invCacheMu.Lock()
	defer s.invCacheMu.Unlock()
	s.invCacheAt = time.Time{}
}
