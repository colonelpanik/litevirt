package grpcapi

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// OwnerEpochReadiness evaluates this node's owner_epoch_v1 readiness. The
// capability latches only when EVERY node advertises it, so each node proves
// its OWN slice of the fleet-wide requirements; the latch is the fleet AND:
//
//  1. a FRESH, COMPLETE local runtime scan — a node that cannot see its own
//     runtime cannot certify its generations;
//  2. every owned workload's epoch is nonzero (the backfill graduated);
//  3. every RUNNING local workload carries a VALID marker matching its DB
//     epoch — missing, corrupt, unreadable, or unequal all withhold;
//  4. no unresolved LWW ties on this node — an unresolved tie can hide a
//     divergent ownership row;
//  5. no active runtime-ownership condition anywhere in the cluster — the
//     regime must not latch OVER a standing dispute.
//
// Once latched the token is monotone (capability machinery); a later
// violation becomes health state (owner_epoch_mismatch) and blocks unsafe
// actions through the admission gate — the latch never re-opens.
//
// Every predicate independently withholds advertisement; the reason names the
// first failure for the operator.
func (s *Server) OwnerEpochReadiness(ctx context.Context) (bool, string) {
	inv := s.collectRuntimeInventory(ctx)
	if !inv.Complete {
		return false, "local runtime inventory incomplete: " + fmt.Sprint(inv.Errors)
	}
	if inv.UnresolvedTies > 0 {
		return false, fmt.Sprintf("%d unresolved LWW tie(s)", inv.UnresolvedTies)
	}

	ok, err := corrosion.OwnerEpochBackfillComplete(ctx, s.db, s.hostName)
	if err != nil {
		return false, "backfill check failed: " + err.Error()
	}
	if !ok {
		return false, "owned workloads remain at epoch 0"
	}

	// Marker/DB agreement for everything RUNNING here.
	for _, w := range inv.Workloads {
		if w.State != health.RuntimeRunning {
			continue
		}
		var dbEpoch int64
		switch w.Kind {
		case corrosion.WorkloadVM:
			vm, gerr := corrosion.GetVM(ctx, s.db, w.Name)
			if gerr != nil {
				return false, fmt.Sprintf("cannot read VM %q: %v", w.Name, gerr)
			}
			if vm == nil {
				continue // external/unmanaged domain — not this regime's subject
			}
			dbEpoch = vm.OwnerEpoch
		case corrosion.WorkloadContainer:
			ct, gerr := corrosion.GetContainer(ctx, s.db, s.hostName, w.Name)
			if gerr != nil {
				return false, fmt.Sprintf("cannot read container %q: %v", w.Name, gerr)
			}
			if ct == nil {
				continue
			}
			dbEpoch = ct.OwnerEpoch
		}
		if w.MarkerStatus != MarkerValid {
			return false, fmt.Sprintf("%s %q owner-epoch marker is %s", w.Kind, w.Name, w.MarkerStatus)
		}
		if w.OwnerEpochMarker != dbEpoch {
			return false, fmt.Sprintf("%s %q marker epoch %d != DB epoch %d", w.Kind, w.Name, w.OwnerEpochMarker, dbEpoch)
		}
	}

	// No standing ownership dispute anywhere: the regime must not latch over one.
	conditions, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		return false, "cannot read health conditions: " + err.Error()
	}
	for _, c := range conditions {
		if ownershipConditionCodes[c.Code] {
			return false, fmt.Sprintf("active ownership condition %s on %s/%s", c.Code, c.SubjectKind, c.SubjectID)
		}
	}
	return true, ""
}
