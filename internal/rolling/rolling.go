// Package rolling implements rolling update strategies for litevirt stacks.
// Strategies: start-first, stop-first, blue-green, all-at-once, in-place,
// snapshot-and-replace, rolling (with order field).
//
// The engine is driven by a pre-resolved set of VMActions (the planner classifies
// each update and resolves its desired spec); rolling never re-lists cluster state,
// re-resolves a spec, or re-classifies a change. Run is synchronous and returns the
// first error so the caller can leave the prior stack record untouched on failure.
//
// The in-place strategy is LIVE-OR-FAIL: it applies live cpu/mem resizes and
// live-metadata patches, and REFUSES (without deleting anything) any change that
// needs a restart or a recreate. Destructive recreation happens ONLY under the
// explicit recreate / all-at-once / blue-green / snapshot-and-replace strategies.
package rolling

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

// Progress is reported for each step of the update via the progress callback.
type Progress struct {
	VMName string
	Phase  string // starting | stopping | deleting | creating | resizing | done | error | rollback
	Detail string
	Err    error
}

// VMAction is a fully-resolved workload update the rolling engine executes. The
// planner builds it — name, the VM's effective update strategy, the classified
// ChangePlan, and the resolved desired spec — so rolling needs no cluster queries.
type VMAction struct {
	Name     string
	Strategy compose.UpdateDef
	Plan     compose.ChangePlan
	Desired  *pb.VMSpec
}

// Ops abstracts the VM lifecycle operations the rolling updater needs.
// Implemented by grpcapi.Server (via serverOps); an interface for testing.
type Ops interface {
	// RecreateVM deletes then recreates the VM under `name` from the desired spec.
	// It DESTROYS the VM's disks — reachable only under an explicit recreate-class
	// strategy, never from in-place.
	RecreateVM(ctx context.Context, name string, desired *pb.VMSpec) error
	// ResizeVMLive applies a live cpu grow and/or balloon resize (no restart).
	ResizeVMLive(ctx context.Context, name string, desired *pb.VMSpec) error
	// ApplyLiveMetadata patches the named live-metadata fields (restart policy,
	// onboot, ordering, labels, placement, migrate) onto the VM's desired spec
	// without a restart.
	ApplyLiveMetadata(ctx context.Context, name string, desired *pb.VMSpec, fields []string) error
	StopVM(ctx context.Context, name string) error
	StartVM(ctx context.Context, name string) error
	WaitHealthy(ctx context.Context, name string, timeout time.Duration) error
	// CreateNextVM creates a <name>-next VM for snapshot-and-replace updates.
	CreateNextVM(ctx context.Context, name string, desired *pb.VMSpec) error
	// DeleteVM removes the VM (blue-green cutover / rollback cleanup).
	DeleteVM(ctx context.Context, name string) error
}

// Run executes a rolling update for the given resolved actions, grouped by their
// effective update strategy, and returns the FIRST error (fail-fast). progressFn is
// invoked for each step (nil-safe). On error the caller must NOT commit the new
// stack record — the prior desired state stays authoritative.
func Run(ctx context.Context, ops Ops, stackName string, actions []VMAction, progressFn func(Progress)) error {
	emit := func(p Progress) {
		if progressFn != nil {
			progressFn(p)
		}
	}
	for _, g := range resolveGroups(actions) {
		strategy := g.ud.Strategy
		if strategy == "" {
			strategy = "recreate"
		}
		slog.Info("rolling update group", "stack", stackName, "strategy", strategy, "vms", len(g.actions))

		var err error
		switch strategy {
		case "in-place":
			err = inPlace(ctx, ops, g.actions, emit)
		case "all-at-once":
			err = allAtOnce(ctx, ops, g.actions, emit)
		case "blue-green":
			err = blueGreen(ctx, ops, stackName, g.actions, emit)
		case "start-first":
			err = ordered(ctx, ops, g.actions, g.ud, true, emit)
		case "rolling":
			err = ordered(ctx, ops, g.actions, g.ud, g.ud.Order == "start-first", emit)
		case "snapshot-and-replace":
			err = snapshotAndReplace(ctx, ops, g.actions, g.ud, emit)
		default: // recreate, stop-first
			err = ordered(ctx, ops, g.actions, g.ud, false, emit)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// updateGroup is a set of actions sharing the same update strategy.
type updateGroup struct {
	ud      compose.UpdateDef
	actions []VMAction
}

// resolveGroups partitions actions by their effective update strategy, preserving
// first-seen group order for determinism.
func resolveGroups(actions []VMAction) []updateGroup {
	type entry struct {
		ud      compose.UpdateDef
		actions []VMAction
	}
	groups := map[string]*entry{}
	var order []string
	for _, a := range actions {
		key := groupKey(a.Strategy)
		if g, ok := groups[key]; ok {
			g.actions = append(g.actions, a)
		} else {
			groups[key] = &entry{ud: a.Strategy, actions: []VMAction{a}}
			order = append(order, key)
		}
	}
	out := make([]updateGroup, 0, len(order))
	for _, k := range order {
		out = append(out, updateGroup{ud: groups[k].ud, actions: groups[k].actions})
	}
	return out
}

// inPlace is LIVE-OR-FAIL: it applies each action's classified live changes and
// REFUSES (without deleting anything) any change that needs a restart or recreate.
func inPlace(ctx context.Context, ops Ops, actions []VMAction, emit func(Progress)) error {
	for _, a := range actions {
		switch a.Plan.Max() {
		case compose.ActionNoChange:
			emit(Progress{VMName: a.Name, Phase: "done", Detail: "no change"})
		case compose.ActionLive:
			emit(Progress{VMName: a.Name, Phase: "resizing", Detail: "applying live changes"})
			if len(a.Plan.ResourceChanges) > 0 {
				if err := ops.ResizeVMLive(ctx, a.Name, a.Desired); err != nil {
					emit(Progress{VMName: a.Name, Phase: "error", Detail: err.Error(), Err: err})
					return fmt.Errorf("in-place update aborted: live resize %s failed: %w", a.Name, err)
				}
			}
			if fields := metadataFields(a.Plan); len(fields) > 0 {
				if err := ops.ApplyLiveMetadata(ctx, a.Name, a.Desired, fields); err != nil {
					emit(Progress{VMName: a.Name, Phase: "error", Detail: err.Error(), Err: err})
					return fmt.Errorf("in-place update aborted: live metadata %s failed: %w", a.Name, err)
				}
			}
			emit(Progress{VMName: a.Name, Phase: "done"})
		case compose.ActionRestart:
			err := fmt.Errorf("in-place update of %s needs a restart (%s); use the `recreate` strategy or stop-and-update — in-place never restarts",
				a.Name, firstReason(a.Plan.RestartReasons))
			emit(Progress{VMName: a.Name, Phase: "error", Detail: err.Error(), Err: err})
			return err
		case compose.ActionRecreate:
			err := fmt.Errorf("in-place update of %s needs a recreate (%s); use the `recreate` strategy — in-place never deletes a VM",
				a.Name, firstReason(a.Plan.RecreateReasons))
			emit(Progress{VMName: a.Name, Phase: "error", Detail: err.Error(), Err: err})
			return err
		}
	}
	return nil
}

// metadataFields lists the live-metadata field names changed in a plan.
func metadataFields(p compose.ChangePlan) []string {
	fields := make([]string, 0, len(p.MetadataChanges))
	for _, d := range p.MetadataChanges {
		fields = append(fields, d.Field)
	}
	return fields
}

func firstReason(reasons []string) string {
	if len(reasons) == 0 {
		return "spec change"
	}
	return reasons[0]
}

// allAtOnce recreates every VM simultaneously.
func allAtOnce(ctx context.Context, ops Ops, actions []VMAction, emit func(Progress)) error {
	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(actions))
	for _, a := range actions {
		go func(a VMAction) {
			results <- result{a.Name, ops.RecreateVM(ctx, a.Name, a.Desired)}
		}(a)
	}
	var firstErr error
	for range actions {
		r := <-results
		if r.err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("all-at-once update aborted: recreate %s failed: %w", r.name, r.err)
			}
			emit(Progress{VMName: r.name, Phase: "error", Detail: r.err.Error(), Err: r.err})
		} else {
			emit(Progress{VMName: r.name, Phase: "done"})
		}
	}
	return firstErr
}

// ordered recreates VMs in batches. Batch size is MaxSurge (start-first) or
// MaxUnavailable (stop-first), default 1. When startFirst, the new VM is started
// before the old one is stopped.
func ordered(ctx context.Context, ops Ops, actions []VMAction, ud compose.UpdateDef, startFirst bool, emit func(Progress)) error {
	healthWait := parseDuration(ud.HealthWait, 30*time.Second)
	pauseBetween := parseDuration(ud.PauseBetween, 0)

	batchSize := ud.MaxUnavailable
	if startFirst {
		batchSize = ud.MaxSurge
	}
	if batchSize <= 0 {
		batchSize = 1
	}

	for i := 0; i < len(actions); i += batchSize {
		end := i + batchSize
		if end > len(actions) {
			end = len(actions)
		}
		batch := actions[i:end]

		if len(batch) == 1 {
			if err := processSingleVM(ctx, ops, batch[0], startFirst, healthWait, emit); err != nil {
				return err
			}
		} else {
			type result struct{ err error }
			results := make(chan result, len(batch))
			for _, a := range batch {
				go func(a VMAction) {
					results <- result{processSingleVM(ctx, ops, a, startFirst, healthWait, emit)}
				}(a)
			}
			var firstErr error
			for range batch {
				if r := <-results; r.err != nil && firstErr == nil {
					firstErr = r.err
				}
			}
			if firstErr != nil {
				return firstErr
			}
		}

		if pauseBetween > 0 && end < len(actions) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pauseBetween):
			}
		}
	}
	return nil
}

// processSingleVM recreates one VM within ordered().
func processSingleVM(ctx context.Context, ops Ops, a VMAction, startFirst bool, healthWait time.Duration, emit func(Progress)) error {
	if startFirst {
		emit(Progress{VMName: a.Name, Phase: "starting"})
		if err := ops.StartVM(ctx, a.Name); err != nil {
			emit(Progress{VMName: a.Name, Phase: "error", Detail: err.Error(), Err: err})
			return fmt.Errorf("ordered update aborted: start %s failed: %w", a.Name, err)
		}
		if err := ops.WaitHealthy(ctx, a.Name, healthWait); err != nil {
			emit(Progress{VMName: a.Name, Phase: "error", Detail: "health check: " + err.Error(), Err: err})
			return fmt.Errorf("ordered update aborted: %s failed health check after start: %w", a.Name, err)
		}
		emit(Progress{VMName: a.Name, Phase: "stopping"})
		_ = ops.StopVM(ctx, a.Name)
	}

	emit(Progress{VMName: a.Name, Phase: "creating"})
	if err := ops.RecreateVM(ctx, a.Name, a.Desired); err != nil {
		emit(Progress{VMName: a.Name, Phase: "error", Detail: err.Error(), Err: err})
		return fmt.Errorf("ordered update aborted: recreate %s failed: %w", a.Name, err)
	}

	if !startFirst {
		if err := ops.WaitHealthy(ctx, a.Name, healthWait); err != nil {
			emit(Progress{VMName: a.Name, Phase: "error", Detail: "health check: " + err.Error(), Err: err})
			return fmt.Errorf("ordered update aborted: %s failed health check: %w", a.Name, err)
		}
	}

	emit(Progress{VMName: a.Name, Phase: "done"})
	return nil
}

// snapshotAndReplace creates -next VMs for each target, leaving cutover to the
// operator via `lv cutover <vm>`.
func snapshotAndReplace(ctx context.Context, ops Ops, actions []VMAction, ud compose.UpdateDef, emit func(Progress)) error {
	healthWait := parseDuration(ud.HealthWait, 30*time.Second)
	for _, a := range actions {
		emit(Progress{VMName: a.Name, Phase: "creating", Detail: "creating " + a.Name + "-next"})
		if err := ops.CreateNextVM(ctx, a.Name, a.Desired); err != nil {
			emit(Progress{VMName: a.Name, Phase: "error", Detail: err.Error(), Err: err})
			if ud.RollbackOnFailure {
				return fmt.Errorf("snapshot-and-replace aborted: %w", err)
			}
			continue
		}
		if err := ops.WaitHealthy(ctx, a.Name+"-next", healthWait); err != nil {
			emit(Progress{VMName: a.Name, Phase: "error", Detail: "health check on -next: " + err.Error(), Err: err})
			continue
		}
		emit(Progress{VMName: a.Name, Phase: "done", Detail: a.Name + "-next ready — run 'lv cutover " + a.Name + "' to complete"})
	}
	return nil
}

// blueGreen creates a complete parallel set of new VMs, then cuts over.
func blueGreen(ctx context.Context, ops Ops, stackName string, actions []VMAction, emit func(Progress)) error {
	greenNames := make([]string, 0, len(actions))
	for _, a := range actions {
		greenName := a.Name + "-green"
		emit(Progress{VMName: greenName, Phase: "creating", Detail: "blue-green new instance"})
		if err := ops.RecreateVM(ctx, greenName, a.Desired); err != nil {
			emit(Progress{VMName: greenName, Phase: "error", Detail: err.Error(), Err: err})
			for _, gn := range greenNames {
				_ = ops.DeleteVM(ctx, gn)
			}
			return err
		}
		greenNames = append(greenNames, greenName)
		emit(Progress{VMName: greenName, Phase: "done", Detail: "green instance ready"})
	}

	for i, a := range actions {
		emit(Progress{VMName: a.Name, Phase: "stopping", Detail: "removing blue instance"})
		_ = ops.DeleteVM(ctx, a.Name)
		emit(Progress{VMName: greenNames[i], Phase: "done", Detail: "cutover complete"})
	}
	slog.Info("blue-green cutover complete", "stack", stackName)
	return nil
}

func groupKey(ud compose.UpdateDef) string {
	return fmt.Sprintf("%s:%s:%d:%d:%v", ud.Strategy, ud.Order, ud.MaxSurge, ud.MaxUnavailable, ud.RollbackOnFailure)
}

func parseDuration(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}
