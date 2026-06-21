// Package rolling implements rolling update strategies for litevirt stacks.
// Strategies: start-first, stop-first, blue-green, all-at-once, in-place,
// snapshot-and-replace, rolling (with order field).
// Auto-rollback reverts to the previous compose YAML on failure.
package rolling

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Progress is sent on the channel for each step of the update.
type Progress struct {
	VMName string
	Phase  string // starting | stopping | deleting | creating | done | error | rollback
	Detail string
	Err    error
}

// Ops abstracts the VM lifecycle operations the rolling updater needs.
// Implemented by grpcapi.Server; extracted as an interface to allow testing.
type Ops interface {
	RecreateVM(ctx context.Context, name string, f *compose.File) error
	StopVM(ctx context.Context, name string) error
	StartVM(ctx context.Context, name string) error
	WaitHealthy(ctx context.Context, name string, timeout time.Duration) error
	// HotModifyVM applies live CPU/memory changes without restarting.
	HotModifyVM(ctx context.Context, name string, cpu, memMiB int) error
	// CreateNextVM creates a <name>-next VM for snapshot-and-replace updates.
	CreateNextVM(ctx context.Context, name string, f *compose.File) error
}

// Update executes a rolling update for a stack according to the update policy
// defined in the new compose file. Progress is sent to the returned channel.
// The channel is closed when the update completes or fails.
func Update(ctx context.Context, db *corrosion.Client, ops Ops, stackName string, newFile *compose.File, oldYAML string) <-chan Progress {
	ch := make(chan Progress, 32)
	go func() {
		defer close(ch)
		err := doUpdate(ctx, db, ops, stackName, newFile, oldYAML, ch)
		if err != nil {
			ch <- Progress{Phase: "error", Detail: err.Error(), Err: err}
		}
	}()
	return ch
}

// updateGroup is a set of VMs sharing the same update strategy.
type updateGroup struct {
	ud      compose.UpdateDef
	targets []string
}

func doUpdate(ctx context.Context, db *corrosion.Client, ops Ops, stackName string, f *compose.File, oldYAML string, ch chan<- Progress) error {
	// Collect VMs that need updating.
	vms, err := corrosion.ListVMs(ctx, db, stackName, "")
	if err != nil {
		return fmt.Errorf("list VMs: %w", err)
	}

	// Skip VMs on draining/fenced hosts — drain handles those separately (#19).
	drainingHosts := map[string]bool{}
	hosts, _ := corrosion.ListHosts(ctx, db)
	for _, h := range hosts {
		if h.State == "draining" || h.State == "fenced" {
			drainingHosts[h.Name] = true
		}
	}

	var targets []string
	for _, vm := range vms {
		if drainingHosts[vm.HostName] {
			ch <- Progress{VMName: vm.Name, Phase: "done", Detail: "skipped — host is draining/fenced"}
			continue
		}
		targets = append(targets, vm.Name)
	}

	groups := resolveUpdateGroups(f, targets)

	for _, g := range groups {
		strategy := g.ud.Strategy
		if strategy == "" {
			strategy = "recreate"
		}

		slog.Info("rolling update group", "stack", stackName, "strategy", strategy, "vms", len(g.targets))

		var groupErr error
		switch strategy {
		case "all-at-once":
			groupErr = allAtOnce(ctx, db, ops, f, g.targets, g.ud, oldYAML, ch)
		case "blue-green":
			groupErr = blueGreen(ctx, db, ops, f, stackName, g.targets, ch)
		case "start-first":
			groupErr = ordered(ctx, ops, f, g.targets, g.ud, true, ch)
		case "rolling":
			startFirst := g.ud.Order == "start-first"
			groupErr = ordered(ctx, ops, f, g.targets, g.ud, startFirst, ch)
		case "snapshot-and-replace":
			groupErr = snapshotAndReplace(ctx, ops, f, g.targets, g.ud, ch)
		case "in-place":
			groupErr = inPlace(ctx, db, ops, f, g.targets, g.ud, ch)
		case "stop-first", "recreate":
			groupErr = ordered(ctx, ops, f, g.targets, g.ud, false, ch)
		default:
			groupErr = ordered(ctx, ops, f, g.targets, g.ud, false, ch)
		}

		if groupErr != nil {
			return groupErr
		}
	}
	return nil
}

// allAtOnce recreates every VM simultaneously.
func allAtOnce(ctx context.Context, db *corrosion.Client, ops Ops, f *compose.File, targets []string, ud compose.UpdateDef, oldYAML string, ch chan<- Progress) error {
	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(targets))

	for _, name := range targets {
		go func(vmName string) {
			err := ops.RecreateVM(ctx, vmName, f)
			results <- result{vmName, err}
		}(name)
	}

	failed := 0
	for range targets {
		r := <-results
		if r.err != nil {
			failed++
			ch <- Progress{VMName: r.name, Phase: "error", Detail: r.err.Error(), Err: r.err}
		} else {
			ch <- Progress{VMName: r.name, Phase: "done"}
		}
	}

	if failed > 0 && ud.RollbackOnFailure {
		return rollback(ctx, db, ops, f.Name, oldYAML, ch)
	}
	return nil
}

// ordered recreates VMs in batches. Batch size is determined by MaxSurge
// (for start-first) or MaxUnavailable (for stop-first). Default batch size is 1.
// If startFirst=true, the new VM is started before the old one is stopped.
func ordered(ctx context.Context, ops Ops, f *compose.File, targets []string, ud compose.UpdateDef, startFirst bool, ch chan<- Progress) error {
	healthWait := parseDuration(ud.HealthWait, 30*time.Second)
	pauseBetween := parseDuration(ud.PauseBetween, 0)

	batchSize := ud.MaxUnavailable
	if startFirst {
		batchSize = ud.MaxSurge
	}
	if batchSize <= 0 {
		batchSize = 1
	}

	for i := 0; i < len(targets); i += batchSize {
		end := i + batchSize
		if end > len(targets) {
			end = len(targets)
		}
		batch := targets[i:end]

		if len(batch) == 1 {
			// Single VM — sequential path (original behavior).
			if err := processSingleVM(ctx, ops, f, batch[0], startFirst, healthWait, ch); err != nil {
				return err
			}
		} else {
			// Concurrent batch.
			type result struct {
				name string
				err  error
			}
			results := make(chan result, len(batch))
			for _, vmName := range batch {
				go func(name string) {
					err := processSingleVM(ctx, ops, f, name, startFirst, healthWait, ch)
					results <- result{name, err}
				}(vmName)
			}

			var firstErr error
			for range batch {
				r := <-results
				if r.err != nil && firstErr == nil {
					firstErr = r.err
				}
			}
			if firstErr != nil {
				return firstErr
			}
		}

		// Pause between batches (not after the last one).
		if pauseBetween > 0 && end < len(targets) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pauseBetween):
			}
		}
	}
	return nil
}

// processSingleVM handles the update of one VM within ordered().
func processSingleVM(ctx context.Context, ops Ops, f *compose.File, vmName string, startFirst bool, healthWait time.Duration, ch chan<- Progress) error {
	if startFirst {
		ch <- Progress{VMName: vmName, Phase: "starting"}
		if err := ops.StartVM(ctx, vmName); err != nil {
			ch <- Progress{VMName: vmName, Phase: "error", Detail: err.Error(), Err: err}
			return fmt.Errorf("ordered update aborted: start %s failed: %w", vmName, err)
		}
		if err := ops.WaitHealthy(ctx, vmName, healthWait); err != nil {
			ch <- Progress{VMName: vmName, Phase: "error", Detail: "health check: " + err.Error(), Err: err}
			return fmt.Errorf("ordered update aborted: %s failed health check after start: %w", vmName, err)
		}
		ch <- Progress{VMName: vmName, Phase: "stopping"}
		_ = ops.StopVM(ctx, vmName)
	}

	ch <- Progress{VMName: vmName, Phase: "creating"}
	if err := ops.RecreateVM(ctx, vmName, f); err != nil {
		ch <- Progress{VMName: vmName, Phase: "error", Detail: err.Error(), Err: err}
		return fmt.Errorf("ordered update aborted: recreate %s failed: %w", vmName, err)
	}

	if !startFirst {
		if err := ops.WaitHealthy(ctx, vmName, healthWait); err != nil {
			ch <- Progress{VMName: vmName, Phase: "error", Detail: "health check: " + err.Error(), Err: err}
			return fmt.Errorf("ordered update aborted: %s failed health check: %w", vmName, err)
		}
	}

	ch <- Progress{VMName: vmName, Phase: "done"}
	return nil
}

// snapshotAndReplace creates -next VMs for each target, leaving cutover
// to the operator via `lv cutover <vm>`.
func snapshotAndReplace(ctx context.Context, ops Ops, f *compose.File, targets []string, ud compose.UpdateDef, ch chan<- Progress) error {
	healthWait := parseDuration(ud.HealthWait, 30*time.Second)

	for _, vmName := range targets {
		ch <- Progress{VMName: vmName, Phase: "creating", Detail: "creating " + vmName + "-next"}

		if err := ops.CreateNextVM(ctx, vmName, f); err != nil {
			ch <- Progress{VMName: vmName, Phase: "error", Detail: err.Error(), Err: err}
			if ud.RollbackOnFailure {
				return fmt.Errorf("snapshot-and-replace aborted: %w", err)
			}
			continue
		}

		nextName := vmName + "-next"
		if err := ops.WaitHealthy(ctx, nextName, healthWait); err != nil {
			ch <- Progress{VMName: vmName, Phase: "error", Detail: "health check on -next: " + err.Error(), Err: err}
			continue
		}

		ch <- Progress{VMName: vmName, Phase: "done", Detail: vmName + "-next ready — run 'lv cutover " + vmName + "' to complete"}
	}
	return nil
}

// inPlace attempts live CPU/memory hot-add. Falls back to ordered recreate
// if the change involves more than CPU/memory or is a reduction.
func inPlace(ctx context.Context, db *corrosion.Client, ops Ops, f *compose.File, targets []string, ud compose.UpdateDef, ch chan<- Progress) error {
	for _, vmName := range targets {
		// Look up the VM's current spec to compare.
		vm, err := corrosion.GetVM(ctx, db, vmName)
		if err != nil || vm == nil {
			ch <- Progress{VMName: vmName, Phase: "error", Detail: "VM not found", Err: fmt.Errorf("VM %s not found", vmName)}
			continue
		}

		// Find the new spec for this VM in the compose file.
		newDef, ok := f.VMs[vmName]
		if !ok {
			// VM not in new compose — skip (will be handled by delete path).
			continue
		}

		newCPU := newDef.CPU
		newMem := newDef.Memory
		if newCPU == 0 {
			newCPU = 2
		}
		if newMem == 0 {
			newMem = 4096
		}

		// Try hot-modify if only CPU/memory changed upward.
		newMemInt := int(newMem)
		if newCPU >= vm.CPUActual && newMemInt >= vm.MemActual &&
			(newCPU != vm.CPUActual || newMemInt != vm.MemActual) {
			ch <- Progress{VMName: vmName, Phase: "creating", Detail: "hot-modify CPU/memory"}
			if err := ops.HotModifyVM(ctx, vmName, newCPU, newMemInt); err != nil {
				slog.Warn("hot-modify failed, falling back to recreate", "vm", vmName, "error", err)
				ch <- Progress{VMName: vmName, Phase: "creating", Detail: "fallback to recreate"}
				if err := ops.RecreateVM(ctx, vmName, f); err != nil {
					ch <- Progress{VMName: vmName, Phase: "error", Detail: err.Error(), Err: err}
					continue
				}
			}
			ch <- Progress{VMName: vmName, Phase: "done"}
			continue
		}

		// Full recreate for other changes.
		ch <- Progress{VMName: vmName, Phase: "creating", Detail: "recreate (non-hot-modifiable change)"}
		if err := ops.RecreateVM(ctx, vmName, f); err != nil {
			ch <- Progress{VMName: vmName, Phase: "error", Detail: err.Error(), Err: err}
			continue
		}
		ch <- Progress{VMName: vmName, Phase: "done"}
	}
	return nil
}

// blueGreen creates a complete parallel set of new VMs, then cuts over.
func blueGreen(ctx context.Context, db *corrosion.Client, ops Ops, f *compose.File, stackName string, targets []string, ch chan<- Progress) error {
	// Create "green" versions (<name>-green).
	greenNames := make([]string, 0, len(targets))
	for _, name := range targets {
		greenName := name + "-green"
		ch <- Progress{VMName: greenName, Phase: "creating", Detail: "blue-green new instance"}
		if err := ops.RecreateVM(ctx, greenName, f); err != nil {
			ch <- Progress{VMName: greenName, Phase: "error", Detail: err.Error(), Err: err}
			// Roll back any green VMs already created.
			for _, gn := range greenNames {
				_ = corrosion.DeleteVM(ctx, db, gn)
			}
			return err
		}
		greenNames = append(greenNames, greenName)
		ch <- Progress{VMName: greenName, Phase: "done", Detail: "green instance ready"}
	}

	// Cut over: stop blue, rename green → original name is not possible in-place;
	// instead we mark old VMs deleted and leave green running.
	for i, name := range targets {
		ch <- Progress{VMName: name, Phase: "stopping", Detail: "removing blue instance"}
		_ = corrosion.DeleteVM(ctx, db, name)
		ch <- Progress{VMName: greenNames[i], Phase: "done", Detail: "cutover complete"}
	}

	slog.Info("blue-green cutover complete", "stack", stackName)
	return nil
}

// rollback redeploys the previous compose YAML for all VMs in the stack.
func rollback(ctx context.Context, db *corrosion.Client, ops Ops, stackName, oldYAML string, ch chan<- Progress) error {
	if oldYAML == "" {
		return fmt.Errorf("no previous compose YAML available for rollback")
	}
	ch <- Progress{Phase: "rollback", Detail: "rolling back to previous version"}

	f, err := compose.ParseBytes([]byte(oldYAML))
	if err != nil {
		return fmt.Errorf("parse rollback compose: %w", err)
	}

	vms, err := corrosion.ListVMs(ctx, db, stackName, "")
	if err != nil {
		return fmt.Errorf("list VMs for rollback: %w", err)
	}

	for _, vm := range vms {
		if err := ops.RecreateVM(ctx, vm.Name, f); err != nil {
			ch <- Progress{VMName: vm.Name, Phase: "error", Detail: "rollback failed: " + err.Error(), Err: err}
		} else {
			ch <- Progress{VMName: vm.Name, Phase: "done", Detail: "rolled back"}
		}
	}
	return nil
}

// resolveUpdateGroups partitions VMs by their effective update strategy.
// VMs with their own UpdateDef form a group; VMs without one use the stack default.
func resolveUpdateGroups(f *compose.File, targets []string) []updateGroup {
	// Find stack default: first explicit UpdateDef, or recreate.
	stackDefault := compose.UpdateDef{Strategy: "recreate"}
	for _, vm := range f.VMs {
		if vm.Update != nil {
			stackDefault = *vm.Update
			break
		}
	}

	type groupEntry struct {
		ud      compose.UpdateDef
		targets []string
	}
	groups := map[string]*groupEntry{}
	var order []string

	for _, vmName := range targets {
		vmDef, _ := compose.FindVMDef(f, vmName)
		ud := stackDefault
		if vmDef != nil && vmDef.Update != nil {
			ud = *vmDef.Update
		}

		key := groupKey(ud)
		if g, ok := groups[key]; ok {
			g.targets = append(g.targets, vmName)
		} else {
			groups[key] = &groupEntry{ud: ud, targets: []string{vmName}}
			order = append(order, key)
		}
	}

	result := make([]updateGroup, 0, len(order))
	for _, k := range order {
		g := groups[k]
		result = append(result, updateGroup{ud: g.ud, targets: g.targets})
	}
	return result
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

