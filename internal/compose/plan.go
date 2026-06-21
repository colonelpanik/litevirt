package compose

import (
	"crypto/sha256"
	"fmt"
	"sort"
)

// OpKind is the type of change in an execution plan.
type OpKind string

const (
	OpCreate  OpKind = "create"
	OpUpdate  OpKind = "update"
	OpDelete  OpKind = "delete"
	OpNoChange OpKind = "no-change"
)

// Op is a single planned operation.
type Op struct {
	Kind      OpKind
	VMName    string
	Detail    string
	Warning   string    // non-fatal advisory (e.g. local disk + failover)
	DependsOn DependsOn // boot-order dependencies (from compose)
}

// Plan is the ordered set of operations to converge the cluster to the desired state.
type Plan struct {
	StackName string
	Ops       []Op
}

// CurrentVM is the caller-supplied current state of a running VM instance.
type CurrentVM struct {
	Name          string
	Image         string
	CPU           int
	MemMiB        int
	State         string
	HostName      string
	CloudInitHash string // sha256 of userdata+networkconfig, empty if none
}

// Build produces an execution plan by diffing desired (compose file) vs current state.
func Build(f *File, current []CurrentVM) (*Plan, error) {
	plan := &Plan{StackName: f.Name}

	// Index current VMs by name for fast lookup.
	currentByName := map[string]CurrentVM{}
	for _, vm := range current {
		currentByName[vm.Name] = vm
	}

	// Track which current VMs are still desired (to find deletions).
	desired := map[string]bool{}

	// Sort VM definition keys for deterministic iteration order.
	// Without this, Go map iteration randomizes the order VMs are sent to
	// SelectBatch, causing different placements between dry-run and execute.
	sortedVMKeys := make([]string, 0, len(f.VMs))
	for k := range f.VMs {
		sortedVMKeys = append(sortedVMKeys, k)
	}
	sort.Strings(sortedVMKeys)

	for _, baseName := range sortedVMKeys {
		vmDef := f.VMs[baseName]
		replicas := vmDef.EffectiveReplicas()
		for r := 0; r < replicas; r++ {
			instanceName := vmDef.InstanceName(baseName, r)
			desired[instanceName] = true

			cur, exists := currentByName[instanceName]
			if !exists {
				op := Op{Kind: OpCreate, VMName: instanceName,
					Detail:    fmt.Sprintf("create %s (image=%s cpu=%d mem=%dMiB)",
						instanceName, vmDef.Image, vmDef.CPU, int(vmDef.Memory)),
					DependsOn: vmDef.DependsOn}

				// Advisory: local disk + restart-any failover
				if vmDef.Migrate != nil && vmDef.Migrate.OnHostFailure == "restart-any" {
					for _, disk := range vmDef.Disks {
						if disk.Storage == "" {
							op.Warning = fmt.Sprintf(
								"on-host-failure: restart-any with local disk %q — data loss risk on host failure", instanceName)
							break
						}
					}
				}
				plan.Ops = append(plan.Ops, op)
				continue
			}

			// Check for in-place changes.
			changed := false
			detail := ""
			if vmDef.CPU != 0 && cur.CPU != vmDef.CPU {
				detail += fmt.Sprintf(" cpu %d→%d", cur.CPU, vmDef.CPU)
				changed = true
			}
			memMiB := int(vmDef.Memory)
			if memMiB != 0 && cur.MemMiB != memMiB {
				detail += fmt.Sprintf(" memory %dMiB→%dMiB", cur.MemMiB, memMiB)
				changed = true
			}
			if vmDef.Image != "" && cur.Image != vmDef.Image {
				detail += fmt.Sprintf(" image %s→%s", cur.Image, vmDef.Image)
				changed = true
			}
			if vmDef.CloudInit != nil && cur.CloudInitHash != "" {
				desiredHash := cloudInitHash(vmDef.CloudInit)
				if desiredHash != cur.CloudInitHash {
					detail += " cloud-init changed"
					changed = true
				}
			} else if vmDef.CloudInit != nil && cur.CloudInitHash == "" {
				detail += " cloud-init added"
				changed = true
			} else if vmDef.CloudInit == nil && cur.CloudInitHash != "" {
				detail += " cloud-init removed"
				changed = true
			}

			// VMs in transient or error states are not in a stable steady
			// state — even if their spec matches, the previous deploy didn't
			// finish cleanly (e.g., daemon was killed mid-create, libvirt
			// failed mid-define). Treat as OpUpdate so the deploy executor
			// re-attempts. Without this, a partial deploy leaves a permanent
			// "exists but doesn't actually run" zombie row that no further
			// `compose up` can recover.
			if isTransientOrErrorState(cur.State) {
				plan.Ops = append(plan.Ops, Op{
					Kind:   OpUpdate,
					VMName: instanceName,
					Detail: fmt.Sprintf("retry %s (was state=%s)", instanceName, cur.State),
				})
			} else if changed {
				plan.Ops = append(plan.Ops, Op{
					Kind:   OpUpdate,
					VMName: instanceName,
					Detail: fmt.Sprintf("update %s:%s", instanceName, detail),
				})
			} else {
				plan.Ops = append(plan.Ops, Op{
					Kind:   OpNoChange,
					VMName: instanceName,
					Detail: fmt.Sprintf("%s: no changes", instanceName),
				})
				_ = cur
			}
		}
	}

	// Anything in current but not desired → delete.
	// Only delete VMs that belong to this stack (name prefix match for replicated VMs).
	for _, cur := range current {
		if !desired[cur.Name] {
			plan.Ops = append(plan.Ops, Op{
				Kind:   OpDelete,
				VMName: cur.Name,
				Detail: fmt.Sprintf("delete %s (no longer in compose)", cur.Name),
			})
		}
	}

	return plan, nil
}

// Summary returns a human-readable one-line summary of the plan.
func (p *Plan) Summary() string {
	var creates, updates, deletes, nochange int
	for _, op := range p.Ops {
		switch op.Kind {
		case OpCreate:
			creates++
		case OpUpdate:
			updates++
		case OpDelete:
			deletes++
		case OpNoChange:
			nochange++
		}
	}
	return fmt.Sprintf("Plan: %d to create, %d to update, %d to delete, %d unchanged",
		creates, updates, deletes, nochange)
}

// isTransientOrErrorState reports whether a VM is in a state that means
// the previous lifecycle action didn't reach a steady end. Such VMs need
// a redeploy to retry; "matches spec" alone is not safe because the row
// can lie (e.g., disk allocated but no libvirt domain).
//
// Stable states (running / stopped / paused / fenced / migrating) are
// treated as steady-state. Migrating is intentionally excluded from
// "needs retry" because a redeploy mid-migration would interrupt it.
func isTransientOrErrorState(state string) bool {
	switch state {
	case "creating", "starting", "stopping", "rebuilding", "error", "failed":
		return true
	}
	return false
}

// cloudInitHash returns a stable hash of a CloudInitDef for change detection.
func cloudInitHash(ci *CloudInitDef) string {
	h := sha256.New()
	h.Write([]byte(ci.UserData))
	h.Write([]byte{0})
	h.Write([]byte(ci.NetworkConfig))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// CloudInitHash exports the cloud-init hash for callers building CurrentVM.
func CloudInitHash(userdata, networkconfig string) string {
	h := sha256.New()
	h.Write([]byte(userdata))
	h.Write([]byte{0})
	h.Write([]byte(networkconfig))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// TopologicalSortOps reorders OpCreate operations in dependency order.
// Non-create ops retain their relative order at the end.
func TopologicalSortOps(ops []Op) []Op {
	// Separate creates from other ops.
	var creates []Op
	var others []Op
	for _, op := range ops {
		if op.Kind == OpCreate && len(op.DependsOn) > 0 {
			creates = append(creates, op)
		} else if op.Kind == OpCreate {
			creates = append(creates, op)
		} else {
			others = append(others, op)
		}
	}

	if len(creates) <= 1 {
		return ops
	}

	// Build dependency graph among create ops.
	// VM names may be instance names (web-1) whose DependsOn uses base names (db).
	// We need to map base names to instance names.
	byName := map[string]*Op{}
	for i := range creates {
		byName[creates[i].VMName] = &creates[i]
	}

	inDegree := map[string]int{}
	dependents := map[string][]string{} // dependency → list of ops that depend on it

	for i := range creates {
		op := &creates[i]
		inDegree[op.VMName] = 0
	}

	for i := range creates {
		op := &creates[i]
		for depBase := range op.DependsOn {
			// Find the actual instance name(s) for this dependency.
			// Match exact name or any name that starts with depBase (replica).
			for name := range byName {
				if name == depBase || (len(name) > len(depBase) && name[:len(depBase)] == depBase && name[len(depBase)] == '-') {
					inDegree[op.VMName]++
					dependents[name] = append(dependents[name], op.VMName)
				}
			}
		}
	}

	// Kahn's algorithm.
	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}

	var sorted []Op
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if op, ok := byName[cur]; ok {
			sorted = append(sorted, *op)
		}
		for _, dep := range dependents[cur] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	// If sorting didn't cover all creates (shouldn't happen if validation passed),
	// append remaining.
	if len(sorted) < len(creates) {
		seen := map[string]bool{}
		for _, op := range sorted {
			seen[op.VMName] = true
		}
		for _, op := range creates {
			if !seen[op.VMName] {
				sorted = append(sorted, op)
			}
		}
	}

	return append(sorted, others...)
}

// HasChanges returns true if the plan contains any actionable operations.
func (p *Plan) HasChanges() bool {
	for _, op := range p.Ops {
		if op.Kind != OpNoChange {
			return true
		}
	}
	return false
}
