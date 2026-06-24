package compose

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parse reads and validates a compose file from disk.
func Parse(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read compose file: %w", err)
	}
	return ParseBytes(data)
}

// ParseBytes parses compose YAML from a byte slice.
func ParseBytes(data []byte) (*File, error) {
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse compose YAML: %w", err)
	}
	if err := foldWorkloads(&f); err != nil {
		return nil, err
	}
	if err := resolveExtends(&f); err != nil {
		return nil, err
	}
	if err := validate(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

// foldWorkloads merges any `workloads:` entries into the canonical
// `VMs` map so the rest of the parser / planner only has to look at
// one place. Each entry's Kind defaults to "vm" — that's the legacy
// behaviour, indistinguishable from a `vms:` entry. Kinds "lxc" and
// "oci" pass through to the deploy dispatcher, which routes to the
// Containers runtime.
//
// Conflicts (same name in both `vms:` and `workloads:`) are an error
// rather than a silent overwrite — the operator's intent is ambiguous.
func foldWorkloads(f *File) error {
	if len(f.Workloads) == 0 {
		return nil
	}
	if f.VMs == nil {
		f.VMs = make(map[string]VMDef, len(f.Workloads))
	}
	for name, wl := range f.Workloads {
		if _, dup := f.VMs[name]; dup {
			return fmt.Errorf("workload %q also appears under vms: — pick one map", name)
		}
		if wl.Kind == "" {
			wl.Kind = WorkloadKindVM
		}
		switch wl.Kind {
		case WorkloadKindVM, WorkloadKindLXC, WorkloadKindOCI:
		default:
			return fmt.Errorf("workload %q: unknown kind %q (want vm | lxc | oci)", name, wl.Kind)
		}
		f.VMs[name] = wl
	}
	// Wipe Workloads so downstream code doesn't double-process.
	f.Workloads = nil
	return nil
}

// resolveExtends processes service inheritance. VMs with `extends: <base>`
// inherit all fields from the base, with child values taking precedence.
// Merge rules: scalars — child wins (zero-value = inherit). Maps — merge keys,
// child wins collisions. Slices — child replaces entirely. Pointer structs —
// child nil = inherit parent, child non-nil = use child's.
func resolveExtends(f *File) error {
	if len(f.VMs) == 0 {
		return nil
	}

	// Build dependency graph and detect cycles via topological sort.
	// inDegree tracks how many extends-dependencies each VM has (0 or 1).
	inDegree := make(map[string]int)
	dependents := make(map[string][]string) // base → list of VMs that extend it

	for name := range f.VMs {
		inDegree[name] = 0
	}
	for name, vm := range f.VMs {
		if vm.Extends == "" {
			continue
		}
		if _, ok := f.VMs[vm.Extends]; !ok {
			return fmt.Errorf("vm %q extends unknown vm %q", name, vm.Extends)
		}
		if vm.Extends == name {
			return fmt.Errorf("vm %q extends itself", name)
		}
		inDegree[name]++
		dependents[vm.Extends] = append(dependents[vm.Extends], name)
	}

	// Kahn's algorithm for topological sort.
	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}

	var order []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		order = append(order, cur)
		for _, dep := range dependents[cur] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	if len(order) != len(f.VMs) {
		return fmt.Errorf("extends cycle detected (involves %d vm(s))", len(f.VMs)-len(order))
	}

	// Apply inheritance in topological order (bases resolved before children).
	for _, name := range order {
		vm := f.VMs[name]
		if vm.Extends == "" {
			continue
		}
		base := f.VMs[vm.Extends]
		merged := mergeVMDef(base, vm)
		merged.Extends = "" // clear after resolution
		f.VMs[name] = merged
	}

	return nil
}

// mergeVMDef merges a base VMDef into a child. Child values take precedence.
func mergeVMDef(base, child VMDef) VMDef {
	m := base // start with base, overlay child

	// Scalars — child wins if non-zero
	if child.Image != "" {
		m.Image = child.Image
	}
	if child.ISO != "" {
		m.ISO = child.ISO
	}
	if child.Firmware != "" {
		m.Firmware = child.Firmware
	}
	if child.Machine != "" {
		m.Machine = child.Machine
	}
	if child.CPU != 0 {
		m.CPU = child.CPU
	}
	if child.Memory != 0 {
		m.Memory = child.Memory
	}
	if child.MinMemory != 0 {
		m.MinMemory = child.MinMemory
	}
	if child.MaxMemory != 0 {
		m.MaxMemory = child.MaxMemory
	}
	if child.Onboot {
		m.Onboot = child.Onboot
	}
	if child.StartupOrder != 0 {
		m.StartupOrder = child.StartupOrder
	}
	if child.StartDelay != 0 {
		m.StartDelay = child.StartDelay
	}
	if child.StopDelay != 0 {
		m.StopDelay = child.StopDelay
	}
	if child.IPHint != "" {
		m.IPHint = child.IPHint
	}
	if child.StopGracePeriod != "" {
		m.StopGracePeriod = child.StopGracePeriod
	}

	// Pointer scalars — child non-nil wins
	if child.Replicas != nil {
		m.Replicas = child.Replicas
	}
	if child.GuestAgent != nil {
		m.GuestAgent = child.GuestAgent
	}

	// Slices — child replaces entirely
	if child.Network != nil {
		m.Network = child.Network
	}
	if child.Devices != nil {
		m.Devices = child.Devices
	}

	// Maps — merge keys, child wins collisions
	if child.Disks != nil {
		m.Disks = mergeMaps(base.Disks, child.Disks)
	}
	if child.Labels != nil {
		m.Labels = mergeStringMaps(base.Labels, child.Labels)
	}

	// Pointer structs — child non-nil replaces entirely
	if child.CloudInit != nil {
		m.CloudInit = child.CloudInit
	}
	if child.Placement != nil {
		m.Placement = child.Placement
	}
	if child.Migrate != nil {
		m.Migrate = child.Migrate
	}
	if child.Update != nil {
		m.Update = child.Update
	}
	if child.LoadBalancer != nil {
		m.LoadBalancer = child.LoadBalancer
	}
	if child.HealthCheck != nil {
		m.HealthCheck = child.HealthCheck
	}
	if child.Hooks != nil {
		m.Hooks = child.Hooks
	}
	if child.Resources != nil {
		m.Resources = child.Resources
	}
	if child.Restart != nil {
		m.Restart = child.Restart
	}
	if child.DependsOn != nil {
		m.DependsOn = child.DependsOn
	}

	return m
}

// mergeStringMaps merges two string→string maps. Child wins on collision.
func mergeStringMaps(base, child map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(child))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range child {
		out[k] = v
	}
	return out
}

// mergeMaps merges two string→DiskDef maps. Child wins on collision.
func mergeMaps[V any](base, child map[string]V) map[string]V {
	out := make(map[string]V, len(base)+len(child))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range child {
		out[k] = v
	}
	return out
}

// validate enforces consistency rules.
func validate(f *File) error {
	var errs []string

	if f.Name == "" {
		errs = append(errs, "stack name is required (add 'name: <stack-name>' to your compose file)")
	}

	// Validate network definitions.
	for name, net := range f.Networks {
		if net.External {
			if net.Subnet != "" || net.DHCP || net.VNI != 0 || net.Type != "" {
				errs = append(errs, fmt.Sprintf(
					"network %q: external network must not set subnet, dhcp, vni, or type", name))
			}
		}
	}

	// Collect all instance names to detect collisions with internal
	// temp naming conventions (e.g. "-next" suffix for cutover) (#46).
	allInstanceNames := map[string]string{} // instanceName → baseName
	for baseName, vm := range f.VMs {
		for r := 0; r < vm.EffectiveReplicas(); r++ {
			iname := vm.InstanceName(baseName, r)
			if owner, ok := allInstanceNames[iname]; ok && owner != baseName {
				errs = append(errs, fmt.Sprintf(
					"workload %q instance name %q conflicts with workload %q — choose a different name or replica count",
					baseName, iname, owner))
				continue
			}
			allInstanceNames[iname] = baseName
		}
	}
	for baseName, vm := range f.VMs {
		for r := 0; r < vm.EffectiveReplicas(); r++ {
			iname := vm.InstanceName(baseName, r)
			// Check if this name looks like a temp name for another VM.
			nextName := iname + "-next"
			_ = nextName
			// Check if another VM's instance name collides with our "-next" pattern.
			for otherIName, otherBase := range allInstanceNames {
				if otherBase == baseName {
					continue
				}
				if otherIName == iname+"-next" {
					errs = append(errs, fmt.Sprintf(
						"vm %q instance name %q conflicts with the rolling update temporary name for %q — choose a different name",
						otherBase, otherIName, iname))
				}
			}
		}
	}

	for name, vm := range f.VMs {
		// Resolve effective image name
		image := vm.Image
		if image == "" {
			image = vm.ISO
		}
		if image == "" {
			errs = append(errs, fmt.Sprintf("vm %q: image or iso required", name))
			continue
		}

		// Validate migration + storage consistency
		if vm.Migrate != nil && vm.Migrate.Strategy == "live" && !vm.Migrate.WithStorage {
			for diskName, disk := range vm.Disks {
				if disk.Storage == "" {
					errs = append(errs, fmt.Sprintf(
						"vm %q disk %q: live migration without with-storage requires shared storage (hint: set storage: <volume> or migrate.with-storage: true)",
						name, diskName))
				}
			}
		}

		// Auto-failover + local disks warning (not an error per spec)
		if vm.Migrate != nil && vm.Migrate.OnHostFailure == "restart-any" {
			for _, disk := range vm.Disks {
				if disk.Storage == "" {
					// This is a warning, not an error — we'll note it in the plan
					_ = disk
				}
			}
		}

		// LB: implicitly enable if VIP is set.
		// NOTE: VMDef is a value type in this map, so we must copy, mutate,
		// and write back. Apply the same pattern for any other mutations.
		if vm.LoadBalancer != nil && !vm.LoadBalancer.Enabled && vm.LoadBalancer.VIP != "" {
			vm.LoadBalancer.Enabled = true
			f.VMs[name] = vm
		}
		// LB validation
		if vm.LoadBalancer != nil && vm.LoadBalancer.Enabled {
			if vm.LoadBalancer.VIP == "" {
				errs = append(errs, fmt.Sprintf("vm %q loadbalancer: vip required when enabled", name))
			} else if _, _, err := net.ParseCIDR(vm.LoadBalancer.VIP); err != nil {
				errs = append(errs, fmt.Sprintf("vm %q loadbalancer: vip must be valid CIDR (e.g. 10.0.0.50/24), got %q", name, vm.LoadBalancer.VIP))
			}
			if len(vm.LoadBalancer.Ports) == 0 {
				errs = append(errs, fmt.Sprintf("vm %q loadbalancer: at least one port required", name))
			}
			for i, p := range vm.LoadBalancer.Ports {
				if p.Listen <= 0 {
					errs = append(errs, fmt.Sprintf("vm %q loadbalancer port[%d]: listen must be > 0", name, i))
				}
				if p.Target <= 0 {
					errs = append(errs, fmt.Sprintf("vm %q loadbalancer port[%d]: target must be > 0", name, i))
				}
			}
		}

		// Replicas validation
		if vm.Replicas != nil && *vm.Replicas < 0 {
			errs = append(errs, fmt.Sprintf("vm %q: replicas must be >= 0", name))
		}
	}

	// Validate depends-on: targets must exist and no cycles.
	if err := validateDependsOn(f); err != nil {
		errs = append(errs, err.Error())
	}

	// Detect contradictory affinity/anti-affinity rules (#56).
	// Build transitive affinity groups and check for anti-affinity conflicts.
	if err := validateAffinityRules(f); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		return fmt.Errorf("compose validation errors:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// validateAffinityRules checks for contradictory affinity + anti-affinity
// constraints. If A has affinity with B, and B has affinity with C, but C
// has anti-affinity with A, the placement is unsatisfiable (#56).
func validateAffinityRules(f *File) error {
	// Build affinity graph: edges mean "must be on same host".
	affinity := map[string]map[string]bool{}
	antiAffinity := map[string]map[string]bool{}

	for name, vm := range f.VMs {
		if vm.Placement == nil {
			continue
		}
		for _, target := range vm.Placement.Affinity {
			if affinity[name] == nil {
				affinity[name] = map[string]bool{}
			}
			affinity[name][target] = true
		}
		for _, target := range vm.Placement.AntiAffinity {
			if antiAffinity[name] == nil {
				antiAffinity[name] = map[string]bool{}
			}
			antiAffinity[name][target] = true
		}
	}

	// Compute transitive affinity closure (union-find style).
	// VMs in the same affinity group must all be co-located.
	group := map[string]string{} // vm → group leader
	var find func(string) string
	find = func(v string) string {
		if group[v] == "" || group[v] == v {
			return v
		}
		group[v] = find(group[v])
		return group[v]
	}
	union := func(a, b string) {
		ga, gb := find(a), find(b)
		if ga != gb {
			group[ga] = gb
		}
	}

	for vm, targets := range affinity {
		for t := range targets {
			union(vm, t)
		}
	}

	// Check: if any two VMs in the same affinity group also have anti-affinity,
	// the constraints are contradictory.
	for vm, targets := range antiAffinity {
		for t := range targets {
			if find(vm) == find(t) {
				return fmt.Errorf(
					"placement constraints are contradictory: %q and %q are transitively co-located (affinity) "+
						"but also have anti-affinity — no placement satisfies all constraints", vm, t)
			}
		}
	}

	return nil
}

// validateDependsOn checks that all depends-on targets exist and there are no cycles.
func validateDependsOn(f *File) error {
	// Check all targets exist.
	for name, vm := range f.VMs {
		for target := range vm.DependsOn {
			if _, ok := f.VMs[target]; !ok {
				return fmt.Errorf("vm %q depends-on unknown vm %q", name, target)
			}
		}
	}

	// Cycle detection via topological sort (Kahn's algorithm).
	inDegree := make(map[string]int)
	dependents := make(map[string][]string) // target → VMs that depend on it

	for name := range f.VMs {
		inDegree[name] = 0
	}
	for name, vm := range f.VMs {
		for target := range vm.DependsOn {
			inDegree[name]++
			dependents[target] = append(dependents[target], name)
		}
	}

	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}

	visited := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		visited++
		for _, dep := range dependents[cur] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	if visited != len(f.VMs) {
		return fmt.Errorf("depends-on cycle detected")
	}
	return nil
}

// parseMemoryString converts "8G", "512M", "1024" to MiB.
// Returns an error for malformed values like "8X" or "abc".
func parseMemoryString(s string) (int, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, fmt.Errorf("empty memory value")
	}
	if strings.HasSuffix(s, "G") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "G"))
		if err != nil {
			return 0, fmt.Errorf("invalid memory value %q: %w", s, err)
		}
		return n * 1024, nil
	}
	if strings.HasSuffix(s, "M") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "M"))
		if err != nil {
			return 0, fmt.Errorf("invalid memory value %q: %w", s, err)
		}
		return n, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid memory value %q: %w", s, err)
	}
	return n, nil
}

// EffectiveReplicas returns 1 if replicas is nil (unset/omitted).
// Explicit replicas: 0 returns 0 (scale-to-zero) (#50).
func (vm *VMDef) EffectiveReplicas() int {
	if vm.Replicas == nil {
		return 1
	}
	return *vm.Replicas
}

// EffectiveGuestAgent returns true unless explicitly set to false.
func (vm *VMDef) EffectiveGuestAgent() bool {
	if vm.GuestAgent == nil {
		return vm.ISO == "" // default true for cloud images, false for ISO installs
	}
	return *vm.GuestAgent
}

// InstanceName returns the instance name for a replica.
// Single-replica VMs use the base name; multi-replica append "-N".
func (vm *VMDef) InstanceName(baseName string, replica int) string {
	if vm.EffectiveReplicas() == 1 {
		return baseName
	}
	return fmt.Sprintf("%s-%d", baseName, replica+1)
}
