package planner

import (
	"context"
	"fmt"
	"sort"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/lb"
	"github.com/litevirt/litevirt/internal/placement"
)

// OpKind mirrors compose.OpKind for the resolved plan.
type OpKind = compose.OpKind

const (
	OpCreate   = compose.OpCreate
	OpUpdate   = compose.OpUpdate
	OpDelete   = compose.OpDelete
	OpNoChange = compose.OpNoChange
)

// ResolvedPlan is the complete, ordered set of actions to converge the cluster
// to the desired state. Every resource action has its target host(s) pre-resolved.
type ResolvedPlan struct {
	StackName string
	Networks  []NetworkAction
	VMs       []VMAction // in dependency/execution order
	LBs       []LBAction
	DNS       []DNSAction
	Warnings  []string
	Summary   string
}

// VMAction is a fully-resolved VM operation.
type VMAction struct {
	Kind       OpKind
	VMName     string
	TargetHost string // pre-resolved (empty for no-change ops on existing VMs)
	Spec       *pb.VMSpec
	Devices    []DeviceAssignment
	ImagePull  bool   // target host needs an image pull
	Storage    string // resolved storage backend
	Detail     string
	DependsOn  compose.DependsOn
	WaitFor    string // condition dependents wait for
	Warning    string
}

// DeviceAssignment is a pre-resolved PCI device allocation.
type DeviceAssignment struct {
	Type    string
	Address string
	Vendor  string
	Device  string
}

// NetworkAction covers network creation, deletion, or updates.
type NetworkAction struct {
	Kind        OpKind
	Name        string
	Type        string
	Config      compose.NetworkDef
	TargetHosts []string // hosts that need this network provisioned
	VTEPHosts   []string // VXLAN: all hosts in the VTEP mesh
	DHCPGateway string   // VXLAN: host elected for dnsmasq
	Detail      string
}

// LBAction describes load balancer setup or teardown.
type LBAction struct {
	Kind        OpKind
	Name        string
	VIP         string
	Algorithm   string
	Ports       []lb.Port
	TargetHosts []string // hosts running haproxy/keepalived
	BackendVMs  []string // VM names (IPs resolved post-boot for DHCP)
	Detail      string
}

// DNSAction describes a DNS record change.
type DNSAction struct {
	Kind     OpKind
	VMName   string
	FQDN     string
	IP       string // empty if deferred
	Deferred bool   // true = IP not known until VM boots (DHCP)
}

// Resolve takes a compose file and cluster state snapshot and produces a
// fully-resolved plan. All placement, device, network, LB, and DNS decisions
// are made here — execution just walks the plan.
func Resolve(ctx context.Context, f *compose.File, state *ClusterState) (*ResolvedPlan, error) {
	plan := &ResolvedPlan{StackName: f.Name}

	// Step 1: Build VM diff (reuse existing compose.Build logic).
	current := buildCurrentVMs(state, f.Name)
	vmPlan, err := compose.Build(f, current)
	if err != nil {
		return nil, fmt.Errorf("build VM plan: %w", err)
	}
	// Topological sort create ops by dependency graph.
	vmPlan.Ops = compose.TopologicalSortOps(vmPlan.Ops)

	// Step 2: Diff networks.
	plan.Networks = diffNetworks(f, state)

	// Step 3: Resolve placements for all create/update VMs.
	var placementReqs []placement.Request
	var placementVMNames []string
	specByVM := map[string]*pb.VMSpec{}

	// Build a map from compose VM definition keys to their expanded instance names,
	// so anti-affinity references like "web" expand to ["web-1", "web-2", "web-3"].
	composeInstances := buildComposeInstanceMap(f)

	for _, op := range vmPlan.Ops {
		if op.Kind != OpCreate && op.Kind != OpUpdate {
			continue
		}
		vmDef, baseName := compose.FindVMDef(f, op.VMName)
		if vmDef == nil {
			continue
		}
		spec, err := compose.BuildVMSpec(op.VMName, baseName, vmDef, f)
		if err != nil {
			return nil, fmt.Errorf("build spec for %s: %w", op.VMName, err)
		}
		specByVM[op.VMName] = spec

		req := buildPlacementRequest(spec)
		// Resolve anti-affinity names: expand compose definition keys to instance names.
		req.AntiAffinity = expandAntiAffinity(req.AntiAffinity, req.VMName, composeInstances)
		placementReqs = append(placementReqs, req)
		placementVMNames = append(placementVMNames, op.VMName)
	}

	placements, err := placement.SelectBatch(state.Hosts, state.VMs, state.Devices, placementReqs)
	if err != nil {
		return nil, fmt.Errorf("batch placement failed: %w", err)
	}

	// Step 4: Build VMActions with resolved hosts and devices.
	vmHostMap := map[string]string{} // vmName → host (for network/LB resolution)
	for _, op := range vmPlan.Ops {
		action := VMAction{
			Kind:      op.Kind,
			VMName:    op.VMName,
			Detail:    op.Detail,
			DependsOn: op.DependsOn,
			Warning:   op.Warning,
		}

		if op.Kind == OpCreate || op.Kind == OpUpdate {
			spec := specByVM[op.VMName]
			br := placements[op.VMName]
			action.TargetHost = br.Host
			action.Spec = spec
			vmHostMap[op.VMName] = br.Host

			// Convert device assignments.
			for _, d := range br.Devices {
				action.Devices = append(action.Devices, DeviceAssignment{
					Type:    d.Type,
					Address: d.Address,
					Vendor:  d.Vendor,
					Device:  d.Device,
				})
			}

			// Check image availability on target host.
			if spec.Image != "" {
				action.ImagePull = !hostHasImage(state.ImageHosts, spec.Image, br.Host)
				if action.ImagePull {
					plan.Warnings = append(plan.Warnings,
						fmt.Sprintf("%s: image %q will be pulled on %s", op.VMName, spec.Image, br.Host))
				}
			}

			// Resolve storage backend.
			action.Storage = resolveStorage(spec, f)

			// Set wait condition for dependents.
			action.WaitFor = highestWaitCondition(op.VMName, vmPlan.Ops)
		} else if op.Kind == OpNoChange {
			// Carry forward existing host for network/LB resolution.
			for _, c := range current {
				if c.Name == op.VMName {
					vmHostMap[op.VMName] = c.HostName
					break
				}
			}
		}

		plan.VMs = append(plan.VMs, action)
	}

	// Step 5: Resolve network target hosts.
	resolveNetworkTargets(plan, f, vmHostMap, state)

	// Step 6: Resolve LB targets.
	plan.LBs = resolveLBs(f, vmHostMap, state)

	// Step 7: Resolve DNS.
	plan.DNS = resolveDNS(f, specByVM, vmHostMap)

	// Step 8: Collect warnings.
	collectWarnings(plan, f)

	// Summary.
	plan.Summary = vmPlan.Summary()

	return plan, nil
}

// buildCurrentVMs converts snapshot VMs into compose.CurrentVM for diffing.
func buildCurrentVMs(state *ClusterState, stackName string) []compose.CurrentVM {
	var current []compose.CurrentVM
	for _, vm := range state.VMs {
		if vm.StackName != stackName {
			continue
		}
		current = append(current, compose.CurrentVM{
			Name:          vm.Name,
			Image:         specField(vm.Spec, "image"),
			CPU:           vm.CPUActual,
			MemMiB:        vm.MemActual,
			State:         vm.State,
			HostName:      vm.HostName,
			CloudInitHash: specField(vm.Spec, "cloud_init_hash"),
		})
	}
	return current
}

// specField extracts a field from the JSON spec. Lightweight — avoids full unmarshal.
func specField(specJSON, field string) string {
	// Simple key extraction for common fields.
	idx := strings.Index(specJSON, `"`+field+`"`)
	if idx < 0 {
		return ""
	}
	rest := specJSON[idx+len(field)+2:]
	// Skip:"
	if len(rest) < 2 || rest[0] != ':' {
		return ""
	}
	rest = strings.TrimLeft(rest[1:], " ")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	end := strings.Index(rest[1:], `"`)
	if end < 0 {
		return ""
	}
	return rest[1 : end+1]
}

// diffNetworks compares compose networks against current state.
func diffNetworks(f *compose.File, state *ClusterState) []NetworkAction {
	currentNets := map[string]bool{}
	for _, n := range state.Networks {
		currentNets[n.Name] = true
	}

	var actions []NetworkAction
	desired := map[string]bool{}

	for name, netDef := range f.Networks {
		ntype := netDef.Type
		if ntype == "" {
			ntype = "bridge"
		}
		iface := netDef.Interface
		if iface == "" {
			iface = name
		}

		if netDef.External {
			desired[name] = true
			actions = append(actions, NetworkAction{
				Kind:   OpNoChange,
				Name:   name,
				Type:   ntype,
				Config: netDef,
				Detail: fmt.Sprintf("network %s (external, type=%s)", name, ntype),
			})
			continue
		}

		scopedName := compose.ScopedNetworkName(f.Name, name)
		desired[scopedName] = true

		if currentNets[scopedName] {
			actions = append(actions, NetworkAction{
				Kind:   OpNoChange,
				Name:   scopedName,
				Type:   ntype,
				Config: netDef,
				Detail: fmt.Sprintf("network %s: no changes", name),
			})
		} else {
			actions = append(actions, NetworkAction{
				Kind:   OpCreate,
				Name:   scopedName,
				Type:   ntype,
				Config: netDef,
				Detail: fmt.Sprintf("create network %s (type=%s interface=%s)", name, ntype, iface),
			})
		}
	}

	// Networks in current state but not in desired → delete (unless external).
	for _, n := range state.Networks {
		if n.StackName == f.Name && !desired[n.Name] {
			actions = append(actions, NetworkAction{
				Kind:   OpDelete,
				Name:   n.Name,
				Type:   n.Type,
				Detail: fmt.Sprintf("delete network %s (no longer in compose)", n.Name),
			})
		}
	}

	return actions
}

// resolveNetworkTargets fills in TargetHosts/VTEPHosts for network actions
// based on where VMs using each network are placed.
func resolveNetworkTargets(plan *ResolvedPlan, f *compose.File, vmHostMap map[string]string, state *ClusterState) {
	// Build network → hosts map from VM placements.
	// Keys use scoped names to match plan.Networks[].Name.
	netHosts := map[string]map[string]bool{}
	scopeNet := func(rawName string) string {
		if nd, ok := f.Networks[rawName]; ok && nd.External {
			return rawName
		}
		return compose.ScopedNetworkName(f.Name, rawName)
	}
	for _, vmDef := range f.VMs {
		for _, na := range vmDef.Network {
			key := scopeNet(na.Name)
			if netHosts[key] == nil {
				netHosts[key] = map[string]bool{}
			}
		}
	}
	for baseName, vmDef := range f.VMs {
		for r := 0; r < vmDef.EffectiveReplicas(); r++ {
			instanceName := vmDef.InstanceName(baseName, r)
			host := vmHostMap[instanceName]
			if host == "" {
				continue
			}
			for _, na := range vmDef.Network {
				key := scopeNet(na.Name)
				if netHosts[key] == nil {
					netHosts[key] = map[string]bool{}
				}
				netHosts[key][host] = true
			}
		}
	}

	// Also include hosts from existing VMs on this stack (for no-change networks).
	for _, vm := range state.VMs {
		if vm.StackName != f.Name {
			continue
		}
		if host := vmHostMap[vm.Name]; host != "" {
			// Already accounted for.
			continue
		}
	}

	for i := range plan.Networks {
		na := &plan.Networks[i]
		hosts := sortedKeys(netHosts[na.Name])

		switch na.Type {
		case "vxlan":
			na.VTEPHosts = hosts
			na.TargetHosts = hosts
			// Elect DHCP gateway: lexicographically first host.
			if len(hosts) > 0 && na.Config.Subnet != "" {
				na.DHCPGateway = hosts[0]
			}
		default:
			na.TargetHosts = hosts
		}
	}
}

// resolveLBs builds LB actions from compose definitions and resolved VM placements.
func resolveLBs(f *compose.File, vmHostMap map[string]string, state *ClusterState) []LBAction {
	var actions []LBAction

	for baseName, vmDef := range f.VMs {
		if vmDef.LoadBalancer == nil || !vmDef.LoadBalancer.Enabled {
			continue
		}

		lbName := f.Name + "-lb"
		lbDef := vmDef.LoadBalancer

		// Build port list.
		var ports []lb.Port
		for _, p := range lbDef.Ports {
			ports = append(ports, lb.Port{
				Listen:   p.Listen,
				Target:   p.Target,
				Protocol: p.Protocol,
			})
		}

		// Backend VMs.
		var backends []string
		for r := 0; r < vmDef.EffectiveReplicas(); r++ {
			backends = append(backends, vmDef.InstanceName(baseName, r))
		}

		// Target hosts: explicit or derived from VM placement.
		var targetHosts []string
		if len(lbDef.Hosts) > 0 {
			targetHosts = lbDef.Hosts
		} else {
			hostSet := map[string]bool{}
			for _, vm := range backends {
				if h := vmHostMap[vm]; h != "" {
					hostSet[h] = true
				}
			}
			targetHosts = sortedKeys(hostSet)
		}

		// Check if LB already exists.
		kind := OpCreate
		for _, existing := range state.LBs {
			if existing.Name == lbName {
				kind = OpUpdate
				break
			}
		}

		detail := fmt.Sprintf("lb %s vip=%s algorithm=%s ports=%d backends=%d hosts=%s",
			lbName, lbDef.VIP, lbDef.Algorithm, len(ports), len(backends), strings.Join(targetHosts, ","))

		actions = append(actions, LBAction{
			Kind:        kind,
			Name:        lbName,
			VIP:         lbDef.VIP,
			Algorithm:   lbDef.Algorithm,
			Ports:       ports,
			TargetHosts: targetHosts,
			BackendVMs:  backends,
			Detail:      detail,
		})
		break // one LB per stack
	}

	return actions
}

// resolveDNS builds DNS actions for VMs with DNS configured.
func resolveDNS(f *compose.File, specByVM map[string]*pb.VMSpec, vmHostMap map[string]string) []DNSAction {
	if f.DNS == nil || f.DNS.Domain == "" {
		return nil
	}

	var actions []DNSAction
	for baseName, vmDef := range f.VMs {
		for r := 0; r < vmDef.EffectiveReplicas(); r++ {
			instanceName := vmDef.InstanceName(baseName, r)
			if vmHostMap[instanceName] == "" {
				continue // no-change or delete
			}

			// Check if VM has a static IP.
			var staticIP string
			for _, na := range vmDef.Network {
				if na.IP != "" {
					staticIP = na.IP
					break
				}
			}

			fqdn := fmt.Sprintf("%s.%s.%s", instanceName, f.Name, f.DNS.Domain)
			actions = append(actions, DNSAction{
				Kind:     OpCreate,
				VMName:   instanceName,
				FQDN:     fqdn,
				IP:       staticIP,
				Deferred: staticIP == "",
			})
		}
	}

	return actions
}

// collectWarnings adds advisory messages to the plan.
func collectWarnings(plan *ResolvedPlan, f *compose.File) {
	for _, vm := range plan.VMs {
		if vm.Kind != OpCreate {
			continue
		}
		vmDef, _ := compose.FindVMDef(f, vm.VMName)
		if vmDef == nil {
			continue
		}

		// Warn: local disk + restart-any failover.
		if vmDef.Migrate != nil && vmDef.Migrate.OnHostFailure == "restart-any" {
			for _, disk := range vmDef.Disks {
				if disk.Storage == "" {
					plan.Warnings = append(plan.Warnings,
						fmt.Sprintf("%s: local disk with on-host-failure=restart-any — data loss risk", vm.VMName))
					break
				}
			}
		}
	}

	// Warn: unresolvable anti-affinity references.
	composeInstances := buildComposeInstanceMap(f)
	allInstances := map[string]bool{}
	for _, instances := range composeInstances {
		for _, inst := range instances {
			allInstances[inst] = true
		}
	}
	for _, vm := range plan.VMs {
		vmDef, _ := compose.FindVMDef(f, vm.VMName)
		if vmDef == nil || vmDef.Placement == nil {
			continue
		}
		for _, ref := range vmDef.Placement.AntiAffinity {
			if _, isKey := composeInstances[ref]; !isKey && !allInstances[ref] {
				plan.Warnings = append(plan.Warnings,
					fmt.Sprintf("%s: anti-affinity reference %q does not match any VM definition in this compose file — anti-affinity will have no effect",
						vm.VMName, ref))
			}
		}
	}

	// Warn: DHCP backends for LB.
	for _, lbAction := range plan.LBs {
		for _, dns := range plan.DNS {
			if dns.Deferred {
				for _, backend := range lbAction.BackendVMs {
					if backend == dns.VMName {
						plan.Warnings = append(plan.Warnings,
							fmt.Sprintf("LB %s: backend %s uses DHCP — LB config deferred until IP discovery",
								lbAction.Name, dns.VMName))
					}
				}
			}
		}
	}
}

// buildPlacementRequest converts a VMSpec into a placement.Request.
func buildPlacementRequest(spec *pb.VMSpec) placement.Request {
	req := placement.Request{
		VMName:       spec.Name,
		CPUNeeded:    int(spec.Cpu),
		MemMiBNeeded: int(spec.MemoryMib),
	}
	if p := spec.Placement; p != nil {
		req.PinHost = p.Host
		req.AntiAffinity = p.AntiAffinity
		req.Affinity = p.Affinity
		req.RequireLabels = p.Require
		req.PreferLabels = p.Prefer
		req.Spread = p.Spread
		req.Policy = placement.ResolvePolicy(placement.Policy(p.Policy))
		if p.MaxPerNode > 0 {
			req.MaxPerNode = int(p.MaxPerNode)
			req.VMBaseName = vmBaseName(spec.Name)
		}
	}
	for _, dev := range spec.Devices {
		req.Devices = append(req.Devices, placement.DeviceRequest{
			Type:   dev.Type,
			Count:  int(dev.Count),
			Vendor: dev.Vendor,
		})
	}
	return req
}

// vmBaseName strips a trailing "-N" replica suffix.
func vmBaseName(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '-' {
			// Check if everything after the dash is digits.
			allDigits := true
			for j := i + 1; j < len(name); j++ {
				if name[j] < '0' || name[j] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits && i+1 < len(name) {
				return name[:i]
			}
			break
		}
	}
	return name
}

// highestWaitCondition checks if any later op depends on vmName.
func highestWaitCondition(vmName string, ops []compose.Op) string {
	best := ""
	for _, op := range ops {
		for dep, def := range op.DependsOn {
			if dep == vmName || strings.HasPrefix(vmName, dep+"-") {
				cond := def.Condition
				if cond == "" {
					cond = "vm_started"
				}
				if cond == "vm_healthy" || (cond == "vm_started" && best == "") {
					best = cond
				}
			}
		}
	}
	return best
}

// resolveStorage returns the storage backend type for a VM's disks.
func resolveStorage(spec *pb.VMSpec, f *compose.File) string {
	for _, d := range spec.Disks {
		if d.Storage != "" {
			if vol, ok := f.Volumes[d.Storage]; ok {
				if vol.Driver != "" {
					return vol.Driver
				}
			}
			return d.Storage
		}
	}
	return "local"
}

func hostHasImage(imageHosts map[string][]string, image, host string) bool {
	for _, h := range imageHosts[image] {
		if h == host {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// buildComposeInstanceMap builds a map from compose VM definition keys to their
// expanded instance names. For single-replica VMs the key maps to itself; for
// multi-replica VMs "web" maps to ["web-1", "web-2", "web-3"].
func buildComposeInstanceMap(f *compose.File) map[string][]string {
	m := make(map[string][]string, len(f.VMs))
	for baseName, vmDef := range f.VMs {
		var names []string
		for r := 0; r < vmDef.EffectiveReplicas(); r++ {
			names = append(names, vmDef.InstanceName(baseName, r))
		}
		m[baseName] = names
	}
	return m
}

// expandAntiAffinity resolves anti-affinity references from compose definition
// keys to actual instance names. For example, if the user writes:
//
//	anti-affinity: [pg-2, pg-3]
//
// and the compose defines VMs "pg-1", "pg-2", "pg-3", each maps to its instance
// name(s). References that are already exact instance names are kept as-is.
// The current VM's own name is excluded to avoid self-anti-affinity.
func expandAntiAffinity(refs []string, selfName string, composeInstances map[string][]string) []string {
	if len(refs) == 0 {
		return nil
	}
	seen := map[string]bool{selfName: true} // exclude self
	var expanded []string
	for _, ref := range refs {
		// Try as a compose definition key first.
		if instances, ok := composeInstances[ref]; ok {
			for _, inst := range instances {
				if !seen[inst] {
					seen[inst] = true
					expanded = append(expanded, inst)
				}
			}
			continue
		}
		// Otherwise keep the literal name (could reference a VM from another stack
		// or an already-running VM not in this compose file).
		if !seen[ref] {
			seen[ref] = true
			expanded = append(expanded, ref)
		}
	}
	return expanded
}
