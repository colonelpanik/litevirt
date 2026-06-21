package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/network"
)

// DeployStack parses a compose YAML, runs the declarative planner to resolve all
// placement, device, network, LB, and DNS decisions up front, then executes the
// plan. Dry-run streams the full resolved plan without applying changes.
func (s *Server) DeployStack(req *pb.DeployStackRequest, stream grpc.ServerStreamingServer[pb.DeployProgress]) error {
	if err := RequireRole(stream.Context(), "operator"); err != nil {
		return err
	}
	ctx := stream.Context()

	if req.ComposeYaml == "" {
		return status.Error(codes.InvalidArgument, "compose_yaml required")
	}

	f, err := compose.ParseBytes([]byte(req.ComposeYaml))
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "parse compose: %v", err)
	}

	// Auto-pull images defined in the compose images: section that are missing locally.
	if err := s.autoPullImages(ctx, f, stream); err != nil {
		return err
	}

	// Pre-deploy validation: verify images and networks exist before creating
	// any VMs. Abort early with clear errors if dependencies are missing (#52).
	if errs := s.validateDeployDependencies(ctx, f); len(errs) > 0 {
		detail := ""
		for _, e := range errs {
			detail += "\n  - " + e
		}
		return status.Errorf(codes.FailedPrecondition, "pre-deploy validation failed:%s", detail)
	}

	// CAS check: if caller supplies expected_hash, verify it matches
	// the current stored hash to prevent concurrent deploy races.
	if req.ExpectedHash != "" {
		existing, _ := corrosion.GetStack(ctx, s.db, f.Name)
		if existing != nil && existing.ComposeHash != req.ExpectedHash {
			return status.Errorf(codes.Aborted,
				"stack %q was modified concurrently (expected hash %s, got %s) — re-fetch and retry",
				f.Name, req.ExpectedHash, existing.ComposeHash)
		}
	}

	// ── Plan phase: snapshot cluster state and resolve everything up front ──

	state, err := planner.LoadClusterState(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.Internal, "load cluster state: %v", err)
	}

	resolved, err := planner.Resolve(ctx, f, state)
	if err != nil {
		return status.Errorf(codes.Internal, "planner: %v", err)
	}

	// ── Dry-run: stream the full resolved plan ──

	if req.DryRun {
		return s.streamResolvedPlan(stream, resolved)
	}

	// ── Execute phase: walk the plan deterministically ──

	// Persist the stack's distributed-firewall config (security groups, ipsets,
	// cluster-tier rules, default-deny) so the per-host reconciler enforces it.
	// Done before VM creation so per-NIC SG bindings resolve against existing
	// groups. Re-deploy is idempotent: the stack's prior firewall rows are
	// cleared first. A malformed block (e.g. an IPv6 CIDR) aborts the deploy.
	if err := s.persistStackFirewall(ctx, f); err != nil {
		return status.Errorf(codes.FailedPrecondition, "firewall config: %v", err)
	}

	// Register the stack's backup repos (logical name → path), so a VM's
	// `backup: { repo: <name> }` resolves cluster-wide without daemon config.
	for name, repo := range f.BackupRepos {
		if repo.Path == "" {
			return status.Errorf(codes.InvalidArgument, "backup-repo %q: path required", name)
		}
		if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{
			Name: name, Path: repo.Path, StackName: f.Name,
		}); err != nil {
			return status.Errorf(codes.Internal, "register backup-repo %q: %v", name, err)
		}
	}

	// Provision networks only on hosts where VMs are placed.
	if err := s.provisionPlannedNetworks(ctx, f, resolved, stream); err != nil {
		return err
	}

	// Prioritize updates: error/failed VMs first.
	current := buildCurrentVMsFromState(state, f.Name)
	sortVMActions(resolved.VMs, current)

	// Check if the compose file specifies a rolling update strategy.
	rollingStrategy := useRollingUpdate(f)
	hasUpdates := false
	for _, a := range resolved.VMs {
		if a.Kind == planner.OpUpdate {
			hasUpdates = true
			break
		}
	}

	if rollingStrategy != "" && hasUpdates {
		// Rolling update mode: creates first, then rolling updates, then deletes.
		if err := s.executeWithRollingUpdates(ctx, f, resolved, stream); err != nil {
			return err
		}
	} else {
		// Inline mode: process all actions sequentially (existing behavior).
		if err := s.executeInlineActions(ctx, f, resolved, stream); err != nil {
			return err
		}
	}

	// Apply LB actions.
	s.applyLBActions(ctx, f, resolved, stream)

	// Persist stack record.
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(req.ComposeYaml)))
	if dbErr := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{
		Name:        f.Name,
		ComposeHash: hash,
		ComposeYAML: req.ComposeYaml,
		State:       "active",
	}); dbErr != nil {
		slog.Warn("upsert stack record failed", "stack", f.Name, "error", dbErr)
	}

	vmOps := 0
	for _, a := range resolved.VMs {
		if a.Kind != planner.OpNoChange {
			vmOps++
		}
	}
	s.publish("stack.deployed", f.Name, fmt.Sprintf("%d VM ops, %d network ops, %d LB ops",
		vmOps, len(resolved.Networks), len(resolved.LBs)))
	s.audit(ctx, "stack.deploy", f.Name, fmt.Sprintf("%d VM ops", vmOps), "ok")
	return nil
}

// persistStackFirewall writes a compose file's distributed-firewall config to
// Corrosion: security groups (+ rules), ip sets, cluster-tier rules, and the
// default-deny policy. The CorrosionPlanLoader on every host then renders these
// into nftables. It is idempotent — the stack's prior firewall rows are
// tombstoned first so edits to the compose block take effect on re-deploy.
func (s *Server) persistStackFirewall(ctx context.Context, f *compose.File) error {
	hasFirewall := len(f.SecurityGroups) > 0 || len(f.IPSets) > 0 || f.FirewallDefaults != nil
	if !hasFirewall {
		// Still clear any rows a previous deploy of this stack left behind, in
		// case the firewall block was removed from the compose file.
		return corrosion.DeleteStackFirewall(ctx, s.db, f.Name)
	}
	if err := corrosion.DeleteStackFirewall(ctx, s.db, f.Name); err != nil {
		return err
	}

	// Security groups + their rules.
	for name, sg := range f.SecurityGroups {
		sgID := newID()
		if err := corrosion.InsertSecurityGroup(ctx, s.db, corrosion.SecurityGroup{
			ID: sgID, Name: name, StackName: f.Name,
		}); err != nil {
			return fmt.Errorf("security-group %q: %w", name, err)
		}
		for i, r := range sg.Rules {
			// Priority follows YAML order (10, 20, …) so an accept-then-drop
			// sequence renders deterministically — equal priorities would sort
			// arbitrarily and could drop traffic an earlier rule meant to allow.
			if err := corrosion.InsertSGRule(ctx, s.db, corrosion.SGRule{
				ID: newID(), SGID: sgID, Direction: r.Direction, Proto: r.Proto,
				PortRange: r.Port, CIDR: r.CIDR, Action: r.Action, Priority: (i + 1) * 10,
			}); err != nil {
				return fmt.Errorf("security-group %q rule: %w", name, err)
			}
		}
	}

	// IP sets.
	for name, set := range f.IPSets {
		if err := corrosion.InsertIPSet(ctx, s.db, corrosion.IPSet{
			ID: newID(), Name: name, CIDRs: set.CIDRs, StackName: f.Name,
		}); err != nil {
			return fmt.Errorf("ipset %q: %w", name, err)
		}
	}

	// Cluster-tier rules + default-deny policy.
	if fd := f.FirewallDefaults; fd != nil {
		for i, r := range fd.ClusterRules {
			if err := corrosion.InsertClusterFirewallRule(ctx, s.db, corrosion.FirewallRule{
				ID: newID(), Direction: r.Direction, Proto: r.Proto, PortRange: r.Port,
				CIDR: r.CIDR, Action: r.Action, Comment: r.Comment, StackName: f.Name, Priority: (i + 1) * 10,
			}); err != nil {
				return fmt.Errorf("cluster rule: %w", err)
			}
		}
		if fd.DefaultDeny {
			// Compose sets the cluster-wide default; per-host overrides live in
			// host config (lv firewall default-deny <host>).
			if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, f.Name); err != nil {
				return fmt.Errorf("default-deny: %w", err)
			}
		}
	}
	return nil
}

// streamResolvedPlan sends the full resolved plan over the deploy progress stream.
func (s *Server) streamResolvedPlan(stream grpc.ServerStreamingServer[pb.DeployProgress], plan *planner.ResolvedPlan) error {
	// Warnings first.
	for _, w := range plan.Warnings {
		if err := stream.Send(&pb.DeployProgress{
			Phase:  "warning",
			Detail: w,
		}); err != nil {
			return err
		}
	}

	// Networks with target hosts.
	for _, na := range plan.Networks {
		hosts := strings.Join(na.TargetHosts, ",")
		detail := fmt.Sprintf("[%s] network %s (type=%s", na.Kind, na.Name, na.Type)
		if hosts != "" {
			detail += " hosts=" + hosts
		}
		if na.DHCPGateway != "" {
			detail += " dhcp=" + na.DHCPGateway
		}
		detail += ")"
		if err := stream.Send(&pb.DeployProgress{
			Phase:  "network",
			Detail: detail,
		}); err != nil {
			return err
		}
	}

	// VMs with placement and device assignments.
	for _, va := range plan.VMs {
		detail := va.Detail
		if va.TargetHost != "" {
			detail += fmt.Sprintf(" → %s", va.TargetHost)
		}
		if len(va.Devices) > 0 {
			var devs []string
			for _, d := range va.Devices {
				devs = append(devs, fmt.Sprintf("%s@%s", d.Type, d.Address))
			}
			detail += fmt.Sprintf(" devices=[%s]", strings.Join(devs, ","))
		}
		if va.ImagePull {
			detail += " [image-pull]"
		}
		if va.Storage != "local" && va.Storage != "" {
			detail += fmt.Sprintf(" storage=%s", va.Storage)
		}
		if err := stream.Send(&pb.DeployProgress{
			Phase:  string(va.Kind),
			VmName: va.VMName,
			Detail: detail,
		}); err != nil {
			return err
		}
	}

	// LBs.
	for _, la := range plan.LBs {
		if err := stream.Send(&pb.DeployProgress{
			Phase:  "loadbalancer",
			Detail: la.Detail,
		}); err != nil {
			return err
		}
	}

	// DNS.
	for _, da := range plan.DNS {
		detail := fmt.Sprintf("dns %s → %s", da.FQDN, da.IP)
		if da.Deferred {
			detail = fmt.Sprintf("dns %s → pending (DHCP)", da.FQDN)
		}
		if err := stream.Send(&pb.DeployProgress{
			Phase:  "dns",
			VmName: da.VMName,
			Detail: detail,
		}); err != nil {
			return err
		}
	}

	// Summary.
	if plan.Summary != "" {
		_ = stream.Send(&pb.DeployProgress{
			Phase:  "summary",
			Detail: plan.Summary,
		})
	}

	return nil
}

// deployCreatePlanned creates a VM using the planner's pre-resolved host and device
// assignments. The spec's Placement.Host is pinned so CreateVM skips placement, and
// device addresses are set so allocateDevices uses exact pinning.
func (s *Server) deployCreatePlanned(ctx context.Context, action planner.VMAction, f *compose.File) error {
	spec := action.Spec
	if spec == nil {
		// Fallback: build spec from compose (shouldn't happen with planner).
		vmDef, baseName := compose.FindVMDef(f, action.VMName)
		if vmDef == nil {
			return fmt.Errorf("no VM definition found for %q", action.VMName)
		}
		var err error
		spec, err = compose.BuildVMSpec(action.VMName, baseName, vmDef, f)
		if err != nil {
			return fmt.Errorf("build VM spec for %q: %w", action.VMName, err)
		}
	}

	// Pin placement to the planner-resolved host.
	if action.TargetHost != "" {
		if spec.Placement == nil {
			spec.Placement = &pb.PlacementSpec{}
		}
		spec.Placement.Host = action.TargetHost
	}

	// Pin pre-resolved device addresses so allocateDevices uses exact binding.
	if len(action.Devices) > 0 {
		for i, dev := range action.Devices {
			if i < len(spec.Devices) {
				spec.Devices[i].Address = dev.Address
			}
		}
	}

	// workloads dispatcher: containers (kind: lxc | oci) can
	// be declared in compose but the deploy path through CreateVM is
	// VM-only. Surface a clear error pointing at `lv ct` so the
	// operator isn't left wondering why their alpine container ends
	// up as a libvirt domain. Wiring container deploys through
	// `Containers` RPCs is a follow-up — until then, deploy stacks
	// containing kind=lxc / kind=oci workloads via `lv ct create` per
	// container rather than `lv compose up`.
	if vmDef, _ := compose.FindVMDef(f, action.VMName); vmDef != nil {
		switch vmDef.Kind {
		case compose.WorkloadKindLXC, compose.WorkloadKindOCI:
			return fmt.Errorf(
				"workload %q has kind=%s; compose deploy doesn't yet route containers — "+
					"create with `lv ct create %s` (or use the Containers gRPC service)",
				action.VMName, vmDef.Kind, action.VMName)
		}
	}

	if _, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec}); err != nil {
		return err
	}

	// compose hook: reconcile a backup_schedules row from
	// the VMDef's `backup:` block. Best-effort — a failure here doesn't
	// roll back the VM creation, just logs and continues.
	if vmDef, _ := compose.FindVMDef(f, action.VMName); vmDef != nil {
		if err := s.syncComposeBackupSchedule(ctx, action.VMName, vmDef); err != nil {
			slog.Warn("compose backup schedule sync", "vm", action.VMName, "error", err)
		}
	}

	// Register DNS records if the compose file defines a dns domain.
	if f.DNS != nil && f.DNS.Domain != "" {
		ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, action.VMName)
		for _, iface := range ifaces {
			if iface.IP != "" {
				dnsName := dns.VMRecordName(action.VMName, f.Name, f.DNS.Domain)
				if err := dns.UpsertRecord(ctx, s.db, dnsName, iface.IP); err != nil {
					slog.Warn("dns record upsert failed", "vm", action.VMName, "error", err)
				}
				break
			}
		}
	}

	// Set webhook URL from compose notifications section if configured.
	if f.Notifications != nil && f.Notifications.Webhook != "" {
		s.SetWebhookURL(f.Notifications.Webhook)
	}

	return nil
}

// provisionPlannedNetworks provisions networks only on hosts where VMs are placed,
// instead of broadcasting to all cluster hosts.
func (s *Server) provisionPlannedNetworks(ctx context.Context, f *compose.File, plan *planner.ResolvedPlan, stream grpc.ServerStreamingServer[pb.DeployProgress]) error {
	// Build the set of hosts that actually need network provisioning.
	targetHosts := map[string]bool{}
	for _, na := range plan.Networks {
		for _, h := range na.TargetHosts {
			targetHosts[h] = true
		}
	}

	// Provision on local host ONLY if it is a target host.
	if targetHosts[s.hostName] {
		if errs := s.provisionComposeNetworks(ctx, f); len(errs) > 0 {
			detail := ""
			for _, e := range errs {
				detail += "\n  - " + e
			}
			return status.Errorf(codes.FailedPrecondition, "network provisioning failed:%s", detail)
		}
	} else {
		// Not a target — still persist network records to Corrosion so the
		// cluster knows about them, but don't provision locally.
		for name, netDef := range f.Networks {
			if netDef.External {
				continue
			}
			ntype := netDef.Type
			if ntype == "" {
				ntype = "bridge"
			}
			cfgJSON, _ := json.Marshal(netDef)
			_ = corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
				Name:      compose.ScopedNetworkName(f.Name, name),
				StackName: f.Name,
				Type:      ntype,
				Config:    string(cfgJSON),
			})
		}
	}

	// Provision networks on each peer target. Failures here are NOT cosmetic:
	// a VM later scheduled on a peer whose network we failed to provision comes
	// up with no connectivity. Aggregate the failures and fail the deploy rather
	// than reporting a clean success over a half-provisioned fabric.
	var provErrs []string
	for host := range targetHosts {
		if host == s.hostName {
			continue
		}
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			provErrs = append(provErrs, fmt.Sprintf("reach %s: %v", host, err))
			continue
		}
		for name, netDef := range f.Networks {
			if netDef.External {
				continue
			}
			cfgJSON, _ := json.Marshal(netDef)
			ntype := netDef.Type
			if ntype == "" {
				ntype = "bridge"
			}
			scopedName := compose.ScopedNetworkName(f.Name, name)
			if _, err := client.ProvisionNetwork(ctx, &pb.ProvisionNetworkRequest{
				Name:      scopedName,
				Config:    string(cfgJSON),
				NetType:   ntype,
				StackName: f.Name,
			}); err != nil {
				provErrs = append(provErrs, fmt.Sprintf("%s/%s: %v", host, scopedName, err))
			}
		}
		conn.Close()
	}

	// Inject subnet routes between cluster hosts so peers can reach VMs on
	// bridge networks with subnets that differ from the host's own subnet.
	// Each hypervisor hosting VMs advertises its subnet via proxy ARP (set
	// during Provision). Peer hosts get explicit routes.
	s.injectSubnetRoutes(ctx, f, plan)

	if len(provErrs) > 0 {
		return status.Errorf(codes.Internal,
			"network provisioning failed on %d peer target(s): %s",
			len(provErrs), strings.Join(provErrs, "; "))
	}
	return nil
}

// injectSubnetRoutes adds static routes on cluster hosts so they can reach
// VM subnets hosted on other hypervisors. For each bridge network with a
// subnet, every cluster host that is NOT a target for that network gets a
// route pointing to the hypervisor(s) that ARE targets.
func (s *Server) injectSubnetRoutes(ctx context.Context, f *compose.File, plan *planner.ResolvedPlan) {
	// Collect bridge subnets and which hosts serve them.
	type subnetRoute struct {
		subnet string
		viaIPs []string // hypervisor IPs that host VMs on this subnet
	}
	routes := map[string]*subnetRoute{} // network name → route info

	for _, na := range plan.Networks {
		netDef, ok := f.Networks[na.Name]
		if !ok || netDef.External || netDef.HostIsolation {
			continue
		}
		ntype := na.Type
		if ntype == "" {
			ntype = "bridge"
		}
		// Only inject routes for bridges where the host is the gateway
		// (DHCP+NAT active). Bridges on physical VLANs don't need routes —
		// VMs are reachable via the VLAN's own router.
		if ntype != "bridge" || netDef.Subnet == "" || !netDef.NATEnabled() {
			continue
		}

		sr := &subnetRoute{subnet: netDef.Subnet}
		for _, host := range na.TargetHosts {
			// Look up the host's IP from cluster state.
			hostRec, err := corrosion.GetHost(ctx, s.db, host)
			if err != nil || hostRec == nil || hostRec.Address == "" {
				continue
			}
			sr.viaIPs = append(sr.viaIPs, hostRec.Address)
		}
		if len(sr.viaIPs) > 0 {
			routes[na.Name] = sr
		}
	}

	if len(routes) == 0 {
		return
	}

	// Get all cluster hosts.
	allHosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return
	}

	// Build target host set per network for fast lookup.
	targetHostSet := map[string]map[string]bool{}
	for _, na := range plan.Networks {
		set := map[string]bool{}
		for _, h := range na.TargetHosts {
			set[h] = true
		}
		targetHostSet[na.Name] = set
	}

	for netName, sr := range routes {
		targets := targetHostSet[netName]
		// Use the first hypervisor as the gateway (all are on the same L2).
		viaIP := sr.viaIPs[0]

		for _, h := range allHosts {
			if h.State != "active" || targets[h.Name] {
				continue // skip target hosts — they have the bridge locally
			}

			if h.Name == s.hostName {
				// Local host: add route directly.
				if err := network.EnsureSubnetRoute(sr.subnet, viaIP); err != nil {
					slog.Warn("local subnet route failed", "subnet", sr.subnet, "via", viaIP, "error", err)
				}
			}
			// Remote non-target hosts: proxy ARP on the target hypervisors
			// handles reachability — the physical network delivers the traffic.
			// If needed in the future, we can add an RPC to push routes to
			// remote non-target hosts as well.
		}
	}
}

// applyLBActions applies load balancer actions from the resolved plan.
func (s *Server) applyLBActions(ctx context.Context, f *compose.File, plan *planner.ResolvedPlan, stream grpc.ServerStreamingServer[pb.DeployProgress]) {
	for _, la := range plan.LBs {
		if la.Kind == planner.OpNoChange {
			continue
		}
		_ = stream.Send(&pb.DeployProgress{
			Phase:  "loadbalancer",
			Detail: fmt.Sprintf("applying %s", la.Detail),
		})

		// Build a stub VMSpec with LB config for the existing apply logic.
		// applyLBFromSpecWithRetry reads spec.Loadbalancer and spec.StackName.
		for _, vmDef := range f.VMs {
			if vmDef.LoadBalancer == nil || !vmDef.LoadBalancer.Enabled {
				continue
			}
			var ports []*pb.LBPort
			for _, p := range la.Ports {
				ports = append(ports, &pb.LBPort{
					Listen:   int32(p.Listen),
					Target:   int32(p.Target),
					Protocol: p.Protocol,
				})
			}
			stubSpec := &pb.VMSpec{
				StackName: f.Name,
				Loadbalancer: &pb.LBSpec{
					Enabled:   true,
					Vip:       la.VIP,
					Algorithm: la.Algorithm,
					Ports:     ports,
					Hosts:     la.TargetHosts,
				},
			}
			s.applyLBFromSpecWithRetry(ctx, stubSpec)
			break
		}
	}
}

// sortVMActions reorders update operations so that already-failed replicas
// are processed first (#32).
func sortVMActions(actions []planner.VMAction, current []compose.CurrentVM) {
	stateOf := make(map[string]string, len(current))
	for _, c := range current {
		stateOf[c.Name] = c.State
	}
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Kind != planner.OpUpdate || actions[j].Kind != planner.OpUpdate {
			return false
		}
		return statePriority(stateOf[actions[i].VMName]) < statePriority(stateOf[actions[j].VMName])
	})
}

// buildCurrentVMsFromState converts snapshot VMs to compose.CurrentVM for sorting.
func buildCurrentVMsFromState(state *planner.ClusterState, stackName string) []compose.CurrentVM {
	var current []compose.CurrentVM
	for _, vm := range state.VMs {
		if vm.StackName != stackName {
			continue
		}
		current = append(current, compose.CurrentVM{
			Name:     vm.Name,
			State:    vm.State,
			HostName: vm.HostName,
		})
	}
	return current
}

// DeleteStack deletes all VMs in a named stack. If any resource fails to clean
// up, the stack is left in "deleting" state for the background reconciler to retry.
func (s *Server) DeleteStack(req *pb.DeleteStackRequest, stream grpc.ServerStreamingServer[pb.DeleteProgress]) error {
	if err := RequireRole(stream.Context(), "operator"); err != nil {
		return err
	}
	ctx := stream.Context()

	vms, err := corrosion.ListVMs(ctx, s.db, req.Name, "")
	if err != nil {
		return status.Errorf(codes.Internal, "list VMs: %v", err)
	}

	// Merge VMs from the stored compose YAML to catch VMs that haven't
	// replicated to local Corrosion yet (created on remote hosts).
	vmNames := map[string]bool{}
	for _, vm := range vms {
		vmNames[vm.Name] = true
	}
	if st, err := corrosion.GetStack(ctx, s.db, req.Name); err == nil && st != nil && st.ComposeYAML != "" {
		if f, err := compose.ParseBytes([]byte(st.ComposeYAML)); err == nil {
			for baseName, vmDef := range f.VMs {
				for r := 0; r < vmDef.EffectiveReplicas(); r++ {
					instName := vmDef.InstanceName(baseName, r)
					if !vmNames[instName] {
						vmNames[instName] = true
						vms = append(vms, corrosion.VMRecord{
							Name:      instName,
							StackName: req.Name,
						})
					}
				}
			}
		}
	}

	// Mark stack as "deleting" first — this is durable and survives crashes.
	// The background StackReconciler will pick up stacks stuck in this state.
	if err := corrosion.SetStackState(ctx, s.db, req.Name, "deleting"); err != nil {
		return status.Errorf(codes.Internal, "set stack state: %v", err)
	}

	// Soft-delete the LB config so that VM deletion's refreshLBForStack
	// goroutines see the record as gone and don't re-apply the LB mid-teardown.
	lbName := req.Name + "-lb"
	corrosion.DeleteLBBackends(ctx, s.db, lbName)
	_ = corrosion.SoftDeleteLBConfig(ctx, s.db, lbName)

	hadFailures := false
	for _, vm := range vms {
		if err := stream.Send(&pb.DeleteProgress{
			VmName: vm.Name,
			Status: "deleting",
		}); err != nil {
			return err
		}

		delErr := s.deleteVMWithFanout(ctx, vm.Name, req.KeepDisks)
		if delErr != nil {
			hadFailures = true
			slog.Warn("stack delete vm failed", "vm", vm.Name, "error", delErr)
			if sendErr := stream.Send(&pb.DeleteProgress{
				VmName: vm.Name,
				Status: "error",
				Error:  delErr.Error(),
			}); sendErr != nil {
				return sendErr
			}
			continue
		}

		if err := stream.Send(&pb.DeleteProgress{
			VmName: vm.Name,
			Status: "deleted",
		}); err != nil {
			return err
		}
	}

	// Deprovision networks associated with this stack (skip external networks).
	externalNets := s.externalNetworkNames(ctx, req.Name)
	nets, _ := corrosion.ListNetworks(ctx, s.db)
	for _, nr := range nets {
		if nr.StackName == req.Name && !externalNets[nr.Name] {
			if err := s.deprovisionNetworkByName(ctx, nr.Name); err != nil {
				hadFailures = true
				slog.Warn("stack network deprovision failed", "network", nr.Name, "error", err)
			}
		}
	}

	// Remove any load balancers associated with this stack.
	s.removeLBForStack(ctx, req.Name, vms)

	// Only tombstone the stack if all resources were cleaned up.
	// If anything failed, leave it in "deleting" state for the reconciler.
	if hadFailures {
		remaining, _ := corrosion.ListVMs(ctx, s.db, req.Name, "")
		slog.Warn("stack deletion incomplete — reconciler will retry",
			"stack", req.Name, "remaining_vms", len(remaining))
		s.publish("stack.deleting", req.Name, fmt.Sprintf("%d VMs remaining", len(remaining)))
	} else {
		// Hard-delete the soft-deleted LB config now that processes are stopped.
		_ = corrosion.DeleteLBConfig(ctx, s.db, lbName)

		// Tombstone the stack's distributed-firewall config (SGs, ipsets,
		// cluster rules, default-deny). The reconciler then drops the rules.
		if dbErr := corrosion.DeleteStackFirewall(ctx, s.db, req.Name); dbErr != nil {
			slog.Warn("delete stack firewall failed", "stack", req.Name, "error", dbErr)
		}

		// Unregister the stack's backup repos.
		if dbErr := corrosion.DeleteStackBackupRepos(ctx, s.db, req.Name); dbErr != nil {
			slog.Warn("delete stack backup repos failed", "stack", req.Name, "error", dbErr)
		}

		if dbErr := corrosion.DeleteStackRecord(ctx, s.db, req.Name); dbErr != nil {
			slog.Warn("delete stack record failed", "stack", req.Name, "error", dbErr)
		}
		s.publish("stack.deleted", req.Name, fmt.Sprintf("%d VMs", len(vms)))
	}

	s.audit(ctx, "stack.delete", req.Name, "", "ok")
	return nil
}

// deleteVMWithFanout tries DeleteVM locally first. If the VM is not found in
// local Corrosion (replication lag from remote host), it fans out to all peer
// hosts until one successfully deletes it. Transient errors (Unavailable, EOF)
// are retried with backoff since remote daemons may be temporarily unresponsive.
func (s *Server) deleteVMWithFanout(ctx context.Context, vmName string, keepDisks bool) error {
	const maxRetries = 3
	var err error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt) * 3 * time.Second
			slog.Info("retrying VM delete", "vm", vmName, "attempt", attempt+1, "backoff", backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		_, err = s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: vmName, KeepDisks: keepDisks})
		if err == nil {
			return nil
		}

		code := status.Code(err)

		// NotFound — fan out to peers (replication lag).
		if code == codes.NotFound {
			if peerErr := s.fanoutDeleteVM(ctx, vmName, keepDisks); peerErr == nil {
				return nil
			}
			return err
		}

		// Unavailable means the peer host is unreachable — retrying
		// locally won't fix that. Try fanout to other peers instead.
		if code == codes.Unavailable {
			if peerErr := s.fanoutDeleteVM(ctx, vmName, keepDisks); peerErr == nil {
				return nil
			}
			return err
		}

		// Transient local errors — retry with backoff.
		if code == codes.Aborted || code == codes.Internal {
			slog.Warn("transient error deleting VM, will retry", "vm", vmName, "error", err, "attempt", attempt+1)
			continue
		}

		// Non-transient error — don't retry.
		return err
	}

	return err
}

// fanoutDeleteVM tries to delete a VM on all peer hosts (for replication-lag cases).
func (s *Server) fanoutDeleteVM(ctx context.Context, vmName string, keepDisks bool) error {
	slog.Info("VM not in local DB, fanning out delete to peers", "vm", vmName)
	hosts, listErr := corrosion.ListHosts(ctx, s.db)
	if listErr != nil {
		return listErr
	}

	for _, h := range hosts {
		if h.Name == s.hostName || h.State != "active" {
			continue
		}
		client, conn, peerErr := s.peerClient(ctx, h.Name)
		if peerErr != nil {
			continue
		}
		_, peerErr = client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: vmName, KeepDisks: keepDisks})
		conn.Close()
		if peerErr == nil {
			slog.Info("VM deleted via peer", "vm", vmName, "host", h.Name)
			return nil
		}
		if status.Code(peerErr) != codes.NotFound {
			return peerErr // real error on the peer
		}
	}

	return fmt.Errorf("VM %q not found on any peer", vmName)
}

// RemoveLBForStack exposes removeLBForStack for the StackReconciler.
func (s *Server) RemoveLBForStack(ctx context.Context, stackName string, vms []corrosion.VMRecord) {
	s.removeLBForStack(ctx, stackName, vms)
}

// DeprovisionNetworkByName exposes deprovisionNetworkByName for the StackReconciler.
func (s *Server) DeprovisionNetworkByName(ctx context.Context, name string) error {
	return s.deprovisionNetworkByName(ctx, name)
}

// ExternalNetworkNames exposes externalNetworkNames for the StackReconciler.
func (s *Server) ExternalNetworkNames(ctx context.Context, stackName string) map[string]bool {
	return s.externalNetworkNames(ctx, stackName)
}

// ListStacks returns a summary of all deployed stacks.
func (s *Server) ListStacks(ctx context.Context, _ *emptypb.Empty) (*pb.ListStacksResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	stacks, err := corrosion.ListStacks(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list stacks: %v", err)
	}

	// Single query for all per-stack VM counts instead of N+1.
	vmCounts, _ := corrosion.CountVMsByStack(ctx, s.db)

	resp := &pb.ListStacksResponse{}
	for _, st := range stacks {
		sc := vmCounts[st.Name]
		resp.Stacks = append(resp.Stacks, &pb.StackSummary{
			Name:      st.Name,
			State:     st.State,
			VmCount:   int32(sc.Total),
			Running:   int32(sc.Running),
			Stopped:   int32(sc.Stopped),
			Error:     int32(sc.Error),
			CreatedAt: parseTimestamp(st.CreatedAt),
		})
	}
	return resp, nil
}

// DiffStack shows what DeployStack would change without applying it.
// DiffStack runs the full planner and returns a resolved plan as DiffEntries.
// Each resource type (network, VM, LB, DNS) gets its own entry with placement,
// device assignments, and target hosts pre-resolved.
func (s *Server) DiffStack(ctx context.Context, req *pb.DiffStackRequest) (*pb.DiffStackResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.ComposeYaml == "" {
		return nil, status.Error(codes.InvalidArgument, "compose_yaml required")
	}

	f, err := compose.ParseBytes([]byte(req.ComposeYaml))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parse compose: %v", err)
	}

	state, err := planner.LoadClusterState(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load cluster state: %v", err)
	}

	resolved, err := planner.Resolve(ctx, f, state)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "planner: %v", err)
	}

	resp := &pb.DiffStackResponse{}

	// Warnings.
	for _, w := range resolved.Warnings {
		resp.Entries = append(resp.Entries, &pb.DiffEntry{
			Operation: pb.DiffOp_DIFF_UNCHANGED,
			Detail:    "⚠ " + w,
		})
	}

	// Networks with target hosts.
	for _, na := range resolved.Networks {
		hosts := strings.Join(na.TargetHosts, ",")
		detail := fmt.Sprintf("network %s (type=%s", na.Name, na.Type)
		if hosts != "" {
			detail += " hosts=" + hosts
		}
		if na.DHCPGateway != "" {
			detail += " dhcp=" + na.DHCPGateway
		}
		detail += ")"
		resp.Entries = append(resp.Entries, &pb.DiffEntry{
			Operation: opKindToDiffOp(na.Kind),
			Detail:    detail,
		})
	}

	// VMs with placement, devices, storage.
	for _, va := range resolved.VMs {
		detail := va.Detail
		if va.TargetHost != "" {
			detail += fmt.Sprintf(" → %s", va.TargetHost)
		}
		if len(va.Devices) > 0 {
			var devs []string
			for _, d := range va.Devices {
				devs = append(devs, fmt.Sprintf("%s@%s", d.Type, d.Address))
			}
			detail += fmt.Sprintf(" devices=[%s]", strings.Join(devs, ","))
		}
		if va.ImagePull {
			detail += " [image-pull]"
		}
		if va.Storage != "local" && va.Storage != "" {
			detail += fmt.Sprintf(" storage=%s", va.Storage)
		}
		resp.Entries = append(resp.Entries, &pb.DiffEntry{
			VmName:    va.VMName,
			Operation: opKindToDiffOp(va.Kind),
			Detail:    detail,
		})
	}

	// LBs.
	for _, la := range resolved.LBs {
		resp.Entries = append(resp.Entries, &pb.DiffEntry{
			Operation: opKindToDiffOp(la.Kind),
			Detail:    la.Detail,
		})
	}

	// DNS.
	for _, da := range resolved.DNS {
		detail := fmt.Sprintf("dns %s → %s", da.FQDN, da.IP)
		if da.Deferred {
			detail = fmt.Sprintf("dns %s → pending (DHCP)", da.FQDN)
		}
		resp.Entries = append(resp.Entries, &pb.DiffEntry{
			VmName:    da.VMName,
			Operation: opKindToDiffOp(da.Kind),
			Detail:    detail,
		})
	}

	return resp, nil
}

func (s *Server) ExportStack(ctx context.Context, req *pb.ExportStackRequest) (*pb.ExportStackResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	stack, err := corrosion.GetStack(ctx, s.db, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get stack: %v", err)
	}
	if stack == nil {
		return nil, status.Errorf(codes.NotFound, "stack %q not found", req.Name)
	}
	return &pb.ExportStackResponse{
		Name:        stack.Name,
		ComposeYaml: stack.ComposeYAML,
		ComposeHash: stack.ComposeHash,
	}, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (s *Server) deployCreate(ctx context.Context, instanceName string, f *compose.File) error {
	vmDef, baseName := compose.FindVMDef(f, instanceName)
	if vmDef == nil {
		return fmt.Errorf("no VM definition found for %q", instanceName)
	}
	spec, err := compose.BuildVMSpec(instanceName, baseName, vmDef, f)
	if err != nil {
		return fmt.Errorf("build VM spec for %q: %w", instanceName, err)
	}
	if _, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec}); err != nil {
		return err
	}

	// compose hook: reconcile a backup_schedules row from
	// the VMDef's `backup:` block. Best-effort — a failure here doesn't
	// roll back the VM creation, just logs and continues.
	if vmDef, _ := compose.FindVMDef(f, instanceName); vmDef != nil {
		if err := s.syncComposeBackupSchedule(ctx, instanceName, vmDef); err != nil {
			slog.Warn("compose backup schedule sync", "vm", instanceName, "error", err)
		}
	}

	// Register DNS records if the compose file defines a dns domain.
	if f.DNS != nil && f.DNS.Domain != "" {
		ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, instanceName)
		for _, iface := range ifaces {
			if iface.IP != "" {
				dnsName := dns.VMRecordName(instanceName, f.Name, f.DNS.Domain)
				if err := dns.UpsertRecord(ctx, s.db, dnsName, iface.IP); err != nil {
					slog.Warn("dns record upsert failed", "vm", instanceName, "error", err)
				}
				break // one A record per VM
			}
		}
	}

	// Set webhook URL from compose notifications section if configured.
	if f.Notifications != nil && f.Notifications.Webhook != "" {
		s.SetWebhookURL(f.Notifications.Webhook)
	}

	return nil
}

// specCloudInitHash extracts cloud-init userdata+networkconfig from a JSON spec
// and returns a stable hash, or "" if no cloud-init is present.
func specCloudInitHash(specJSON string) string {
	if specJSON == "" {
		return ""
	}
	var raw struct {
		CloudInit *struct {
			Userdata      string `json:"userdata"`
			Networkconfig string `json:"networkconfig"`
		} `json:"cloud_init"`
	}
	if err := json.Unmarshal([]byte(specJSON), &raw); err != nil || raw.CloudInit == nil {
		return ""
	}
	return compose.CloudInitHash(raw.CloudInit.Userdata, raw.CloudInit.Networkconfig)
}

// specImage extracts the image name from a JSON spec blob.
func specImage(specJSON string) string {
	// Fast path: scan for "image":"<value>" without full JSON parse.
	const prefix = `"image":"`
	idx := 0
	for i := 0; i < len(specJSON)-len(prefix); i++ {
		if specJSON[i:i+len(prefix)] == prefix {
			idx = i + len(prefix)
			end := idx
			for end < len(specJSON) && specJSON[end] != '"' {
				end++
			}
			return specJSON[idx:end]
		}
	}
	return ""
}

// sortDeployOps reorders update operations so that already-failed replicas
// are processed first. This allows rolling updates to replace broken VMs
// immediately (they're already unavailable, so no additional disruption) (#32).
func sortDeployOps(ops []compose.Op, current []compose.CurrentVM) {
	stateOf := make(map[string]string, len(current))
	for _, c := range current {
		stateOf[c.Name] = c.State
	}

	// Stable sort: error < stopped < running, preserving order within each group.
	// Only reorder OpUpdate ops; creates and deletes stay in their original position.
	sort.SliceStable(ops, func(i, j int) bool {
		if ops[i].Kind != compose.OpUpdate || ops[j].Kind != compose.OpUpdate {
			return false
		}
		return statePriority(stateOf[ops[i].VMName]) < statePriority(stateOf[ops[j].VMName])
	})
}

func statePriority(state string) int {
	switch state {
	case "error":
		return 0
	case "stopped":
		return 1
	default:
		return 2
	}
}

func opKindToDiffOp(k compose.OpKind) pb.DiffOp {
	switch k {
	case compose.OpCreate:
		return pb.DiffOp_DIFF_CREATE
	case compose.OpUpdate:
		return pb.DiffOp_DIFF_UPDATE
	case compose.OpDelete:
		return pb.DiffOp_DIFF_DELETE
	default:
		return pb.DiffOp_DIFF_UNCHANGED
	}
}

// externalNetworkNames returns a set of network names marked as external in the
// stored compose YAML for a stack. Returns an empty map on any error.
func (s *Server) externalNetworkNames(ctx context.Context, stackName string) map[string]bool {
	st, err := corrosion.GetStack(ctx, s.db, stackName)
	if err != nil || st == nil || st.ComposeYAML == "" {
		return nil
	}
	f, err := compose.ParseBytes([]byte(st.ComposeYAML))
	if err != nil {
		return nil
	}
	ext := make(map[string]bool)
	for name, netDef := range f.Networks {
		if netDef.External {
			ext[name] = true
		}
	}
	return ext
}

// highestDependencyCondition checks if any later ops depend on vmName and returns
// the most demanding condition ("vm_healthy" > "vm_started").
func highestDependencyCondition(vmName string, ops []compose.Op) string {
	best := ""
	for _, op := range ops {
		for dep, def := range op.DependsOn {
			// Match exact name or base name (for replicas: "db" matches "db-1").
			if dep == vmName || (len(vmName) > len(dep) && vmName[:len(dep)] == dep && vmName[len(dep)] == '-') {
				if def.Condition == "vm_healthy" {
					return "vm_healthy" // highest possible
				}
				if best == "" {
					best = def.Condition
				}
			}
		}
	}
	return best
}

// waitForCondition polls until a VM reaches the specified condition or times out.
func (s *Server) waitForCondition(ctx context.Context, vmName, condition string) error {
	timeout := 5 * time.Minute
	if condition == "vm_healthy" {
		timeout = 10 * time.Minute
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		vm, err := corrosion.GetVM(ctx, s.db, vmName)
		if err != nil || vm == nil {
			time.Sleep(2 * time.Second)
			continue
		}

		switch condition {
		case "vm_started":
			if vm.State == "running" {
				return nil
			}
		case "vm_healthy":
			if vm.State == "running" && vm.StateDetail != "unhealthy" {
				// Check if healthcheck is passing — if no healthcheck defined,
				// "running" is sufficient.
				return nil
			}
		}

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("timeout waiting for %s on %s", condition, vmName)
}

// autoPullImages checks each image referenced by VMs in the compose file. If
// an image is missing locally but has a source URL in the compose images:
// section, it is downloaded automatically before deploy proceeds.
func (s *Server) autoPullImages(ctx context.Context, f *compose.File, stream grpc.ServerStreamingServer[pb.DeployProgress]) error {
	seen := map[string]bool{}
	for _, vmDef := range f.VMs {
		img := vmDef.Image
		if img == "" || seen[img] {
			continue
		}
		seen[img] = true

		if s.images.ImageExists(img) {
			continue
		}

		def, ok := f.Images[img]
		if !ok || def.Source == "" {
			continue // no source URL — validateDeployDependencies will catch it
		}

		slog.Info("auto-pulling image from compose definition", "image", img, "source", def.Source)
		_ = stream.Send(&pb.DeployProgress{
			Phase:  "pull-image",
			Detail: fmt.Sprintf("pulling image %s from %s", img, def.Source),
		})

		// Pull synchronously so the image is ready before VM creation.
		progressCh := make(chan image.PullProgress, 10)
		errCh := make(chan error, 1)
		go func() {
			errCh <- image.Pull(s.images, img, def.Source, def.Checksum, progressCh)
		}()

		// Drain progress, forwarding to deploy stream.
		for p := range progressCh {
			_ = stream.Send(&pb.DeployProgress{
				Phase:       "pull-image",
				Detail:      fmt.Sprintf("pulling image %s", img),
				ProgressPct: p.ProgressPct,
			})
		}

		if err := <-errCh; err != nil {
			return status.Errorf(codes.Internal, "auto-pull image %q: %v", img, err)
		}

		// Persist image + image_host records.
		now := time.Now().UTC().Format(time.RFC3339)
		corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
			Name:      img,
			Format:    def.Format,
			SourceURL: def.Source,
			Checksum:  def.Checksum,
		})
		corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
			ImageName: img,
			HostName:  s.hostName,
			Path:      s.images.ImagePath(img),
			Status:    "ready",
			PulledAt:  now,
		})

		slog.Info("image auto-pulled successfully", "image", img)
		_ = stream.Send(&pb.DeployProgress{
			Phase:       "pull-image",
			Detail:      fmt.Sprintf("image %s pulled successfully", img),
			ProgressPct: 100,
		})
	}
	return nil
}

// validateDeployDependencies checks that images and networks referenced in the
// compose file actually exist in the cluster before any VMs are created (#52).
func (s *Server) validateDeployDependencies(ctx context.Context, f *compose.File) []string {
	var errs []string

	// Check images exist on at least one host.
	seenImages := map[string]bool{}
	for name, vmDef := range f.VMs {
		// Container workloads (kind: lxc | oci) don't deploy through the VM
		// path yet. Reject them up front with a clear pointer to `lv ct`,
		// rather than letting the VM image check below fire the misleading
		// "pull it first with 'lv image pull'" (the value is an OCI image
		// reference, not a registered VM image). Matches the deploy-time
		// guard in applyVMAction.
		if vmDef.Kind == compose.WorkloadKindLXC || vmDef.Kind == compose.WorkloadKindOCI {
			errs = append(errs, fmt.Sprintf(
				"workload %q has kind=%s; compose deploy doesn't route containers yet — "+
					"create it with `lv ct pull` + `lv ct create %s` (see docs/containers.md)",
				name, vmDef.Kind, name))
			continue
		}
		img := vmDef.Image
		if img == "" || seenImages[img] {
			continue
		}
		seenImages[img] = true
		if !s.images.ImageExists(img) {
			errs = append(errs, fmt.Sprintf("image %q not found on any host — pull it first with 'lv image pull'", img))
		}
	}

	// Network name collisions between stacks are prevented by scoping
	// non-external network names with the stack prefix (e.g. stack1_LAN).

	// Check named volumes reference accessible storage.
	for volName, vol := range f.Volumes {
		if vol.Driver == "nfs" && vol.Source != "" {
			// Best-effort: we can't fully validate NFS mounts remotely,
			// but log a note so the operator sees it.
			slog.Info("pre-deploy: NFS volume referenced", "volume", volName, "source", vol.Source)
		}
	}

	return errs
}

// provisionComposeNetworks ensures all networks defined in the compose file
// exist on this host (creates bridges, VXLAN tunnels, etc.).
func (s *Server) provisionComposeNetworks(ctx context.Context, f *compose.File) []string {
	var errs []string
	for name, netDef := range f.Networks {
		// External networks must already exist — don't create or modify them.
		if netDef.External {
			nr, err := corrosion.GetNetwork(ctx, s.db, name)
			if err != nil {
				errs = append(errs, fmt.Sprintf("network %q: lookup failed: %v", name, err))
			} else if nr == nil {
				errs = append(errs, fmt.Sprintf("network %q: declared as external but does not exist", name))
			} else {
				slog.Info("pre-deploy: using external network", "name", name)
			}
			continue
		}
		if netDef.Interface == "" {
			netDef.Interface = name
		}
		scopedName := compose.ScopedNetworkName(f.Name, name)
		if _, err := s.provisionAndPersistNetwork(ctx, scopedName, f.Name, netDef); err != nil {
			errs = append(errs, fmt.Sprintf("network %q: %v", name, err))
		} else {
			slog.Info("pre-deploy: provisioned network", "name", scopedName, "type", netDef.Type, "interface", netDef.Interface)
		}
	}
	return errs
}

// forwardProvisionNetworks sends ProvisionNetwork RPCs to all remote hosts
// so that networks are ready before VMs are placed there.
func (s *Server) forwardProvisionNetworks(ctx context.Context, f *compose.File) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return
	}

	for _, h := range hosts {
		if h.Name == s.hostName {
			continue
		}
		for name, netDef := range f.Networks {
			if netDef.External {
				continue
			}
			if netDef.Interface == "" {
				netDef.Interface = name
			}
			cfgJSON, _ := json.Marshal(netDef)
			client, conn, err := s.peerClient(ctx, h.Name)
			if err != nil {
				slog.Warn("forwardProvisionNetworks: cannot reach host", "host", h.Name, "error", err)
				break // skip remaining networks for this host
			}
			ntype := netDef.Type
			if ntype == "" {
				ntype = "bridge"
			}
			scopedName := compose.ScopedNetworkName(f.Name, name)
			if _, err := client.ProvisionNetwork(ctx, &pb.ProvisionNetworkRequest{
				Name:      scopedName,
				Config:    string(cfgJSON),
				NetType:   ntype,
				StackName: f.Name,
			}); err != nil {
				slog.Warn("forwardProvisionNetworks: provision failed", "host", h.Name, "network", scopedName, "error", err)
			}
			conn.Close()
		}
	}
}
