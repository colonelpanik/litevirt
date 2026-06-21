package compose

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// BuildVMSpec converts a compose VMDef into a gRPC VMSpec.
// Used by both the CLI (lv compose up) and the server-side DeployStack handler.
func BuildVMSpec(instanceName, baseName string, vm *VMDef, f *File) (*pb.VMSpec, error) {
	spec := &pb.VMSpec{
		Name:          instanceName,
		StackName:     f.Name,
		Image:         vm.Image,
		Cpu:           int32(vm.CPU),
		CpuMode:       vm.CPUMode,
		MemoryMib:     int32(vm.Memory),
		MinMemoryMib:  int32(vm.MinMemory),
		MaxMemoryMib:  int32(vm.MaxMemory),
		Machine:       vm.Machine,
		Firmware:      vm.Firmware,
		GuestAgent:    vm.EffectiveGuestAgent(),
		Boot:          "disk",
		Labels:        vm.Labels,
		Onboot:        vm.Onboot,
		StartupOrder:  int32(vm.StartupOrder),
		StartDelaySec: int32(vm.StartDelay),
		StopDelaySec:  int32(vm.StopDelay),
	}

	// Graphics defaults: VNC on, SPICE off. Compose can opt out of VNC
	// (`graphics.vnc: false`) or opt into SPICE (`graphics.spice: true`).
	if g := vm.Graphics; g != nil {
		if g.VNC != nil && !*g.VNC {
			spec.DisableVnc = true
		}
		if g.SPICE {
			spec.EnableSpice = true
		}
	}

	if vm.ISO != "" {
		spec.Image = vm.ISO
		spec.Boot = "cdrom"
	}

	// Deterministic disk ordering: "root" first, then alphabetical.
	// The first disk becomes vda and gets boot order 1, so root must be first.
	diskNames := make([]string, 0, len(vm.Disks))
	for name := range vm.Disks {
		if name != "root" {
			diskNames = append(diskNames, name)
		}
	}
	sort.Strings(diskNames)
	if _, ok := vm.Disks["root"]; ok {
		diskNames = append([]string{"root"}, diskNames...)
	}

	for _, diskName := range diskNames {
		disk := vm.Disks[diskName]
		spec.Disks = append(spec.Disks, &pb.DiskSpec{
			Name:    diskName,
			Size:    disk.Size,
			Bus:     disk.Bus,
			Cache:   disk.Cache,
			Storage: disk.Storage,
		})
	}

	for _, n := range vm.Network {
		netDef := f.Networks[n.Name]
		trunk := make([]int32, len(n.Trunk))
		for i, v := range n.Trunk {
			trunk[i] = int32(v)
		}
		if netDef.VLAN > 0 && len(trunk) == 0 {
			trunk = []int32{int32(netDef.VLAN)}
		}
		// Use the stack-scoped name so that DB lookups in CreateVM
		// (provisionNetworkForVM, lookupNetworkDef) find the correct record.
		// External networks keep their raw name.
		networkName := n.Name
		if !netDef.External {
			networkName = ScopedNetworkName(f.Name, n.Name)
		}
		spec.Network = append(spec.Network, &pb.NetworkAttachment{
			Name:           networkName,
			Model:          n.Model,
			Ip:             n.IP,
			Gateway:        n.Gateway,
			Mac:            n.MAC,
			Trunk:          trunk,
			Ipv6:           n.IPv6,
			Ipv6Gateway:    n.IPv6Gateway,
			SecurityGroups: n.SecurityGroups,
		})
	}

	if vm.CloudInit != nil {
		spec.CloudInit = &pb.CloudInitSpec{
			Userdata:      vm.CloudInit.UserData,
			Networkconfig: vm.CloudInit.NetworkConfig,
		}
	}

	if vm.Placement != nil {
		// Expand named-mode aliases into concrete Policy + Rebalance fields
		// before the spec leaves compose. Higher scopes (project, cluster
		// default) merge later via MergePlacement.
		eff := copyPlacement(vm.Placement)
		ExpandPlacementMode(eff)

		spec.Placement = &pb.PlacementSpec{
			Host:         eff.Host,
			AntiAffinity: eff.AntiAffinity,
			Affinity:     eff.Affinity,
			Require:      eff.Require,
			Prefer:       eff.Prefer,
			Spread:       eff.Spread,
			MaxPerNode:   int32(eff.MaxPerNode),
			Policy:       eff.Policy,
			NoMigrate:    eff.NoMigrate,
		}
		if eff.Rebalance != nil {
			rb := &pb.RebalanceSpec{
				Mode:      eff.Rebalance.Mode,
				Threshold: int32(eff.Rebalance.Threshold),
				Cooldown:  eff.Rebalance.Cooldown,
			}
			if eff.Rebalance.Budget != nil {
				rb.Budget = &pb.RebalanceBudget{
					MaxConcurrent: int32(eff.Rebalance.Budget.MaxConcurrent),
					MaxPerHour:    int32(eff.Rebalance.Budget.MaxPerHour),
					Window:        eff.Rebalance.Budget.Window,
				}
			}
			spec.Placement.Rebalance = rb
		}
	}

	if vm.LoadBalancer != nil && vm.LoadBalancer.Enabled {
		lbSpec := &pb.LBSpec{
			Enabled:        true,
			Vip:            vm.LoadBalancer.VIP,
			Algorithm:      vm.LoadBalancer.Algorithm,
			StickySessions: vm.LoadBalancer.Sticky,
			Hosts:          vm.LoadBalancer.Hosts,
			Snat:           vm.LoadBalancer.SNAT,
		}
		for _, p := range vm.LoadBalancer.Ports {
			pbPort := &pb.LBPort{
				Listen:        int32(p.Listen),
				Target:        int32(p.Target),
				Protocol:      p.Protocol,
				RedirectHttps: p.RedirectHTTPS,
			}
			if p.TLS != nil {
				pbPort.Tls = &pb.LBTlsSpec{
					Cert: p.TLS.Cert,
					Key:  p.TLS.Key,
				}
			}
			lbSpec.Ports = append(lbSpec.Ports, pbPort)
		}
		if vm.LoadBalancer.Health != nil {
			lbSpec.Health = &pb.LBHealthSpec{
				UseVmHealthcheck: vm.LoadBalancer.Health.UseVMHealthcheck,
				Type:             vm.LoadBalancer.Health.Type,
				Path:             vm.LoadBalancer.Health.Path,
				Interval:         fmt.Sprintf("%dms", vm.LoadBalancer.Health.IntervalMS),
			}
		}
		spec.Loadbalancer = lbSpec
	}

	if vm.HealthCheck != nil {
		spec.Healthcheck = &pb.HealthCheckSpec{
			Type:     vm.HealthCheck.Type,
			Target:   vm.HealthCheck.Target,
			Interval: vm.HealthCheck.Interval,
			Timeout:  vm.HealthCheck.Timeout,
			Retries:  int32(vm.HealthCheck.Retries),
			Action:   vm.HealthCheck.Action,
		}
	}

	if vm.Hooks != nil {
		spec.Hooks = &pb.HooksSpec{
			PreStart:    vm.Hooks.PreStart,
			PostStart:   vm.Hooks.PostStart,
			PreStop:     vm.Hooks.PreStop,
			PostStop:    vm.Hooks.PostStop,
			PreMigrate:  vm.Hooks.PreMigrate,
			PostMigrate: vm.Hooks.PostMigrate,
		}
	}

	if vm.Resources != nil {
		cpuPins := make([]int32, len(vm.Resources.CPUPinning))
		for i, p := range vm.Resources.CPUPinning {
			cpuPins[i] = int32(p)
		}
		spec.Resources = &pb.ResourceTuning{
			Hugepages:    vm.Resources.HugePages,
			CpuPinning:   cpuPins,
			NumaTopology: vm.Resources.NUMATopology,
			IoThreads:    int32(vm.Resources.IOThreads),
		}
	}

	for _, dev := range vm.Devices {
		count := int32(dev.Count)
		if count == 0 {
			count = 1
		}
		spec.Devices = append(spec.Devices, &pb.DeviceSpec{
			Type:    dev.Type,
			Vendor:  dev.Vendor,
			Model:   dev.Model,
			Count:   count,
			Address: dev.Address,
			Sriov:   dev.SRIOV,
			Parent:  dev.Parent,
			Mapping: dev.Mapping,
		})
	}

	// Stop grace period → stop_timeout_sec
	if vm.StopGracePeriod != "" {
		secs, err := parseDurationSeconds(vm.StopGracePeriod)
		if err != nil {
			return nil, fmt.Errorf("vm %q stop-grace-period: %w", instanceName, err)
		}
		spec.StopTimeoutSec = int32(secs)
	}

	// Placement max-per-node
	if spec.Placement != nil && vm.Placement != nil && vm.Placement.MaxPerNode > 0 {
		spec.Placement.MaxPerNode = int32(vm.Placement.MaxPerNode)
	}

	// Restart policy
	if vm.Restart != nil {
		spec.Restart = &pb.RestartPolicy{
			Condition:   vm.Restart.Condition,
			Delay:       vm.Restart.Delay,
			MaxAttempts: int32(vm.Restart.MaxAttempts),
			Window:      vm.Restart.Window,
		}
	}

	// Migration policy
	if vm.Migrate != nil {
		strategy := pb.MigrateStrategy_MIGRATE_LIVE
		switch vm.Migrate.Strategy {
		case "cold":
			strategy = pb.MigrateStrategy_MIGRATE_COLD
		case "none":
			strategy = pb.MigrateStrategy_MIGRATE_NONE
		}
		onFailure := pb.HostFailurePolicy_RESTART_ANY
		switch vm.Migrate.OnHostFailure {
		case "restart-same":
			onFailure = pb.HostFailurePolicy_RESTART_SAME
		case "none":
			onFailure = pb.HostFailurePolicy_FAILURE_NONE
		}
		spec.Migrate = &pb.MigrationPolicy{
			Strategy:        strategy,
			MaxDowntime:     vm.Migrate.MaxDowntime,
			AutoConverge:    vm.Migrate.AutoConverge,
			WithStorage:     vm.Migrate.WithStorage,
			OnHostFailure:   onFailure,
			Priority:        int32(vm.Migrate.Priority),
			FenceStrategy:   vm.Migrate.FenceStrategy,
			BandwidthMibSec: int32(vm.Migrate.BandwidthMiB),
			TimeoutSec:      int32(vm.Migrate.TimeoutSec),
		}
	}

	// Update policy
	if vm.Update != nil {
		spec.Update = &pb.UpdatePolicy{
			Strategy:          vm.Update.Strategy,
			MaxUnavailable:    int32(vm.Update.MaxUnavailable),
			MaxSurge:          int32(vm.Update.MaxSurge),
			Order:             vm.Update.Order,
			HealthWait:        vm.Update.HealthWait,
			RollbackOnFailure: vm.Update.RollbackOnFailure,
			PauseBetween:      vm.Update.PauseBetween,
		}
	}

	_ = baseName
	return spec, nil
}

// parseDurationSeconds converts a human-friendly duration string like "30s", "2m", "1h"
// to seconds. Returns an error for malformed values.
func parseDurationSeconds(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}
	// Try suffixed formats
	if strings.HasSuffix(s, "s") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "s"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return n, nil
	}
	if strings.HasSuffix(s, "m") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "m"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return n * 60, nil
	}
	if strings.HasSuffix(s, "h") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "h"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return n * 3600, nil
	}
	// Bare number = seconds
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return n, nil
}

// FindVMDef locates the VMDef for an instance name (handles replica suffixes).
func FindVMDef(f *File, instanceName string) (*VMDef, string) {
	// Exact match first.
	if def, ok := f.VMs[instanceName]; ok {
		return &def, instanceName
	}
	// Strip replica suffix "-N".
	for baseName, def := range f.VMs {
		for r := 0; r < def.EffectiveReplicas(); r++ {
			if def.InstanceName(baseName, r) == instanceName {
				return &def, baseName
			}
		}
	}
	return nil, ""
}
