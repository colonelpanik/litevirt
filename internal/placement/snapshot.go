package placement

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ClusterSnapshot is a frozen view of cluster state used to evaluate one or
// more placement requests. It is built once per Select / SelectBatch call
// (instead of re-reading Corrosion per host as the v1 engine did), which
// keeps placement decisions internally consistent and makes scoring O(1) per
// (host, dimension) lookup after construction.
//
// Snapshots are NOT live: they are valid only for the duration of one
// placement operation. Mutating cluster state during placement (a peer
// reporting a new VM, etc.) is reflected only in the next snapshot.
type ClusterSnapshot struct {
	// Hosts indexed by name. Witnesses are present but excluded by Select.
	Hosts   map[string]corrosion.HostRecord
	HostsBy []corrosion.HostRecord // stable iteration order

	// VMs indexed by name AND grouped by host.
	VMs       map[string]corrosion.VMRecord
	VMsByHost map[string][]corrosion.VMRecord

	// Per-host accumulated usage, derived once during construction so the
	// dimensions don't have to recompute on every Used() call.
	CPUUsed map[string]int // cores
	MemUsed map[string]int // MiB
	VMCount map[string]int

	// Per-host runtime telemetry (from host_runtime_usage; empty when not loaded
	// — e.g. the SelectBatch in-memory path). The DiskIOPS/NetBW dimensions read
	// these for Used; capacity comes from host labels.
	DiskIOPSUsed map[string]int // aggregate disk IOPS
	NetMbpsUsed  map[string]int // aggregate network Mbps

	// Per-host PCI device pool — used by Devices dimension and topology
	// scoring. Optional; lazily loaded by Select if Devices > 0.
	Devices map[string][]corrosion.PCIDeviceRecord

	// Replica counts grouped by base name (for MaxPerNode).
	ReplicasByBase map[string]map[string]int // baseName → host → count

	// Anti/affinity lookup: which host runs a given VM.
	VMHost map[string]string
}

// BuildSnapshot reads the current cluster state and returns a ClusterSnapshot
// usable for one placement operation.
func BuildSnapshot(ctx context.Context, db *corrosion.Client) (*ClusterSnapshot, error) {
	hosts, err := corrosion.ListHosts(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	vms, err := corrosion.ListVMs(ctx, db, "", "")
	if err != nil {
		return nil, fmt.Errorf("list VMs: %w", err)
	}
	// Per-host runtime telemetry for the DiskIOPS/NetBW dimensions. Best-effort:
	// on error the maps stay empty (those dims are then skipped, like a host with
	// no capacity label) rather than failing placement.
	usage, _ := corrosion.ListHostRuntimeUsage(ctx, db)
	return BuildSnapshotFromUsage(hosts, vms, usage), nil
}

// BuildSnapshotFrom constructs a snapshot from already-fetched slices, with no
// runtime telemetry (the DiskIOPS/NetBW Used maps stay empty). Used by SelectBatch
// which manipulates a working copy mid-pass and by tests.
func BuildSnapshotFrom(hosts []corrosion.HostRecord, vms []corrosion.VMRecord) *ClusterSnapshot {
	return BuildSnapshotFromUsage(hosts, vms, nil)
}

// BuildSnapshotFromUsage is BuildSnapshotFrom plus per-host runtime telemetry
// (host_runtime_usage, keyed by host name). usage may be nil.
func BuildSnapshotFromUsage(hosts []corrosion.HostRecord, vms []corrosion.VMRecord, usage map[string]corrosion.HostRuntimeUsage) *ClusterSnapshot {
	s := &ClusterSnapshot{
		Hosts:          make(map[string]corrosion.HostRecord, len(hosts)),
		HostsBy:        hosts,
		VMs:            make(map[string]corrosion.VMRecord, len(vms)),
		VMsByHost:      make(map[string][]corrosion.VMRecord, len(hosts)),
		CPUUsed:        make(map[string]int, len(hosts)),
		MemUsed:        make(map[string]int, len(hosts)),
		VMCount:        make(map[string]int, len(hosts)),
		DiskIOPSUsed:   make(map[string]int, len(hosts)),
		NetMbpsUsed:    make(map[string]int, len(hosts)),
		ReplicasByBase: make(map[string]map[string]int),
		VMHost:         make(map[string]string, len(vms)),
	}
	for _, h := range hosts {
		s.Hosts[h.Name] = h
		if u, ok := usage[h.Name]; ok {
			s.DiskIOPSUsed[h.Name] = int(u.DiskIOPS)
			s.NetMbpsUsed[h.Name] = int(u.NetMbps)
		}
	}
	for _, vm := range vms {
		s.VMs[vm.Name] = vm
		// Only count VMs that are or are about to consume resources.
		if vm.State == "running" || vm.State == "creating" || vm.State == "starting" {
			s.CPUUsed[vm.HostName] += vm.CPUActual
			s.MemUsed[vm.HostName] += vm.MemActual
			s.VMCount[vm.HostName]++
			s.VMHost[vm.Name] = vm.HostName
			s.VMsByHost[vm.HostName] = append(s.VMsByHost[vm.HostName], vm)
		}
	}
	return s
}

// CountReplicas adds VM `name` (with base `base`) on `host` to the replica
// index. Used by SelectBatch to track in-flight placements within one batch.
func (s *ClusterSnapshot) CountReplicas(base, host, name string) {
	if base == "" {
		return
	}
	if name != base && !strings.HasPrefix(name, base+"-") {
		return
	}
	if s.ReplicasByBase[base] == nil {
		s.ReplicasByBase[base] = map[string]int{}
	}
	s.ReplicasByBase[base][host]++
}

// SeedReplicasForBase walks live VMs and seeds the replica index for `base`.
// Cheaper than scanning all bases up front; we only do it for bases that
// appear in a request with MaxPerNode > 0.
func (s *ClusterSnapshot) SeedReplicasForBase(base string) {
	if base == "" || s.ReplicasByBase[base] != nil {
		return
	}
	s.ReplicasByBase[base] = map[string]int{}
	for _, vm := range s.VMs {
		if vm.State != "running" && vm.State != "creating" && vm.State != "starting" {
			continue
		}
		if vm.Name == base || strings.HasPrefix(vm.Name, base+"-") {
			s.ReplicasByBase[base][vm.HostName]++
		}
	}
}

// CommitPlacement updates the snapshot in-place to reflect a placement
// decision made within a batch. Subsequent scoring sees the new occupancy.
func (s *ClusterSnapshot) CommitPlacement(host, vmName, baseName string, cpu, mem int) {
	s.CPUUsed[host] += cpu
	s.MemUsed[host] += mem
	s.VMCount[host]++
	s.VMHost[vmName] = host
	if baseName != "" {
		if s.ReplicasByBase[baseName] == nil {
			s.ReplicasByBase[baseName] = map[string]int{}
		}
		s.ReplicasByBase[baseName][host]++
	}
}

// hostCostMultiplier reads the cost.hourly label off a host. Used by
// PolicyCostAware. Default 1.0 if missing/unparseable.
func hostCostMultiplier(h corrosion.HostRecord) float64 {
	if h.Labels == nil {
		return 1.0
	}
	v, ok := h.Labels["cost.hourly"]
	if !ok || v == "" {
		return 1.0
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 {
		return 1.0
	}
	return f
}
