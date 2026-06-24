// Package placement selects the best host for a new VM given cluster state
// and the VM's placement constraints.
package placement

import (
	"context"
	"fmt"
	"sort"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Request describes what a VM needs and where it should (not) go.
type Request struct {
	VMName       string
	CPUNeeded    int
	MemMiBNeeded int

	// Policy chooses the scoring strategy. Empty = balance.
	Policy Policy

	// Hard constraints — violation = host is excluded
	PinHost       string            // exact host name, empty = any
	RequireLabels map[string]string // host must have all these label k/v pairs
	AntiAffinity  []string          // VM names that must NOT be on the same host

	// Soft preferences — violation = lower score but not excluded
	PreferLabels map[string]string
	Affinity     []string // VM names that should be on the same host

	// Spread is the legacy boolean spread toggle. Prefer setting Policy
	// directly; we translate Spread=true → PolicySpreadStrict (and Spread=false
	// → PolicyBalance) when Policy is empty so existing call sites keep
	// working without source changes.
	Spread bool

	// Per-node replica limit
	MaxPerNode int    // max replicas of this VM group on a single host (0 = unlimited)
	VMBaseName string // base name for counting replicas (e.g. "web" for "web-1", "web-2")

	// Devices required (each {type, count} must be satisfied).
	Devices []DeviceRequest

	// Networks the VM will attach to — used for soft scoring; SR-IOV is
	// penalized if the host has no matching VF.
	Networks []NetworkReq

	// Weights overrides DefaultWeights for this request. Zero value uses
	// DefaultWeights. Tests use this; production paths leave it zero.
	Weights *DimensionWeights
}

// effectivePolicy resolves Policy + Spread legacy toggle into a canonical Policy.
func (r *Request) effectivePolicy() Policy {
	if r.Policy.Valid() {
		return r.Policy
	}
	if r.Spread {
		return PolicySpreadStrict
	}
	return PolicyBalance
}

// effectiveWeights returns the active weight set.
func (r *Request) effectiveWeights() DimensionWeights {
	if r.Weights != nil {
		return *r.Weights
	}
	return DefaultWeights()
}

// NetworkReq describes a network the VM will attach to.
type NetworkReq struct {
	Name string // compose network name
	Type string // bridge | vxlan | isolated | sriov
}

// DeviceRequest describes a PCI device type and how many the VM needs.
type DeviceRequest struct {
	Type     string // gpu | network | nvme | infiniband
	Count    int
	Vendor   string // optional vendor filter
	Clique   string // prefer specific NVLink/xGMI clique
	SameNUMA bool   // require all devices on same NUMA node
}

// hostCandidate is an evaluated host during selection.
type hostCandidate struct {
	host    corrosion.HostRecord
	cpuFree int
	memFree int
	vmCount int
	score   float64
}

// strictSpreadPressureCap is the per-dimension pressure ceiling for
// PolicySpreadStrict. A host whose post-placement pressure on any wired
// dimension would exceed this is excluded outright.
const strictSpreadPressureCap = 0.5

// Select returns the best host name for a VM, or an error if no host qualifies.
//
// The scoring algorithm:
//   - Build (or reuse) a ClusterSnapshot of current state.
//   - For each host, run the hard-filter pipeline (state, witness, resources,
//     anti-affinity, MaxPerNode, labels, devices). Eliminated hosts contribute nothing.
//   - For survivors, compute a weighted-sum score across all enabled
//     dimensions, plus the soft bonuses (PreferLabels, Affinity, networks).
//   - Sort by score descending; tie-break by fewest VMs then name.
//
// The scorer's sign is policy-dependent: balance/spread-strict prefer
// LOW pressure (spread); bin-pack prefers HIGH pressure (concentrate).
// cost-aware divides the final score by the host's `cost.hourly` label.
func Select(ctx context.Context, db *corrosion.Client, req Request) (string, error) {
	// Pinned to a specific host — just validate it exists and is active.
	if req.PinHost != "" {
		h, err := corrosion.GetHost(ctx, db, req.PinHost)
		if err != nil || h == nil {
			return "", fmt.Errorf("pinned host %q not found", req.PinHost)
		}
		if h.State != "active" {
			return "", fmt.Errorf("pinned host %q is not active (state: %s)", req.PinHost, h.State)
		}
		if h.IsWitness() {
			return "", fmt.Errorf("pinned host %q is a witness; witnesses do not host workloads", req.PinHost)
		}
		return req.PinHost, nil
	}

	snap, err := BuildSnapshot(ctx, db)
	if err != nil {
		return "", err
	}

	// Optional device pool load (only when a device is requested).
	if len(req.Devices) > 0 {
		snap.Devices = make(map[string][]corrosion.PCIDeviceRecord)
		for _, h := range snap.HostsBy {
			devs, err := corrosion.GetAvailableDevicesWithTopology(ctx, db, h.Name, "")
			if err == nil {
				snap.Devices[h.Name] = devs
			}
		}
	}

	if req.MaxPerNode > 0 {
		snap.SeedReplicasForBase(req.VMBaseName)
	}

	candidates, err := scoreCandidates(snap, &req, false)
	if err != nil {
		return "", err
	}

	return pickBest(candidates), nil
}

// scoreCandidates runs hard filters + soft scoring against snapshot.
// fromBatch=true uses the snapshot's mutable Devices pool (already deep-
// copied by SelectBatch); fromBatch=false uses the read-only pool.
func scoreCandidates(snap *ClusterSnapshot, req *Request, fromBatch bool) ([]hostCandidate, error) {
	policy := req.effectivePolicy()
	weights := req.effectiveWeights()
	dims := AllDimensions(weights)

	// Anti-affinity host set.
	antiAffinityHosts := map[string]bool{}
	for _, vmName := range req.AntiAffinity {
		if h, ok := snap.VMHost[vmName]; ok {
			antiAffinityHosts[h] = true
		}
	}

	// Affinity bonus map.
	affinityHosts := map[string]int{}
	for _, vmName := range req.Affinity {
		if h, ok := snap.VMHost[vmName]; ok {
			affinityHosts[h]++
		}
	}

	var candidates []hostCandidate
	for _, h := range snap.HostsBy {
		if h.State != "active" {
			continue
		}
		if h.IsWitness() {
			continue
		}

		// Hard: resources fit.
		freeCPU := h.CPUTotal - snap.CPUUsed[h.Name]
		freeMem := h.MemTotal - snap.MemUsed[h.Name]
		if req.CPUNeeded > 0 && freeCPU < req.CPUNeeded {
			continue
		}
		if req.MemMiBNeeded > 0 && freeMem < req.MemMiBNeeded {
			continue
		}

		// Hard: anti-affinity.
		if antiAffinityHosts[h.Name] {
			continue
		}

		// Hard: max-per-node replica limit.
		if req.MaxPerNode > 0 && req.VMBaseName != "" {
			if snap.ReplicasByBase[req.VMBaseName][h.Name] >= req.MaxPerNode {
				continue
			}
		}

		// Hard: required labels.
		if len(req.RequireLabels) > 0 && !labelsMatch(h.Labels, req.RequireLabels) {
			continue
		}

		// Hard: device requirements.
		var deviceBonus int
		if len(req.Devices) > 0 {
			pool := snap.Devices[h.Name]
			ok, bonus := scoreHostDevices(pool, req.Devices)
			if !ok {
				continue
			}
			deviceBonus = bonus
		}

		// Hard (spread-strict only): no dimension may exceed the pressure cap.
		if policy == PolicySpreadStrict {
			over := false
			for _, d := range dims {
				if d.Weight() <= 0 || d.Capacity(snap, h.Name) <= 0 {
					continue
				}
				if Pressure(d, snap, h.Name, req) > strictSpreadPressureCap {
					over = true
					break
				}
			}
			if over {
				continue
			}
		}

		// Weighted-sum dimensional score.
		var dimScore float64
		for _, d := range dims {
			dimScore += scoreDimension(d, snap, h.Name, req, policy)
		}

		// Soft: PreferLabels (+5 per match — small nudge, not decisive).
		var labelBonus float64
		if len(req.PreferLabels) > 0 {
			for k, v := range req.PreferLabels {
				if h.Labels[k] == v {
					labelBonus += 5
				}
			}
		}

		// Soft: Affinity (+20 per matching VM on this host).
		affinityBonus := float64(affinityHosts[h.Name] * 20)

		// Soft: SR-IOV penalty when no device match was provided.
		var networkPenalty float64
		for _, nr := range req.Networks {
			if nr.Type == "sriov" && len(req.Devices) == 0 {
				networkPenalty += 30
			}
		}

		score := dimScore + labelBonus + affinityBonus + float64(deviceBonus) - networkPenalty

		// Cost-aware: divide by cost multiplier (cheaper hosts score higher).
		if policy == PolicyCostAware {
			cm := hostCostMultiplier(h)
			if cm > 0 {
				score = score / cm
			}
		}

		candidates = append(candidates, hostCandidate{
			host:    h,
			cpuFree: freeCPU,
			memFree: freeMem,
			vmCount: snap.VMCount[h.Name],
			score:   score,
		})
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no eligible host found for VM %q (insufficient resources, constraint violation, or strict-spread pressure cap)", req.VMName)
	}

	// Sort by score descending; ties by fewest VMs then name (stable).
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].vmCount != candidates[j].vmCount {
			return candidates[i].vmCount < candidates[j].vmCount
		}
		return candidates[i].host.Name < candidates[j].host.Name
	})
	return candidates, nil
}

func pickBest(c []hostCandidate) string {
	if len(c) == 0 {
		return ""
	}
	return c[0].host.Name
}

// Candidate is one eligible host with its computed placement score, returned by
// RankFromSnapshot. Higher Score is better (the sign is already policy-adjusted:
// balance/spread prefer headroom, bin-pack prefers fill).
type Candidate struct {
	Host  string
	Score float64
}

// RankFromSnapshot runs the full hard-filter + scoring pipeline for req against
// a caller-supplied snapshot and returns every eligible host ranked best-first.
//
// Unlike Select, it neither builds a snapshot nor touches the DB: the caller
// (e.g. the rebalancer) passes a snapshot it already holds and has adjusted —
// typically with the VM-under-consideration removed from its source so the VM
// neither blocks itself on resources/replicas nor anchors its own anti-affinity.
// This is what makes rebalance destination scoring honor the SAME hard
// constraints (anti-affinity, required labels, max-per-node, devices, witness,
// spread-strict pressure cap) as initial placement. Devices, when required,
// must already be present in snap.Devices.
func RankFromSnapshot(snap *ClusterSnapshot, req *Request) ([]Candidate, error) {
	if req.MaxPerNode > 0 {
		snap.SeedReplicasForBase(req.VMBaseName)
	}
	cands, err := scoreCandidates(snap, req, true)
	if err != nil {
		return nil, err
	}
	out := make([]Candidate, len(cands))
	for i, c := range cands {
		out[i] = Candidate{Host: c.host.Name, Score: c.score}
	}
	return out, nil
}

// BatchResult holds the resolved host and device assignments for a VM.
type BatchResult struct {
	Host    string
	Devices []BatchDevice
}

// BatchDevice is a pre-assigned PCI device.
type BatchDevice struct {
	Type    string
	Address string
	Vendor  string
	Device  string
}

// SelectBatch resolves placements for multiple VMs in one pass, working
// entirely from in-memory state. After placing each VM it updates the
// snapshot so subsequent VMs in the batch see accurate state — fixing the
// replication-lag race that breaks anti-affinity/spread when Select() is
// called per-VM during deploy.
//
// Each request's Policy is honored independently: a batch can mix
// bin-pack batch jobs and spread-strict prod VMs without one's policy
// influencing the other's placement.
func SelectBatch(
	hosts []corrosion.HostRecord,
	vms []corrosion.VMRecord,
	devices map[string][]corrosion.PCIDeviceRecord,
	requests []Request,
) (map[string]BatchResult, error) {
	snap := BuildSnapshotFrom(hosts, vms)

	// Deep-copy device pools so the scoring loop can mutate them as we
	// place each VM.
	snap.Devices = make(map[string][]corrosion.PCIDeviceRecord, len(devices))
	for h, devs := range devices {
		pool := make([]corrosion.PCIDeviceRecord, len(devs))
		copy(pool, devs)
		snap.Devices[h] = pool
	}

	// Pre-seed replica indices for every distinct base name appearing in
	// the batch so per-iteration MaxPerNode checks are O(1).
	for _, req := range requests {
		if req.MaxPerNode > 0 && req.VMBaseName != "" {
			snap.SeedReplicasForBase(req.VMBaseName)
		}
	}

	results := make(map[string]BatchResult, len(requests))

	for _, req := range requests {
		// Pinned host — validate and skip scoring.
		if req.PinHost != "" {
			found := false
			for _, h := range hosts {
				if h.Name == req.PinHost && h.State == "active" && !h.IsWitness() {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("pinned host %q not found, not active, or is a witness for VM %q", req.PinHost, req.VMName)
			}
			devAssign := assignDevices(snap.Devices, req.PinHost, req.Devices)
			results[req.VMName] = BatchResult{Host: req.PinHost, Devices: devAssign}
			snap.CommitPlacement(req.PinHost, req.VMName, req.VMBaseName, req.CPUNeeded, req.MemMiBNeeded)
			continue
		}

		candidates, err := scoreCandidates(snap, &req, true)
		if err != nil {
			return nil, err
		}
		chosen := pickBest(candidates)

		devAssign := assignDevices(snap.Devices, chosen, req.Devices)
		results[req.VMName] = BatchResult{Host: chosen, Devices: devAssign}
		snap.CommitPlacement(chosen, req.VMName, req.VMBaseName, req.CPUNeeded, req.MemMiBNeeded)
	}

	return results, nil
}

// assignDevices selects and removes devices from the mutable pool for a host.
func assignDevices(devPool map[string][]corrosion.PCIDeviceRecord, host string, reqs []DeviceRequest) []BatchDevice {
	if len(reqs) == 0 {
		return nil
	}

	pool := devPool[host]
	var assigned []BatchDevice

	for _, req := range reqs {
		count := req.Count
		if count <= 0 {
			count = 1
		}

		// Filter by type and unassigned.
		var typed []corrosion.PCIDeviceRecord
		for _, d := range pool {
			if d.Type == req.Type && d.VMName == "" {
				if req.Vendor == "" || d.VendorID == req.Vendor || d.VendorName == req.Vendor {
					typed = append(typed, d)
				}
			}
		}

		// Use topology scoring to pick best devices.
		_, selected := TopologyScore(typed, req)
		if len(selected) < count {
			selected = selected[:0]
			// Fallback: just take first available.
			for _, d := range typed {
				selected = append(selected, d.Address)
				if len(selected) >= count {
					break
				}
			}
		}

		// Mark selected devices as taken in the pool.
		taken := map[string]bool{}
		for _, addr := range selected {
			taken[addr] = true
		}
		for i := range pool {
			if taken[pool[i].Address] {
				assigned = append(assigned, BatchDevice{
					Type:    pool[i].Type,
					Address: pool[i].Address,
					Vendor:  pool[i].VendorName,
					Device:  pool[i].DeviceName,
				})
				pool[i].VMName = "reserved" // mark as taken in-memory
			}
		}
	}

	devPool[host] = pool
	return assigned
}

func labelsMatch(hostLabels, required map[string]string) bool {
	for k, v := range required {
		if hostLabels[k] != v {
			return false
		}
	}
	return true
}
