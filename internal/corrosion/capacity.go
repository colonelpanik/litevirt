package corrosion

import "context"

// Capacity policy: how much of a host litevirt is willing to hand to workloads.
//
// This is the SINGLE place that answer is computed. It used to be three: the
// admission check, the placement engine, and the VM reconciler each did their own
// `total - used`, which is how `lv run --host` (no check at all) and `lv update`
// (checked) came to disagree — one refused what the other had just allowed.
//
// Two knobs, deliberately with OPPOSITE defaults, because CPU and memory are not
// alike:
//
//   - vCPU is time-sliced. Running more vCPUs than cores is normal; the guests
//     simply share. Oversubscribing is the point, so the default ratio is >1.
//   - Memory is not. A guest's RAM is either backed or it is not, and without
//     ballooning/KSM/swap, handing out more than exists means the kernel starts
//     reclaiming and the host thrashes. The default ratio is exactly 1.
//
// And a reserve, which matters more than either ratio: even at ratio 1.0,
// "free = total - guests" hands guests 100% of RAM and leaves nothing for the
// kernel, page cache, qemu's per-VM overhead, or litevirtd itself. That is not a
// theoretical failure — it is how a 3 GiB lab node with 3 GiB of guests thrashed
// until sshd stopped answering.

// CapacityPolicy is the cluster-wide default, overridable per host.
type CapacityPolicy struct {
	// CPUOvercommit multiplies a host's physical vCPU count. 4.0 means a 4-core
	// host advertises 16 schedulable vCPUs.
	CPUOvercommit float64
	// MemOvercommit multiplies physical memory. Keep at 1.0 unless the host has
	// ballooning/KSM/swap to make the promise real.
	MemOvercommit float64
	// CPUReserve is vCPUs withheld for the host itself.
	CPUReserve int
	// MemReserveMiB / MemReservePct withhold memory for the host. The EFFECTIVE
	// reserve is the larger of the two, so a fixed floor protects small nodes
	// while a percentage scales with large ones.
	MemReserveMiB int
	MemReservePct int
	// VMMemOverheadMiB is charged per running VM on top of its configured memory,
	// covering qemu's own footprint (device models, video, page tables). Ignoring
	// it systematically under-counts usage, by more the denser the host.
	VMMemOverheadMiB int
	// DiskOvercommit divides a new disk's DECLARED size before it is compared to a
	// pool's ACTUAL free space. Thin provisioning is the norm — a declared 100 GiB
	// qcow2 may occupy 2 GiB — so admitting declared-against-actual at 1.0 would
	// refuse ordinary practice. >1 is therefore the safe default here, the opposite
	// of memory, for the same underlying reason: only count what is really taken.
	DiskOvercommit float64
	// PoolReservePct is the share of a storage pool held back so it can never be
	// driven to zero. A full pool is worse than a full host: qcow2 images cannot
	// grow, and guests take I/O errors rather than merely thrashing.
	PoolReservePct int
}

// DefaultCapacityPolicy is what a cluster gets with nothing configured.
//
// The CPU ratio is 4.0 rather than 1.0 on purpose: an effective 1.0 would cap a
// 4-core node at four 1-vCPU VMs, which is far stricter than any comparable
// system and would refuse workloads that run perfectly well.
func DefaultCapacityPolicy() CapacityPolicy {
	return CapacityPolicy{
		CPUOvercommit:    4.0,
		MemOvercommit:    1.0,
		CPUReserve:       1,
		MemReserveMiB:    1024,
		MemReservePct:    5,
		VMMemOverheadMiB: 128,
		DiskOvercommit:   3.0,
		PoolReservePct:   5,
	}
}

// forHost applies a host's overrides. A ratio of 0 and a reserve of -1 mean
// "inherit"; 0 is a real reserve and must stay distinguishable from unset.
func (p CapacityPolicy) forHost(h HostRecord) CapacityPolicy {
	out := p
	if h.CPUOvercommit > 0 {
		out.CPUOvercommit = h.CPUOvercommit
	}
	if h.MemOvercommit > 0 {
		out.MemOvercommit = h.MemOvercommit
	}
	if h.CPUReserve != nil {
		out.CPUReserve = *h.CPUReserve
	}
	if h.MemReserveMiB != nil {
		out.MemReserveMiB = *h.MemReserveMiB
		out.MemReservePct = 0 // an explicit per-host MiB reserve replaces the percentage
	}
	return out
}

// normalize resolves an unset or partially-set policy.
//
// The WHOLLY zero value means "not configured" and yields the defaults outright —
// including the reserves. Resolving field-by-field would be wrong here: a zero
// CPUReserve/MemReserveMiB is indistinguishable from "no reserve", so a caller
// that simply never set a policy would silently lose the host headroom that is
// the main thing this exists to protect. (That is not hypothetical — the
// placement engine's zero-value Request hit exactly this and started admitting an
// 8-vCPU VM onto a 2-core host.)
//
// Once ANY field is set the struct is treated as deliberate: ratios still fall
// back if nonsensical (<= 0 would make every host look full), but a 0 reserve is
// honoured as a real choice to hand guests everything.
func (p CapacityPolicy) normalize() CapacityPolicy {
	d := DefaultCapacityPolicy()
	if p == (CapacityPolicy{}) {
		return d
	}
	if p.CPUOvercommit <= 0 {
		p.CPUOvercommit = d.CPUOvercommit
	}
	if p.MemOvercommit <= 0 {
		p.MemOvercommit = d.MemOvercommit
	}
	if p.CPUReserve < 0 {
		p.CPUReserve = 0
	}
	if p.MemReserveMiB < 0 {
		p.MemReserveMiB = 0
	}
	if p.MemReservePct < 0 {
		p.MemReservePct = 0
	}
	if p.VMMemOverheadMiB < 0 {
		p.VMMemOverheadMiB = 0
	}
	if p.DiskOvercommit <= 0 {
		p.DiskOvercommit = d.DiskOvercommit
	}
	if p.PoolReservePct < 0 {
		p.PoolReservePct = 0
	}
	return p
}

// PoolFreeBytes is a storage pool's ACTUAL free space, less the reserve.
//
// Actual, not allocated: pool used_bytes is statfs-sampled by the daemon
// (daemon.go:1265), so this compares against what the filesystem really has
// rather than the sum of declared disk sizes — which under thin provisioning is
// wildly larger than reality and would refuse ordinary practice.
//
// ok=false when the pool carries no capacity sample (total 0 — never sampled, or
// a driver that reports nothing). Callers must treat that as "unknown, do not
// admit", never as "full": refusing on missing telemetry would break every
// cluster whose pools have not been sampled yet.
func PoolFreeBytes(total, used int64, policy CapacityPolicy) (free int64, ok bool) {
	if total <= 0 {
		return 0, false
	}
	p := policy.normalize()
	reserve := total * int64(p.PoolReservePct) / 100
	free = total - used - reserve
	if free < 0 {
		free = 0
	}
	return free, true
}

// DiskNeedBytes is how much of a pool a newly declared disk should be charged,
// after the thin-provisioning ratio.
func DiskNeedBytes(declared int64, policy CapacityPolicy) int64 {
	p := policy.normalize()
	return int64(float64(declared) / p.DiskOvercommit)
}

// HostAllocatable reports how much of a host may be handed to workloads, after
// ratios and reserves. Returned values are never negative: a host reserving more
// than it has is simply full, not owed capacity.
func HostAllocatable(h HostRecord, cluster CapacityPolicy) (cpu, memMiB int) {
	p := cluster.normalize().forHost(h)

	cpu = int(float64(h.CPUTotal)*p.CPUOvercommit) - p.CPUReserve

	memReserve := p.MemReserveMiB
	if pct := h.MemTotal * p.MemReservePct / 100; pct > memReserve {
		memReserve = pct
	}
	memMiB = int(float64(h.MemTotal)*p.MemOvercommit) - memReserve

	if cpu < 0 {
		cpu = 0
	}
	if memMiB < 0 {
		memMiB = 0
	}
	return cpu, memMiB
}

// MemOverheadFor returns the qemu overhead to charge for n running VMs.
func (p CapacityPolicy) MemOverheadFor(n int) int {
	return p.normalize().VMMemOverheadMiB * n
}

// SumContainerMemoryByHost returns per-host memory (MiB) committed to RUNNING
// containers.
//
// Containers were entirely absent from host capacity accounting: usage came from
// the vms table alone, so a host packed with containers still reported 100% of
// its memory free and VMs were admitted onto memory containers already held.
//
// MEMORY ONLY, deliberately. A container's cpu_limit is CPU *shares* — a
// relative cgroup weight, not a reservation — so adding it to a vCPU total would
// be meaningless arithmetic (a container with the conventional 1024 shares is not
// 1024 vCPUs). Container CPU therefore stays uncounted rather than counted wrong.
//
// A container with memory_mib = 0 is UNCAPPED and contributes nothing here. That
// is a real limitation, not an oversight: litevirt knows the cap, not the actual
// footprint, and inventing a number for an unbounded container would be a guess
// dressed as accounting. Cap containers if you want them accounted.
// The counting rule (running, capped, non-deleted) is shared with the
// in-memory ContainerMemoryByHost — keep the two in lockstep.
func SumContainerMemoryByHost(ctx context.Context, c *Client) (map[string]int, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, COALESCE(SUM(memory_mib),0) AS mem
		   FROM containers
		  WHERE deleted_at IS NULL AND state = 'running' AND memory_mib > 0
		  GROUP BY host_name`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int, len(rows))
	for _, r := range rows {
		out[r.String("host_name")] = r.Int("mem")
	}
	return out, nil
}

// ContainerMemoryByHost is the in-memory equivalent of SumContainerMemoryByHost
// for callers that already hold the container records (the compose planner works
// off a snapshot, not live queries). Same counting rule: running, capped
// (MemMiB > 0); deletion filtering is the lister's job.
func ContainerMemoryByHost(cts []ContainerRecord) map[string]int {
	out := make(map[string]int)
	for _, ct := range cts {
		if ct.State == "running" && ct.MemMiB > 0 {
			out[ct.HostName] += ct.MemMiB
		}
	}
	return out
}
