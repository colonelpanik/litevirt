package corrosion

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
	return p
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
