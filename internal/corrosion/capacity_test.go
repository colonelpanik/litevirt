package corrosion

import "testing"

// The lab node that started this: 4 vCPU, 2971 MiB. Under the OLD arithmetic it
// advertised all 2971 MiB to guests, three 1 GiB VMs were accepted, and it
// thrashed until sshd stopped answering.
const (
	labCPU = 4
	labMem = 2971
)

func labHost() HostRecord {
	return HostRecord{Name: "lab", CPUTotal: labCPU, MemTotal: labMem}
}

// TestHostAllocatable_MemoryKeepsHeadroomForTheHost is the property that would
// have prevented the outage: guests must never be offered 100% of RAM.
func TestHostAllocatable_MemoryKeepsHeadroomForTheHost(t *testing.T) {
	_, mem := HostAllocatable(labHost(), DefaultCapacityPolicy())
	if mem >= labMem {
		t.Fatalf("allocatable memory = %d MiB of %d physical — the host is left nothing for its kernel, page cache, qemu overhead or litevirtd", mem, labMem)
	}
	// Default reserve is max(1024 MiB, 5%) = 1024 here.
	if want := labMem - 1024; mem != want {
		t.Errorf("allocatable memory = %d, want %d (physical - 1024 MiB reserve)", mem, want)
	}
	// The three 1 GiB VMs that wedged the node must no longer all fit.
	if mem >= 3*1024 {
		t.Errorf("allocatable %d MiB still admits 3x1024 MiB — the original overcommit is still possible", mem)
	}
}

// TestHostAllocatable_CPUOvercommitsButMemoryDoesNot pins the asymmetry. Treating
// them alike is wrong in both directions: a 1.0 CPU ratio refuses workloads that
// run fine, and a >1.0 memory ratio invites the thrash.
func TestHostAllocatable_CPUOvercommitsButMemoryDoesNot(t *testing.T) {
	cpu, mem := HostAllocatable(labHost(), DefaultCapacityPolicy())
	if cpu <= labCPU {
		t.Errorf("allocatable vCPU = %d, want more than the %d physical — vCPU is time-sliced and must oversubscribe", cpu, labCPU)
	}
	if mem > labMem {
		t.Errorf("allocatable memory = %d exceeds the %d physical — memory must not oversubscribe by default", mem, labMem)
	}
}

// TestHostAllocatable_PerHostOverridesWin: a host with swap/KSM may be allowed to
// overcommit memory while its peers may not.
func TestHostAllocatable_PerHostOverridesWin(t *testing.T) {
	h := labHost()
	h.MemOvercommit = 2.0
	zero := 0
	h.MemReserveMiB = &zero // explicit zero: hand guests everything

	_, mem := HostAllocatable(h, DefaultCapacityPolicy())
	if want := labMem * 2; mem != want {
		t.Errorf("allocatable memory = %d, want %d (2x ratio, explicit zero reserve)", mem, want)
	}
}

// TestHostAllocatable_ZeroReserveIsDistinctFromUnset is the encoding trap: 0 is a
// MEANINGFUL reserve, so "not configured" cannot also be 0 or an operator could
// never opt out of the default headroom.
func TestHostAllocatable_ZeroReserveIsDistinctFromUnset(t *testing.T) {
	unset := labHost() // MemReserveMiB = -1
	explicitZero := labHost()
	zero := 0
	explicitZero.MemReserveMiB = &zero

	_, memUnset := HostAllocatable(unset, DefaultCapacityPolicy())
	_, memZero := HostAllocatable(explicitZero, DefaultCapacityPolicy())

	if memUnset == memZero {
		t.Fatalf("unset and explicit-zero reserve both yield %d MiB — an operator cannot opt out of the default headroom", memUnset)
	}
	if memZero != labMem {
		t.Errorf("explicit zero reserve yields %d, want the full %d", memZero, labMem)
	}
}

// TestHostAllocatable_PercentReserveScalesWithLargeHosts: a fixed 1 GiB floor is
// right for a small node and far too little for a big one, so the effective
// reserve is the larger of floor and percentage.
func TestHostAllocatable_PercentReserveScalesWithLargeHosts(t *testing.T) {
	big := HostRecord{Name: "big", CPUTotal: 64, MemTotal: 512 * 1024}
	_, mem := HostAllocatable(big, DefaultCapacityPolicy())

	pct := 512 * 1024 * 5 / 100 // 5% = 26214 MiB, well above the 1024 floor
	if want := 512*1024 - pct; mem != want {
		t.Errorf("allocatable memory = %d, want %d (5%% reserve, not the 1 GiB floor)", mem, want)
	}
}

// TestHostAllocatable_NeverNegative: a host reserving more than it has is full,
// not owed capacity.
func TestHostAllocatable_NeverNegative(t *testing.T) {
	tiny := HostRecord{Name: "tiny", CPUTotal: 1, MemTotal: 256}
	cpu, mem := HostAllocatable(tiny, DefaultCapacityPolicy())
	if cpu < 0 || mem < 0 {
		t.Errorf("allocatable = (%d cpu, %d mem), want both clamped to >= 0", cpu, mem)
	}
	if mem != 0 {
		t.Errorf("a 256 MiB host with a 1024 MiB reserve should offer 0, got %d", mem)
	}
}

// TestCapacityPolicy_ZeroValueDoesNotStarveEveryHost: a caller that forgets to
// configure a policy must not get ratio 0, which would make every host look full
// and refuse all placement.
func TestCapacityPolicy_ZeroValueDoesNotStarveEveryHost(t *testing.T) {
	cpu, mem := HostAllocatable(labHost(), CapacityPolicy{})
	if cpu <= 0 || mem <= 0 {
		t.Fatalf("zero-value policy yields (%d cpu, %d mem) — an unconfigured cluster would refuse everything", cpu, mem)
	}
}
