package corrosion

import (
	"context"
	"maps"
	"testing"
)

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

func TestCapacityPolicyFingerprintNormalizesDefaults(t *testing.T) {
	zero, err := CapacityPolicyFingerprint(CapacityPolicy{}, nil)
	if err != nil {
		t.Fatalf("zero fingerprint: %v", err)
	}
	defaults, err := CapacityPolicyFingerprint(DefaultCapacityPolicy(), map[string]HostCapacityOverride{})
	if err != nil {
		t.Fatalf("default fingerprint: %v", err)
	}
	if zero != defaults {
		t.Fatalf("zero policy fingerprint %q != normalized defaults %q", zero, defaults)
	}
}

func TestCapacityPolicyFingerprintIncludesEveryCapacityField(t *testing.T) {
	base := DefaultCapacityPolicy()
	baseFingerprint, err := CapacityPolicyFingerprint(base, nil)
	if err != nil {
		t.Fatalf("base fingerprint: %v", err)
	}
	variants := []CapacityPolicy{
		func() CapacityPolicy { p := base; p.CPUOvercommit++; return p }(),
		func() CapacityPolicy { p := base; p.MemOvercommit++; return p }(),
		func() CapacityPolicy { p := base; p.CPUReserve++; return p }(),
		func() CapacityPolicy { p := base; p.MemReserveMiB++; return p }(),
		func() CapacityPolicy { p := base; p.MemReservePct++; return p }(),
		func() CapacityPolicy { p := base; p.VMMemOverheadMiB++; return p }(),
	}
	for i, variant := range variants {
		got, err := CapacityPolicyFingerprint(variant, nil)
		if err != nil {
			t.Fatalf("variant %d: %v", i, err)
		}
		if got == baseFingerprint {
			t.Errorf("capacity field variant %d did not change fingerprint", i)
		}
	}
}

func TestCapacityPolicyFingerprintCanonicalizesHostOverrides(t *testing.T) {
	cpuZero, memZero := 0, 0
	overridesA := map[string]HostCapacityOverride{
		"node-b": {CPUOvercommit: 2, MemOvercommit: 1.25},
		"node-a": {CPUReserve: &cpuZero, MemReserveMiB: &memZero},
	}
	overridesB := map[string]HostCapacityOverride{}
	overridesB["node-a"] = overridesA["node-a"]
	overridesB["node-b"] = overridesA["node-b"]

	a, err := CapacityPolicyFingerprint(DefaultCapacityPolicy(), overridesA)
	if err != nil {
		t.Fatalf("fingerprint A: %v", err)
	}
	b, err := CapacityPolicyFingerprint(DefaultCapacityPolicy(), overridesB)
	if err != nil {
		t.Fatalf("fingerprint B: %v", err)
	}
	if a != b {
		t.Fatalf("map insertion order changed fingerprint: %q != %q", a, b)
	}

	changed := maps.Clone(overridesA)
	changed["node-b"] = HostCapacityOverride{CPUOvercommit: 3, MemOvercommit: 1.25}
	c, err := CapacityPolicyFingerprint(DefaultCapacityPolicy(), changed)
	if err != nil {
		t.Fatalf("changed fingerprint: %v", err)
	}
	if c == a {
		t.Fatal("host override change did not change fingerprint")
	}
}

func TestHostCapacityOverridesPreserveExplicitZeroAndIgnoreUnrelatedFields(t *testing.T) {
	zero := 0
	hosts := []HostRecord{
		{
			Name: "node-b", Labels: map[string]string{"zone": "west"},
			CPUOvercommit: 2,
		},
		{
			Name: "node-a", Address: "10.0.0.1",
			CPUReserve: &zero, MemReserveMiB: &zero,
		},
	}
	got := HostCapacityOverrides(hosts)
	if got["node-a"].CPUReserve == nil || *got["node-a"].CPUReserve != 0 {
		t.Fatalf("explicit zero CPU reserve lost: %+v", got["node-a"])
	}
	if got["node-a"].MemReserveMiB == nil || *got["node-a"].MemReserveMiB != 0 {
		t.Fatalf("explicit zero memory reserve lost: %+v", got["node-a"])
	}

	changedUnrelated := append([]HostRecord(nil), hosts...)
	changedUnrelated[0].Labels = map[string]string{"zone": "east"}
	changedUnrelated[1].Address = "10.0.0.99"
	a, _ := CapacityPolicyFingerprint(DefaultCapacityPolicy(), got)
	b, _ := CapacityPolicyFingerprint(DefaultCapacityPolicy(), HostCapacityOverrides(changedUnrelated))
	if a != b {
		t.Fatal("non-capacity host fields changed capacity-policy fingerprint")
	}
}

// TestHostFreeCapacity_CountsRunningContainers is the hole this closes: host
// usage came from the vms table alone, so a host packed with containers reported
// 100% of its memory free and VMs were admitted on top of memory already held.
func TestHostFreeCapacity_CountsRunningContainers(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := InsertHost(ctx, db, HostRecord{Name: "h1", CPUTotal: 8, MemTotal: 8192, State: "HOST_ACTIVE"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	_, baseline, ok, err := HostFreeCapacity(ctx, db, "h1")
	if err != nil || !ok {
		t.Fatalf("HostFreeCapacity: ok=%v err=%v", ok, err)
	}

	if err := UpsertContainer(ctx, db, ContainerRecord{
		HostName: "h1", Name: "ct1", State: "running", MemMiB: 2048,
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	_, withCT, _, err := HostFreeCapacity(ctx, db, "h1")
	if err != nil {
		t.Fatalf("HostFreeCapacity: %v", err)
	}
	if want := baseline - 2048; withCT != want {
		t.Errorf("free memory with a running 2048 MiB container = %d, want %d — containers hold host memory and must be counted",
			withCT, want)
	}
}

// TestSumContainerMemoryByHost_OnlyRunningAndCapped: a stopped container holds
// nothing, and an UNCAPPED one (memory 0) cannot be accounted — litevirt knows
// the cap, not the footprint, and inventing a number would be a guess dressed as
// accounting.
func TestSumContainerMemoryByHost_OnlyRunningAndCapped(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, ct := range []ContainerRecord{
		{HostName: "h1", Name: "running-capped", State: "running", MemMiB: 512},
		{HostName: "h1", Name: "stopped-capped", State: "stopped", MemMiB: 4096},
		{HostName: "h1", Name: "running-uncapped", State: "running", MemMiB: 0},
	} {
		if err := UpsertContainer(ctx, db, ct); err != nil {
			t.Fatalf("UpsertContainer %s: %v", ct.Name, err)
		}
	}

	got, err := SumContainerMemoryByHost(ctx, db)
	if err != nil {
		t.Fatalf("SumContainerMemoryByHost: %v", err)
	}
	if got["h1"] != 512 {
		t.Errorf("h1 container memory = %d, want 512 (running+capped only; stopped holds nothing, uncapped is unknowable)", got["h1"])
	}
}
