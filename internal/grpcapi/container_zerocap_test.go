package grpcapi

import (
	"context"
	"testing"
)

// findWorkload returns the inventory entry for a container by name.
func findWorkload(t *testing.T, inv runtimeInventory, name string) runtimeWorkload {
	t.Helper()
	for _, w := range inv.Workloads {
		if w.Name == name {
			return w
		}
	}
	t.Fatalf("workload %q not in inventory", name)
	return runtimeWorkload{}
}

// A container with a FINITE zero-byte memory cap must not be reported as
// uncapped. cgroup2 accepts both "max" and "0"; the parse used to collapse
// them, so the most restrictive cap there is read as no cap at all — which
// trips the uncapped gate and blocks new admission on the host.
//
// Charging 0 MiB is correct either way; what must not happen is the Uncapped
// flag.
func TestRuntimeInventory_FiniteZeroCapIsNotUncapped(t *testing.T) {
	orig := lxcCapable
	lxcCapable = func() bool { return true }
	defer func() { lxcCapable = orig }()

	s := testServer(t)
	s.containerRuntime = &fakeCT{
		names:  []string{"zerocap", "unlimited", "normal"},
		states: map[string]string{"zerocap": "running", "unlimited": "running", "normal": "running"},
		mem: map[string]ContainerMemoryLimit{
			"zerocap":   {MiB: 0, Unlimited: false}, // cgroup2 "0"
			"unlimited": {Unlimited: true},          // cgroup2 "max"
			"normal":    {MiB: 512},
		},
	}

	inv := s.collectRuntimeInventory(context.Background())

	zero := findWorkload(t, inv, "zerocap")
	if zero.Uncapped {
		t.Error("a finite zero-byte memory cap was reported as UNCAPPED; cgroup2 \"0\" is a cap, not the absence of one")
	}
	if zero.MemoryMiB != 0 {
		t.Errorf("zerocap charged %d MiB, want 0", zero.MemoryMiB)
	}

	if unl := findWorkload(t, inv, "unlimited"); !unl.Uncapped {
		t.Error("cgroup2 \"max\" must still report as uncapped")
	}

	normal := findWorkload(t, inv, "normal")
	if normal.Uncapped {
		t.Error("a 512 MiB cap must not report as uncapped")
	}
	if normal.MemoryMiB != 512 {
		t.Errorf("normal charged %d MiB, want 512", normal.MemoryMiB)
	}
}
