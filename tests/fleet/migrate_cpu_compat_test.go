// Fleet scenarios for the migration CPU-compatibility preflight.
//
// A guest whose CPU is derived from its host (host-model — the create default —
// or host-passthrough) may be executing instructions the destination host does
// not have. litevirt ran no CPU check at all before this: the migration was
// provisioned on the target and the guest's memory started moving before libvirt
// on the far end refused the CPU, leaving a half-built target to clean up.
//
// This is multi-node by construction and cannot be reached from one package: the
// requirement is read from the SOURCE's live domain XML, the verdict comes from
// the TARGET's hypervisor over real gRPC, and the entry node is a third party. A
// check that asked the wrong host would pass a single-node test.

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// errUnavailableCompare stands in for a hypervisor that cannot answer a CPU
// compare right now (as opposed to answering "incompatible").
var errUnavailableCompare = errors.New("libvirt: cannot compare CPU right now")

// expandedHostModelXML is what libvirt's LIVE domain XML looks like for a
// host-model guest: the mode has already been resolved to a concrete model plus
// the feature list the guest is actually running with.
const expandedHostModelXML = `<domain type='kvm'>
  <name>%s</name>
  <cpu mode='custom' match='exact' check='full'>
    <model fallback='forbid'>Skylake-Server-IBRS</model>
    <feature policy='require' name='avx2'/>
  </cpu>
</domain>`

// seedRunningCPUVM stages a running diskless VM on n with a given cpu_mode, and
// gives its live domain XML the shape libvirt would produce for that mode.
func seedRunningCPUVM(t *testing.T, c *Cluster, n *Node, name, cpuMode, liveXML string) {
	t.Helper()
	specJSON, err := json.Marshal(&pb.VMSpec{
		Name: name, Cpu: 2, MemoryMib: 2048, CpuMode: cpuMode,
	})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	if err := corrosion.InsertVM(context.Background(), c.Nodes[0].DB, corrosion.VMRecord{
		Name: name, HostName: n.Name, State: "running", Spec: string(specJSON),
		CPUActual: 2, MemActual: 2048,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
	n.Virt.SetState(name, "running")
	if liveXML != "" {
		n.Virt.SetActiveXML(name, liveXML)
	}
}

// TestFleet_MigrateVM_RefusedWhenTargetCPUCannotRunTheGuest is the point of the
// whole preflight: the TARGET's verdict decides, and it decides before anything
// is provisioned there.
//
// Only the target is made incompatible. Entry node and source both report a
// superset CPU (the fake's default), so a preflight that asked the entry node,
// asked the source, or asked nobody would admit this migration.
func TestFleet_MigrateVM_RefusedWhenTargetCPUCannotRunTheGuest(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	defer c.Stop()

	entry, source, target := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	seedRunningCPUVM(t, c, source, "vm-avx", lv.CPUModeHostModel,
		strings.Replace(expandedHostModelXML, "%s", "vm-avx", 1))

	incompatible := lv.CPUCompareIncompatible
	target.Virt.CPUCompareResult = &incompatible

	err := migrateAt(t, c, entry, "vm-avx", target.Name)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("migrate status = %v, want FailedPrecondition (err = %v)", got, err)
	}
	if !strings.Contains(err.Error(), "CPU does not provide") {
		t.Errorf("refusal does not explain the CPU mismatch: %v", err)
	}

	// The target must have been asked, and asked about the guest's ACTUAL
	// expanded CPU — not some placeholder.
	asked := target.Virt.ComparedCPUXML()
	if len(asked) == 0 {
		t.Fatal("target was never asked to compare a CPU")
	}
	if !strings.Contains(asked[0], "Skylake-Server-IBRS") || !strings.Contains(asked[0], "avx2") {
		t.Errorf("target was asked about the wrong CPU: %q", asked[0])
	}

	// And the VM must not have moved.
	vm, err := corrosion.GetVM(context.Background(), source.DB, "vm-avx")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != source.Name {
		t.Errorf("VM host = %q, want it left on the source %q", vm.HostName, source.Name)
	}

	// Control: the same migration once the target's CPU is a superset. Without
	// this the refusal above would pass for any reason at all — including a
	// migrate path broken for reasons that have nothing to do with CPUs.
	superset := lv.CPUCompareSuperset
	target.Virt.CPUCompareResult = &superset
	if err := migrateAt(t, c, entry, "vm-avx", target.Name); err != nil {
		t.Fatalf("migrate onto a CPU-compatible target: %v", err)
	}
	vm, err = corrosion.GetVM(context.Background(), target.DB, "vm-avx")
	if err != nil || vm == nil {
		t.Fatalf("GetVM after migrate: vm=%v err=%v", vm, err)
	}
	if vm.HostName != target.Name {
		t.Errorf("VM host = %q after a permitted migration, want %q", vm.HostName, target.Name)
	}
}

// A compatible target is not blocked. The preflight consults the target and gets
// out of the way — proving the refusal above came from the verdict and not from
// the preflight refusing everything.
func TestFleet_MigrateVM_AllowedWhenTargetCPUIsASuperset(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()

	source, target := c.Nodes[0], c.Nodes[1]
	seedRunningCPUVM(t, c, source, "vm-ok", lv.CPUModeHostModel,
		strings.Replace(expandedHostModelXML, "%s", "vm-ok", 1))

	superset := lv.CPUCompareSuperset
	target.Virt.CPUCompareResult = &superset

	if err := migrateAt(t, c, source, "vm-ok", target.Name); err != nil {
		t.Fatalf("migrate of a CPU-compatible VM was refused: %v", err)
	}
	if len(target.Virt.ComparedCPUXML()) == 0 {
		t.Error("target was never asked to compare a CPU, so the pass proves nothing")
	}
}

// The blast radius is bounded to VMs that actually carry a host-derived CPU. A
// VM with an empty cpu_mode renders with no <cpu> element at all — QEMU's
// qemu64, identical on every host — so it must not be preflighted, and must
// migrate to a host that would refuse a host-model guest.
//
// This is the compatibility half of the change: every VM created before the
// cpu_mode default existed keeps migrating exactly as it did.
func TestFleet_MigrateVM_LegacyEmptyCPUModeIsNotPreflighted(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()

	source, target := c.Nodes[0], c.Nodes[1]
	// Its live XML DOES carry a <cpu> element: libvirt resolves and writes back
	// the concrete model for a running domain even when the definition named
	// none. So the gate cannot key off "the live XML has no CPU" — it keys off
	// the stored spec's cpu_mode, which is the operator's actual intent.
	seedRunningCPUVM(t, c, source, "vm-legacy", "",
		`<domain type='kvm'><name>vm-legacy</name>`+
			`<cpu mode='custom' match='exact' check='full'>`+
			`<model fallback='forbid'>qemu64</model></cpu></domain>`)

	// A target that would refuse ANY compared CPU.
	incompatible := lv.CPUCompareIncompatible
	target.Virt.CPUCompareResult = &incompatible

	if err := migrateAt(t, c, source, "vm-legacy", target.Name); err != nil {
		t.Fatalf("migrate of a legacy (no cpu_mode) VM was refused: %v", err)
	}
	if asked := target.Virt.ComparedCPUXML(); len(asked) != 0 {
		t.Errorf("a VM with no cpu_mode was preflighted anyway: %q", asked)
	}
}

// A target that cannot run the compare at all is "could not verify", not
// "incompatible". The preflight must fail OPEN there: a peer mid-upgrade, or one
// whose libvirt is briefly unhappy, must never be the reason migration stops
// working. libvirt still has the final say at cutover.
func TestFleet_MigrateVM_CPUPreflightFailsOpenWhenTargetCannotAnswer(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()

	source, target := c.Nodes[0], c.Nodes[1]
	seedRunningCPUVM(t, c, source, "vm-unknown", lv.CPUModeHostModel,
		strings.Replace(expandedHostModelXML, "%s", "vm-unknown", 1))

	target.Virt.FailCompareCPU = func(string) error {
		return errUnavailableCompare
	}

	if err := migrateAt(t, c, source, "vm-unknown", target.Name); err != nil {
		t.Fatalf("migrate was refused on an UNVERIFIABLE target CPU; the preflight must fail open: %v", err)
	}
	if len(target.Virt.ComparedCPUXML()) == 0 {
		t.Error("target was never asked, so this scenario proves nothing about failing open")
	}
}

// A target on an older build does not have the RPC at all and answers
// Unimplemented. That MUST be a no-op, not a refusal: a preflight added in one
// release cannot become the reason migration onto a not-yet-upgraded peer stops
// working mid-rollout. This is the one scenario a same-build cluster cannot
// produce on its own, so the target is told to answer as an old peer would.
func TestFleet_MigrateVM_CPUPreflightSkippedOnAPeerWithoutTheRPC(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()

	source, target := c.Nodes[0], c.Nodes[1]
	seedRunningCPUVM(t, c, source, "vm-mixed", lv.CPUModeHostModel,
		strings.Replace(expandedHostModelXML, "%s", "vm-mixed", 1))

	// Belt and braces: if the call DID reach the handler it would refuse.
	incompatible := lv.CPUCompareIncompatible
	target.Virt.CPUCompareResult = &incompatible
	restore := target.DoNotImplement("CheckCPUCompatibility")
	defer restore()

	if err := migrateAt(t, c, source, "vm-mixed", target.Name); err != nil {
		t.Fatalf("migrate onto a peer that does not implement the preflight was refused: %v", err)
	}
	// The handler must never have run — Unimplemented is returned ahead of it.
	if asked := target.Virt.ComparedCPUXML(); len(asked) != 0 {
		t.Errorf("the old-peer simulation did not actually bypass the handler: %q", asked)
	}
}

// A host-passthrough guest names no model in its live XML, so the requirement is
// the SOURCE HOST's own CPU. The target must be asked about that, not skipped —
// passthrough is the mode most likely to be unrunnable elsewhere.
func TestFleet_MigrateVM_PassthroughComparesTheSourceHostCPU(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()

	source, target := c.Nodes[0], c.Nodes[1]
	source.Virt.HostCPUModel = "Sapphire-Rapids"
	seedRunningCPUVM(t, c, source, "vm-pt", lv.CPUModeHostPassthrough,
		`<domain type='kvm'><name>vm-pt</name><cpu mode='host-passthrough' check='none'/></domain>`)

	incompatible := lv.CPUCompareIncompatible
	target.Virt.CPUCompareResult = &incompatible

	err := migrateAt(t, c, source, "vm-pt", target.Name)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("migrate status = %v, want FailedPrecondition (err = %v)", got, err)
	}
	asked := target.Virt.ComparedCPUXML()
	if len(asked) == 0 {
		t.Fatal("a host-passthrough VM was not preflighted at all")
	}
	if !strings.Contains(asked[0], "Sapphire-Rapids") {
		t.Errorf("target was not asked about the SOURCE host's CPU: %q", asked[0])
	}
}
