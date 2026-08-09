// Fleet scenario for the libvirt domain-event crash handler.
//
// A qemu process that dies takes its domain down with it; libvirt reports that
// as a lifecycle event, and health.DomainEventHandler is what turns that event
// into a cluster-visible state=error so an operator (and the reconciler) can see
// the VM failed rather than watch it sit at its last-known state until the next
// polling sweep. The handler carries three guards worth pinning: it acts only on
// crash/stop events, only for VMs this host owns, and never on a VM an operator
// deliberately stopped.
//
// This runs in tests/fleet/ rather than as a unit test because the crash write
// is a REPLICATED write: it has to leave this node's mutation_log, cross real
// gRPC + mTLS, and survive the receiver's applyStatementLWW + statement-shape
// apply guard on the peer. A single-package test structurally cannot reach that.
//
// The daemon registers this handler inside daemon.Run (a ~700-line function no
// test can invoke), so the harness registers the SAME handler on each node's
// libvirt fake in buildServer — the scenario drives the real code, not a copy.
//
// Scope note: nothing in production invokes this handler today. internal/libvirt
// stores the callback but never subscribes to go-libvirt's lifecycle-event
// stream, so what this pins is the handler's decision logic, the fake's dispatch
// and the replication of its write — NOT that a crashed qemu on a real host
// reaches the handler. That wiring is a separate change.
package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func TestFleet_DomainEventCrashed_MarksVMErrorAndSparesOperatorStop(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	// Seed through the registered corrosion writer only. The receiver's apply
	// guard refuses ad-hoc statement shapes, so a test that seeded with inline
	// SQL would break the moment its mutations were pumped to the peer below
	// (see owner_epoch_test.go).
	seed := func(name, host, state, detail string) {
		t.Helper()
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
			Name: name, HostName: host, State: state, StateDetail: detail,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
	}
	seed("vm-crash", a.Name, "running", "")               // the crash victim
	seed("vm-opstop", a.Name, "stopped", "operator-stop") // deliberately stopped
	seed("vm-remote", b.Name, "running", "")              // owned by the peer
	seed("vm-idle", a.Name, "running", "")                // gets a non-lifecycle event

	// Both nodes agree before anything is fired, so a later divergence on b can
	// only come from the crash write itself.
	pumpMutations(t, c, a, b)
	for _, name := range []string{"vm-crash", "vm-opstop", "vm-remote", "vm-idle"} {
		if vm, _ := corrosion.GetVM(ctx, b.DB, name); vm == nil {
			t.Fatalf("seed for %s did not replicate to %s", name, b.Name)
		}
	}

	// The fake's view of the crashed domain matches reality: the domain is down.
	a.Virt.SetState("vm-crash", libvirtfake.StateShutdown)

	// Act — every event fires on node a, the host running the handler.
	a.Virt.FireEvent("vm-crash", lv.DomainEventCrashed, 3)
	a.Virt.FireEvent("vm-opstop", lv.DomainEventCrashed, 3)
	a.Virt.FireEvent("vm-remote", lv.DomainEventCrashed, 3)
	a.Virt.FireEvent("vm-idle", lv.DomainEventStarted, 0)

	get := func(node *Node, name string) *corrosion.VMRecord {
		t.Helper()
		vm, err := corrosion.GetVM(ctx, node.DB, name)
		if err != nil {
			t.Fatalf("GetVM %s on %s: %v", name, node.Name, err)
		}
		if vm == nil {
			t.Fatalf("GetVM %s on %s: no row", name, node.Name)
		}
		return vm
	}

	// (1) The crash is recorded as an error, carrying the libvirt detail code.
	// Substring match on detail= only — the OOM advice text is not a contract.
	if vm := get(a, "vm-crash"); vm.State != "error" {
		t.Errorf("vm-crash state = %q, want %q (detail=%q)", vm.State, "error", vm.StateDetail)
	} else if !strings.Contains(vm.StateDetail, "detail=3") {
		t.Errorf("vm-crash state_detail = %q, want it to carry detail=3", vm.StateDetail)
	}

	// (2) An operator-stopped VM is left alone: a stop the operator asked for is
	// not a failure, and overwriting it would manufacture a phantom incident.
	if vm := get(a, "vm-opstop"); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
		t.Errorf("vm-opstop = (%q, %q), want (%q, %q)",
			vm.State, vm.StateDetail, "stopped", "operator-stop")
	}

	// (3) A VM owned by another host is not this node's to mark — the peer's own
	// handler covers it, and acting here would stomp the real owner's row.
	if vm := get(a, "vm-remote"); vm.State != "running" || vm.HostName != b.Name {
		t.Errorf("vm-remote = (state %q, host %q), want (%q, %q)",
			vm.State, vm.HostName, "running", b.Name)
	}

	// (4) A non-lifecycle event carries no failure: widening the handler's switch
	// to a bare default would mark a VM that merely started as errored.
	if vm := get(a, "vm-idle"); vm.State != "running" {
		t.Errorf("vm-idle state = %q after DomainEventStarted, want %q", vm.State, "running")
	}

	// (5) The multi-node dimension: the crash write must actually reach the peer.
	// This runs the real spine — mutation_log → PushMutations over gRPC/mTLS →
	// applyStatementLWW + the receiver's statement-shape apply guard — and would
	// catch the write being emitted in a shape a peer silently discards.
	pumpMutations(t, c, a, b)
	if vm := get(b, "vm-crash"); vm.State != "error" {
		t.Errorf("vm-crash on %s = %q, want %q — crash write did not replicate",
			b.Name, vm.State, "error")
	}
	if vm := get(b, "vm-opstop"); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
		t.Errorf("vm-opstop on %s = (%q, %q), want (%q, %q)",
			b.Name, vm.State, vm.StateDetail, "stopped", "operator-stop")
	}
	if vm := get(b, "vm-remote"); vm.State != "running" {
		t.Errorf("vm-remote on %s = %q, want %q", b.Name, vm.State, "running")
	}
}
