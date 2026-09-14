// Fleet scenarios for `lv cutover` — giving a replacement VM the name a REPLACED
// VM still holds.
//
// The transition is gated on vm_replace_v1 because it needs a guarantee the
// pre-existing replicated statement shapes cannot express: the replaced VM is
// soft-deleted, so its tombstone still occupies that PRIMARY KEY, and every way
// of clearing or moving it out of existing shapes leaves the handover as two or
// more INDEPENDENTLY gated statements. A receiver can then commit one and skip
// another — leaving no row at the name, or moving a still-live VM aside when its
// own newer ownership made the sender's delete decline there.
//
// internal/corrosion/vm_replace_test.go covers the receiver decision against a
// Replicator directly. What a single-package test structurally cannot cover, and
// what this file does, is the rollout: a REAL health.Checker negotiating the token
// over real Ping RPCs between separate daemons, the real CutoverVM handler behind
// real gRPC, and the real anti-entropy pull carrying the finished transition — or
// a stale pre-cutover snapshot — between them.

package fleet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// enableVMReplaceFleet wires what the daemon wires for this capability: the
// config opt-in that drives advertisement, and the receiver-side accept predicate
// reading the DURABLE latch (so acceptance of an in-flight batch survives a
// restart).
func enableVMReplaceFleet(c *Cluster, gates map[string]*health.Checker, nodes ...*Node) {
	if len(nodes) == 0 {
		nodes = c.Nodes
	}
	for _, n := range nodes {
		n.Server.SetVMReplaceEnforce(true)
		gate := gates[n.Name]
		n.DB.SetVMReplaceAccept(func() bool {
			return gate.DurablyLatched(capabilities.VMReplaceV1)
		})
	}
}

// latchCutoverCapabilities brings a cluster to the state a cutover requires:
// enforcement.vm_replace and enforcement.operation_protocol on every node, both
// tokens latched, and the receiver-side accept predicate wired. For a fixture
// that already built its own gates (boundCluster), a fresh Checker re-reads the
// same durable markers, so tokens latched earlier stay latched.
func latchCutoverCapabilities(t *testing.T, c *Cluster) {
	t.Helper()
	gates := gateAll(t, c)
	latchOperationProtocol(t, c, gates)
	enableVMReplaceFleet(c, gates)
	eventually(t, 10*time.Second, "vm_replace_v1 to latch fleet-wide", func() bool {
		return gates[c.Nodes[0].Name].Enforced(context.Background(), capabilities.VMReplaceV1)
	})
}

// seedCutoverPair puts a VM and its ready replacement on owner, each with one
// disk, and converges every other node onto that state.
func seedCutoverPair(t *testing.T, c *Cluster, owner *Node) {
	t.Helper()
	ctx := context.Background()
	for _, vm := range []struct{ name, path string }{
		{"app", "/disks/app-root.qcow2"},
		{"app-next", "/disks/app-next-root.qcow2"},
	} {
		if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
			Name: vm.name, HostName: owner.Name, Spec: `{"name":"` + vm.name + `"}`, State: "stopped",
		}, nil, []corrosion.DiskRecord{{
			VMName: vm.name, DiskName: "root", HostName: owner.Name,
			Path: vm.path, StorageType: "local",
		}}); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
		if err := owner.Virt.DefineDomain(`<domain><name>` + vm.name + `</name></domain>`); err != nil {
			t.Fatalf("DefineDomain %s: %v", vm.name, err)
		}
	}
	for _, n := range c.Nodes {
		if n != owner {
			converge(t, c, n, owner)
		}
	}
}

// A cutover must refuse until EVERY node has opted in. One node with the flag off
// holds the latch open, and a cutover that ran anyway would emit a guard protocol
// that node cannot evaluate — back-pressuring its replication stream at the
// cutover and never advancing past it.
func TestFleet_Cutover_RefusedUntilEveryNodeOptsIn(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	gates := gateAll(t, c)
	owner := c.Nodes[0]
	seedCutoverPair(t, c, owner)
	// The operation journal is a hard dependency (it carries the cleanup
	// manifest), so latch it up front — vm_replace is the variable under test.
	latchOperationProtocol(t, c, gates)

	// Two of three opt in: no latch, so no cutover anywhere.
	enableVMReplaceFleet(c, gates, c.Nodes[0], c.Nodes[1])
	_, err := c.SelfClient(owner).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"})
	if err == nil {
		t.Fatal("cutover ran with a node still opted out")
	}
	if !strings.Contains(err.Error(), "enforcement.vm_replace") {
		t.Errorf("refusal %q does not name the flag an operator has to set", err)
	}
	// Nothing was touched — not the domains, not either VM's rows.
	for _, name := range []string{"app", "app-next"} {
		vm, gErr := corrosion.GetVM(ctx, owner.DB, name)
		if gErr != nil || vm == nil {
			t.Fatalf("%s after a refused cutover: %+v err=%v", name, vm, gErr)
		}
	}
	if _, err := owner.Virt.DumpXML("app"); err != nil {
		t.Errorf("a refused cutover undefined the replaced VM's domain: %v", err)
	}

	// The last node opts in, the fleet latches, and the same call succeeds.
	enableVMReplaceFleet(c, gates, c.Nodes[2])
	eventually(t, 10*time.Second, "vm_replace_v1 to latch fleet-wide", func() bool {
		return gates[owner.Name].Enforced(ctx, capabilities.VMReplaceV1)
	})
	if _, err := c.SelfClient(owner).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover with every node opted in: %v", err)
	}
	vm, err := corrosion.GetVM(ctx, owner.DB, "app")
	if err != nil || vm == nil {
		t.Fatalf(`no live VM named "app" after the cutover: %+v err=%v`, vm, err)
	}
	if vm.Spec != `{"name":"app"}` {
		t.Fatalf("VM %q carries %q, want the replacement's spec patched to the new name", "app", vm.Spec)
	}
}

// latchedCutoverCluster is the common fixture: a latched fleet with the pair
// seeded on c.Nodes[0].
func latchedCutoverCluster(t *testing.T, nodes int) (*Cluster, map[string]*health.Checker, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: nodes})
	gates := gateAll(t, c)
	owner := c.Nodes[0]
	seedCutoverPair(t, c, owner)
	latchOperationProtocol(t, c, gates)
	enableVMReplaceFleet(c, gates)
	eventually(t, 10*time.Second, "vm_replace_v1 to latch fleet-wide", func() bool {
		return gates[owner.Name].Enforced(context.Background(), capabilities.VMReplaceV1)
	})
	return c, gates, owner
}

// The finished transition must reach every peer intact: the replacement under the
// contested name, carrying ITS OWN incarnation and an authority above both inputs,
// and its temporary name tombstoned rather than merely absent.
func TestFleet_Cutover_ConvergesOnEveryPeer(t *testing.T) {
	c, _, owner := latchedCutoverCluster(t, 3)
	ctx := context.Background()

	replacement, err := corrosion.GetVM(ctx, owner.DB, "app-next")
	if err != nil || replacement == nil {
		t.Fatalf("replacement before the cutover: %+v err=%v", replacement, err)
	}
	replaced, err := corrosion.GetVM(ctx, owner.DB, "app")
	if err != nil || replaced == nil {
		t.Fatalf("replaced VM before the cutover: %+v err=%v", replaced, err)
	}

	if _, err := c.SelfClient(owner).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	for _, n := range c.Nodes {
		if n != owner {
			converge(t, c, n, owner)
		}
	}

	for _, n := range c.Nodes {
		vm, gErr := corrosion.GetVM(ctx, n.DB, "app")
		if gErr != nil || vm == nil {
			t.Fatalf("%s: no live VM at the contested name: %+v err=%v", n.Name, vm, gErr)
		}
		if vm.CreatedAt != replacement.CreatedAt {
			t.Errorf("%s: created_at = %q, want the REPLACEMENT's %q — inheriting the replaced "+
				"VM's stamp would let a delayed tombstone of it read as the same incarnation",
				n.Name, vm.CreatedAt, replacement.CreatedAt)
		}
		if vm.OwnerEpoch <= replaced.OwnerEpoch || vm.OwnerEpoch <= replacement.OwnerEpoch {
			t.Errorf("%s: owner epoch %d does not exceed both inputs (%d, %d)",
				n.Name, vm.OwnerEpoch, replaced.OwnerEpoch, replacement.OwnerEpoch)
		}
		if vm.SpecGeneration <= replaced.SpecGeneration || vm.SpecGeneration <= replacement.SpecGeneration {
			t.Errorf("%s: spec generation %d does not exceed both inputs (%d, %d)",
				n.Name, vm.SpecGeneration, replaced.SpecGeneration, replacement.SpecGeneration)
		}
		if gone, _ := corrosion.GetVM(ctx, n.DB, "app-next"); gone != nil {
			t.Errorf("%s: the replacement is still live under its temporary name", n.Name)
		}
		if tomb, tErr := corrosion.GetDeletedVM(ctx, n.DB, "app-next"); tErr != nil || tomb == nil {
			t.Errorf("%s: the temporary name is absent rather than tombstoned: %+v err=%v",
				n.Name, tomb, tErr)
		}
		disks, dErr := corrosion.GetVMDisks(ctx, n.DB, "app")
		if dErr != nil {
			t.Fatalf("%s: GetVMDisks: %v", n.Name, dErr)
		}
		if len(disks) != 1 || disks[0].Path != "/disks/app-next-root.qcow2" {
			t.Errorf("%s: the name holds %+v, want exactly the replacement's disk", n.Name, disks)
		}
	}
}

// A peer that lagged the whole cutover still holds the replaced VM live. Pulling
// its state must not undo the transition — and the replaced VM normally has the
// HIGHER authority of the two, since it has been running longer than its
// replacement, so nothing but authority written above BOTH inputs saves it.
func TestFleet_Cutover_StaleSnapshotCannotOverwriteTheReplacement(t *testing.T) {
	c, _, owner := latchedCutoverCluster(t, 2)
	ctx := context.Background()
	lagging := c.Nodes[1]

	// Give the replaced VM the higher authority, as a longer-running VM has.
	if err := corrosion.TransferVMOwner(ctx, owner.DB, "app", owner.Name, "stopped", 0); err != nil {
		t.Fatalf("advance the replaced VM's ownership: %v", err)
	}
	converge(t, c, lagging, owner)

	if _, err := c.SelfClient(owner).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	// The laggard never saw any of it; the owner pulls its stale view.
	converge(t, c, owner, lagging)

	vm, err := corrosion.GetVM(ctx, owner.DB, "app")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm == nil {
		t.Fatal("the lagging peer's stale state removed the replacement entirely")
	}
	disks, err := corrosion.GetVMDisks(ctx, owner.DB, "app")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 1 || disks[0].Path != "/disks/app-next-root.qcow2" {
		t.Fatalf("the lagging peer's stale state resurrected the replaced VM: %+v", disks)
	}
}

// A peer whose own newer ownership made the sender's delete decline THERE keeps
// that VM live. The whole transition has to decline with it — one receiver
// decision — rather than moving its live VM aside or emptying the name.
func TestFleet_Cutover_DeclinesOnAPeerThatRefusedTheDelete(t *testing.T) {
	c, _, owner := latchedCutoverCluster(t, 2)
	ctx := context.Background()
	peer := c.Nodes[1]

	// The peer advances the replaced VM's ownership locally, so the delete the
	// cutover emits cannot apply there.
	if err := corrosion.TransferVMOwner(ctx, peer.DB, "app", peer.Name, "stopped", 0); err != nil {
		t.Fatalf("advance the peer's ownership: %v", err)
	}
	if _, err := c.SelfClient(owner).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	converge(t, c, peer, owner)

	held, err := corrosion.GetVM(ctx, peer.DB, "app")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if held == nil {
		t.Fatal("the peer's newer-authority VM was destroyed by a transition it had to decline")
	}
}

// A daemon that died after the transition committed must finish the destruction
// when it comes back, from the journal alone — the rows that said what the
// replaced VM owned are gone, and the name they were under now belongs to the
// replacement.
//
// This is the multi-node half of the guarantee: the journal is REPLICATED, so the
// manifest and the step authorizing it reach every peer, and only the owning host
// acts on them.
func TestFleet_Cutover_RestartFinishesCommittedCleanup(t *testing.T) {
	c, _, owner := latchedCutoverCluster(t, 2)
	ctx := context.Background()
	peer := c.Nodes[1]

	// Die immediately after the transition commits.
	owner.Server.SetCutoverCrashHook(func(stage string) error {
		if stage == "after-commit" {
			return errFleetCrash
		}
		return nil
	})
	if _, err := c.SelfClient(owner).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon after the commit")
	}

	// The transition is committed and replicates; the cleanup is still owed.
	converge(t, c, peer, owner)
	for _, n := range c.Nodes {
		vm, err := corrosion.GetVM(ctx, n.DB, "app")
		if err != nil || vm == nil {
			t.Fatalf("%s: the committed transition is missing: %+v err=%v", n.Name, vm, err)
		}
	}
	owed, err := corrosion.ListVMReplaceCleanups(ctx, owner.DB, owner.Name)
	if err != nil {
		t.Fatalf("ListVMReplaceCleanups: %v", err)
	}
	if len(owed) != 1 || owed[0].Manifest.ReplacedVM != "app" {
		t.Fatalf("committed cleanup awaiting a restart = %+v, want one for the replaced VM", owed)
	}
	// The journal reached the peer too, and the peer must NOT act on another
	// host's cleanup.
	if peerOwed, pErr := corrosion.ListVMReplaceCleanups(ctx, peer.DB, peer.Name); pErr != nil {
		t.Fatalf("peer ListVMReplaceCleanups: %v", pErr)
	} else if len(peerOwed) != 0 {
		t.Fatalf("the peer claimed another host's cleanup: %+v", peerOwed)
	}

	// The restart finishes it, and nothing is owed afterwards.
	owner.Server.SetCutoverCrashHook(nil)
	if err := owner.Server.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if left, lErr := corrosion.ListVMReplaceCleanups(ctx, owner.DB, owner.Name); lErr != nil || len(left) != 0 {
		t.Fatalf("cleanup is not recorded as done: %+v err=%v", left, lErr)
	}
	// The replacement is untouched by any of it.
	disks, err := corrosion.GetVMDisks(ctx, owner.DB, "app")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 1 || disks[0].Path != "/disks/app-next-root.qcow2" {
		t.Fatalf("the name holds %+v, want exactly the replacement's disk", disks)
	}
}

var errFleetCrash = errors.New("simulated process exit")

// latchedRealCutoverCluster is latchedCutoverCluster with the pair created through
// the real CreateVM RPC instead of seeded rows.
//
// The difference that matters is the libvirt domain. seedCutoverPair defines a
// name-only XML with no uuid, and an empty replacement uuid is what cutover reads
// as "no local domain to hand off" — so the runtime handoff never runs under it.
// A scenario about what the handoff restores has to start from a domain that
// actually has an identity.
func latchedRealCutoverCluster(t *testing.T, nodes int) (*Cluster, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: nodes})
	gates := gateAll(t, c)
	owner := c.Nodes[0]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}
	for _, name := range []string{"app", "app-next"} {
		if _, err := c.SelfClient(owner).CreateVM(context.Background(), &pb.CreateVMRequest{
			Spec: &pb.VMSpec{
				Name: name, Cpu: 1, MemoryMib: 512,
				Placement: &pb.PlacementSpec{Host: owner.Name},
				Disks:     []*pb.DiskSpec{{Name: "root", Size: "64M"}},
			},
		}); err != nil {
			t.Fatalf("CreateVM %s: %v", name, err)
		}
	}
	latchOperationProtocol(t, c, gates)
	enableVMReplaceFleet(c, gates)
	eventually(t, 10*time.Second, "vm_replace_v1 to latch fleet-wide", func() bool {
		return gates[owner.Name].Enforced(context.Background(), capabilities.VMReplaceV1)
	})
	return c, owner
}

// A manifest is captured before the FIRST attempt's teardown and adopted verbatim
// by every retry, so it cannot be where the runtime intent comes from: an operator
// who starts the replacement between two attempts made a decision, and replaying
// the older snapshot would stop the VM for the rename and then not start it again.
// The intent is journaled with the transition instead, which is the moment it is
// actually accepted.
func TestFleet_Cutover_RetryHonoursAStartAcceptedBetweenAttempts(t *testing.T) {
	c, owner := latchedRealCutoverCluster(t, 1)
	ctx := context.Background()

	// The replacement is stopped when the first attempt captures its manifest.
	if _, err := c.SelfClient(owner).StopVM(ctx, &pb.StopVMRequest{Name: "app-next", Force: true}); err != nil {
		t.Fatalf("stop the replacement: %v", err)
	}
	owner.Server.SetCutoverCrashHook(func(stage string) error {
		if stage == "before-commit" {
			return errFleetCrash
		}
		return nil
	})
	if _, err := c.SelfClient(owner).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the injected crash did not fail the cutover")
	}
	owner.Server.SetCutoverCrashHook(nil)

	// The operator starts it between the two attempts.
	if _, err := c.SelfClient(owner).StartVM(ctx, &pb.StartVMRequest{Name: "app-next"}); err != nil {
		t.Fatalf("start the replacement: %v", err)
	}
	if active, err := owner.Virt.DomainIsActive("app-next"); err != nil || !active {
		t.Fatalf("the accepted start did not reach the domain: active=%v err=%v", active, err)
	}

	if _, err := c.SelfClient(owner).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if active, err := owner.Virt.DomainIsActive("app"); err != nil || !active {
		t.Fatalf("the retry undid a start the operator had accepted: active=%v err=%v", active, err)
	}
}

// The same intent, read back by a RESTART rather than by the attempt that wrote
// it. Recovery has only the journal — the manifest it carries is the first
// attempt's — so the accepted state has to survive there, not in the handler's
// memory.
func TestFleet_Cutover_RecoveryHonoursAStartAcceptedBetweenAttempts(t *testing.T) {
	c, owner := latchedRealCutoverCluster(t, 1)
	ctx := context.Background()

	if _, err := c.SelfClient(owner).StopVM(ctx, &pb.StopVMRequest{Name: "app-next", Force: true}); err != nil {
		t.Fatalf("stop the replacement: %v", err)
	}
	owner.Server.SetCutoverCrashHook(func(stage string) error {
		if stage == "before-commit" {
			return errFleetCrash
		}
		return nil
	})
	if _, err := c.SelfClient(owner).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the injected crash did not fail the first attempt")
	}

	// The operator starts it, then the attempt that COMMITS dies before the
	// handoff — so only a restart can finish the start it owes.
	owner.Server.SetCutoverCrashHook(nil)
	if _, err := c.SelfClient(owner).StartVM(ctx, &pb.StartVMRequest{Name: "app-next"}); err != nil {
		t.Fatalf("start the replacement: %v", err)
	}
	owner.Server.SetCutoverCrashHook(func(stage string) error {
		if stage == "before-runtime" {
			return errFleetCrash
		}
		return nil
	})
	if _, err := c.SelfClient(owner).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the injected crash did not fail the committing attempt")
	}
	owner.Server.SetCutoverCrashHook(nil)

	if err := owner.Server.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if active, err := owner.Virt.DomainIsActive("app"); err != nil || !active {
		t.Fatalf("recovery undid a start the operator had accepted: active=%v err=%v", active, err)
	}
}
