// Fleet scenario: cluster-wide latching of live_resize, and what it gates.
//
// live_resize does NOT follow the config-uniformity shape that operation_protocol
// and hardware_v2 use, and the difference is easy to get backwards. Its
// advertisement is build-STATIC: advertisedCapabilities withholds only
// operation_protocol_v1, canonical_identity_v1, canonical_registry_v1 and
// hardware_v2 (server.go:381-413), so live_resize_v1 latches as soon as every
// voting-eligible member is running a build that understands it. That is the
// right latch for the risk being managed — an old peer rewriting a spec would
// DROP max_cpu and strand a guest that had hot-added CPUs above its boot count
// (vm.go:2780) — and understanding max_cpu is a property of the build, not of a
// flag.
//
// The `enforcement.live_resize` flag is a separate, purely LOCAL kill-switch on
// ORIGINATING the behaviour: liveResizeActive ANDs the flag with the latch
// (server.go:543). So both halves must hold, and each fails independently. See
// tokenEnabled's note — "enabled ≠ latched ≠ advertised".
//
// Only a fleet can run the negotiation for real: separate health.Checker
// instances exchanging real Ping RPCs over real mTLS, then a real UpdateVM
// driven through whatever gate that produced.

package fleet

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// liveResizeRefusal is the text the max_cpu gate refuses with. Matched on text
// because FailedPrecondition is shared with several unrelated preconditions on
// UpdateVM, and the point is to pin THIS refusal.
const liveResizeRefusal = "live resize is not enabled and latched cluster-wide"

// putVM seeds a VM row owned by n with the given vCPU count in its spec.
func putVM(t *testing.T, n *Node, name string, cpu int, state string) {
	t.Helper()
	spec := `{"name":"` + name + `","cpu":` + strconv.Itoa(cpu) + `}`
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: n.Name, Spec: spec, State: state,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s on %s: %v", name, n.Name, err)
	}
}

// setMaxCPU drives a real UpdateVM setting max_cpu, returning the RPC error.
func setMaxCPU(t *testing.T, c *Cluster, at *Node, vmName string, maxCPU int32) error {
	t.Helper()
	_, err := c.SelfClient(at).UpdateVM(context.Background(), &pb.UpdateVMRequest{
		Name: vmName, MaxCpu: &maxCPU,
	})
	return err
}

// TestFleet_LiveResize_LocalFlagOffRefusesEvenWhenLatched pins the local
// kill-switch half. The fleet has latched — every peer's build understands
// max_cpu — but THIS node's operator has not opted in, so it must still refuse.
//
// This is the half a latch-only implementation would get wrong: consult the
// cluster token, forget the flag, and `enforcement.live_resize: false` silently
// stops meaning anything.
func TestFleet_LiveResize_LocalFlagOffRefusesEvenWhenLatched(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	owner := c.Nodes[0]

	const vmName = "vm-live-flagoff"
	putVM(t, owner, vmName, 2, "stopped")

	// No SetLiveResize anywhere: advertisement is build-static, so the token
	// latches regardless — which is exactly why the flag has to be checked too.
	if !gates[owner.Name].Enforced(ctx, capabilities.LiveResizeV1) {
		t.Fatal("live_resize_v1 did not latch on a uniform build — advertisement is build-static, so this test's premise is broken")
	}

	err := setMaxCPU(t, c, owner, vmName, 8)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(errText(err), liveResizeRefusal) {
		t.Fatalf("set max_cpu with the local flag off: got %v, want FailedPrecondition containing %q", err, liveResizeRefusal)
	}

	// And nothing was written: a refusal that still persisted the ceiling would
	// leave exactly the spec an old peer drops.
	if got := specMaxCPU(t, owner, vmName); got != 0 {
		t.Errorf("max_cpu persisted as %d despite the refusal", got)
	}
}

// TestFleet_LiveResize_LatchIsBuildUniformNotConfigUniform pins the shape
// itself, so nobody "fixes" live_resize into conditional advertisement by
// analogy with operation_protocol. A peer with its flag off still advertises,
// because whether a peer would DROP max_cpu depends on its build, not its
// config — and the peer's own flag only governs what that peer originates.
func TestFleet_LiveResize_LatchIsBuildUniformNotConfigUniform(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	owner, peer := c.Nodes[0], c.Nodes[1]

	// Flag on HERE only; the peer stays default-off.
	owner.Server.SetLiveResize(true)

	caps, err := owner.Server.PeerCapabilities(ctx, peer.Name)
	if err != nil {
		t.Fatalf("ping peer for capabilities: %v", err)
	}
	if !containsCap(caps, capabilities.LiveResizeV1) {
		t.Fatalf("a flag-off peer withheld live_resize_v1 (advertised %v) — advertisement is meant to be build-static; if this changed deliberately, the local kill-switch test above is now the only thing keeping the flag meaningful",
			caps)
	}
	if !gates[owner.Name].Enforced(ctx, capabilities.LiveResizeV1) {
		t.Error("live_resize_v1 failed to latch on a uniform build with one node's flag off")
	}
}

// TestFleet_LiveResize_UniformConfigLatchesAndPermitsMaxCPU is the other half:
// flag on AND latched, so the same request must succeed and stick.
func TestFleet_LiveResize_UniformConfigLatchesAndPermitsMaxCPU(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	owner := c.Nodes[0]

	const vmName = "vm-live-ok"
	putVM(t, owner, vmName, 2, "stopped")

	for _, n := range c.Nodes {
		n.Server.SetLiveResize(true)
	}
	if !gates[owner.Name].Enforced(ctx, capabilities.LiveResizeV1) {
		t.Fatal("live_resize_v1 failed to latch with the config flag on everywhere")
	}

	if err := setMaxCPU(t, c, owner, vmName, 8); err != nil {
		t.Fatalf("set max_cpu with the fleet latched: %v", err)
	}
	if got := specMaxCPU(t, owner, vmName); got != 8 {
		t.Errorf("max_cpu = %d after a permitted update, want 8", got)
	}
}

// TestFleet_LiveResize_UnreachablePeerBlocksTheInitialLatch is the latch half
// of the AND: the operator has opted in HERE, but a peer cannot be reached, so
// the fleet has never confirmed every member understands max_cpu. Writing it
// now is exactly the unsafe case — the unreachable peer may be the old build
// that drops it.
//
// Note the asymmetry with the monotonicity test below: losing a peer AFTER the
// latch formed keeps it closed; losing one BEFORE prevents it forming at all.
func TestFleet_LiveResize_UnreachablePeerBlocksTheInitialLatch(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	owner, peer := c.Nodes[0], c.Nodes[1]

	const vmName = "vm-live-unreachable"
	putVM(t, owner, vmName, 2, "stopped")

	// Opt in locally, then take the peer down BEFORE anything latches.
	owner.Server.SetLiveResize(true)
	peer.GRPCSrv.Stop()

	if gates[owner.Name].Enforced(ctx, capabilities.LiveResizeV1) {
		t.Fatal("live_resize_v1 latched while a peer was unreachable — an unconfirmed member must block the initial latch")
	}
	err := setMaxCPU(t, c, owner, vmName, 8)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(errText(err), liveResizeRefusal) {
		t.Fatalf("set max_cpu with the flag on but the fleet unlatched: got %v, want FailedPrecondition containing %q", err, liveResizeRefusal)
	}
	if got := specMaxCPU(t, owner, vmName); got != 0 {
		t.Errorf("max_cpu persisted as %d despite the refusal", got)
	}
}

// TestFleet_LiveResize_LatchSurvivesAPeerGoingUnreachable: the latch is monotone
// and fails CLOSED. Once formed, losing a peer must not silently re-open the
// gate — a partition that reverted capability decisions would flip behaviour
// underneath running VMs at exactly the worst moment.
func TestFleet_LiveResize_LatchSurvivesAPeerGoingUnreachable(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	owner, peer := c.Nodes[0], c.Nodes[1]

	const vmName = "vm-live-partition"
	putVM(t, owner, vmName, 2, "stopped")

	for _, n := range c.Nodes {
		n.Server.SetLiveResize(true)
	}
	if !gates[owner.Name].Enforced(ctx, capabilities.LiveResizeV1) {
		t.Fatal("live_resize_v1 failed to latch with the config flag on everywhere")
	}

	// Take the peer off the air entirely — its gRPC server stops answering Pings.
	peer.GRPCSrv.Stop()

	if !gates[owner.Name].Enforced(ctx, capabilities.LiveResizeV1) {
		t.Fatal("live_resize_v1 un-latched after a peer became unreachable — the latch must be monotone and fail closed")
	}
	if err := setMaxCPU(t, c, owner, vmName, 6); err != nil {
		t.Fatalf("set max_cpu after losing a peer: %v — a latched capability must keep working", err)
	}
}

// TestFleet_LiveResize_LatchIsDurableAcrossRestart: the decision is persisted, so
// a daemon restart does not re-open a gate the fleet already closed (which would
// let a freshly-booted node refuse work it accepted a minute earlier).
func TestFleet_LiveResize_LatchIsDurableAcrossRestart(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	owner, peer := c.Nodes[0], c.Nodes[1]

	for _, n := range c.Nodes {
		n.Server.SetLiveResize(true)
	}
	if !gates[owner.Name].Enforced(ctx, capabilities.LiveResizeV1) {
		t.Fatal("live_resize_v1 failed to latch with the config flag on everywhere")
	}

	// Simulate a restart: a brand-new Checker reading the SAME durable marker
	// base a restarted daemon would find on disk. The peer is taken down first so
	// the fresh Checker cannot simply re-negotiate the latch from scratch — the
	// only way it can report latched is by reading what was persisted.
	peer.GRPCSrv.Stop()
	fresh := health.NewChecker(owner.Name, owner.PKIDir, owner.DB)
	fresh.SetPeerPinger(owner.Server.PeerCapabilities)
	fresh.SetActivationMarker(markerBase(c, owner))

	if !fresh.Enforced(ctx, capabilities.LiveResizeV1) {
		t.Fatal("a restarted node lost the live_resize_v1 latch — the activation marker must be durable")
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// specMaxCPU reads the persisted max_cpu out of the VM's stored spec.
func specMaxCPU(t *testing.T, n *Node, vmName string) int32 {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), n.DB, vmName)
	if err != nil || vm == nil {
		t.Fatalf("read VM %s: vm=%v err=%v", vmName, vm, err)
	}
	spec := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			t.Fatalf("parse spec for %s: %v", vmName, err)
		}
	}
	return spec.MaxCpu
}

// containsCap reports whether caps advertises token.
func containsCap(caps []string, token string) bool {
	for _, c := range caps {
		if c == token {
			return true
		}
	}
	return false
}
