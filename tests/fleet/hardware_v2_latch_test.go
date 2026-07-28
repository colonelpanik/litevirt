// Fleet scenario: cluster-wide latching of hardware_v2 (VM Hardware Foundation,
// CONTRACT h).
//
// hardware_v2 is not a local flag — it is NEGOTIATED. A node advertises it only
// once its own BackfillHardwareTables audit pass has populated the typed-hardware
// tables AND operation_protocol_v1 (the crash-safe operation journal it
// hard-depends on) has latched locally. The fleet latches hardware_v2 only when
// EVERY voting-eligible member advertises it. Once latched the decision is
// monotone and durable: a peer that later goes unreachable fails CLOSED (stays
// latched) instead of silently reverting to the legacy dual-write path.
//
// internal/grpcapi/hardware_v2_test.go covers the decision functions in isolation
// against a fake gate. What a single-package test structurally cannot cover — and
// what this file does — is the negotiation itself: real health.Checker instances,
// real Ping RPCs over real mTLS between separate daemons, real corrosion.ListHosts
// membership, and the durable activation marker. The dangerous failure mode is
// inherently multi-node: one node latching the fleet — and so stopping legacy
// dual-writes / permitting stopped-VM hardware mutations — before a peer's typed
// tables are populated, which is exactly what internal/grpcapi/server.go:407-413
// warns about.

package fleet

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/health"
)

// ── harness helpers ─────────────────────────────────────────────────────────

// markerBase is a node's durable activation-marker base path. health.Checker
// appends "." + token per capability, so one base latches every token
// independently. Kept in a helper so a simulated restart can re-open the SAME
// base a fresh Checker would find on disk.
func markerBase(c *Cluster, n *Node) string {
	return filepath.Join(c.tmpRoot, n.Name, "markers", "activated")
}

// gateFor wires a REAL health.Checker as node n's capability gate, pinging peers
// through the node's own Server.PeerCapabilities. That is the production wiring —
// the daemon injects grpcapi.Server.PeerCapabilities as the health.PeerPinger — so
// activation here runs the true path: fresh Ping per voting-eligible host in
// corrosion.ListHosts, over the harness's real loopback mTLS.
func gateFor(t *testing.T, c *Cluster, n *Node) *health.Checker {
	t.Helper()
	if err := mkdirAll(filepath.Dir(markerBase(c, n))); err != nil {
		t.Fatalf("mkdir markers for %s: %v", n.Name, err)
	}
	ch := health.NewChecker(n.Name, n.PKIDir, n.DB)
	ch.SetPeerPinger(n.Server.PeerCapabilities)
	ch.SetActivationMarker(markerBase(c, n))
	n.Server.SetGate(ch)
	return ch
}

// gateAll wires a gate on every node and returns them keyed by node name.
func gateAll(t *testing.T, c *Cluster) map[string]*health.Checker {
	t.Helper()
	gates := make(map[string]*health.Checker, len(c.Nodes))
	for _, n := range c.Nodes {
		gates[n.Name] = gateFor(t, c, n)
	}
	return gates
}

// latchOperationProtocol turns the operation_protocol_v1 config kill-switch on
// everywhere and drives its cluster latch on every node.
//
// Every node must latch it LOCALLY before any node will advertise hardware_v2:
// hardwareV2Ready deliberately reads the cheap in-memory gate.Latched rather than
// Enforced (calling Enforced from inside the Ping handler would recurse), so a
// node whose op-protocol latch has not closed yet withholds hardware_v2 even with
// its backfill done.
func latchOperationProtocol(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		n.Server.SetOperationProtocol(true)
	}
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.OperationProtocolV1) {
			t.Fatalf("%s: operation_protocol_v1 failed to latch with the config flag on everywhere", n.Name)
		}
	}
}

// backfillAll runs the typed-hardware audit pass on every node, setting each
// node's advertise-readiness flag.
func backfillAll(t *testing.T, c *Cluster) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		if err := n.Server.BackfillHardwareTables(ctx); err != nil {
			t.Fatalf("BackfillHardwareTables on %s: %v", n.Name, err)
		}
	}
}

// latchHardwareV2 brings the whole fleet to a latched hardware_v2 state.
func latchHardwareV2(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	ctx := context.Background()
	latchOperationProtocol(t, c, gates)
	backfillAll(t, c)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.HardwareV2) {
			t.Fatalf("%s: hardware_v2 failed to latch with every node ready", n.Name)
		}
	}
}

// eventually polls cond until it holds or the deadline passes.
//
// Needed because health.Checker caches a NEGATIVE CapabilityActive result for
// capActiveNegTTL (3s) to avoid a Ping storm on hot paths: once a test has
// asserted "not latched", the very next Enforced call reads that cached miss even
// after the underlying cause is fixed.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ── scenarios ───────────────────────────────────────────────────────────────

// TestFleet_HardwareV2_LatchWaitsForEveryNodeBackfill is the core CONTRACT h
// guarantee: a single node whose typed-hardware tables are not yet populated must
// hold the whole fleet back, including the nodes that ARE ready. A ready node that
// latched early would stop legacy dual-writes while the laggard still reads from
// them — the peer would miss data.
func TestFleet_HardwareV2_LatchWaitsForEveryNodeBackfill(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	gates := gateAll(t, c)
	latchOperationProtocol(t, c, gates)

	// Everyone but the laggard completes the audit pass: 2 of 3 ready.
	laggard := c.Nodes[len(c.Nodes)-1]
	for _, n := range c.Nodes {
		if n == laggard {
			continue
		}
		if err := n.Server.BackfillHardwareTables(ctx); err != nil {
			t.Fatalf("BackfillHardwareTables on %s: %v", n.Name, err)
		}
	}

	// The laggard withholds hardware_v2 from its advertisement, so no node may
	// latch — not even the two that are themselves ready.
	for _, n := range c.Nodes {
		if gates[n.Name].Enforced(ctx, capabilities.HardwareV2) {
			t.Fatalf("%s: hardware_v2 latched while %s had not completed its backfill", n.Name, laggard.Name)
		}
	}

	// Finish the laggard's pass — now every node advertises and the latch closes.
	if err := laggard.Server.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables on %s: %v", laggard.Name, err)
	}
	for _, n := range c.Nodes {
		eventually(t, 10*time.Second, "hardware_v2 to latch on "+n.Name, func() bool {
			return gates[n.Name].Enforced(ctx, capabilities.HardwareV2)
		})
	}
}

// TestFleet_HardwareV2_BlockedByOperationProtocolConfigSkew: hardware_v2
// hard-depends on operation_protocol_v1, and that token is advertised
// CONDITIONALLY on its config kill-switch so the latch requires CONFIG
// uniformity, not merely a uniform build. A half-rolled config change — one node
// still opted out — must therefore block hardware_v2 even when every node's
// typed-hardware backfill has completed.
func TestFleet_HardwareV2_BlockedByOperationProtocolConfigSkew(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	gates := gateAll(t, c)

	// Mid-roll: every node has opted into the operation protocol except one.
	holdout := c.Nodes[1]
	for _, n := range c.Nodes {
		n.Server.SetOperationProtocol(n != holdout)
	}
	for _, n := range c.Nodes {
		if gates[n.Name].Enforced(ctx, capabilities.OperationProtocolV1) {
			t.Fatalf("%s: operation_protocol_v1 latched while %s has the config flag off", n.Name, holdout.Name)
		}
	}

	// Readiness is satisfied everywhere — the audit pass succeeds regardless of
	// the op-protocol flag — so the ONLY thing standing between the fleet and a
	// hardware_v2 latch is the unmet prerequisite.
	backfillAll(t, c)
	for _, n := range c.Nodes {
		if gates[n.Name].Enforced(ctx, capabilities.HardwareV2) {
			t.Fatalf("%s: hardware_v2 latched with operation_protocol_v1 unlatched (holdout %s)", n.Name, holdout.Name)
		}
	}
}

// TestFleet_HardwareV2_AdvertisementCrossesTheWire pins the advertisement as a
// PEER-OBSERVABLE fact rather than an in-process one. The unit tests call
// advertisedCapabilities() directly; here a different daemon reads the token out
// of a real Ping response over real mTLS, which is how activation actually learns
// it.
func TestFleet_HardwareV2_AdvertisementCrossesTheWire(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	latchOperationProtocol(t, c, gates)

	observer, subject := c.Nodes[0], c.Nodes[1]
	client := c.PeerClient(observer, subject)
	subjectCaps := func() []string {
		resp, err := client.Ping(ctx, &pb.PingRequest{})
		if err != nil {
			t.Fatalf("Ping %s from %s: %v", subject.Name, observer.Name, err)
		}
		return resp.GetCapabilities()
	}

	// operation_protocol_v1 is already latched on the subject, so readiness is the
	// only thing still withholding the token.
	if capabilities.Has(subjectCaps(), capabilities.HardwareV2) {
		t.Fatalf("%s advertised hardware_v2 over Ping before its backfill completed", subject.Name)
	}
	if err := subject.Server.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables on %s: %v", subject.Name, err)
	}
	if !capabilities.Has(subjectCaps(), capabilities.HardwareV2) {
		t.Fatalf("%s did not advertise hardware_v2 over Ping after its backfill completed", subject.Name)
	}
}

// TestFleet_HardwareV2_UnreachablePeerBlocksLatch: activation is computed from
// FRESH Pings and fails closed. With readiness satisfied on every node and
// operation_protocol_v1 already latched, an unreachable voting-eligible member is
// the sole remaining variable — and "can't confirm" must read as "don't latch",
// never as assumed support.
func TestFleet_HardwareV2_UnreachablePeerBlocksLatch(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	latchOperationProtocol(t, c, gates)
	backfillAll(t, c)

	// Take the peer off the air BEFORE the latch closes.
	survivor, downed := c.Nodes[0], c.Nodes[1]
	downed.GRPCSrv.Stop()

	if gates[survivor.Name].Enforced(ctx, capabilities.HardwareV2) {
		t.Fatalf("%s: hardware_v2 latched while voting-eligible peer %s was unreachable", survivor.Name, downed.Name)
	}
}

// TestFleet_HardwareV2_LatchSurvivesPeerLoss is the other half of fail-closed:
// once the latch HAS closed, losing a peer must not re-open the legacy ungated
// path. A partition makes confirmation impossible, which is precisely when the
// gate matters most, so Enforced stays true off the durable latch.
func TestFleet_HardwareV2_LatchSurvivesPeerLoss(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	latchHardwareV2(t, c, gates)

	survivor, downed := c.Nodes[0], c.Nodes[1]
	downed.GRPCSrv.Stop()

	if !gates[survivor.Name].Enforced(ctx, capabilities.HardwareV2) {
		t.Fatalf("%s: hardware_v2 un-latched after peer %s became unreachable — must fail closed", survivor.Name, downed.Name)
	}
}

// TestFleet_HardwareV2_LatchSurvivesDaemonRestart: the latch is persisted per
// token so a restart cannot reset it. Modeled with a brand-new health.Checker over
// the same marker base and NO pinger wired — nothing can re-confirm activation, so
// a latch that returns true can only have come from the durable marker. Without
// this, a daemon restarting mid-partition would silently revert to the legacy
// path.
func TestFleet_HardwareV2_LatchSurvivesDaemonRestart(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	latchHardwareV2(t, c, gates)

	n := c.Nodes[0]
	restarted := health.NewChecker(n.Name, n.PKIDir, n.DB)
	restarted.SetActivationMarker(markerBase(c, n))

	if !restarted.Latched(capabilities.HardwareV2) {
		t.Fatalf("%s: hardware_v2 latch did not survive a restart — durable marker was not preloaded", n.Name)
	}
	// Enforced must agree without pinging anyone (the pinger is deliberately nil;
	// a non-latched token would fail closed to false here).
	if !restarted.Enforced(ctx, capabilities.HardwareV2) {
		t.Fatalf("%s: Enforced(hardware_v2) false after restart despite a preloaded latch", n.Name)
	}
	// Sanity: the same restarted Checker must NOT invent a latch for a token that
	// never activated — proving the assertion above came from the marker rather
	// than a blanket true.
	if restarted.Latched(capabilities.LiveResizeV1) {
		t.Fatalf("%s: live_resize_v1 reported latched though it never activated", n.Name)
	}
}
