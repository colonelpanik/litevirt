package fleet

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Shared-storage fence readiness is a multi-node mechanism: one daemon asks
// every other for its own enforcement posture over a real Ping, and decides
// whether a shared-disk VM's cross-host transfer would be fenced.
//
// A single-package test structurally cannot reach that path. `testServer` sets
// pkiDir to a directory that does not exist, so dialPeer fails before any
// network I/O and EVERY peer comes back unreachable — which means the peer
// branch, and postureFromPing with it, is dead code in the unit tests.
// Replacing the whole peer arm with an unconditional "enforcing" posture leaves
// the entire single-package suite green, and that mutation is precisely the
// false all-clear this feature exists to prevent. These tests are what makes it
// go red.
//
// They also carry the only end-to-end check of the posture DISCLOSURE gate. Ping
// answers not_enforcing / posture_reported only to a caller presenting a host
// certificate, and these peers present real ones over real mTLS — so a gate that
// wrongly refused a peer would blank every posture here, while the unit tests
// (which hand Ping a hand-built context) would not notice.

// seedSharedDiskVM gives the cluster something to be exposed: a VM with a disk
// on shared storage, which is the only kind whose cross-host transfer needs the
// proof-grade fence.
func seedSharedDiskVM(t *testing.T, n *Node, vm string) {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`INSERT INTO vm_disks (vm_name, disk_name, host_name, path, storage_type, updated_at)
		 VALUES (?, 'd0', ?, '/pool/d0', 'ceph', ?)`, vm, n.Name, n.DB.NowTS()); err != nil {
		t.Fatalf("seed shared disk on %s: %v", n.Name, err)
	}
}

func fenceReadinessFrom(t *testing.T, c *Cluster, n *Node) *pb.FenceReadiness {
	t.Helper()
	r, err := c.SelfClient(n).GetFenceReadiness(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetFenceReadiness on %s: %v", n.Name, err)
	}
	return r
}

func postureOf(t *testing.T, r *pb.FenceReadiness, host string) *pb.FenceHostPosture {
	t.Helper()
	for _, p := range r.GetHosts() {
		if p.GetHost() == host {
			return p
		}
	}
	t.Fatalf("no posture reported for %s; an omitted host is invisible to the operator", host)
	return nil
}

// TestFleet_FenceReadiness_PostureCrossesTheWire pins the kill-switch as a
// PEER-OBSERVABLE fact. The unit tests call postureFromPing with hand-built
// PingResponse literals; here one daemon reads another's posture out of a real
// Ping over real mTLS, which is how the diagnostic actually learns it.
func TestFleet_FenceReadiness_PostureCrossesTheWire(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	observer, holdout := c.Nodes[0], c.Nodes[1]
	seedSharedDiskVM(t, observer, "db-1")

	// Every node enforces except one — the mixed-config state a cluster reaches
	// mid-rollout, and the one no peer could previously observe.
	for _, n := range c.Nodes {
		n.Server.SetEnforcementConfig(false, false, false, false, false, n != holdout)
	}

	r := fenceReadinessFrom(t, c, observer)

	// Both halves are asserted. "not enforcing" alone would still pass if the
	// holdout came back UNKNOWN, and unknown is the wrong answer here: the
	// holdout answered, and what it said — advertising other tokens while
	// withholding this one — is exactly how a node reports the switch is off.
	// Reporting that as unknown would hide the single finding this command exists
	// to produce behind the word used for a host nothing could reach.
	if p := postureOf(t, r, holdout.Name); p.GetEnforcing() || !p.GetPostureKnown() {
		t.Errorf("%s has enforcement.shared_storage_fence off, but %s reads it as "+
			"enforcing=%v posture_known=%v (reachable=%v detail=%q)",
			holdout.Name, observer.Name, p.GetEnforcing(), p.GetPostureKnown(),
			p.GetReachable(), p.GetDetail())
	}
	for _, n := range c.Nodes {
		if n == holdout {
			continue
		}
		p := postureOf(t, r, n.Name)
		if !p.GetEnforcing() || !p.GetPostureKnown() {
			t.Errorf("%s enforces, but is reported enforcing=%v posture_known=%v detail=%q",
				n.Name, p.GetEnforcing(), p.GetPostureKnown(), p.GetDetail())
		}
	}
	if r.GetEnforcedEverywhere() {
		t.Errorf("enforced_everywhere = true with %s not enforcing", holdout.Name)
	}
	if r.GetVmsWithSharedDisk() == 0 {
		t.Error("the seeded shared-disk VM was not counted, so the report understates the exposure")
	}
}

// TestFleet_FenceReadiness_EveryNodeEnforcing is the other direction: with the
// switch on everywhere, the sweep must actually reach every peer and come back
// covered. Without it, a check that reported "not enforcing" for everything —
// including a peer it simply failed to reach — would pass the test above while
// being useless.
func TestFleet_FenceReadiness_EveryNodeEnforcing(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	observer := c.Nodes[0]
	seedSharedDiskVM(t, observer, "db-1")
	for _, n := range c.Nodes {
		n.Server.SetEnforcementConfig(false, false, false, false, false, true)
	}

	r := fenceReadinessFrom(t, c, observer)

	for _, n := range c.Nodes {
		p := postureOf(t, r, n.Name)
		if !p.GetReachable() || !p.GetPostureKnown() || !p.GetEnforcing() {
			t.Errorf("%s: reachable=%v posture_known=%v enforcing=%v detail=%q — every node enforces",
				n.Name, p.GetReachable(), p.GetPostureKnown(), p.GetEnforcing(), p.GetDetail())
		}
	}
	if !r.GetEnforcedEverywhere() {
		t.Error("enforced_everywhere = false with the kill-switch on across the fleet")
	}
}

// TestFleet_FenceReadiness_DownedPeerIsUnknown is the real unreachability test.
// The single-package version could not be one: its dial fails on missing local
// PKI material in 0.02s, identically for a routable and an unroutable address,
// so it never exercised a peer that is genuinely unreachable.
//
// Cluster.Partition is deliberately not used here — it severs only the
// replication methods (see partitionedMethods) and leaves Ping answering, so a
// "partitioned" peer still reports its posture perfectly well. Taking the
// daemon off the air, as the hardware_v2 latch test does, is what actually
// makes a peer unreachable.
//
// An unreachable peer must read as UNKNOWN and clear readiness. Reporting it
// covered would tell an operator a corruption hazard is closed on behalf of a
// host nothing could reach.
func TestFleet_FenceReadiness_DownedPeerIsUnknown(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	observer, downed := c.Nodes[0], c.Nodes[2]
	seedSharedDiskVM(t, observer, "db-1")
	for _, n := range c.Nodes {
		n.Server.SetEnforcementConfig(false, false, false, false, false, true)
	}

	// Everything enforces, so losing the peer is the ONLY variable between this
	// and the covered case above.
	if r := fenceReadinessFrom(t, c, observer); !r.GetEnforcedEverywhere() {
		t.Fatalf("fixture: cluster is not covered before the peer goes down")
	}

	downed.GRPCSrv.Stop()

	r := fenceReadinessFrom(t, c, observer)
	p := postureOf(t, r, downed.Name)
	if p.GetReachable() || p.GetPostureKnown() || p.GetEnforcing() {
		t.Errorf("%s is off the air but reads reachable=%v posture_known=%v enforcing=%v detail=%q; "+
			"a host that cannot be reached has not answered",
			downed.Name, p.GetReachable(), p.GetPostureKnown(), p.GetEnforcing(), p.GetDetail())
	}
	if r.GetEnforcedEverywhere() {
		t.Error("enforced_everywhere = true with a peer off the air — unknown must never read as covered")
	}
}
