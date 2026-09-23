package corrosion

import (
	"context"
	"testing"
)

// RelayEligibleHosts returns nil when its local read fails, and nil means
// "no information" — which ComputeRelays reproduces as the ORIGINAL
// sorted-hostname ordering. For the self-upgrade caller that is right. For
// the replication caller it is the exact failure ComputeRelays documents as
// forbidden: a local query error is a node's own opinion, and acting on it
// makes that one node compute a topology no peer agrees with.
//
// The consequence is not symmetric. Only a node that believes itself a relay
// re-records forwarded mutations for fan-out, so the diverged node pushes to
// two hosts that apply its writes locally and forward nothing. Its mutations
// reach nowhere else until anti-entropy catches up.
//
// So the replication path must RETAIN the last eligibility it successfully
// computed rather than silently switching to a different total order.
func TestRelayEligibility_ReplicationRetainsTheLastGoodMapOnReadFailure(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer c.Close()
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, h := range []HostRecord{
		{Name: "a1", Address: "10.0.0.1", State: "draining"},
		{Name: "b1", Address: "10.0.0.2", State: "active"},
		{Name: "b2", Address: "10.0.0.3", State: "active"},
	} {
		if err := InsertHost(ctx, c, h); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}

	r := NewReplicator(c, "", RelayConfig{})

	good := r.relayEligibility(ctx)
	if !good["b1"] || good["a1"] {
		t.Fatalf("baseline eligibility = %v, want the active hosts only", good)
	}

	// The read now fails. The replicator must keep using what it last proved,
	// not fall back to a different ordering every peer disagrees with.
	if err := c.Execute(ctx, `DROP TABLE hosts`); err != nil {
		t.Fatalf("drop hosts: %v", err)
	}
	after := r.relayEligibility(ctx)
	if len(after) == 0 {
		t.Fatal("eligibility went empty on a read failure; ComputeRelays then reproduces the " +
			"plain name ordering and this node alone elects a different relay set")
	}
	if !after["b1"] || after["a1"] {
		t.Fatalf("eligibility after a failed read = %v, want the last good map %v", after, good)
	}
}

// Before anything has been proved, a failure must not invent eligibility —
// an empty map is "no information", which is the documented nil behaviour and
// the only honest answer at startup.
func TestRelayEligibility_NoRetainedMapYieldsNoInformation(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer c.Close()
	ctx := context.Background()
	// No schema at all: the very first read fails.
	r := NewReplicator(c, "", RelayConfig{})
	if got := r.relayEligibility(ctx); len(got) != 0 {
		t.Fatalf("eligibility = %v on the first read failing, want empty (no information)", got)
	}
}
