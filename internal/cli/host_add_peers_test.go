package cli

import (
	"context"
	"strings"
	"testing"
)

// TestHostAdd_RefusesToProvisionAHostWithNoGossipPeers.
//
// The peer list is gathered best-effort: `lv host add` calls ListHosts and, if the
// daemon cannot be reached or returns nothing, proceeds with an empty list. The
// target is then provisioned with `join_peers: []` — a node that has been given
// certificates, a binary and a running daemon, and no way to find the cluster. It
// reports success.
//
// Found rebuilding the lab from the other end: nodes 2, 3 and 4 came up with a
// join_peers that could not work, and nothing said so at add time. An empty list is
// never a valid outcome for `add` — by definition there is at least one existing
// host to join, or you would be running `init`.
func TestHostAdd_RefusesToProvisionAHostWithNoGossipPeers(t *testing.T) {
	err := HostAdd(context.Background(), nil, "root@10.0.0.9", "node-9", nil)
	if err == nil {
		t.Fatal("provisioning a host with no gossip peers was allowed\n" +
			"the node gets certificates, a binary and a daemon, and no way to reach the " +
			"cluster — and the command exits 0")
	}
	if !strings.Contains(err.Error(), "join") && !strings.Contains(err.Error(), "peer") {
		t.Errorf("the refusal does not explain that there are no peers to join: %v", err)
	}
	// And it must refuse BEFORE touching the target: the CA check and every push
	// come after, so a failure here has to mean nothing was changed remotely.
	if strings.Contains(err.Error(), "SSH") {
		t.Errorf("the refusal happened after the SSH connect, so the target may already "+
			"have been modified: %v", err)
	}
}
