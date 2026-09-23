package failover

import (
	"testing"

	"github.com/litevirt/litevirt/internal/health"
)

// TestHeartbeatFitsInsideHealthFreshness pins the relationship #196 broke.
//
// recoverHosts (and the fence-quorum read above it) only count a host_health
// row whose updated_at is newer than healthFreshness. Nothing here writes those
// rows — internal/health does, on its own schedule — so the two numbers have to
// be kept in step across a package boundary, and nothing kept them.
//
// The original defect was worse than a mistuned pair: internal/health wrote a
// row only on TRANSITION, so a steadily healthy peer had no refresh interval at
// all and its row aged without bound. That is now health.HeartbeatInterval, and
// this is the assertion that stops either side drifting past the other again.
//
// Two heartbeats of head-room, not one: a row must survive a missed beat (a
// slow probe cycle, a replication hiccup) and still be fresh when the next one
// lands. At one-to-one the steady state would sit exactly on the cutoff.
//
// This test lives in internal/failover on purpose. failover owns
// healthFreshness and is the package that suffers when the relationship breaks;
// internal/health cannot import it back.
func TestHeartbeatFitsInsideHealthFreshness(t *testing.T) {
	if health.HeartbeatInterval <= 0 {
		t.Fatalf("health.HeartbeatInterval = %v; a non-positive interval disables the "+
			"refresh entirely and no healthy row can ever satisfy healthFreshness",
			health.HeartbeatInterval)
	}
	if 2*health.HeartbeatInterval > healthFreshness {
		t.Errorf("health.HeartbeatInterval = %v, healthFreshness = %v: a healthy "+
			"observation is re-published too rarely to stay fresh, so recoverHosts "+
			"counts zero healthy observers and a fenced or offline host never "+
			"auto-recovers (want 2*heartbeat <= freshness)",
			health.HeartbeatInterval, healthFreshness)
	}
}
