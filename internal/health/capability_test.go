package health

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func TestCapabilityActive(t *testing.T) {
	const tok = capabilities.SplitBrainGateV1

	setup := func(t *testing.T) *Checker {
		db := testCheckHostDB(t)
		gateHost(t, db, "host-a", "active", "worker")
		gateHost(t, db, "host-b", "active", "worker")
		gateHost(t, db, "host-c", "fenced", "worker") // not enforcement-relevant
		return NewChecker("host-a", "/etc/litevirt/pki", db)
	}

	t.Run("all support -> active", func(t *testing.T) {
		c := setup(t)
		c.SetPeerPinger(func(_ context.Context, host string) ([]string, error) {
			return []string{tok}, nil
		})
		if ok, reason := c.CapabilityActive(context.Background(), tok); !ok {
			t.Fatalf("all-support: got inactive reason=%q; want active", reason)
		}
	})

	t.Run("unreachable relevant member -> inactive (fail closed)", func(t *testing.T) {
		c := setup(t)
		c.SetPeerPinger(func(_ context.Context, host string) ([]string, error) {
			if host == "host-b" {
				return nil, errors.New("dial timeout")
			}
			return []string{tok}, nil
		})
		if ok, reason := c.CapabilityActive(context.Background(), tok); ok || reason != ReasonActivationUnconfirm {
			t.Fatalf("unreachable: got ok=%v reason=%q; want inactive/activation_unconfirmed", ok, reason)
		}
	})

	t.Run("member lacks token -> inactive", func(t *testing.T) {
		c := setup(t)
		c.SetPeerPinger(func(_ context.Context, host string) ([]string, error) {
			if host == "host-b" {
				return []string{}, nil // old peer, no capabilities
			}
			return []string{tok}, nil
		})
		if ok, reason := c.CapabilityActive(context.Background(), tok); ok || reason != ReasonUnsupportedCapability {
			t.Fatalf("unsupported: got ok=%v reason=%q; want inactive/unsupported_capability", ok, reason)
		}
	})

	t.Run("fenced member is not consulted", func(t *testing.T) {
		c := setup(t)
		c.SetPeerPinger(func(_ context.Context, host string) ([]string, error) {
			if host == "host-c" {
				t.Errorf("fenced host-c must not be pinged for activation")
			}
			return []string{tok}, nil
		})
		if ok, _ := c.CapabilityActive(context.Background(), tok); !ok {
			t.Fatalf("fenced-skipped: want active (fenced member excluded)")
		}
	})

	t.Run("no pinger -> inactive", func(t *testing.T) {
		c := setup(t)
		if ok, reason := c.CapabilityActive(context.Background(), tok); ok || reason != ReasonActivationUnconfirm {
			t.Fatalf("no pinger: got ok=%v reason=%q; want inactive/activation_unconfirmed", ok, reason)
		}
	})
}

// A positive CapabilityActive result is cached for capActivePosTTL: a second call within
// the window returns the cached positive WITHOUT re-sweeping every voting peer, so the
// post-latch HA monitor doesn't fan out a fresh capability sweep on every tick.
func TestCapabilityActive_PositiveCached(t *testing.T) {
	const tok = capabilities.SplitBrainGateV1
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker")
	gateHost(t, db, "host-b", "active", "worker")
	c := NewChecker("host-a", "/etc/litevirt/pki", db)

	var calls int
	c.SetPeerPinger(func(_ context.Context, _ string) ([]string, error) {
		calls++
		return []string{tok}, nil
	})

	if ok, _ := c.CapabilityActive(context.Background(), tok); !ok {
		t.Fatal("first call: want active")
	}
	first := calls
	if first == 0 {
		t.Fatal("first call must sweep peers")
	}
	if ok, _ := c.CapabilityActive(context.Background(), tok); !ok {
		t.Fatal("second call: want active")
	}
	if calls != first {
		t.Fatalf("second call re-swept peers (pinger calls %d→%d); want a cached positive with no fresh sweep", first, calls)
	}
}

// Enforced latches: once activation is confirmed cluster-wide it stays on even
// when a later fresh Ping can't confirm (a partition must fail closed, not revert
// to the legacy path).
func TestEnforced_Latches(t *testing.T) {
	const tok = capabilities.SplitBrainGateV1
	ctx := context.Background()
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker") // self
	gateHost(t, db, "host-b", "active", "worker")
	c := NewChecker("host-a", "/etc/litevirt/pki", db)

	supporting := true
	c.SetPeerPinger(func(_ context.Context, _ string) ([]string, error) {
		if supporting {
			return []string{tok}, nil
		}
		return nil, errors.New("partitioned")
	})

	if !c.Enforced(ctx, tok) {
		t.Fatal("all members advertise the token → Enforced must be true")
	}
	// Simulate a partition: peers unreachable → CapabilityActive would be false.
	supporting = false
	// Clear the cached positive so this exercises a FRESH sweep; the positive cache would
	// otherwise mask the partition for capActivePosTTL, which is orthogonal to the latch
	// under test.
	c.mu.Lock()
	c.capActivePos = map[string]time.Time{}
	c.mu.Unlock()
	if ok, _ := c.CapabilityActive(ctx, tok); ok {
		t.Fatal("precondition: CapabilityActive should now be false (partition)")
	}
	if !c.Enforced(ctx, tok) {
		t.Fatal("Enforced must LATCH on through a partition (fail closed), not revert to legacy")
	}
}

// A persisted activation marker keeps enforcement on across a restart (so a
// restart mid-partition can't re-open the legacy path). Markers are PER TOKEN:
// base + "." + token, so latches don't conflate across features.
func TestEnforced_MarkerPersists(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir() + "/split_brain_activated"
	// Write only the split_brain_gate_v1 marker.
	if err := os.WriteFile(base+"."+capabilities.SplitBrainGateV1, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewChecker("host-a", "/etc/litevirt/pki", testCheckHostDB(t))
	c.SetActivationMarker(base) // simulates a restart that loads the latch
	if !c.Enforced(ctx, capabilities.SplitBrainGateV1) {
		t.Fatal("a persisted activation marker must keep enforcement latched on after restart")
	}
	// A DIFFERENT token has no marker → not latched (no PeerPinger → CapabilityActive
	// false), proving the latch is per-token, not a shared global flag.
	if c.Enforced(ctx, capabilities.VIPDemoteV1) {
		t.Fatal("a different token must NOT be latched by the split_brain_gate_v1 marker")
	}
}

func TestPeerSupports(t *testing.T) {
	const tok = capabilities.SplitBrainGateV1
	ctx := context.Background()

	t.Run("supporting peer -> true, and caches", func(t *testing.T) {
		c := NewChecker("host-a", "/etc/litevirt/pki", testCheckHostDB(t))
		var pings int
		c.SetPeerPinger(func(_ context.Context, _ string) ([]string, error) {
			pings++
			return []string{tok}, nil
		})
		if !c.PeerSupports(ctx, "host-b", tok) {
			t.Fatal("host-b advertises the token; want supported")
		}
		if c.PeerSupports(ctx, "host-b", tok); pings != 1 {
			t.Fatalf("second call pinged again (pings=%d); want cached (1)", pings)
		}
	})

	t.Run("non-supporting / unreachable / no pinger -> false", func(t *testing.T) {
		c := NewChecker("host-a", "/etc/litevirt/pki", testCheckHostDB(t))
		if c.PeerSupports(ctx, "host-b", tok) {
			t.Fatal("no pinger: must be false (fail-closed)")
		}
		c.SetPeerPinger(func(_ context.Context, host string) ([]string, error) {
			if host == "down" {
				return nil, errors.New("timeout")
			}
			return []string{}, nil // advertises nothing
		})
		if c.PeerSupports(ctx, "host-b", tok) {
			t.Fatal("peer advertises nothing: want false")
		}
		if c.PeerSupports(ctx, "down", tok) {
			t.Fatal("unreachable peer: want false (fail-closed)")
		}
	})
}

// PeerSupportsFresh must bypass a cached POSITIVE: a peer that advertised the token
// (cached), then was downgraded/de-advertised within peerCapTTL, must be caught by
// the fresh mint-site check even while cached PeerSupports still returns the stale
// positive. This is the regression the proof-mint destination check exists to close.
func TestPeerSupportsFresh_BypassesStalePositive(t *testing.T) {
	const tok = capabilities.SplitBrainGateV1
	ctx := context.Background()
	c := NewChecker("host-a", "/etc/litevirt/pki", testCheckHostDB(t))

	advertises := true
	c.SetPeerPinger(func(_ context.Context, _ string) ([]string, error) {
		if advertises {
			return []string{tok}, nil
		}
		return []string{}, nil // downgraded: advertises nothing
	})

	// Seed a positive into the cache.
	if !c.PeerSupports(ctx, "host-b", tok) {
		t.Fatal("precondition: host-b advertises the token")
	}
	// Peer regresses within the cache TTL.
	advertises = false

	// Cached PeerSupports still returns the STALE positive (this is why it's unsafe
	// for mint sites).
	if !c.PeerSupports(ctx, "host-b", tok) {
		t.Fatal("precondition: cached PeerSupports should still return the stale positive within TTL")
	}
	// The mint-site fresh check catches the regression immediately.
	if c.PeerSupportsFresh(ctx, "host-b", tok) {
		t.Fatal("PeerSupportsFresh must re-Ping and see the downgrade — a regressed target must be refused a proof")
	}
	// And the fresh Ping refreshed the cache, so subsequent cached reads also flip.
	if c.PeerSupports(ctx, "host-b", tok) {
		t.Fatal("after PeerSupportsFresh, the cache should reflect the downgrade too")
	}
}
