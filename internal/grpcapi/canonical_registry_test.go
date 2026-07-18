package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestCanonicalRegistry_AdvertiseAndTokenEnabled: canonical_registry_v1 is advertised (and
// tokenEnabled — the predicate driveCapabilityActivation uses to flip the durable latch) ONLY when
// the node is config-enforcing. Latching accepts replicated canonical writes (mutating shared
// state), so it must require CONFIG uniformity: a not-yet-opted-in node withholds advertisement and
// stops the latch.
func TestCanonicalRegistry_AdvertiseAndTokenEnabled(t *testing.T) {
	off := testServer(t) // enfCanonicalRegistry defaults false
	if hasCap(off.advertisedCapabilities(), capabilities.CanonicalRegistryV1) {
		t.Fatal("canonical_registry_v1 must NOT be advertised when config-off")
	}
	if off.tokenEnabled(capabilities.CanonicalRegistryV1) {
		t.Fatal("tokenEnabled(canonical_registry_v1) must be false when config-off (latch not driven)")
	}

	on := testServer(t)
	on.SetCanonicalRegistryEnforce(true)
	if !hasCap(on.advertisedCapabilities(), capabilities.CanonicalRegistryV1) {
		t.Fatal("canonical_registry_v1 must be advertised when config-on")
	}
	if !on.tokenEnabled(capabilities.CanonicalRegistryV1) {
		t.Fatal("tokenEnabled(canonical_registry_v1) must be true when config-on (drives the latch)")
	}

	if !hasCap(capabilities.Supported(), capabilities.CanonicalRegistryV1) {
		t.Fatal("advertisedCapabilities filtering corrupted the shared Supported() slice")
	}
}

// TestCanonicalRegistryActive_AdvertiseGatedOnReadiness: the phase-2 token
// canonical_registry_active_v1 is advertised (and tokenEnabled) ONLY when the node is
// config-enforcing AND locally writer-ready — so it latches only when every node has consolidated,
// the machine check that switches the writer.
func TestCanonicalRegistryActive_AdvertiseGatedOnReadiness(t *testing.T) {
	s := testServer(t)
	s.SetCanonicalRegistryEnforce(true)
	// Config-on but not yet writer-ready (no readiness hook) ⇒ NOT advertised.
	if hasCap(s.advertisedCapabilities(), capabilities.CanonicalRegistryActiveV1) {
		t.Fatal("phase-2 token must not be advertised before writer-ready")
	}
	if s.tokenEnabled(capabilities.CanonicalRegistryActiveV1) {
		t.Fatal("tokenEnabled(active) must be false before writer-ready")
	}
	// Writer-ready ⇒ advertised + tokenEnabled (latch driven).
	s.SetRegistryLocallyReady(func() bool { return true })
	if !hasCap(s.advertisedCapabilities(), capabilities.CanonicalRegistryActiveV1) {
		t.Fatal("phase-2 token must be advertised once writer-ready")
	}
	if !s.tokenEnabled(capabilities.CanonicalRegistryActiveV1) {
		t.Fatal("tokenEnabled(active) must be true once writer-ready")
	}
	// Writer-ready but the phase-1 flag is off ⇒ NOT advertised (phase 2 requires phase 1).
	off := testServer(t)
	off.SetRegistryLocallyReady(func() bool { return true })
	if hasCap(off.advertisedCapabilities(), capabilities.CanonicalRegistryActiveV1) {
		t.Fatal("phase-2 token requires enforcement.canonical_registry")
	}
}
