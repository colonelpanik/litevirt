package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestCanonicalIdentity_AdvertiseAndTokenEnabled: canonical_identity_v1 is advertised (and
// tokenEnabled — the predicate driveCapabilityActivation uses to flip the durable latch) ONLY
// when the node is config-enforcing. Identity resolution mutates shared state, so the cluster-wide
// latch must require CONFIG uniformity: a not-yet-opted-in node withholds advertisement and stops
// the latch. Without tokenEnabled the latch would never be driven and the daemon predicate
// (flag AND Latched) could never activate in production.
func TestCanonicalIdentity_AdvertiseAndTokenEnabled(t *testing.T) {
	off := testServer(t) // enfCanonicalIdentity defaults false
	if hasCap(off.advertisedCapabilities(), capabilities.CanonicalIdentityV1) {
		t.Fatal("canonical_identity_v1 must NOT be advertised when config-off")
	}
	if off.tokenEnabled(capabilities.CanonicalIdentityV1) {
		t.Fatal("tokenEnabled(canonical_identity_v1) must be false when config-off (latch not driven)")
	}

	on := testServer(t)
	on.SetCanonicalIdentityEnforce(true)
	if !hasCap(on.advertisedCapabilities(), capabilities.CanonicalIdentityV1) {
		t.Fatal("canonical_identity_v1 must be advertised when config-on")
	}
	if !on.tokenEnabled(capabilities.CanonicalIdentityV1) {
		t.Fatal("tokenEnabled(canonical_identity_v1) must be true when config-on (drives the latch)")
	}

	// Filtering must never mutate the shared build-static Supported() slice.
	if !hasCap(capabilities.Supported(), capabilities.CanonicalIdentityV1) {
		t.Fatal("advertisedCapabilities filtering corrupted the shared Supported() slice")
	}
}
