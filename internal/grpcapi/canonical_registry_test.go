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
