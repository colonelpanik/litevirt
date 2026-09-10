package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestAdvertisedCapabilities_NetBoxIPAMConditional: netbox_ipam_v1 is advertised
// only when the node is config-enabled, so the cluster-wide latch requires CONFIG
// uniformity. An older binary does not parse the NetBoxPrefixID field on a network
// definition at all, and would silently allocate from the builtin allocator across
// the whole prefix — replicated state alone can't make a bound prefix safe, because
// every node observing the same bytes is not the same thing as every node
// INTERPRETING them the same way. The build-static tokens are unaffected.
func TestAdvertisedCapabilities_NetBoxIPAMConditional(t *testing.T) {
	off := testServer(t) // enfNetBoxIPAM defaults false
	if hasCap(off.advertisedCapabilities(), capabilities.NetBoxIPAMV1) {
		t.Fatal("netbox_ipam_v1 must NOT be advertised when config-off")
	}
	if !hasCap(off.advertisedCapabilities(), capabilities.SplitBrainGateV1) {
		t.Fatal("build-static tokens must still be advertised")
	}
	if off.tokenEnabled(capabilities.NetBoxIPAMV1) {
		t.Fatal("tokenEnabled(netbox_ipam_v1) must be false when config-off (latch not driven)")
	}

	on := testServer(t)
	on.SetNetBoxIPAM(true)
	if !hasCap(on.advertisedCapabilities(), capabilities.NetBoxIPAMV1) {
		t.Fatal("netbox_ipam_v1 must be advertised when config-on")
	}
	// tokenEnabled is the predicate driveCapabilityActivation uses to decide which
	// tokens to latch-drive. A token missing from its switch falls to `default:
	// return false`, so the latch is never driven at all and netboxIPAMActive
	// could never become true in production — silently, with every test above still
	// green.
	if !on.tokenEnabled(capabilities.NetBoxIPAMV1) {
		t.Fatal("tokenEnabled(netbox_ipam_v1) must be true when config-on (drives the latch)")
	}

	// Filtering must never mutate the shared build-static Supported() slice.
	if !hasCap(capabilities.Supported(), capabilities.NetBoxIPAMV1) {
		t.Fatal("advertisedCapabilities filtering corrupted the shared Supported() slice")
	}
}
