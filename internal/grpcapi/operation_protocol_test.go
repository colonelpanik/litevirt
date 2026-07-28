package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func hasCap(caps []string, x string) bool {
	for _, c := range caps {
		if c == x {
			return true
		}
	}
	return false
}

// TestAdvertisedCapabilities_OperationProtocolConditional: operation_protocol_v1
// is advertised only when the node is config-enforcing, so the cluster-wide latch
// requires CONFIG uniformity (a not-yet-opted-in node stops the latch, keeping
// the barrier from being relied upon before every node enforces it). The
// build-static tokens are unaffected.
func TestAdvertisedCapabilities_OperationProtocolConditional(t *testing.T) {
	off := testServer(t) // enfOperationProtocol defaults false
	caps := off.advertisedCapabilities()
	if hasCap(caps, capabilities.OperationProtocolV1) {
		t.Fatal("operation_protocol_v1 must NOT be advertised when config-off")
	}
	if !hasCap(caps, capabilities.SplitBrainGateV1) {
		t.Fatal("build-static tokens must still be advertised")
	}

	on := testServer(t)
	on.SetOperationProtocol(true)
	if !hasCap(on.advertisedCapabilities(), capabilities.OperationProtocolV1) {
		t.Fatal("operation_protocol_v1 must be advertised when config-on")
	}

	// Filtering must never mutate the shared build-static Supported() slice.
	if !hasCap(capabilities.Supported(), capabilities.OperationProtocolV1) {
		t.Fatal("advertisedCapabilities filtering corrupted the shared Supported() slice")
	}
}
