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
	if hasCap(caps, capabilities.CapacityAdmissionV1) {
		t.Fatal("capacity_admission_v1 must NOT be advertised when operation protocol is config-off")
	}
	if !hasCap(caps, capabilities.SplitBrainGateV1) {
		t.Fatal("build-static tokens must still be advertised")
	}

	on := testServer(t)
	on.SetOperationProtocol(true)
	if !hasCap(on.advertisedCapabilities(), capabilities.OperationProtocolV1) {
		t.Fatal("operation_protocol_v1 must be advertised when config-on")
	}
	if !hasCap(on.advertisedCapabilities(), capabilities.CapacityAdmissionV1) {
		t.Fatal("capacity_admission_v1 must be advertised when operation protocol is config-on")
	}

	// Filtering must never mutate the shared build-static Supported() slice.
	if !hasCap(capabilities.Supported(), capabilities.OperationProtocolV1) {
		t.Fatal("advertisedCapabilities filtering corrupted the shared Supported() slice")
	}
	if !hasCap(capabilities.Supported(), capabilities.CapacityAdmissionV1) {
		t.Fatal("advertisedCapabilities filtering corrupted capacity admission in Supported()")
	}
}

func TestCapacityAdmissionLatched_RequiresConfigAndBothCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		configOn bool
		latched  map[string]bool
		want     bool
	}{
		{name: "config off despite both", latched: map[string]bool{
			capabilities.OperationProtocolV1: true,
			capabilities.CapacityAdmissionV1: true,
		}},
		{name: "nil gate", configOn: true},
		{name: "operation protocol absent", configOn: true, latched: map[string]bool{
			capabilities.CapacityAdmissionV1: true,
		}},
		{name: "capacity admission absent", configOn: true, latched: map[string]bool{
			capabilities.OperationProtocolV1: true,
		}},
		{name: "both latched", configOn: true, want: true, latched: map[string]bool{
			capabilities.OperationProtocolV1: true,
			capabilities.CapacityAdmissionV1: true,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			s.SetOperationProtocol(tc.configOn)
			if tc.latched != nil {
				s.gate = fakeServerGate{enforcedTok: tc.latched}
			}
			if got := s.capacityAdmissionLatched(); got != tc.want {
				t.Fatalf("capacityAdmissionLatched() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCapacityAdmissionTokenEnabledWithOperationProtocol(t *testing.T) {
	off := testServer(t)
	if off.tokenEnabled(capabilities.CapacityAdmissionV1) {
		t.Fatal("capacity admission latch driver must be disabled when operation protocol is off")
	}
	on := testServer(t)
	on.SetOperationProtocol(true)
	if !on.tokenEnabled(capabilities.CapacityAdmissionV1) {
		t.Fatal("capacity admission latch driver must be enabled when operation protocol is on")
	}
}
