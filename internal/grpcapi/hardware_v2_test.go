package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestHardwareV2Latched_RequiresOperationProtocol: hardware_v2 depends on the
// crash-safe operation journal (operation_protocol_v1) as a hard prerequisite.
// Even when the hardware_v2 marker itself is latched cluster-wide,
// hardwareV2Latched must return false while operation_protocol_v1 is inactive —
// short-circuiting on the protocol check FIRST, regardless of the hardware
// marker's state.
func TestHardwareV2Latched_RequiresOperationProtocol(t *testing.T) {
	ctx := context.Background()

	s := &Server{
		hostName: "h",
		gate: fakeServerGate{
			enforcedTok: map[string]bool{
				capabilities.OperationProtocolV1: false, // NOT active
				capabilities.HardwareV2:          true,  // latched anyway
			},
		},
	}
	// enfOperationProtocol defaults false too (config kill-switch off), so this
	// also covers the "config off" half of operationProtocolActive's own gate.
	if s.hardwareV2Latched(ctx) {
		t.Fatal("hardwareV2Latched must be false when operation_protocol_v1 is inactive, even with hardware_v2 latched")
	}

	// Turning the config flag on alone (protocol still not cluster-latched, since
	// enforcedTok still says false) must not flip the result.
	s.SetOperationProtocol(true)
	if s.hardwareV2Latched(ctx) {
		t.Fatal("hardwareV2Latched must be false when operation_protocol_v1 is not cluster-latched")
	}
}

// TestHardwareV2Latched_BothActive: with operation_protocol_v1 active (config
// flag on AND cluster-latched) and hardware_v2 latched, hardwareV2Latched
// returns true.
func TestHardwareV2Latched_BothActive(t *testing.T) {
	ctx := context.Background()

	s := &Server{
		hostName: "h",
		gate: fakeServerGate{
			enforcedTok: map[string]bool{
				capabilities.OperationProtocolV1: true,
				capabilities.HardwareV2:          true,
			},
		},
	}
	s.SetOperationProtocol(true)

	if !s.hardwareV2Latched(ctx) {
		t.Fatal("hardwareV2Latched must be true when operation_protocol_v1 is active and hardware_v2 is latched")
	}
}

// TestHardwareV2Latched_ProtocolActiveButHardwareNot: operation_protocol_v1
// active is necessary but not sufficient — the hardware_v2 marker itself must
// also be latched.
func TestHardwareV2Latched_ProtocolActiveButHardwareNot(t *testing.T) {
	ctx := context.Background()

	s := &Server{
		hostName: "h",
		gate: fakeServerGate{
			enforcedTok: map[string]bool{
				capabilities.OperationProtocolV1: true,
				capabilities.HardwareV2:          false,
			},
		},
	}
	s.SetOperationProtocol(true)

	if s.hardwareV2Latched(ctx) {
		t.Fatal("hardwareV2Latched must be false when hardware_v2 itself is not latched")
	}
}

// TestHardwareV2Latched_NilGate: a nil gate must fail closed (matches the rest
// of the family's fail-closed-on-nil-gate posture).
func TestHardwareV2Latched_NilGate(t *testing.T) {
	s := &Server{hostName: "h"}
	s.SetOperationProtocol(true)
	if s.hardwareV2Latched(context.Background()) {
		t.Fatal("hardwareV2Latched must fail closed with a nil gate")
	}
}
