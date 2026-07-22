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

// TestAdvertiseHardwareV2_GatedOnBackfillReadiness (CONTRACT h): a node with
// operation_protocol_v1 active must STILL withhold hardware_v2 from its advertised
// capabilities until BackfillHardwareTables has completed its audit pass (the
// hwV2Ready flag). Advertising earlier could let the fleet latch hardware_v2 — and
// stop legacy dual-writes / permit stopped mutations — before this node's typed
// tables are populated, so a peer could miss data.
func TestAdvertiseHardwareV2_GatedOnBackfillReadiness(t *testing.T) {
	s := testServer(t)
	s.gate = fakeServerGate{enforcedTok: map[string]bool{capabilities.OperationProtocolV1: true}}
	s.SetOperationProtocol(true)

	// Before backfill: op-protocol active but readiness unset → NOT advertised.
	if hasCap(s.advertisedCapabilities(), capabilities.HardwareV2) {
		t.Fatal("hardware_v2 must not be advertised before BackfillHardwareTables completes")
	}
	// Backfill (no owned VMs → the audit pass trivially completes) sets readiness.
	if err := s.BackfillHardwareTables(adminCtx()); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}
	if !hasCap(s.advertisedCapabilities(), capabilities.HardwareV2) {
		t.Fatal("hardware_v2 must be advertised once backfill completes with operation_protocol active")
	}
}

// TestAdvertiseHardwareV2_RequiresOperationProtocol: readiness alone is not enough —
// hardware_v2 hard-depends on operation_protocol_v1 (hardware mutations need the
// crash-safe operation journal). Advertisement is withheld while the op-protocol
// config kill-switch is off OR while op-protocol has not latched cluster-wide.
func TestAdvertiseHardwareV2_RequiresOperationProtocol(t *testing.T) {
	s := testServer(t)
	if err := s.BackfillHardwareTables(adminCtx()); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}

	// Readiness set, op-protocol LATCHED, but the config kill-switch is OFF.
	s.gate = fakeServerGate{enforcedTok: map[string]bool{capabilities.OperationProtocolV1: true}}
	if hasCap(s.advertisedCapabilities(), capabilities.HardwareV2) {
		t.Fatal("hardware_v2 must not be advertised while the operation_protocol config flag is off")
	}

	// Config on but op-protocol NOT latched cluster-wide.
	s.SetOperationProtocol(true)
	s.gate = fakeServerGate{enforcedTok: map[string]bool{capabilities.OperationProtocolV1: false}}
	if hasCap(s.advertisedCapabilities(), capabilities.HardwareV2) {
		t.Fatal("hardware_v2 must not be advertised while operation_protocol is not latched")
	}

	// Both on → advertised.
	s.gate = fakeServerGate{enforcedTok: map[string]bool{capabilities.OperationProtocolV1: true}}
	if !hasCap(s.advertisedCapabilities(), capabilities.HardwareV2) {
		t.Fatal("hardware_v2 must be advertised with readiness + operation_protocol active")
	}
}

// TestAdvertiseHardwareV2_NilGate: with a nil gate the op-protocol latch cannot be
// confirmed, so hardware_v2 advertisement fails closed even after backfill.
func TestAdvertiseHardwareV2_NilGate(t *testing.T) {
	s := testServer(t)
	if err := s.BackfillHardwareTables(adminCtx()); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}
	s.SetOperationProtocol(true) // gate stays nil
	if hasCap(s.advertisedCapabilities(), capabilities.HardwareV2) {
		t.Fatal("hardware_v2 must not be advertised with a nil gate (op-protocol unconfirmable)")
	}
}
