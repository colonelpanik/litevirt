package capabilities

import (
	"slices"
	"testing"
)

// TestHardwareV2Registered proves the hardware_v2 token is registered in both the
// full known-token set (All) and this build's advertised set (Supported), so peers
// see it via Ping.Capabilities and the latch machinery can reference it by name.
func TestHardwareV2Registered(t *testing.T) {
	if HardwareV2 != "hardware_v2" {
		t.Fatalf("HardwareV2 = %q, want %q", HardwareV2, "hardware_v2")
	}
	if !slices.Contains(Supported(), HardwareV2) {
		t.Fatalf("Supported() = %v, want it to contain %q", Supported(), HardwareV2)
	}
	if !slices.Contains(All(), HardwareV2) {
		t.Fatalf("All() = %v, want it to contain %q", All(), HardwareV2)
	}
}

// TestAuditSignatureV1Registered pins the audit_signature_v1 token in both sets.
// Supported() is what peers see via Ping, so the cluster can never latch a token
// missing from it; All() is what health.SetActivationMarker walks to preload the
// durable latch markers and what daemon rollback detection diffs against, so a
// token absent there loses its latch across a restart.
func TestAuditSignatureV1Registered(t *testing.T) {
	if AuditSignatureV1 != "audit_signature_v1" {
		t.Fatalf("AuditSignatureV1 = %q, want %q", AuditSignatureV1, "audit_signature_v1")
	}
	if !slices.Contains(Supported(), AuditSignatureV1) {
		t.Fatalf("Supported() = %v, want it to contain %q", Supported(), AuditSignatureV1)
	}
	if !slices.Contains(All(), AuditSignatureV1) {
		t.Fatalf("All() = %v, want it to contain %q", All(), AuditSignatureV1)
	}
}

func TestCapacityAdmissionV1Registered(t *testing.T) {
	if CapacityAdmissionV1 != "capacity_admission_v1" {
		t.Fatalf("CapacityAdmissionV1 = %q, want %q", CapacityAdmissionV1, "capacity_admission_v1")
	}
	if !slices.Contains(Supported(), CapacityAdmissionV1) {
		t.Fatalf("Supported() = %v, want it to contain %q", Supported(), CapacityAdmissionV1)
	}
	if !slices.Contains(All(), CapacityAdmissionV1) {
		t.Fatalf("All() = %v, want it to contain %q", All(), CapacityAdmissionV1)
	}
}
