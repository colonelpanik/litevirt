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
