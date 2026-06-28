package grpcapi

import (
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestVmStateToPB(t *testing.T) {
	tests := []struct {
		input string
		want  pb.VMState
	}{
		{"creating", pb.VMState_VM_CREATING},
		{"starting", pb.VMState_VM_STARTING},
		{"running", pb.VMState_VM_RUNNING},
		{"stopping", pb.VMState_VM_STOPPING},
		{"stopped", pb.VMState_VM_STOPPED},
		{"migrating", pb.VMState_VM_MIGRATING},
		{"error", pb.VMState_VM_ERROR},
		{"unknown", pb.VMState_VM_UNKNOWN},
		{"", pb.VMState_VM_UNKNOWN},
		{"garbage", pb.VMState_VM_UNKNOWN},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := vmStateToPB(tt.input)
			if got != tt.want {
				t.Errorf("vmStateToPB(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestHostStateToPB(t *testing.T) {
	tests := []struct {
		input string
		want  pb.HostState
	}{
		{"active", pb.HostState_HOST_ACTIVE},
		{"draining", pb.HostState_HOST_DRAINING},
		{"maintenance", pb.HostState_HOST_MAINTENANCE},
		{"suspect", pb.HostState_HOST_SUSPECT},
		{"offline", pb.HostState_HOST_OFFLINE},
		{"fenced", pb.HostState_HOST_OFFLINE},     // fenced ⇒ down, never ACTIVE
		{"upgrading", pb.HostState_HOST_DRAINING}, // transient, never ACTIVE
		{"", pb.HostState_HOST_OFFLINE},           // default fails safe (not ACTIVE)
		{"unknown", pb.HostState_HOST_OFFLINE},    // default fails safe (not ACTIVE)
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := hostStateToPB(tt.input)
			if got != tt.want {
				t.Errorf("hostStateToPB(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseTimestamp_Empty(t *testing.T) {
	ts := parseTimestamp("")
	if ts != nil {
		t.Errorf("parseTimestamp('') should return nil, got %v", ts)
	}
}

func TestParseTimestamp_NonEmpty(t *testing.T) {
	ts := parseTimestamp("2024-01-01T00:00:00Z")
	if ts == nil {
		t.Fatal("parseTimestamp returned nil for valid RFC3339 input")
	}
	want := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := ts.AsTime(); !got.Equal(want) {
		t.Errorf("parseTimestamp = %v, want %v", got, want)
	}
}

func TestGenerateMAC_Format(t *testing.T) {
	mac := GenerateMAC()
	// Verify format: 52:54:00:XX:XX:XX with random bytes.
	if len(mac) != 17 || mac[:9] != "52:54:00:" {
		t.Errorf("unexpected MAC format: %s", mac)
	}
	// Verify randomness: two calls should (almost certainly) differ.
	mac2 := GenerateMAC()
	if mac == mac2 {
		t.Errorf("GenerateMAC returned identical MACs: %s", mac)
	}
}
