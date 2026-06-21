package network

import (
	"errors"
	"testing"
)

func TestEnsureVXLAN_NewInterface(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	bridge, err := EnsureVXLAN(100, "eth0", "10.0.0.1")
	if err != nil {
		t.Fatalf("EnsureVXLAN returned error: %v", err)
	}
	if bridge != "br-vni100" {
		t.Errorf("expected bridge br-vni100, got %s", bridge)
	}
	if len(calls) != 5 {
		t.Fatalf("expected 5 commands, got %d: %v", len(calls), calls)
	}

	// Verify commands in order
	expected := [][]string{
		{"ip", "link", "add", "vxlan100", "type", "vxlan", "id", "100", "dstport", "4789", "local", "10.0.0.1", "dev", "eth0", "nolearning"},
		{"ip", "link", "add", "br-vni100", "type", "bridge"},
		{"ip", "link", "set", "vxlan100", "master", "br-vni100"},
		{"ip", "link", "set", "vxlan100", "up"},
		{"ip", "link", "set", "br-vni100", "up"},
	}
	for i, exp := range expected {
		if len(calls[i]) != len(exp) {
			t.Errorf("call %d: expected %v, got %v", i, exp, calls[i])
			continue
		}
		for j, arg := range exp {
			if calls[i][j] != arg {
				t.Errorf("call %d arg %d: expected %q, got %q", i, j, arg, calls[i][j])
			}
		}
	}
}

func TestEnsureVXLAN_Idempotent(t *testing.T) {
	callCount := 0
	execCommand = func(name string, args ...string) ([]byte, error) {
		callCount++
		// First call (ip link add vxlan) returns "File exists"
		if callCount == 1 {
			return []byte("RTNETLINK answers: File exists\n"), errors.New("exit status 2")
		}
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	bridge, err := EnsureVXLAN(200, "eth0", "10.0.0.2")
	if err != nil {
		t.Fatalf("EnsureVXLAN returned error for File exists: %v", err)
	}
	if bridge != "br-vni200" {
		t.Errorf("expected br-vni200, got %s", bridge)
	}
}

func TestVXLANBridgeName(t *testing.T) {
	tests := []struct {
		vni  int
		want string
	}{
		{100, "br-vni100"},
		{1, "br-vni1"},
		{4094, "br-vni4094"},
	}
	for _, tt := range tests {
		got := vxlanBridgeName(tt.vni)
		if got != tt.want {
			t.Errorf("vxlanBridgeName(%d) = %q, want %q", tt.vni, got, tt.want)
		}
	}
}

func TestDeprovisionVXLAN(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := DeprovisionVXLAN(300)
	if err != nil {
		t.Fatalf("DeprovisionVXLAN returned error: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(calls))
	}

	// First: del bridge
	if calls[0][3] != "br-vni300" {
		t.Errorf("expected del br-vni300, got %v", calls[0])
	}
	// Second: del vxlan
	if calls[1][3] != "vxlan300" {
		t.Errorf("expected del vxlan300, got %v", calls[1])
	}
}
