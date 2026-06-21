package network

import (
	"errors"
	"testing"
)

func TestGatewayForSubnet(t *testing.T) {
	tests := []struct {
		cidr string
		want string
	}{
		{"10.100.0.0/24", "10.100.0.1/24"},
		{"192.168.1.0/24", "192.168.1.1/24"},
		{"10.0.0.0/8", "10.0.0.1/8"},
		{"172.16.0.0/16", "172.16.0.1/16"},
	}
	for _, tt := range tests {
		got, err := gatewayForSubnet(tt.cidr)
		if err != nil {
			t.Errorf("gatewayForSubnet(%q): unexpected error: %v", tt.cidr, err)
			continue
		}
		if got != tt.want {
			t.Errorf("gatewayForSubnet(%q) = %q, want %q", tt.cidr, got, tt.want)
		}
	}
}

func TestGatewayForSubnet_Invalid(t *testing.T) {
	cases := []string{
		"not-a-cidr",
		"256.0.0.0/24",
		"",
	}
	for _, cidr := range cases {
		_, err := gatewayForSubnet(cidr)
		if err == nil {
			t.Errorf("gatewayForSubnet(%q): expected error, got nil", cidr)
		}
	}
}

func TestEnsureIRB(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	gwIP, err := EnsureIRB(100, "10.100.0.0/24")
	if err != nil {
		t.Fatalf("EnsureIRB error: %v", err)
	}
	if gwIP != "10.100.0.1" {
		t.Errorf("expected gateway 10.100.0.1, got %s", gwIP)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 commands, got %d: %v", len(calls), calls)
	}

	// First: ip addr add
	if calls[0][0] != "ip" || calls[0][1] != "addr" || calls[0][2] != "add" {
		t.Errorf("first command should be ip addr add, got %v", calls[0])
	}
	if calls[0][3] != "10.100.0.1/24" {
		t.Errorf("expected 10.100.0.1/24, got %s", calls[0][3])
	}
	if calls[0][4] != "dev" || calls[0][5] != "br-vni100" {
		t.Errorf("expected dev br-vni100, got %v", calls[0][4:])
	}

	// Second: bridge link set neigh_suppress
	if calls[1][0] != "bridge" || calls[1][1] != "link" {
		t.Errorf("second command should be bridge link, got %v", calls[1])
	}
	found := false
	for _, a := range calls[1] {
		if a == "neigh_suppress" {
			found = true
		}
	}
	if !found {
		t.Errorf("second command missing neigh_suppress: %v", calls[1])
	}
}

func TestEnsureIRB_Idempotent(t *testing.T) {
	callCount := 0
	execCommand = func(name string, args ...string) ([]byte, error) {
		callCount++
		if callCount == 1 {
			// addr add returns File exists
			return []byte("RTNETLINK answers: File exists\n"), errors.New("exit status 2")
		}
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	_, err := EnsureIRB(200, "192.168.1.0/24")
	if err != nil {
		t.Fatalf("EnsureIRB should not error on File exists: %v", err)
	}
}

func TestRemoveIRB(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := RemoveIRB(300, "10.200.0.0/24")
	if err != nil {
		t.Fatalf("RemoveIRB error: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 command, got %d", len(calls))
	}
	if calls[0][0] != "ip" || calls[0][2] != "del" {
		t.Errorf("expected ip addr del, got %v", calls[0])
	}
	if calls[0][3] != "10.200.0.1/24" {
		t.Errorf("expected 10.200.0.1/24, got %s", calls[0][3])
	}
	if calls[0][5] != "br-vni300" {
		t.Errorf("expected br-vni300, got %s", calls[0][5])
	}
}
