package network

import (
	"strings"
	"testing"
)

func TestIsolationChainName(t *testing.T) {
	if got := isolationChainName("br0"); got != "iso-br0" {
		t.Errorf("isolationChainName(br0) = %q, want iso-br0", got)
	}
	if got := isolationChainName("br-vni1000"); got != "iso-br-vni1000" {
		t.Errorf("isolationChainName(br-vni1000) = %q, want iso-br-vni1000", got)
	}
}

func TestSnatChainName(t *testing.T) {
	if got := snatChainName("br0"); got != "snat-br0" {
		t.Errorf("snatChainName(br0) = %q, want snat-br0", got)
	}
}

func TestEnsureHostIsolation_NoExceptions(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := EnsureHostIsolation("br-vni100", nil)
	if err != nil {
		t.Fatalf("EnsureHostIsolation: %v", err)
	}

	// Should have: add table, add chain, flush, add drop rule = at least 4 calls.
	if len(calls) < 4 {
		t.Fatalf("expected at least 4 calls, got %d: %v", len(calls), calls)
	}

	// Verify chain is on input hook.
	foundInput := false
	for _, call := range calls {
		for _, a := range call {
			if strings.Contains(a, "hook input") {
				foundInput = true
			}
		}
	}
	if !foundInput {
		t.Errorf("isolation chain should use input hook, calls: %v", calls)
	}

	// Verify final drop rule.
	lastCall := calls[len(calls)-1]
	if lastCall[len(lastCall)-1] != "drop" {
		t.Errorf("last rule should be drop, got: %v", lastCall)
	}

	// Verify bridge name in drop rule.
	foundBridge := false
	for _, a := range lastCall {
		if a == "br-vni100" {
			foundBridge = true
		}
	}
	if !foundBridge {
		t.Errorf("drop rule should reference bridge, got: %v", lastCall)
	}

	// No VRRP or VIP rules without exceptions.
	for _, call := range calls {
		for _, a := range call {
			if a == "112" || strings.Contains(a, "daddr") {
				t.Errorf("no VRRP/VIP rules expected without exceptions, got: %v", call)
			}
		}
	}
}

func TestEnsureHostIsolation_WithLBExceptions(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	exc := []IsolationLBException{
		{VIP: "10.100.0.50", Ports: []int{80, 443}},
	}
	err := EnsureHostIsolation("br-vni100", exc)
	if err != nil {
		t.Fatalf("EnsureHostIsolation with exceptions: %v", err)
	}

	// Should have: add table, add chain, flush, VRRP rule, 2 VIP rules, drop rule = 7 calls.
	if len(calls) < 7 {
		t.Fatalf("expected at least 7 calls, got %d: %v", len(calls), calls)
	}

	// Verify VRRP rule (IP protocol 112).
	foundVRRP := false
	for _, call := range calls {
		for _, a := range call {
			if a == "112" {
				foundVRRP = true
			}
		}
	}
	if !foundVRRP {
		t.Error("expected VRRP rule (protocol 112) with LB exceptions")
	}

	// Verify VIP accept rules for both ports.
	foundPort80 := false
	foundPort443 := false
	for _, call := range calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "10.100.0.50") && strings.Contains(joined, "80") && strings.Contains(joined, "accept") {
			foundPort80 = true
		}
		if strings.Contains(joined, "10.100.0.50") && strings.Contains(joined, "443") && strings.Contains(joined, "accept") {
			foundPort443 = true
		}
	}
	if !foundPort80 {
		t.Error("expected VIP accept rule for port 80")
	}
	if !foundPort443 {
		t.Error("expected VIP accept rule for port 443")
	}

	// Last call should still be drop.
	lastCall := calls[len(calls)-1]
	if lastCall[len(lastCall)-1] != "drop" {
		t.Errorf("last rule should be drop, got: %v", lastCall)
	}
}

func TestEnsureHostIsolation_Idempotent(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	// Calling twice should not error.
	if err := EnsureHostIsolation("br0", nil); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := EnsureHostIsolation("br0", nil); err != nil {
		t.Fatalf("second call: %v", err)
	}
}

func TestRemoveHostIsolation(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := RemoveHostIsolation("br-vni100")
	if err != nil {
		t.Fatalf("RemoveHostIsolation: %v", err)
	}

	// Should have flush + delete = 2 calls.
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %v", len(calls), calls)
	}

	// First call: flush.
	if calls[0][1] != "flush" {
		t.Errorf("expected flush, got: %v", calls[0])
	}

	// Second call: delete.
	if calls[1][1] != "delete" {
		t.Errorf("expected delete, got: %v", calls[1])
	}

	// Verify chain name.
	foundChain := false
	for _, a := range calls[1] {
		if a == "iso-br-vni100" {
			foundChain = true
		}
	}
	if !foundChain {
		t.Errorf("expected chain name iso-br-vni100 in delete call: %v", calls[1])
	}
}

func TestRemoveHostIsolation_NoSuchChain(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		// Simulate "No such" error on delete.
		for _, a := range args {
			if a == "delete" {
				return []byte("Error: No such chain"), &execError{}
			}
		}
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	// Should not return error for missing chain.
	if err := RemoveHostIsolation("br-nonexistent"); err != nil {
		t.Fatalf("RemoveHostIsolation should ignore missing chain: %v", err)
	}
}

func TestEnsureSNAT(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := EnsureSNAT("br-vni100", "10.100.0.0/24", "192.168.1.50", "ens18")
	if err != nil {
		t.Fatalf("EnsureSNAT: %v", err)
	}

	// Should have: add table, add chain, flush, sysctl, snat rule = 5 calls.
	if len(calls) < 5 {
		t.Fatalf("expected at least 5 calls, got %d: %v", len(calls), calls)
	}

	// Verify chain is on nat postrouting hook.
	foundNat := false
	for _, call := range calls {
		for _, a := range call {
			if strings.Contains(a, "hook postrouting") {
				foundNat = true
			}
		}
	}
	if !foundNat {
		t.Error("SNAT chain should use nat postrouting hook")
	}

	// Verify SNAT rule contains VIP.
	foundSNAT := false
	for _, call := range calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "snat") && strings.Contains(joined, "192.168.1.50") &&
			strings.Contains(joined, "10.100.0.0/24") && strings.Contains(joined, "ens18") {
			foundSNAT = true
		}
	}
	if !foundSNAT {
		t.Error("expected SNAT rule with VIP, subnet, and outIface")
	}

	// Verify IP forwarding is enabled.
	foundSysctl := false
	for _, call := range calls {
		if call[0] == "sysctl" {
			foundSysctl = true
		}
	}
	if !foundSysctl {
		t.Error("expected sysctl call to enable IP forwarding")
	}
}

func TestRemoveSNAT(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := RemoveSNAT("br-vni100")
	if err != nil {
		t.Fatalf("RemoveSNAT: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %v", len(calls), calls)
	}

	// Verify chain name.
	foundChain := false
	for _, a := range calls[1] {
		if a == "snat-br-vni100" {
			foundChain = true
		}
	}
	if !foundChain {
		t.Errorf("expected chain name snat-br-vni100 in delete call: %v", calls[1])
	}
}

func TestRemoveSNAT_NoSuchChain(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		for _, a := range args {
			if a == "delete" {
				return []byte("Error: No such chain"), &execError{}
			}
		}
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	if err := RemoveSNAT("br-nonexistent"); err != nil {
		t.Fatalf("RemoveSNAT should ignore missing chain: %v", err)
	}
}

func TestEnsureHostIsolation_MultipleExceptions(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	exc := []IsolationLBException{
		{VIP: "10.0.0.50", Ports: []int{80}},
		{VIP: "10.0.0.51", Ports: []int{443, 8080}},
	}
	err := EnsureHostIsolation("br0", exc)
	if err != nil {
		t.Fatalf("EnsureHostIsolation multiple exceptions: %v", err)
	}

	// Count VIP accept rules: 1 (port 80) + 2 (ports 443, 8080) = 3.
	vipRules := 0
	for _, call := range calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "daddr") && strings.Contains(joined, "accept") {
			vipRules++
		}
	}
	if vipRules != 3 {
		t.Errorf("expected 3 VIP accept rules, got %d", vipRules)
	}
}

// execError implements the error interface for test mocking.
type execError struct{}

func (e *execError) Error() string { return "exec error" }
