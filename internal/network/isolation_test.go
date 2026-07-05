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

func TestEnableIPForwarding(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	if err := EnableIPForwarding(); err != nil {
		t.Fatalf("EnableIPForwarding: %v", err)
	}
	if len(calls) != 1 || calls[0][0] != "sysctl" || calls[0][len(calls[0])-1] != "net.ipv4.ip_forward=1" {
		t.Errorf("expected one sysctl ip_forward=1 call, got: %v", calls)
	}
}

func TestRemoveHostIsolation(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	if err := RemoveHostIsolation("br-vni100"); err != nil {
		t.Fatalf("RemoveHostIsolation: %v", err)
	}
	// Should have flush + delete = 2 calls.
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %v", len(calls), calls)
	}
	if calls[0][1] != "flush" {
		t.Errorf("expected flush, got: %v", calls[0])
	}
	if calls[1][1] != "delete" {
		t.Errorf("expected delete, got: %v", calls[1])
	}
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
		for _, a := range args {
			if a == "delete" {
				return []byte("Error: No such chain"), &execError{}
			}
		}
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	if err := RemoveHostIsolation("br-nonexistent"); err != nil {
		t.Fatalf("RemoveHostIsolation should ignore missing chain: %v", err)
	}
}

func TestRemoveSNAT(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	if err := RemoveSNAT("br-vni100"); err != nil {
		t.Fatalf("RemoveSNAT: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %v", len(calls), calls)
	}
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

// TestRemoveLegacyBridgeFirewall covers the upgrade-migration cleanup: it clears
// the old iso + snat nft chains, and (only when a masquerade subnet is given) the
// iptables MASQUERADE rule too.
func TestRemoveLegacyBridgeFirewall(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	// Isolation-only bridge (no masquerade subnet): must NOT touch iptables.
	RemoveLegacyBridgeFirewall("br-iso", "")
	for _, c := range calls {
		if c[0] == "iptables" {
			t.Errorf("no iptables calls expected without a masquerade subnet, got: %v", c)
		}
	}
	sawIsoDelete, sawSnatDelete := false, false
	for _, c := range calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "delete") && strings.Contains(j, "iso-br-iso") {
			sawIsoDelete = true
		}
		if strings.Contains(j, "delete") && strings.Contains(j, "snat-br-iso") {
			sawSnatDelete = true
		}
	}
	if !sawIsoDelete || !sawSnatDelete {
		t.Errorf("expected old iso + snat chain deletes, got: %v", calls)
	}

	// Masquerade bridge: iptables MASQUERADE delete for the subnet.
	calls = nil
	RemoveLegacyBridgeFirewall("br-mgd", "10.0.1.0/24")
	sawMasq := false
	for _, c := range calls {
		j := strings.Join(c, " ")
		if c[0] == "iptables" && strings.Contains(j, "MASQUERADE") && strings.Contains(j, "10.0.1.0/24") {
			sawMasq = true
		}
	}
	if !sawMasq {
		t.Errorf("expected iptables MASQUERADE delete for the subnet, got: %v", calls)
	}
}

// execError implements the error interface for test mocking.
type execError struct{}

func (e *execError) Error() string { return "exec error" }
