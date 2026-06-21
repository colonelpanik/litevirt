package libvirt

import (
	"fmt"
	"strings"
	"testing"
)

// fakeVirshDumpXML returns a minimal domain XML with a single interface whose
// MAC matches mac and whose tap target device is tapDev.
func fakeVirshDumpXML(mac, tapDev string) []byte {
	return []byte(fmt.Sprintf(`<domain>
  <devices>
    <interface type='bridge'>
      <mac address='%s'/>
      <target dev='%s'/>
    </interface>
  </devices>
</domain>`, mac, tapDev))
}

func TestConfigureVLANTap_callsBridgeVlanAdd(t *testing.T) {
	const (
		domain = "testvm"
		mac    = "52:54:00:aa:bb:cc"
		tapDev = "vnet0"
		vlanID = 42
	)

	// findTapDevice uses go-libvirt (requires live connection), so we test
	// the bridge VLAN logic directly via configureAccessBridgeVLAN with a
	// fake execVLAN. The XML parsing logic is tested in vlan_parse_test.go.

	var recorded [][]string

	// Override execVLAN to capture bridge vlan add calls.
	orig := execVLAN
	defer func() { execVLAN = orig }()

	execVLAN = func(name string, args ...string) ([]byte, error) {
		recorded = append(recorded, append([]string{name}, args...))
		return nil, nil
	}

	// Call the internal bridge-add logic directly by bypassing findTapDevice.
	// We test configureTrunkBridgeVLANs which is the core of ConfigureTrunkTap.
	vlanIDs := []int{10, 20, 30}
	if err := configureTrunkBridgeVLANs(tapDev, vlanIDs); err != nil {
		t.Fatalf("configureTrunkBridgeVLANs: %v", err)
	}

	if len(recorded) != len(vlanIDs) {
		t.Fatalf("expected %d bridge calls, got %d", len(vlanIDs), len(recorded))
	}

	for i, vid := range vlanIDs {
		call := recorded[i]
		if call[0] != "bridge" {
			t.Errorf("call %d: expected binary 'bridge', got %q", i, call[0])
		}
		vidStr := fmt.Sprintf("%d", vid)
		found := false
		for _, arg := range call {
			if arg == vidStr {
				found = true
			}
		}
		if !found {
			t.Errorf("call %d: VID %d not found in args %v", i, vid, call)
		}
		// Trunk mode must NOT include pvid or untagged flags.
		for _, arg := range call {
			if strings.EqualFold(arg, "pvid") || strings.EqualFold(arg, "untagged") {
				t.Errorf("call %d: trunk mode should not have %q flag, args: %v", i, arg, call)
			}
		}
	}
	_ = domain
	_ = mac
	_ = vlanID
}

func TestConfigureVLANTap_pvid_untagged(t *testing.T) {
	const tapDev = "vnet1"

	var recorded [][]string
	orig := execVLAN
	defer func() { execVLAN = orig }()
	execVLAN = func(name string, args ...string) ([]byte, error) {
		recorded = append(recorded, append([]string{name}, args...))
		return nil, nil
	}

	if err := configureAccessBridgeVLAN(tapDev, 100); err != nil {
		t.Fatalf("configureAccessBridgeVLAN: %v", err)
	}

	if len(recorded) != 1 {
		t.Fatalf("expected 1 bridge call, got %d", len(recorded))
	}

	call := recorded[0]
	hasPVID := false
	hasUntagged := false
	for _, arg := range call {
		if arg == "pvid" {
			hasPVID = true
		}
		if arg == "untagged" {
			hasUntagged = true
		}
	}
	if !hasPVID {
		t.Errorf("access mode should have pvid flag; args: %v", call)
	}
	if !hasUntagged {
		t.Errorf("access mode should have untagged flag; args: %v", call)
	}
}

func TestConfigureTrunkTap_emptyVlanIDs(t *testing.T) {
	var called int
	orig := execVLAN
	defer func() { execVLAN = orig }()
	execVLAN = func(name string, args ...string) ([]byte, error) {
		called++
		return nil, nil
	}

	if err := configureTrunkBridgeVLANs("vnet2", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called != 0 {
		t.Errorf("expected no bridge calls for empty vlanIDs, got %d", called)
	}
}
