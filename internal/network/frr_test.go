package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderFRRConfig_TwoPeers(t *testing.T) {
	cfg := FRRConfig{
		RouterID: "10.0.0.1",
		LocalASN: 65000,
		Peers: []BGPPeer{
			{HostName: "host2", VTEPAddr: "10.0.0.2", ASN: 65000},
			{HostName: "host3", VTEPAddr: "10.0.0.3", ASN: 65000},
		},
	}

	out, err := RenderFRRConfig("host1", cfg)
	if err != nil {
		t.Fatalf("RenderFRRConfig error: %v", err)
	}
	if !strings.Contains(out, "router bgp 65000") {
		t.Errorf("missing router bgp 65000: %s", out)
	}
	if !strings.Contains(out, "bgp router-id 10.0.0.1") {
		t.Errorf("missing bgp router-id: %s", out)
	}
	if !strings.Contains(out, "neighbor 10.0.0.2 remote-as 65000") {
		t.Errorf("missing neighbor 10.0.0.2: %s", out)
	}
	if !strings.Contains(out, "neighbor 10.0.0.3 remote-as 65000") {
		t.Errorf("missing neighbor 10.0.0.3: %s", out)
	}
	if !strings.Contains(out, "address-family l2vpn evpn") {
		t.Errorf("missing address-family l2vpn evpn: %s", out)
	}
	if !strings.Contains(out, "advertise-all-vni") {
		t.Errorf("missing advertise-all-vni: %s", out)
	}
	if !strings.Contains(out, "hostname host1") {
		t.Errorf("missing hostname host1: %s", out)
	}
}

func TestRenderFRRConfig_NoPeers(t *testing.T) {
	cfg := FRRConfig{
		RouterID: "192.168.1.1",
		LocalASN: 65001,
		Peers:    nil,
	}

	out, err := RenderFRRConfig("solo", cfg)
	if err != nil {
		t.Fatalf("RenderFRRConfig error: %v", err)
	}
	if !strings.Contains(out, "router bgp 65001") {
		t.Errorf("missing router bgp 65001: %s", out)
	}
	if !strings.Contains(out, "hostname solo") {
		t.Errorf("missing hostname solo: %s", out)
	}
	if strings.Contains(out, "neighbor") {
		t.Errorf("should not have neighbor entries: %s", out)
	}
}

func TestWriteFRRConfig_NoFRR(t *testing.T) {
	origInstalled := frrInstalledFn
	frrInstalledFn = func() bool { return false }
	defer func() { frrInstalledFn = origInstalled }()

	// Should not write any file
	origPath := frrConfigPath
	frrConfigPath = "/nonexistent/frr.conf"
	defer func() { frrConfigPath = origPath }()

	err := WriteFRRConfig("host1", FRRConfig{RouterID: "1.2.3.4", LocalASN: 65000})
	if err != nil {
		t.Fatalf("WriteFRRConfig with no FRR should not error: %v", err)
	}

	// Verify file was not written
	if _, err := os.Stat("/nonexistent/frr.conf"); !os.IsNotExist(err) {
		t.Error("should not have written file when FRR not installed")
	}
}

func TestWriteFRRConfig_WritesFile(t *testing.T) {
	origInstalled := frrInstalledFn
	frrInstalledFn = func() bool { return true }
	defer func() { frrInstalledFn = origInstalled }()

	tmpDir := t.TempDir()
	origPath := frrConfigPath
	frrConfigPath = filepath.Join(tmpDir, "frr.conf")
	defer func() { frrConfigPath = origPath }()

	origReload := reloadFRRFn
	reloadFRRFn = func() error { return nil }
	defer func() { reloadFRRFn = origReload }()

	cfg := FRRConfig{
		RouterID: "10.1.1.1",
		LocalASN: 65000,
		Peers: []BGPPeer{
			{HostName: "peer1", VTEPAddr: "10.1.1.2", ASN: 65000},
		},
	}

	err := WriteFRRConfig("myhost", cfg)
	if err != nil {
		t.Fatalf("WriteFRRConfig error: %v", err)
	}

	content, err := os.ReadFile(frrConfigPath)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if !strings.Contains(string(content), "router bgp 65000") {
		t.Errorf("file missing router bgp: %s", content)
	}
	if !strings.Contains(string(content), "neighbor 10.1.1.2") {
		t.Errorf("file missing neighbor: %s", content)
	}
}
