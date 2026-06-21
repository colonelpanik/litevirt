package main

import "testing"

func TestParseCTNetworks(t *testing.T) {
	nics, err := parseCTNetworks([]string{
		"bridge=br0,name=eth0,ip=10.0.0.5/24,mac=aa:bb:cc:dd:ee:ff",
		"bridge=br1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nics) != 2 {
		t.Fatalf("want 2 NICs, got %d", len(nics))
	}
	if nics[0].Bridge != "br0" || nics[0].Name != "eth0" ||
		nics[0].Ip != "10.0.0.5/24" || nics[0].Mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("nic0 parsed wrong: %+v", nics[0])
	}
	if nics[1].Bridge != "br1" {
		t.Errorf("nic1 bridge wrong: %+v", nics[1])
	}

	// bridge is required
	if _, err := parseCTNetworks([]string{"name=eth0"}); err == nil {
		t.Error("expected error when bridge is missing")
	}
	// unknown key rejected
	if _, err := parseCTNetworks([]string{"bridge=br0,foo=bar"}); err == nil {
		t.Error("expected error for unknown key")
	}
	// malformed pair rejected
	if _, err := parseCTNetworks([]string{"bridge"}); err == nil {
		t.Error("expected error for non key=value token")
	}
	// empty input → nil, no error
	if got, err := parseCTNetworks(nil); err != nil || got != nil {
		t.Errorf("empty input: got %v err %v", got, err)
	}
}
