package network

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveBridgeIfUnused(t *testing.T) {
	root := t.TempDir()
	sysClassNet = root
	defer func() { sysClassNet = "/sys/class/net" }()
	addrs := map[string][]net.Addr{
		"hc_ip":  {&net.IPNet{IP: net.ParseIP("10.0.0.1").To4(), Mask: net.CIDRMask(24, 32)}},
		"hc_ip6": {&net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)}},
		"hc_ll":  {&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}},
	}
	origAddrs := interfaceAddrs
	interfaceAddrs = func(name string) ([]net.Addr, error) {
		if name == "hc_gone" {
			return nil, errors.New("route ip+net: no such network interface")
		}
		return addrs[name], nil
	}
	defer func() { interfaceAddrs = origAddrs }()
	var deleted []string
	execCommand = func(name string, args ...string) ([]byte, error) {
		deleted = append(deleted, args[len(args)-1])
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	mk := func(name string, bridge bool, ports ...string) {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if bridge {
			if err := os.MkdirAll(filepath.Join(dir, "bridge"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "brif"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, p := range ports {
				if err := os.WriteFile(filepath.Join(dir, "brif", p), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	mk("hc_hc", true)
	mk("hc_busy", true, "vnet3")
	mk("hc_ip", true)
	mk("hc_ip6", true)
	mk("hc_gone", true)
	mk("hc_ll", true)
	mk("hc_nic", false)
	// A tree a traversing name would reach: "../x" resolves inside root to
	// this bridge-shaped directory, which must never be deleted by that name.
	mk("x", true)

	for _, tc := range []struct {
		name    string
		want    bool
		wantErr bool
	}{
		{"hc_hc", true, false},                 // empty bridge
		{"hc_busy", false, false},              // a port is attached
		{"hc_ip", false, false},                // carries an IPv4 address
		{"hc_ip6", false, false},               // carries only an IPv6 address: still in use
		{"hc_gone", false, true},               // its addresses cannot be read: unknown, refused
		{"hc_ll", true, false},                 // only the kernel's own fe80:: link-local
		{"hc_nic", false, false},               // not a bridge
		{"hc_absent", false, false},            // not there
		{"hc_hc/../x", false, true},            // not an interface name
		{"..", false, true},                    // reserved
		{"", false, true},                      // empty
		{strings.Repeat("a", 16), false, true}, // longer than IFNAMSIZ-1
		{"-x", false, true},                    // would read as an ip(8) option
		{"hc hc", false, true},                 // whitespace
	} {
		got, err := RemoveBridgeIfUnused(tc.name)
		if (err != nil) != tc.wantErr {
			t.Errorf("RemoveBridgeIfUnused(%q) error = %v, want error %v", tc.name, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("RemoveBridgeIfUnused(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
	if strings.Join(deleted, ",") != "hc_hc,hc_ll" {
		t.Errorf("ip link del ran for %v, want only hc_hc and hc_ll", deleted)
	}
}
