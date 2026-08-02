package cli

import (
	"strings"
	"testing"
)

// TestResolveHost_PrefersIPv4 covers the second way an IPv6 address could enter
// hosts.address — one that validating advertise_address does NOT close.
//
// resolveHost's result becomes the host cert SAN, the hosts.address every peer
// dials, and a gossip seed entry. It used to return addrs[0], so a dual-stack
// name could hand the cluster an IPv6 address with advertise_address unset, and
// because LookupHost order is not stable the same `lv host add` could work once
// and produce an unreachable host the next time.
func TestResolveHost_PrefersIPv4(t *testing.T) {
	for _, c := range []struct {
		name  string
		addrs []string
		want  string
	}{
		{"ipv4 only", []string{"10.0.0.5"}, "10.0.0.5"},
		{"ipv6 first, ipv4 second", []string{"fd00::1", "10.0.0.5"}, "10.0.0.5"},
		{"ipv4 first", []string{"10.0.0.5", "fd00::1"}, "10.0.0.5"},
		{"multiple ipv6 then ipv4", []string{"2001:db8::1", "fd00::1", "192.168.1.7"}, "192.168.1.7"},
		{"v4-mapped v6 counts as ipv4 and is canonicalized", []string{"::ffff:10.0.0.5"}, "10.0.0.5"},
	} {
		t.Run(c.name, func(t *testing.T) {
			restore := stubLookupHost(t, c.addrs, nil)
			defer restore()

			got, err := resolveHost("node.example.com")
			if err != nil {
				t.Fatalf("resolveHost: %v", err)
			}
			if got != c.want {
				t.Errorf("resolveHost = %q, want %q — this value becomes the cert SAN, "+
					"hosts.address and a gossip seed", got, c.want)
			}
		})
	}
}

// TestResolveHost_RejectsIPv6Only: an AAAA-only name must fail loudly at
// `lv host add` time. Silently accepting it registers a host every peer probe
// will fail to reach, which the failure detector reads as a dead node.
func TestResolveHost_RejectsIPv6Only(t *testing.T) {
	restore := stubLookupHost(t, []string{"2001:db8::1", "fd00::1"}, nil)
	defer restore()

	_, err := resolveHost("v6only.example.com")
	if err == nil {
		t.Fatal("resolveHost accepted an AAAA-only name; want an error")
	}
	if !strings.Contains(err.Error(), "IPv4-only") {
		t.Errorf("error = %q, want it to explain that cluster transport is IPv4-only", err)
	}
}

// TestResolveHost_RejectsIPv6Literal: a bare IPv6 literal short-circuits the
// resolver, so it needs its own guard.
func TestResolveHost_RejectsIPv6Literal(t *testing.T) {
	if _, err := resolveHost("fd00::1"); err == nil {
		t.Fatal("resolveHost accepted an IPv6 literal; want an error")
	}
	got, err := resolveHost("10.0.0.5")
	if err != nil || got != "10.0.0.5" {
		t.Fatalf("resolveHost(\"10.0.0.5\") = %q, %v; want 10.0.0.5, nil", got, err)
	}
}

func stubLookupHost(t *testing.T, addrs []string, err error) func() {
	t.Helper()
	prev := lookupHost
	lookupHost = func(string) ([]string, error) { return addrs, err }
	return func() { lookupHost = prev }
}
