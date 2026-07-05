package network

import (
	"strings"
	"testing"
)

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// TestDnsmasqArgs_ExcludesLoopback is the regression for the multi-bridge DHCP
// collision: without --except-interface=lo, dnsmasq binds 127.0.0.1:53 and only
// the first per-bridge instance on a host can start (the rest exit 2). litevirt
// serves guest DNS via the bridge gateway IP, so loopback must be excluded.
func TestDnsmasqArgs_ExcludesLoopback(t *testing.T) {
	args := dnsmasqArgs("br-test", "10.0.0.2", "10.0.0.254", "255.255.255.0", "10.0.0.1/24",
		"/var/run/litevirt-dnsmasq-br-test.pid", []string{"8.8.8.8"}, "litevirt.local", 5354)

	for _, want := range []string{
		"--interface=br-test",
		"--except-interface=lo",
		"--bind-dynamic",
		"--pid-file=/var/run/litevirt-dnsmasq-br-test.pid",
		// Lease file must live in the dir the IP scanner reads, or lease-based
		// IP discovery silently never fires (ARP-only fallback).
		"--dhcp-leasefile=/var/lib/libvirt/dnsmasq/litevirt-br-test.leases",
		"--dhcp-range=10.0.0.2,10.0.0.254,255.255.255.0,12h",
		"--server=8.8.8.8",
		"--no-resolv",
		// Domain-specific forward to the embedded DNS so guests resolve litevirt names.
		"--server=/litevirt.local/127.0.0.1#5354",
	} {
		if !hasArg(args, want) {
			t.Errorf("dnsmasq args missing %q\ngot: %s", want, strings.Join(args, " "))
		}
	}
	// IPv4 gateway must NOT enable RA.
	if hasArg(args, "--enable-ra") {
		t.Error("--enable-ra should not be set for an IPv4 gateway")
	}
}

// TestCmdlineMatchesArgs covers the drift check that decides whether a running
// dnsmasq must be restarted to pick up new args (e.g. the embedded-DNS
// --server= forward added on upgrade).
func TestCmdlineMatchesArgs(t *testing.T) {
	want := dnsmasqArgs("br0", "10.0.0.2", "10.0.0.254", "255.255.255.0", "10.0.0.1/24",
		"/run/lv-br0.pid", []string{"8.8.8.8"}, "litevirt.local", 5354)

	// A cmdline built from exactly these args (argv[0] + args, NUL-joined, any
	// order) is considered current — no restart.
	blob := func(argv0 string, args []string) []byte {
		return []byte(strings.Join(append([]string{argv0}, args...), "\x00"))
	}
	if !cmdlineMatchesArgs(blob("dnsmasq", want), want) {
		t.Error("identical arg set must be reported current")
	}
	// Order must not matter.
	shuffled := append([]string(nil), want...)
	shuffled[0], shuffled[len(shuffled)-1] = shuffled[len(shuffled)-1], shuffled[0]
	if !cmdlineMatchesArgs(blob("dnsmasq", shuffled), want) {
		t.Error("reordered arg set must still be current")
	}
	// The load-bearing case: a dnsmasq started BEFORE the local resolver was
	// configured lacks the --server=/domain/ forward → must be flagged stale.
	stale := dnsmasqArgs("br0", "10.0.0.2", "10.0.0.254", "255.255.255.0", "10.0.0.1/24",
		"/run/lv-br0.pid", []string{"8.8.8.8"}, "", 0)
	if cmdlineMatchesArgs(blob("dnsmasq", stale), want) {
		t.Error("a cmdline missing the embedded-DNS forward must be flagged stale")
	}
	// An empty / unreadable cmdline defaults to current (no spurious restart).
	if !cmdlineMatchesArgs(nil, want) {
		t.Error("empty cmdline must default to current")
	}
	if !cmdlineMatchesArgs([]byte("dnsmasq"), want) {
		t.Error("argv0-only cmdline must default to current")
	}
}

// TestDnsmasqArgs_V6EnablesRA confirms an IPv6 gateway turns on router
// advertisements (and still excludes loopback).
func TestDnsmasqArgs_V6EnablesRA(t *testing.T) {
	args := dnsmasqArgs("br-v6", "2001:db8::2", "2001:db8::ffff", "64", "2001:db8::1/64",
		"/var/run/litevirt-dnsmasq-br-v6.pid", nil, "", 0)
	if !hasArg(args, "--enable-ra") {
		t.Error("--enable-ra not set for IPv6 gateway")
	}
	if !hasArg(args, "--except-interface=lo") {
		t.Error("--except-interface=lo missing for IPv6 case")
	}
	// No upstream DNS supplied → must NOT force --no-resolv (fall back to resolv.conf).
	if hasArg(args, "--no-resolv") {
		t.Error("--no-resolv should not be set when no upstream DNS was resolved")
	}
	// No local resolver configured → no domain-specific forward.
	for _, a := range args {
		if strings.HasPrefix(a, "--server=/") {
			t.Errorf("unexpected domain-specific --server with no local resolver: %q", a)
		}
	}
}
