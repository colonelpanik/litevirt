package grpcapi

import (
	"strings"
	"testing"
)

// TestBuildIsolatedNetworkConfig_IPv4Only is the regression test that
// existing single-stack VMs don't pick up an empty static6 block.
func TestBuildIsolatedNetworkConfig_IPv4Only(t *testing.T) {
	got := buildIsolatedNetworkConfig([]isolatedIface{{
		MAC:     "aa:bb:cc:dd:ee:01",
		Address: "10.0.0.10/24",
		Gateway: "10.0.0.1",
		DNS:     []string{"1.1.1.1"},
	}})
	mustNotContain(t, got, "static6")
	mustContain(t, got, "static", "10.0.0.10/24", "10.0.0.1")
}

// TestBuildIsolatedNetworkConfig_IPv6Only covers a v6-only NIC where
// the operator wants no v4 at all.
func TestBuildIsolatedNetworkConfig_IPv6Only(t *testing.T) {
	got := buildIsolatedNetworkConfig([]isolatedIface{{
		MAC:      "aa:bb:cc:dd:ee:02",
		Address6: "2001:db8::10/64",
		Gateway6: "2001:db8::1",
	}})
	// No v4 → no plain `type: static` block.
	if strings.Contains(got, "type: static\n") {
		t.Errorf("IPv6-only iface should not emit a static (v4) subnet:\n%s", got)
	}
	mustContain(t, got, "static6", "2001:db8::10/64", "2001:db8::1")
}

// TestBuildIsolatedNetworkConfig_DualStack is the headline new
// behaviour: v4 + v6 on the same MAC end up as two `subnets:` entries.
func TestBuildIsolatedNetworkConfig_DualStack(t *testing.T) {
	got := buildIsolatedNetworkConfig([]isolatedIface{{
		MAC:      "aa:bb:cc:dd:ee:03",
		Address:  "10.0.0.10/24",
		Gateway:  "10.0.0.1",
		DNS:      []string{"1.1.1.1"},
		Address6: "2001:db8::10/64",
		Gateway6: "2001:db8::1",
	}})
	mustContain(t, got,
		"type: static",
		"10.0.0.10/24",
		"type: static6",
		"2001:db8::10/64",
		"2001:db8::1",
	)
	// V4 must come before V6 (cloud-init reads order-sensitively when
	// resolving multiple DNS nameservers; we keep v4 first to match
	// the prior single-stack default).
	if strings.Index(got, "static\n") > strings.Index(got, "static6\n") {
		t.Errorf("static (v4) should come before static6 (v6) in:\n%s", got)
	}
}

// TestBuildIsolatedNetworkConfig_IPv6NoGateway covers SLAAC-style
// fallback: the NIC has a static v6 address but no gateway because
// the network does router-advertisement.
func TestBuildIsolatedNetworkConfig_IPv6NoGateway(t *testing.T) {
	got := buildIsolatedNetworkConfig([]isolatedIface{{
		MAC:      "aa:bb:cc:dd:ee:04",
		Address6: "2001:db8::20/64",
	}})
	mustContain(t, got, "static6", "2001:db8::20/64")
	if strings.Contains(got, "gateway: 2001") {
		t.Errorf("missing Gateway6 should not emit gateway line:\n%s", got)
	}
}

func mustContain(t *testing.T, body string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(body, n) {
			t.Errorf("expected %q in:\n%s", n, body)
		}
	}
}

func mustNotContain(t *testing.T, body string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if strings.Contains(body, n) {
			t.Errorf("did NOT expect %q in:\n%s", n, body)
		}
	}
}
