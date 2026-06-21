package network

import "testing"

// TestSubnetRange_V4 sanity-checks v4 still works with the unified parser.
func TestSubnetRange_V4(t *testing.T) {
	gw, start, end, mask, err := SubnetRange("10.0.0.0/24")
	if err != nil {
		t.Fatalf("SubnetRange v4: %v", err)
	}
	if gw != "10.0.0.1/24" {
		t.Errorf("gateway = %q, want 10.0.0.1/24", gw)
	}
	if start != "10.0.0.2" {
		t.Errorf("start = %q, want 10.0.0.2", start)
	}
	if end != "10.0.0.254" {
		t.Errorf("end = %q, want 10.0.0.254", end)
	}
	if mask != "255.255.255.0" {
		t.Errorf("mask = %q, want 255.255.255.0", mask)
	}
}

func TestSubnetRange_V6_Basic(t *testing.T) {
	gw, start, end, mask, err := SubnetRange("2001:db8::/64")
	if err != nil {
		t.Fatalf("SubnetRange v6: %v", err)
	}
	if gw != "2001:db8::1/64" {
		t.Errorf("gateway = %q, want 2001:db8::1/64", gw)
	}
	if start != "2001:db8::2" {
		t.Errorf("start = %q, want 2001:db8::2", start)
	}
	// End is capped at network + 0xffff.
	if end != "2001:db8::ffff" {
		t.Errorf("end = %q, want 2001:db8::ffff", end)
	}
	if mask != "64" {
		t.Errorf("mask (prefix) = %q, want 64", mask)
	}
}

// TestSubnetRange_V6_TooSmall verifies we refuse subnets too small for DHCP.
func TestSubnetRange_V6_TooSmall(t *testing.T) {
	if _, _, _, _, err := SubnetRange("2001:db8::/127"); err == nil {
		t.Error("expected error for /127 v6 subnet")
	}
}

// TestSubnetRange_V6_BoundedByPrefix verifies a smaller v6 subnet caps `end`
// at the actual subnet boundary, not at network+0xffff.
func TestSubnetRange_V6_BoundedByPrefix(t *testing.T) {
	_, start, end, _, err := SubnetRange("fd00::/120")
	if err != nil {
		t.Fatalf("SubnetRange v6: %v", err)
	}
	if start != "fd00::2" {
		t.Errorf("start = %q, want fd00::2", start)
	}
	if end != "fd00::ff" {
		t.Errorf("end = %q, want fd00::ff (last addr in /120)", end)
	}
}

func TestIsIPv6Gateway(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"10.0.0.1/24", false},
		{"10.0.0.1", false},
		{"2001:db8::1/64", true},
		{"2001:db8::1", true},
		{"::1", true},
		{"", false},
	}
	for _, c := range cases {
		if got := isIPv6Gateway(c.in); got != c.want {
			t.Errorf("isIPv6Gateway(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
