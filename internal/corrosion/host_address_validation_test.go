package corrosion

import "testing"

// TestValidHostAddress is the second half of the `lv host add` injection fix.
//
// Quoting the remote command line stops the shell executing hosts.address, but
// the column should never have held a shell payload in the first place. The
// cluster transport is IPv4-only and the daemon already refuses to start on a
// hostname, a host:port or IPv6 — so requiring a bare IPv4 literal at the write
// costs nothing and removes the class.
func TestValidHostAddress(t *testing.T) {
	valid := []string{"10.0.0.1", "192.168.1.254", "127.0.0.1", "0.0.0.0"}
	for _, a := range valid {
		if !ValidHostAddress(a) {
			t.Errorf("ValidHostAddress(%q) = false, want true", a)
		}
	}
	invalid := []string{
		"",
		"$(touch /tmp/pwned)",
		"10.0.0.1`id`",
		"10.0.0.1; rm -rf /",
		"10.0.0.1 10.0.0.2",
		"node-1.example.com", // hostname: transport is IPv4-only
		"10.0.0.1:7946",      // host:port
		"::1",                // IPv6
		"fe80::1",
		"10.0.0.1\nHOST_NAME=evil",
	}
	for _, a := range invalid {
		if ValidHostAddress(a) {
			t.Errorf("ValidHostAddress(%q) = true, want false", a)
		}
	}
}
