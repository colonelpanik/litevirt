package netutil

import (
	"net"
	"testing"
)

// TestOutboundIP_ReturnsARoutableAddress.
//
// The contract callers depend on: a parseable IP, or "" — never a loopback
// placeholder standing in for "unknown". The distinction matters because
// `lv host init --local` mints a certificate from this value, and a loopback
// placeholder produces a certificate no peer can verify while looking successful.
func TestOutboundIP_ReturnsARoutableAddress(t *testing.T) {
	got := OutboundIP()
	if got == "" {
		t.Skip("no route to the outside world in this environment")
	}
	ip := net.ParseIP(got)
	if ip == nil {
		t.Fatalf("OutboundIP() = %q, which does not parse as an IP", got)
	}
	if ip.IsLoopback() {
		t.Fatalf("OutboundIP() = %q — a loopback address is indistinguishable from the "+
			"failure case, and a certificate minted from it is verifiable by nobody", got)
	}
}
