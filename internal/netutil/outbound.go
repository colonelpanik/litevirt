// Package netutil holds small network helpers shared across packages.
package netutil

import "net"

// OutboundIP is the source address the kernel would use toward the default
// route, or "" if it cannot be determined.
//
// It is a route lookup, not a connection: a UDP "dial" to a public address binds
// a local socket and sends nothing, so this works with no network reachable and
// costs no packets. 8.8.8.8 is a routing landmark here, never contacted.
//
// This is the RIGHT answer only on a single-homed host. On a machine whose
// cluster network is not the default route it reports the wrong interface, which
// is why litevirt has advertise_address and why `lv host init --local` takes
// --address: callers that need the cluster address must let the operator name it
// and use this only as a fallback.
//
// It returns "" rather than a loopback placeholder so the caller decides what an
// unknown address means. Four copies of this function existed, three of them
// returning "127.0.0.1" on failure and one returning "" — and the difference was
// invisible at every call site, which for the certificate-minting caller was the
// difference between a usable certificate and a loopback-only one that no peer
// can verify. Making the failure explicit is the point.
func OutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return addr.IP.String()
}
