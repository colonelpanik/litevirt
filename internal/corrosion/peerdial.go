package corrosion

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
)

// defaultPeerGRPCPort is the gRPC port used to dial a peer whose host record
// carries no explicit port (grpc_port DEFAULT 7443 in schema).
const defaultPeerGRPCPort = 7443

// PeerTarget builds a dialable "host:port" target from a hosts.address value,
// defaulting the port to defaultPeerGRPCPort.
//
// hosts.address stores a BARE host, so every dial site must go through here.
// A raw fmt.Sprintf("%s:%d") turns an IPv6 address into "fd00::1:7443", which no
// dialer can parse — and a probe that can never succeed is indistinguishable
// from a dead peer, so the health checker marks a healthy host suspect and hands
// it to fencing. Use net.JoinHostPort, always.
func PeerTarget(addr string, port int) string {
	if port == 0 {
		port = defaultPeerGRPCPort
	}
	return net.JoinHostPort(addr, strconv.Itoa(port))
}

// URIHost brackets an IPv6 literal so it can be embedded in a URI authority that
// carries no port of its own (qemu+tls://<host>/system, tcp://<host>). An IPv4
// address, a hostname, and an already-bracketed literal all pass through
// unchanged, so this is safe to wrap around an existing format string.
func URIHost(addr string) string {
	if strings.HasPrefix(addr, "[") {
		return addr
	}
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		return "[" + addr + "]"
	}
	return addr
}

// resolvePeerTarget resolves a peer host name to a dialable "host:port" target.
//
// It prefers the replicated hosts table and falls back to the gossip memberlist
// address for a peer that has not yet received the hosts table (bootstrap, when
// a new node joins before replication catches up). The port defaults to 7443.
// The target is built with net.JoinHostPort so IPv6 addresses are bracketed.
func resolvePeerTarget(ctx context.Context, c *Client, peerName string) (string, error) {
	var addr string
	var port int

	host, err := GetHost(ctx, c, peerName)
	if err != nil {
		return "", fmt.Errorf("look up host %q: %w", peerName, err)
	}
	if host != nil {
		addr = host.Address
		port = host.GRPCPort
	} else {
		for _, m := range c.Members() {
			if m.Name == peerName {
				if h, _, _ := net.SplitHostPort(m.Addr); h != "" {
					addr = h
				} else {
					addr = m.Addr
				}
				break
			}
		}
		if addr == "" {
			return "", fmt.Errorf("look up host %q: not found in cluster state or gossip", peerName)
		}
		slog.Debug("resolvePeerTarget: using gossip address for peer", "peer", peerName, "addr", addr)
	}
	return PeerTarget(addr, port), nil
}
