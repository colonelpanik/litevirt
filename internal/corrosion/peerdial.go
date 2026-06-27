package corrosion

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
)

// defaultPeerGRPCPort is the gRPC port used to dial a peer whose host record
// carries no explicit port (grpc_port DEFAULT 7443 in schema).
const defaultPeerGRPCPort = 7443

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
	if port == 0 {
		port = defaultPeerGRPCPort
	}
	return net.JoinHostPort(addr, strconv.Itoa(port)), nil
}
