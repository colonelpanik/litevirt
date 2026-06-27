package pki

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// PeerDial dials a peer daemon over host-to-host mTLS (PeerTLSConfig). The
// caller passes an already-resolved "host:port" target — build it with
// net.JoinHostPort so IPv6 addresses are bracketed correctly — plus any extra
// dial options.
//
// The peer-TLS transport credential is appended LAST so it is authoritative:
// a caller's extra option cannot accidentally swap the transport credentials
// (the last WithTransportCredentials wins). Extra opts are therefore expected
// to be non-transport options (e.g. grpc.WithDefaultCallOptions(...)).
//
// grpc.NewClient is lazy and does not connect here; the first RPC dials. The
// caller owns the returned connection and must Close it.
func PeerDial(pkiDir, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	tlsCfg, err := PeerTLSConfig(pkiDir)
	if err != nil {
		return nil, fmt.Errorf("peer TLS config: %w", err)
	}
	dialOpts := make([]grpc.DialOption, 0, len(opts)+1)
	dialOpts = append(dialOpts, opts...)
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	return conn, nil
}
