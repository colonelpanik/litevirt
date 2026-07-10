package pki

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// FwdBearerMDKey is the outgoing metadata key that relays a forwarded user's
// bearer from an entry node to the owning node. It is deliberately NOT
// "authorization": an old or not-yet-flipped receiver ignores this key, so its
// identity resolution is unchanged on rollout; only a receiver enforcing
// ForwardedIdentityV1 promotes it to the real user.
const FwdBearerMDKey = "x-litevirt-fwd-bearer"

// propagateFwdBearer copies the inbound authorization bearer (a forwarded user
// request) onto the outgoing context under FwdBearerMDKey. It APPENDS, so any
// existing outgoing metadata (repair-actor, relocate-token, console, proof
// tokens, …) is preserved. When there is no inbound bearer — a system
// continuation off a background context — nothing is propagated and the receiver
// sees a plain peer call (system identity).
func propagateFwdBearer(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	auth := md.Get("authorization")
	if len(auth) == 0 || auth[0] == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, FwdBearerMDKey, auth[0])
}

func fwdBearerUnaryInterceptor(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return invoker(propagateFwdBearer(ctx), method, req, reply, cc, opts...)
}

func fwdBearerStreamInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return streamer(propagateFwdBearer(ctx), desc, cc, method, opts...)
}

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
	dialOpts := make([]grpc.DialOption, 0, len(opts)+3)
	// Forwarded-identity relay (send-side, always on + forward-compatible): copy
	// the inbound user bearer onto the peer call under FwdBearerMDKey.
	dialOpts = append(dialOpts,
		grpc.WithChainUnaryInterceptor(fwdBearerUnaryInterceptor),
		grpc.WithChainStreamInterceptor(fwdBearerStreamInterceptor),
	)
	dialOpts = append(dialOpts, opts...)
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	return conn, nil
}
