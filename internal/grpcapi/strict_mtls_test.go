package grpcapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// mtlsPeerCtx builds a server-incoming context as the auth interceptor sees it:
// a peer.Peer carrying a TLS client cert with CommonName cn (empty cn = no
// usable cert), an optional source address (for loopback detection), and an
// optional bearer in incoming metadata.
func mtlsPeerCtx(cn string, addr net.Addr, bearer string) context.Context {
	ctx := context.Background()
	var certs []*x509.Certificate
	if cn != "" {
		certs = []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}
	}
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr:     addr,
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: certs}},
	})
	if bearer != "" {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+bearer))
	}
	return ctx
}

// nonTCPAddr is an addr whose String() is not host:port (e.g. a unix/pipe
// transport), used to prove isLoopbackPeer treats it as not-loopback.
type nonTCPAddr struct{ s string }

func (a nonTCPAddr) Network() string { return "pipe" }
func (a nonTCPAddr) String() string  { return a.s }

func tcpAddr(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 5000} }

// strictServer returns a test server with the strict-mTLS config flag set and a
// fake gate whose Enforced returns gateOn, plus the named live host rows.
func strictServer(t *testing.T, flag, gateOn bool, hosts ...string) *Server {
	t.Helper()
	s := testServer(t)
	for _, h := range hosts {
		if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.9", State: "active"}); err != nil {
			t.Fatalf("InsertHost(%s): %v", h, err)
		}
	}
	s.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.StrictMTLSIdentityV1: gateOn}})
	s.SetStrictMTLSIdentity(flag)
	return s
}

func TestIsLoopbackPeer(t *testing.T) {
	cases := []struct {
		name string
		addr net.Addr
		want bool
	}{
		{"ipv4 loopback", tcpAddr("127.0.0.1"), true},
		{"ipv4 loopback high", tcpAddr("127.5.6.7"), true},
		{"ipv6 loopback", &net.TCPAddr{IP: net.ParseIP("::1"), Port: 5000}, true},
		{"ipv4-mapped loopback", &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 5000}, true},
		{"remote ipv4", tcpAddr("10.0.0.9"), false},
		{"non-tcp addr", nonTCPAddr{"bufconn"}, false},
		{"nil addr", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: tc.addr})
			if got := isLoopbackPeer(ctx); got != tc.want {
				t.Errorf("isLoopbackPeer(%v) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
	// No peer info at all → not loopback.
	if isLoopbackPeer(context.Background()) {
		t.Error("isLoopbackPeer(bare ctx) = true, want false")
	}
}

func TestAuthenticate_MTLSClassification(t *testing.T) {
	remote := tcpAddr("10.0.0.9")
	loop := tcpAddr("127.0.0.1")

	cases := []struct {
		name         string
		flag, gateOn bool
		cn           string
		addr         net.Addr
		wantErr      codes.Code // OK sentinel = codes.OK means no error
		wantKind     string
	}{
		{"peer strict-on", true, true, "peer-1", remote, codes.OK, principalKindPeer},
		{"client lv-cli strict-on denied", true, true, "lv-cli", remote, codes.Unauthenticated, ""},
		{"client dark (flag off)", false, true, "lv-cli", remote, codes.OK, principalKindClient},
		{"client dark (gate off, mid-roll)", true, false, "lv-cli", remote, codes.OK, principalKindClient},
		{"local-root loopback strict-on", true, true, "self", loop, codes.OK, principalKindLocalRoot},
		{"unknown CN strict-on denied", true, true, "ghost", remote, codes.Unauthenticated, ""},
		{"no cert strict-on denied", true, true, "", remote, codes.Unauthenticated, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := strictServer(t, tc.flag, tc.gateOn, "peer-1", "self")
			newCtx, err := s.authenticate(mtlsPeerCtx(tc.cn, tc.addr, ""))
			if tc.wantErr != codes.OK {
				if status.Code(err) != tc.wantErr {
					t.Fatalf("err = %v, want code %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("authenticate: unexpected err %v", err)
			}
			if got := callerRole(newCtx); got != "admin" {
				t.Errorf("role = %q, want admin", got)
			}
			if got := callerPrincipalKind(newCtx); got != tc.wantKind {
				t.Errorf("principalKind = %q, want %q", got, tc.wantKind)
			}
		})
	}
}

// TestAuthenticate_RemovedHostCN pins the isTrustedHostCN predicate: a live host
// CN is a trusted peer, but once the host is removed (DeleteHost → deleted_at),
// its still-CA-valid cert classifies as client and is denied under strict mode.
func TestAuthenticate_RemovedHostCN(t *testing.T) {
	s := strictServer(t, true, true, "gone")

	// Live → peer/admin.
	ctx, err := s.authenticate(mtlsPeerCtx("gone", tcpAddr("10.0.0.9"), ""))
	if err != nil || callerPrincipalKind(ctx) != principalKindPeer {
		t.Fatalf("live host: err=%v kind=%q, want peer", err, callerPrincipalKind(ctx))
	}

	// Remove the host (soft-delete) → cert no longer trusted → denied.
	if err := corrosion.DeleteHost(context.Background(), s.db, "gone"); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	_, err = s.authenticate(mtlsPeerCtx("gone", tcpAddr("10.0.0.9"), ""))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("removed host: err = %v, want Unauthenticated", err)
	}
}

// TestAuthenticate_BearerWins: a valid session bearer resolves to the real user
// even from a client cert under strict mode (the bearer branch bypasses the
// mTLS classification entirely).
func TestAuthenticate_BearerWins(t *testing.T) {
	s := strictServer(t, true, true)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "alice", "viewer", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	token, _, _, err := s.mintSession(ctx, "alice", "local", "10.0.0.9", "test")
	if err != nil {
		t.Fatalf("mintSession: %v", err)
	}
	// client cert (would be denied bearerless) + a valid bearer → alice/viewer.
	newCtx, err := s.authenticate(mtlsPeerCtx("lv-cli", tcpAddr("10.0.0.9"), token))
	if err != nil {
		t.Fatalf("authenticate with bearer: %v", err)
	}
	if u := callerUsername(newCtx); u != "alice" {
		t.Errorf("username = %q, want alice", u)
	}
	if r := callerRole(newCtx); r != "viewer" {
		t.Errorf("role = %q, want viewer (not admin)", r)
	}
}

// TestStep0Gates_PeerOnly: the peer-only RPCs reject an operator bearer and a
// viewer, and let a trusted peer through the gate (peer may still fail deeper on
// the actual network op — we assert only that the auth gate did not deny it).
func TestStep0Gates_PeerOnly(t *testing.T) {
	s := testServer(t)
	peerCtx := peerCtxFor(t, s, "peer-1")
	op := userCtx("op", "operator")
	viewer := userCtx("v", "viewer")

	deniedForNonPeer := func(t *testing.T, name string, call func(context.Context) error) {
		t.Helper()
		if c := status.Code(call(op)); c != codes.PermissionDenied {
			t.Errorf("%s operator: code = %v, want PermissionDenied", name, c)
		}
		if c := status.Code(call(viewer)); c != codes.PermissionDenied {
			t.Errorf("%s viewer: code = %v, want PermissionDenied", name, c)
		}
		if c := status.Code(call(peerCtx)); c == codes.PermissionDenied {
			t.Errorf("%s peer: gate wrongly denied a trusted peer", name)
		}
	}

	deniedForNonPeer(t, "SyncVTEP", func(ctx context.Context) error {
		_, err := s.SyncVTEP(ctx, &pb.SyncVTEPRequest{Vni: 100, VtepIp: "10.0.0.9"})
		return err
	})
	deniedForNonPeer(t, "UpdateFDB", func(ctx context.Context) error {
		_, err := s.UpdateFDB(ctx, &pb.UpdateFDBRequest{Vni: 100})
		return err
	})
	deniedForNonPeer(t, "RefreshLB", func(ctx context.Context) error {
		_, err := s.RefreshLB(ctx, &pb.RefreshLBRequest{StackName: "x"})
		return err
	})
	deniedForNonPeer(t, "ProvisionNetwork", func(ctx context.Context) error {
		_, err := s.ProvisionNetwork(ctx, &pb.ProvisionNetworkRequest{Name: "n", Config: `{"interface":"br-x"}`, NetType: "bridge"})
		return err
	})
}

// TestStep0Gates_DualUse: GetStateDigest/GetStateDump accept BOTH a trusted peer
// and an operator bearer (UI diagnostics / `lv cluster sync`), but deny a viewer.
func TestStep0Gates_DualUse(t *testing.T) {
	s := testServer(t)
	peerCtx := peerCtxFor(t, s, "peer-1")
	op := userCtx("op", "operator")
	viewer := userCtx("v", "viewer")

	for _, tc := range []struct {
		name string
		call func(context.Context) error
	}{
		{"GetStateDigest", func(ctx context.Context) error { _, err := s.GetStateDigest(ctx, nil); return err }},
		{"GetStateDump", func(ctx context.Context) error { _, err := s.GetStateDump(ctx, nil); return err }},
	} {
		if err := tc.call(peerCtx); err != nil {
			t.Errorf("%s peer: unexpected err %v", tc.name, err)
		}
		if err := tc.call(op); err != nil {
			t.Errorf("%s operator: unexpected err %v (bearer path must pass)", tc.name, err)
		}
		if c := status.Code(tc.call(viewer)); c != codes.PermissionDenied {
			t.Errorf("%s viewer: code = %v, want PermissionDenied", tc.name, c)
		}
	}
}

// --- Stage 2: forwarded identity ---

// fwdServer returns a test server with the forwarded-identity config flag set
// and a fake gate whose Enforced(ForwardedIdentityV1) returns gateOn.
func fwdServer(t *testing.T, flag, gateOn bool, hosts ...string) *Server {
	t.Helper()
	s := testServer(t)
	for _, h := range hosts {
		if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.9", State: "active"}); err != nil {
			t.Fatalf("InsertHost(%s): %v", h, err)
		}
	}
	s.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.ForwardedIdentityV1: gateOn}})
	s.SetForwardedIdentity(flag)
	return s
}

// withFwdBearer adds a forwarded user bearer to the incoming metadata of ctx.
func withFwdBearer(ctx context.Context, val string) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.MD{}
	} else {
		md = md.Copy()
	}
	md.Set(pki.FwdBearerMDKey, val)
	return metadata.NewIncomingContext(ctx, md)
}

func aliceSession(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "alice", "viewer", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	token, _, _, err := s.mintSession(ctx, "alice", "local", "10.0.0.9", "test")
	if err != nil {
		t.Fatalf("mintSession: %v", err)
	}
	return token
}

func TestForwardedIdentity_PeerPromotesToRealUser(t *testing.T) {
	s := fwdServer(t, true, true, "peer-1")
	token := aliceSession(t, s)
	ctx := withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+token)

	newCtx, err := s.authenticate(ctx)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u := callerUsername(newCtx); u != "alice" {
		t.Errorf("username = %q, want alice (promoted from fwd-bearer)", u)
	}
	if r := callerRole(newCtx); r != "viewer" {
		t.Errorf("role = %q, want viewer (not admin)", r)
	}
}

func TestForwardedIdentity_DarkKeepsPeerAdmin(t *testing.T) {
	// Flag/gate off: the fwd-bearer is ignored, peer stays admin (trusted forward).
	s := fwdServer(t, false, false, "peer-1")
	token := aliceSession(t, s)
	ctx := withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+token)

	newCtx, err := s.authenticate(ctx)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u := callerUsername(newCtx); u != "admin" {
		t.Errorf("username = %q, want admin (dark: fwd-bearer ignored)", u)
	}
}

func TestForwardedIdentity_PeerNoBearerIsSystemAdmin(t *testing.T) {
	// A peer with NO fwd-bearer (a system continuation) stays admin even when enforced.
	s := fwdServer(t, true, true, "peer-1")
	newCtx, err := s.authenticate(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if r := callerRole(newCtx); r != "admin" {
		t.Errorf("role = %q, want admin (system continuation)", r)
	}
	if k := callerPrincipalKind(newCtx); k != principalKindPeer {
		t.Errorf("kind = %q, want peer", k)
	}
}

func TestForwardedIdentity_ClientCannotImpersonate(t *testing.T) {
	// A client cert injecting a fwd-bearer must NOT be promoted (only a peer may).
	// With strict OFF the client is a dark admin; the fwd-bearer is ignored.
	s := fwdServer(t, true, true) // fwd enforced, but caller is a client (unknown CN)
	token := aliceSession(t, s)
	ctx := withFwdBearer(mtlsPeerCtx("lv-cli", tcpAddr("10.0.0.9"), ""), "Bearer "+token)

	newCtx, err := s.authenticate(ctx)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u := callerUsername(newCtx); u == "alice" {
		t.Error("client cert was promoted to alice via injected fwd-bearer — impersonation")
	}
}

func TestForwardedIdentity_FailClosedCodes(t *testing.T) {
	s := fwdServer(t, true, true, "peer-1")
	peerAddr := tcpAddr("10.0.0.9")

	// (a) session not present locally (not-yet-replicated) → Unavailable (retryable).
	ctx := withFwdBearer(mtlsPeerCtx("peer-1", peerAddr, ""), "Bearer "+SessionTokenPrefix+"deadbeef")
	if _, err := s.authenticate(ctx); status.Code(err) != codes.Unavailable {
		t.Errorf("missing session: code = %v, want Unavailable", status.Code(err))
	}

	// (b) revoked session → Unauthenticated (do not retry).
	token := aliceSession(t, s)
	sid := token[len(SessionTokenPrefix):]
	if err := corrosion.RevokeSession(context.Background(), s.db, sid); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	ctx = withFwdBearer(mtlsPeerCtx("peer-1", peerAddr, ""), "Bearer "+token)
	if _, err := s.authenticate(ctx); status.Code(err) != codes.Unauthenticated {
		t.Errorf("revoked session: code = %v, want Unauthenticated", status.Code(err))
	}

	// (c) malformed (no Bearer prefix) → Unauthenticated.
	ctx = withFwdBearer(mtlsPeerCtx("peer-1", peerAddr, ""), "not-a-bearer")
	if _, err := s.authenticate(ctx); status.Code(err) != codes.Unauthenticated {
		t.Errorf("malformed fwd-bearer: code = %v, want Unauthenticated", status.Code(err))
	}
}

// TestRequirePeerCert_PromotedForwardedPeer: a forwarded-identity promotion changes
// authMethod to session but PRESERVES the peer transport (principalKind=peer + CN),
// so requirePeerCert must still accept it — otherwise flipping forwarded_identity_v1
// would break every user-initiated fan-out to a peer-only RPC (network/LB provision,
// remote backup, container migrate). An operator bearer and a client cert stay denied.
func TestRequirePeerCert_PromotedForwardedPeer(t *testing.T) {
	s := newPeerAuthServer(t) // inserts trusted host "peer-1"

	// Promoted forwarded peer: transport peer (principalKind=peer, CN=peer-1), but
	// the identity was promoted to a user (authMethod=session).
	promoted := context.WithValue(context.Background(), ctxKeyPrincipalKind, principalKindPeer)
	promoted = context.WithValue(promoted, ctxKeyMTLSCommonName, "peer-1")
	promoted = context.WithValue(promoted, ctxKeyAuthMethod, authMethodSession)
	promoted = context.WithValue(promoted, ctxKeyUsername, "alice")
	if err := s.requirePeerCert(promoted); err != nil {
		t.Errorf("promoted forwarded peer must pass requirePeerCert (peer transport): got %v", err)
	}
	if err := requireReplicationPeer(promoted, "peer-1"); err != nil {
		t.Errorf("promoted forwarded peer must pass requireReplicationPeer for its sender: got %v", err)
	}

	// An operator bearer (no principalKind) is still rejected.
	op := context.WithValue(context.Background(), ctxKeyAuthMethod, authMethodSession)
	op = context.WithValue(op, ctxKeyRole, "operator")
	if err := s.requirePeerCert(op); status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator bearer must be rejected: got %v", err)
	}

	// A client cert (principalKind=client) is still rejected.
	cl := context.WithValue(context.Background(), ctxKeyPrincipalKind, principalKindClient)
	cl = context.WithValue(cl, ctxKeyMTLSCommonName, "lv-cli")
	if err := s.requirePeerCert(cl); status.Code(err) != codes.PermissionDenied {
		t.Errorf("client cert must be rejected: got %v", err)
	}

	// A promoted peer claiming a DIFFERENT sender is still rejected by CN==sender.
	if err := requireReplicationPeer(promoted, "peer-2"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("replication sender mismatch must be rejected: got %v", err)
	}
}
