package pki

import (
	"testing"

	"google.golang.org/grpc"
)

func TestPeerDial_BadPKIDir(t *testing.T) {
	// PeerTLSConfig reads ca.crt synchronously, so a missing PKI dir fails fast
	// (grpc.NewClient is lazy and wouldn't surface this until first RPC).
	if _, err := PeerDial(t.TempDir(), "127.0.0.1:7443"); err == nil {
		t.Fatal("expected error for missing CA in PKI dir")
	}
}

func TestPeerDial_ConstructsClient(t *testing.T) {
	// grpc.NewClient is lazy: this only proves PeerDial loads the peer TLS config
	// and constructs a client. It does NOT assert a successful TLS dial.
	dir := setupPKI(t)
	conn, err := PeerDial(dir, "127.0.0.1:7443")
	if err != nil {
		t.Fatalf("PeerDial: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
	t.Cleanup(func() { conn.Close() })
}

func TestPeerDial_AcceptsExtraOpts(t *testing.T) {
	// A non-transport call option (as anti-entropy passes for the legacy
	// state-dump receive limit) is accepted alongside the peer TLS credential.
	dir := setupPKI(t)
	conn, err := PeerDial(dir, "127.0.0.1:7443",
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64<<20)))
	if err != nil {
		t.Fatalf("PeerDial with extra opt: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
}
