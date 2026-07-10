package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func mtlsCtx(cn string) context.Context {
	ctx := context.WithValue(context.Background(), ctxKeyAuthMethod, authMethodMTLS)
	ctx = context.WithValue(ctx, ctxKeyMTLSCommonName, cn)
	return context.WithValue(ctx, ctxKeyPrincipalKind, principalKindPeer)
}

func TestJitterDuration(t *testing.T) {
	if got := jitterDuration(0); got != 0 {
		t.Errorf("jitter(0) = %v, want 0", got)
	}
	if got := jitterDuration(-time.Second); got != -time.Second {
		t.Errorf("jitter(negative) = %v, want unchanged", got)
	}
	d := 100 * time.Second
	for i := 0; i < 2000; i++ {
		j := jitterDuration(d)
		if j < d/2 || j >= d+d/2 {
			t.Fatalf("jitter(%v) = %v, out of [%v, %v)", d, j, d/2, d+d/2)
		}
	}
}

func newPeerAuthServer(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "peer-1", Address: "127.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	return NewServerForTests(TestServerOpts{HostName: "self", DataDir: t.TempDir(), DB: db, Virt: libvirtfake.New()})
}

// TestRequirePeerCert: the peer-only gate accepts a known cluster host cert over
// mTLS and rejects everything else — an operator/non-mTLS caller cannot pass.
func TestRequirePeerCert(t *testing.T) {
	s := newPeerAuthServer(t)
	if err := s.requirePeerCert(context.Background()); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no-mTLS: got %v, want PermissionDenied", err)
	}
	if err := s.requirePeerCert(mtlsCtx("ghost")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("unknown CN: got %v, want PermissionDenied", err)
	}
	if err := s.requirePeerCert(mtlsCtx("peer-1")); err != nil {
		t.Errorf("known host cert: got %v, want nil", err)
	}
}

type fakeFetchStream struct {
	grpc.ServerStreamingServer[pb.FetchBinaryChunk]
	ctx context.Context
}

func (f *fakeFetchStream) Context() context.Context        { return f.ctx }
func (f *fakeFetchStream) Send(*pb.FetchBinaryChunk) error { return nil }

// TestFetchBinary_PeerOnlyAndSemaphore: FetchBinary rejects a non-peer caller
// (operator context) and sheds load with ResourceExhausted when its serving
// semaphore is full — both before touching the binary on disk.
func TestFetchBinary_PeerOnlyAndSemaphore(t *testing.T) {
	s := newPeerAuthServer(t)

	if err := s.FetchBinary(&pb.FetchBinaryRequest{}, &fakeFetchStream{ctx: adminCtx()}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator ctx: got %v, want PermissionDenied", err)
	}

	// Saturate the serving semaphore → next peer request sheds.
	for i := 0; i < fetchBinaryMaxConcurrent; i++ {
		s.fetchBinarySem <- struct{}{}
	}
	if err := s.FetchBinary(&pb.FetchBinaryRequest{}, &fakeFetchStream{ctx: mtlsCtx("peer-1")}); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("semaphore full: got %v, want ResourceExhausted", err)
	}
}

// TestCandidateConfirmed: the confirm-Ping must match the (eventually-consistent)
// hosts-table candidate exactly, or the pull aborts (stale row / rollback).
func TestCandidateConfirmed(t *testing.T) {
	cand := peerVersionInfo{host: "p1", version: "v2", schema: 30}
	cases := []struct {
		name      string
		live      peerVersionInfo
		reachable bool
		want      bool
	}{
		{"match", peerVersionInfo{host: "p1", version: "v2", schema: 30}, true, true},
		{"unreachable", peerVersionInfo{}, false, false},
		{"version drifted (row stale)", peerVersionInfo{host: "p1", version: "v1", schema: 30}, true, false},
		{"schema drifted (row stale)", peerVersionInfo{host: "p1", version: "v2", schema: 29}, true, false},
	}
	for _, c := range cases {
		if got := candidateConfirmed(cand, c.live, c.reachable); got != c.want {
			t.Errorf("%s: candidateConfirmed = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestVerifyPulledBinary: the streamed binary's header must match the confirmed
// (version, schema), never be a schema downgrade, never a no-op equal-version.
func TestVerifyPulledBinary(t *testing.T) {
	const localSchema, localVer = 30, "v1"
	cases := []struct {
		name         string
		peerVer      string
		peerSchema   int
		expectVer    string
		expectSchema int
		wantErr      bool
	}{
		{"valid upgrade", "v2", 30, "v2", 30, false},
		{"valid higher schema", "v2", 31, "v2", 31, false},
		{"header version mismatch", "v3", 30, "v2", 30, true},
		{"header schema mismatch", "v2", 31, "v2", 30, true},
		{"schema downgrade", "v0", 29, "v0", 29, true},
		{"no-op equal version", "v1", 30, "v1", 30, true},
	}
	for _, c := range cases {
		err := verifyPulledBinary(c.peerVer, c.peerSchema, c.expectVer, c.expectSchema, localSchema, localVer)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: verifyPulledBinary err = %v, wantErr = %v", c.name, err, c.wantErr)
		}
	}
}

// TestPreferRelaySource_Fallback: with no gossip members (no relays elected),
// preferRelaySource returns a candidate matching the target without panicking.
func TestPreferRelaySource_Fallback(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	s := NewServerForTests(TestServerOpts{HostName: "self", DataDir: t.TempDir(), DB: db, Virt: libvirtfake.New()})
	target := peerVersionInfo{host: "p1", version: "v2", schema: 30}
	peers := []peerVersionInfo{target, {host: "p2", version: "v2", schema: 30}}
	got := s.preferRelaySource(target, peers)
	if got.host != "p1" && got.host != "p2" {
		t.Errorf("preferRelaySource returned %q, want one of the matching candidates", got.host)
	}
}
