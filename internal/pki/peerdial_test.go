package pki

import (
	"sync"
	"sync/atomic"
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

// PeerDial must consult the trace-dial-options hook when one is installed —
// this is what makes tracing dial options (obs.ClientDialOptions) reach the
// corrosion replicator/anti-entropy dials, which today pass none explicitly
// and so silently drop trace propagation (finding 8).
func TestPeerDial_TraceDialOptionsHook_CalledWhenSet(t *testing.T) {
	dir := setupPKI(t)
	var calls int32
	SetTraceDialOptions(func() []grpc.DialOption {
		atomic.AddInt32(&calls, 1)
		return nil
	})
	t.Cleanup(func() { SetTraceDialOptions(nil) })

	conn, err := PeerDial(dir, "127.0.0.1:7443")
	if err != nil {
		t.Fatalf("PeerDial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("trace dial options hook called %d times; want 1", got)
	}
}

// With no hook installed, PeerDial must not panic or otherwise misbehave —
// a daemon that never calls SetTraceDialOptions (e.g. tracing inactive, or
// pre-boot-wiring code paths) still dials normally.
func TestPeerDial_TraceDialOptionsHook_UnsetIsNoop(t *testing.T) {
	dir := setupPKI(t)
	SetTraceDialOptions(nil)

	conn, err := PeerDial(dir, "127.0.0.1:7443")
	if err != nil {
		t.Fatalf("PeerDial with no hook: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
}

// The hook is set once at boot but the replicator/anti-entropy dial
// concurrently — a plain package var would race under tests/fleet. Must be
// race-clean (run with -race).
func TestPeerDial_TraceDialOptionsHook_ConcurrentSetAndDial_RaceSafe(t *testing.T) {
	dir := setupPKI(t)
	t.Cleanup(func() { SetTraceDialOptions(nil) })

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		SetTraceDialOptions(func() []grpc.DialOption { return nil })
	}()
	go func() {
		defer wg.Done()
		if conn, err := PeerDial(dir, "127.0.0.1:7443"); err == nil {
			conn.Close()
		}
	}()
	wg.Wait()
}
