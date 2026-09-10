package grpcapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/netbox"
)

// phaseTestClient is a NetBox client pointed at a server that answers nothing.
// netboxMirror only needs a NON-NIL client to build a reconciler; this test
// never runs a pass.
func phaseTestClient(t *testing.T) *netbox.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("t\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := netbox.New(netbox.Config{BaseURL: srv.URL, TokenPath: tok, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The mirror and the orphan sweeper's maintenance loop run on the same
// configured cadence, serialise on this node's nbPassMu, and are started by the
// daemon microseconds apart. Equal-period tickers created together stay in
// lockstep, so without a skew the mirror's sweep reaches the gate second every
// interval and is declined for the life of the process.
//
// That starves the whole mirror, not one tick: the sweep is the only caller that
// acquires the leader lease, and the queue poll acts only on a lease already
// held — so no node leads, the poll can never pull queued work forward, and no
// inventory is written at all. Nothing fails while this happens, which is why
// the skew has to be pinned where it is decided rather than only where it is
// obeyed.
func TestMirrorIsBuiltHalfAnIntervalOffTheMaintenanceLoop(t *testing.T) {
	for _, interval := range []time.Duration{
		20 * time.Second,
		2 * time.Minute,
		15 * time.Minute,
	} {
		s := &Server{netbox: phaseTestClient(t)}
		m := s.netboxMirror(interval)
		if got, want := m.SweepPhase(), interval/2; got != want {
			t.Errorf("interval %v: sweep phase = %v, want %v — the mirror would tick "+
				"in lockstep with maintenance and be declined every pass", interval, got, want)
		}
	}
}

// An unset `netbox.sweep_interval_sec` arrives as zero and is normalised to the
// default cadence. The skew must be half of what the loop ACTUALLY runs at, not
// half of the raw zero — a zero phase is exactly the starvation this prevents,
// and it is the default deployment that would carry it.
func TestMirrorSweepPhaseIsHalfTheEffectiveIntervalWhenUnconfigured(t *testing.T) {
	s := &Server{netbox: phaseTestClient(t)}
	m := s.netboxMirror(0)
	want := defaultNetBoxSweepInterval / 2
	if got := m.SweepPhase(); got != want {
		t.Fatalf("sweep phase for an unset interval = %v, want %v", got, want)
	}
}
