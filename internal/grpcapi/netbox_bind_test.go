package grpcapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// netboxPrefix is the fake's canned answer for GET /api/ipam/prefixes/{id}/.
type netboxPrefix struct {
	ID     int
	Prefix string
	VRFID  int // 0 = global table, no VRF
}

// fakeNetBox configures a fake NetBox server serving exactly the two endpoints
// validateAndBindPrefix needs: the prefix lookup and its VRF's enforce_unique
// flag. Unlike fakeNetBoxDeletes (netbox_claims_test.go), which serves the IP
// release path, this fake serves the read side of the bind flow.
type fakeNetBox struct {
	prefix        netboxPrefix
	enforceUnique bool
}

func (f fakeNetBox) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/ipam/prefixes/"):
		if f.prefix.VRFID == 0 {
			fmt.Fprintf(w, `{"id":%d,"prefix":%q,"vrf":null}`, f.prefix.ID, f.prefix.Prefix)
			return
		}
		fmt.Fprintf(w, `{"id":%d,"prefix":%q,"vrf":{"id":%d}}`, f.prefix.ID, f.prefix.Prefix, f.prefix.VRFID)
	case strings.HasPrefix(r.URL.Path, "/api/ipam/vrfs/"):
		fmt.Fprintf(w, `{"id":%d,"enforce_unique":%v}`, f.prefix.VRFID, f.enforceUnique)
	default:
		http.Error(w, "fakeNetBox: unsupported path "+r.URL.Path, http.StatusNotFound)
	}
}

// newTestServerWithNetBox returns a *Server wired to a real *netbox.Client
// pointed at an in-process fake serving fb's canned prefix/VRF, with an
// in-memory corrosion DB (schema applied, a cluster row seeded so
// corrosion.ClusterFingerprint can derive a value), and a gate that reports
// netbox_ipam_v1 as durably latched — the precondition every bind test in this
// file except TestBindRefusesWhenLatchNotDurable wants satisfied by default.
func newTestServerWithNetBox(t *testing.T, fb fakeNetBox) *Server {
	t.Helper()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// ClusterFingerprint derives from cluster.ca_cert; seed a row so bind
	// validation can pin a fingerprint.
	if err := db.Execute(ctx,
		`INSERT INTO cluster (id, name, domain, ca_cert, created_at, updated_at)
		 VALUES ('default', 'test-cluster', 'test.local', 'test-ca-cert', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}

	httpSrv := httptest.NewServer(http.HandlerFunc(fb.handler))
	t.Cleanup(httpSrv.Close)

	tokenPath := filepath.Join(t.TempDir(), "netbox-token")
	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	client, err := netbox.New(netbox.Config{
		BaseURL:   httpSrv.URL,
		TokenPath: tokenPath,
		Timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("netbox.New: %v", err)
	}

	s := &Server{
		hostName: "test-host",
		db:       db,
		netbox:   client,
	}
	s.SetGate(fakeServerGate{enforced: true})
	return s
}

func TestBindRefusesGlobalTablePrefix(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix: netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 0}, // no VRF
	})
	err := s.validateAndBindPrefix(context.Background(), "net-a", 7)
	if err == nil {
		t.Fatal("want refusal for a global-table prefix")
	}
	// "global table" (not the generic substring "VRF", which every error path in
	// validateAndBindPrefix mentions somewhere) pins this to the SPECIFIC
	// global-table check, not any later VRF-uniqueness check reached instead.
	if !strings.Contains(err.Error(), "global table") {
		t.Fatalf("error must name the global-table requirement, got: %v", err)
	}
}

func TestBindRefusesVRFWithoutUniqueness(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: false,
	})
	err := s.validateAndBindPrefix(context.Background(), "net-a", 7)
	if err == nil {
		t.Fatal("want refusal when the VRF does not enforce uniqueness")
	}
}

func TestBindRefusesSecondNetworkOnSamePrefix(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	ctx := context.Background()
	if err := s.validateAndBindPrefix(ctx, "net-a", 7); err != nil {
		t.Fatal(err)
	}
	err := s.validateAndBindPrefix(ctx, "net-b", 7)
	if err == nil {
		t.Fatal("want refusal: one litevirt network per NetBox prefix")
	}
	if !strings.Contains(err.Error(), "net-a") {
		t.Fatalf("error must name the network already holding the prefix, got: %v", err)
	}
}

// TestConcurrentBindsDoNotStealThePrefix exercises the safety-critical race:
// both goroutines pass the GetBindingByPrefix check before either inserts.
// Without a non-overwriting insert plus read-back (corrosion.ClaimBinding),
// the second silently steals it.
func TestConcurrentBindsDoNotStealThePrefix(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	ctx := context.Background()
	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() { errA <- s.validateAndBindPrefix(ctx, "net-a", 7) }()
	go func() { errB <- s.validateAndBindPrefix(ctx, "net-b", 7) }()
	a, b := <-errA, <-errB
	if (a == nil) == (b == nil) {
		t.Fatalf("exactly one bind must win, got a=%v b=%v", a, b)
	}
}

func TestBindPinsClusterFingerprint(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	ctx := context.Background()
	if err := s.validateAndBindPrefix(ctx, "net-a", 7); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("bind must have recorded a binding row")
	}
	if b.ClusterFingerprint == "" {
		t.Fatal("bind must PIN the cluster fingerprint, not recompute it per call")
	}
	if b.ObservedCIDR != "10.0.5.0/24" {
		t.Fatalf("bind must record the CIDR as a drift baseline, got %q", b.ObservedCIDR)
	}
}

// TestBindRefusesWhenLatchNotDurable pins the DURABLE form of the latch check:
// a token latched only in memory (not yet persisted to its marker) must still
// refuse the bind, because that state does not survive a restart — a node
// that comes back up before the marker lands would momentarily disagree with
// the rest of the fleet about whether netbox_ipam_v1 is safe to rely on.
func TestBindRefusesWhenLatchNotDurable(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	// Latched (Enforced/Latched both true), but NOT durable.
	s.SetGate(fakeServerGate{
		enforced:          true,
		durablyLatchedTok: map[string]bool{},
	})
	err := s.validateAndBindPrefix(context.Background(), "net-a", 7)
	if err == nil {
		t.Fatal("want refusal when the latch is not durably persisted")
	}
	if !strings.Contains(err.Error(), "durably latched") {
		t.Fatalf("error must name the durable-latch requirement, got: %v", err)
	}
}
