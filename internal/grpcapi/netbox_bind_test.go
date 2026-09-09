package grpcapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/netbox"
)

// noDHCPNetworkDef is the network definition every bind test that is NOT about
// the DHCP refusal binds. It records NO SUBNET, which is a claim and not a
// convenience: litevirt starts dnsmasq only for a network with a subnet, so this
// def is the one shape check 2b provably passes over. Spelling it at every call
// site keeps the hazard input visible — a fixture that defaulted it would make
// every one of these tests silently assert the safe branch, which is exactly how
// TestExplicitClaimCrossChecksAndRefusesDisagreement came to pass for the wrong
// reason.
//
// The refusal's own scenarios are in netbox_dhcp_bind_test.go and pass real
// subnets.
var noDHCPNetworkDef = compose.NetworkDef{Type: "bridge", Interface: "lv-bind-test"}

// netboxPrefix is the fake's canned answer for GET /api/ipam/prefixes/{id}/.
type netboxPrefix struct {
	ID     int
	Prefix string
	VRFID  int // 0 = global table, no VRF
}

// requestCounter records what a fake NetBox was ASKED, so a test can pin that a
// refusal happened BEFORE anything reached the API rather than only that it
// happened. Shared by pointer, because the handler is a value receiver.
//
// It exists because "refused before any NetBox request is made" was a claim
// several refusal tests made in a comment and none of them asserted: every one
// of them would have passed against a bind that enumerated the whole prefix
// first and then refused.
type requestCounter struct {
	mu        sync.Mutex
	addresses int
	total     int
}

func (c *requestCounter) record(path string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	if strings.HasPrefix(path, "/api/ipam/ip-addresses") ||
		strings.Contains(path, "/available-ips") {
		c.addresses++
	}
}

// AddressRequests is every request to the ipam ADDRESS surface — reads included,
// because enumerating a prefix is exactly the cost these controls forbid.
func (c *requestCounter) AddressRequests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addresses
}

// Requests is every request of any kind.
func (c *requestCounter) Requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// fakeNetBox configures a fake NetBox server serving exactly the two endpoints
// validateAndBindPrefix needs: the prefix lookup and its VRF's enforce_unique
// flag. Unlike fakeNetBoxDeletes (netbox_claims_test.go), which serves the IP
// release path, this fake serves the read side of the bind flow.
type fakeNetBox struct {
	prefix        netboxPrefix
	enforceUnique bool
	// counter, when set, records every request. Optional so the fixtures that do
	// not care keep their one-line literals.
	counter *requestCounter
	// failReads makes the two bind-time precondition endpoints — the prefix and
	// its VRF — answer 500. It models the NetBox nobody can read: the state in
	// which a drift check establishes NOTHING, which is a different answer from
	// "nothing has drifted" and must never be confused with it.
	failReads bool
}

func (f fakeNetBox) handler(w http.ResponseWriter, r *http.Request) {
	f.counter.record(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if f.failReads && (strings.HasPrefix(r.URL.Path, "/api/ipam/prefixes/") ||
		strings.HasPrefix(r.URL.Path, "/api/ipam/vrfs/")) {
		http.Error(w, "fakeNetBox: this NetBox cannot be read", http.StatusInternalServerError)
		return
	}
	switch {
	case r.URL.Path == "/api/ipam/ip-addresses/" && r.Method == http.MethodGet:
		// A re-key enumerates the bound prefix before rewriting anything. An
		// empty list is the honest answer from a fake that never claimed an
		// address, and it keeps the enumeration on the real code path rather
		// than short-circuiting it with a 404.
		fmt.Fprint(w, `{"results":[],"next":""}`)
	case strings.HasPrefix(r.URL.Path, "/api/ipam/prefixes/"):
		if f.prefix.VRFID == 0 {
			fmt.Fprintf(w, `{"id":%d,"prefix":%q,"vrf":null}`, f.prefix.ID, f.prefix.Prefix)
			return
		}
		fmt.Fprintf(w, `{"id":%d,"prefix":%q,"vrf":{"id":%d}}`, f.prefix.ID, f.prefix.Prefix, f.prefix.VRFID)
	case strings.HasPrefix(r.URL.Path, "/api/ipam/vrfs/"):
		fmt.Fprintf(w, `{"id":%d,"enforce_unique":%v}`, f.prefix.VRFID, f.enforceUnique)
	case r.URL.Path == "/api/virtualization/clusters/":
		// A re-key resolves the cluster the inventory mirror writes into, then
		// enumerates it. Answering with a real id keeps the enumeration on the
		// production code path; answering 0 would short-circuit it, and the
		// re-key's inventory half would then be exercised by nothing here.
		fmt.Fprint(w, `{"count":1,"results":[{"id":77}]}`)
	case strings.HasPrefix(r.URL.Path, "/api/virtualization/virtual-machines/"),
		strings.HasPrefix(r.URL.Path, "/api/virtualization/interfaces/"):
		// Empty, like the address list above: the honest answer from a fake that
		// never mirrored anything, and it keeps the walk real.
		fmt.Fprint(w, `{"results":[],"next":""}`)
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
		dataDir:  t.TempDir(),
		db:       db,
		netbox:   client,
		events:   events.NewBus(),
		vmLocks:  make(map[string]*sync.Mutex),
		bridgeEnsure: func(string) error {
			return nil
		},
	}
	s.SetGate(fakeServerGate{enforced: true})
	// The inventory mirror is a SEPARATE opt-in (`netbox.mirror_inventory`, see
	// enfNetBoxMirror), so a fixture that only wired the client would model a
	// pure-IPAM node and every mirror scenario would pass by declining. The
	// daemon sets both from one config block; so does this. A scenario whose
	// subject IS the opt-in turns it back off explicitly.
	s.SetNetBoxMirrorInventory(true)
	return s
}

func TestBindRefusesGlobalTablePrefix(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix: netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 0}, // no VRF
	})
	err := s.validateAndBindPrefix(context.Background(), "net-a", 7, noDHCPNetworkDef)
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
	err := s.validateAndBindPrefix(context.Background(), "net-a", 7, noDHCPNetworkDef)
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
	if err := s.validateAndBindPrefix(ctx, "net-a", 7, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	err := s.validateAndBindPrefix(ctx, "net-b", 7, noDHCPNetworkDef)
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
	go func() { errA <- s.validateAndBindPrefix(ctx, "net-a", 7, noDHCPNetworkDef) }()
	go func() { errB <- s.validateAndBindPrefix(ctx, "net-b", 7, noDHCPNetworkDef) }()
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
	if err := s.validateAndBindPrefix(ctx, "net-a", 7, noDHCPNetworkDef); err != nil {
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
	err := s.validateAndBindPrefix(context.Background(), "net-a", 7, noDHCPNetworkDef)
	if err == nil {
		t.Fatal("want refusal when the latch is not durably persisted")
	}
	if !strings.Contains(err.Error(), "durably latched") {
		t.Fatalf("error must name the durable-latch requirement, got: %v", err)
	}
}

// TestBindRefusesSecondPrefixForSameNetwork pins the OTHER direction of the
// 1:1. The prefix-side check alone leaves netbox_bindings.network free to
// repeat — nothing in the schema forbids it — and a network holding two
// prefixes is a state GetBindingByNetwork (one row) cannot even represent, so
// the allocator would silently pick whichever row SQLite returned first.
func TestBindRefusesSecondPrefixForSameNetwork(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	ctx := context.Background()
	if err := s.validateAndBindPrefix(ctx, "net-a", 7, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	err := s.validateAndBindPrefix(ctx, "net-a", 8, noDHCPNetworkDef)
	if err == nil {
		t.Fatal("want refusal: one NetBox prefix per litevirt network")
	}
	if !strings.Contains(err.Error(), "already bound") {
		t.Fatalf("error must say the network is already bound, got: %v", err)
	}
	// And the refusal must not have created the second row.
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 8)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil {
		t.Fatalf("refused bind must not have claimed prefix 8, got %+v", b)
	}
}

// failNetworkInserts installs a BEFORE INSERT trigger that aborts every write
// to `networks`, which is how these tests reach the failure window between the
// prefix claim and the network row: reads still resolve (so the duplicate check
// and the bind run normally) and only the persist fails.
func failNetworkInserts(t *testing.T, s *Server) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`CREATE TRIGGER test_fail_network_insert BEFORE INSERT ON networks
		 BEGIN SELECT RAISE(ABORT, 'induced persist failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
}

// TestCreateNetworkReleasesBindingWhenUpsertFails pins the compensation. The
// prefix is claimed BEFORE the network row is written, so a failed write used
// to leave a binding with no network behind it: invisible to every operator
// command, and blocking that prefix against any later bind — including a bind
// of the same prefix under a different network name — until someone edited the
// database by hand.
func TestCreateNetworkReleasesBindingWhenUpsertFails(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	ctx := adminCtx()
	failNetworkInserts(t, s)

	_, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "net-a", Type: "sriov", Pf: "ens1f0", NetboxPrefixId: 7,
	})
	if err == nil {
		t.Fatal("CreateNetwork must fail when the network row cannot be persisted")
	}

	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil {
		t.Fatalf("a failed create must not leave the prefix bound, got %+v", b)
	}
	// The real recovery the operator needs: the prefix is bindable again, under
	// a different network name.
	if err := s.validateAndBindPrefix(ctx, "net-b", 7, noDHCPNetworkDef); err != nil {
		t.Fatalf("released prefix must be bindable again, got: %v", err)
	}
}

// TestDeleteNetworkReleasesBinding: a network that no longer exists must not
// keep holding a NetBox prefix. Nothing else in the system releases one, so
// without this the prefix stays claimed by a deleted network forever.
func TestDeleteNetworkReleasesBinding(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	ctx := adminCtx()

	if _, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "net-a", Type: "sriov", Pf: "ens1f0", NetboxPrefixId: 7,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7); err != nil || b == nil {
		t.Fatalf("create must have bound the prefix, got %+v err=%v", b, err)
	}

	if _, err := s.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "net-a"}); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}

	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil {
		t.Fatalf("deleting the network must release its prefix, got %+v", b)
	}
	if err := s.validateAndBindPrefix(ctx, "net-b", 7, noDHCPNetworkDef); err != nil {
		t.Fatalf("released prefix must be bindable by another network, got: %v", err)
	}
}
