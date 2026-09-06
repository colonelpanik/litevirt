package grpcapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// fakeNetBoxDeletes is a minimal NetBox stand-in that serves only the
// DELETE /api/ipam/ip-addresses/{id}/ endpoint releaseAll calls. It records
// every id it releases so a test can assert on the actual set the real
// *netbox.Client's request path produced, rather than on a hand-rolled seam.
type fakeNetBoxDeletes struct {
	mu          sync.Mutex
	released    []int
	FailRelease bool
}

// Released returns a snapshot of the ids that were released.
func (f *fakeNetBoxDeletes) Released() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]int, len(f.released))
	copy(out, f.released)
	return out
}

func (f *fakeNetBoxDeletes) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "fakeNetBoxDeletes: unsupported method "+r.Method, http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/ipam/ip-addresses/"), "/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "fakeNetBoxDeletes: bad id in path "+r.URL.Path, http.StatusBadRequest)
		return
	}
	if f.FailRelease {
		http.Error(w, "fakeNetBoxDeletes: forced failure", http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.released = append(f.released, id)
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// newTestServerWithFakeNetBox returns a bare *Server (real in-memory corrosion
// DB, schema applied) wired to a real *netbox.Client pointed at an in-process
// fake NetBox server. Going through the real client — rather than a hand-rolled
// interface — means releaseAll exercises the real HTTP request path (method,
// URL, status handling) that production runs.
func newTestServerWithFakeNetBox(t *testing.T) (*Server, *fakeNetBoxDeletes) {
	t.Helper()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	nb := &fakeNetBoxDeletes{}
	httpSrv := httptest.NewServer(http.HandlerFunc(nb.handler))
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
	return s, nb
}

func TestClaimSetReleasesEveryClaim(t *testing.T) {
	s, nb := newTestServerWithFakeNetBox(t)
	cs := &claimSet{srv: s}
	cs.add(claimedAddr{Network: "n", IP: "10.0.5.100", NetBoxID: 41, Identity: "id-1"})
	cs.add(claimedAddr{Network: "n", IP: "10.0.5.101", NetBoxID: 42, Identity: "id-2"})

	cs.releaseAll(context.Background())

	if len(nb.Released()) != 2 {
		t.Fatalf("every claim must be released on rollback, got %v", nb.Released())
	}
}

func TestClaimSetEnqueuesOrphanCheckWhenReleaseFails(t *testing.T) {
	s, nb := newTestServerWithFakeNetBox(t)
	nb.FailRelease = true
	cs := &claimSet{srv: s}
	cs.add(claimedAddr{Network: "n", IP: "10.0.5.100", NetBoxID: 41, Identity: "id-1"})

	cs.releaseAll(context.Background())

	// A release that fails during rollback leaves an address nothing references.
	// It MUST become a sweeper candidate, or it is stranded forever.
	items, err := corrosion.DrainSyncQueue(context.Background(), s.db, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Key != "id-1" {
		t.Fatalf("want an orphan check enqueued, got %v", items)
	}
}
