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
	"github.com/litevirt/litevirt/internal/network"
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
	cs.add(claimedAddr{Network: "n", IP: "10.0.5.100", OwnerKind: "vm", OwnerHost: "", NetBoxID: 41, Identity: "id-1"})
	cs.add(claimedAddr{Network: "n", IP: "10.0.5.101", OwnerKind: "vm", OwnerHost: "", NetBoxID: 42, Identity: "id-2"})

	cs.releaseAll(context.Background())

	if len(nb.Released()) != 2 {
		t.Fatalf("every claim must be released on rollback, got %v", nb.Released())
	}
}

func TestClaimSetEnqueuesOrphanCheckWhenReleaseFails(t *testing.T) {
	s, nb := newTestServerWithFakeNetBox(t)
	nb.FailRelease = true
	cs := &claimSet{srv: s}
	cs.add(claimedAddr{Network: "n", IP: "10.0.5.100", OwnerKind: "vm", OwnerHost: "", NetBoxID: 41, Identity: "id-1"})

	cs.releaseAll(context.Background())

	// A release that fails during rollback leaves an address nothing references.
	// It MUST become a sweeper candidate, or it is stranded forever.
	items, err := corrosion.DrainSyncQueue(context.Background(), s.db, "orphan", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Key != "id-1" {
		t.Fatalf("want an orphan check enqueued, got %v", items)
	}
}

// TestClaimSetTombstonesTheLocalLeaseBeforeReleasingNetBox pins that rollback
// undoes BOTH halves of a claim.
//
// A successful claim persists a local ip_allocations lease as well as the NetBox
// object. Compensating only the remote half leaves a live lease for a VM that
// was never created: the orphan sweeper deliberately skips any address a live
// local lease references, so nothing would ever reclaim it, and a later create
// handed that same address by NetBox would fail its read-back against the stale
// row.
func TestClaimSetTombstonesTheLocalLeaseBeforeReleasingNetBox(t *testing.T) {
	s, nb := newTestServerWithFakeNetBox(t)
	ctx := context.Background()

	// The state a successful claim leaves behind: a live lease owned by the VM.
	const mac = "52:54:00:aa:bb:cc"
	ip, err := network.AllocateIPFor(ctx, s.db, "n", "10.0.5.0/24", mac, "vm", "", "vm-1")
	if err != nil {
		t.Fatalf("seed lease: %v", err)
	}

	cs := &claimSet{srv: s}
	cs.add(claimedAddr{Network: "n", IP: ip, MAC: mac, OwnerKind: "vm", OwnerHost: "", Name: "vm-1", NetBoxID: 41, Identity: "id-1"})

	cs.releaseAll(ctx)

	rows, err := s.db.Query(ctx,
		`SELECT ip FROM ip_allocations WHERE network = 'n' AND ip = ? AND deleted_at IS NULL`, ip)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("rollback must tombstone the local lease for %s, it is still live", ip)
	}
	if got := nb.Released(); len(got) != 1 || got[0] != 41 {
		t.Fatalf("rollback must also release the NetBox object, got %v", got)
	}
}

// TestClaimSetSkipsTheNetBoxDeleteWhenTheLocalTombstoneFails pins the ORDER,
// which is the safety half of the previous test.
//
// Freeing the address in NetBox while litevirt still holds the lease lets
// another system take an address litevirt believes is its own — the one
// direction that cannot be repaired by a sweep. So a local tombstone that does
// not happen must stop the remote delete, and hand the address to the sweeper.
func TestClaimSetSkipsTheNetBoxDeleteWhenTheLocalTombstoneFails(t *testing.T) {
	s, nb := newTestServerWithFakeNetBox(t)
	ctx := context.Background()

	// The lease is held by a DIFFERENT owner, so the owner-scoped release
	// refuses it — the same refusal a stale or mismatched rollback would hit.
	const mac = "52:54:00:aa:bb:cc"
	ip, err := network.AllocateIPFor(ctx, s.db, "n", "10.0.5.0/24", mac, "vm", "", "someone-else")
	if err != nil {
		t.Fatalf("seed lease: %v", err)
	}

	cs := &claimSet{srv: s}
	cs.add(claimedAddr{Network: "n", IP: ip, MAC: mac, OwnerKind: "vm", OwnerHost: "", Name: "vm-1", NetBoxID: 41, Identity: "id-1"})

	cs.releaseAll(ctx)

	if got := nb.Released(); len(got) != 0 {
		t.Fatalf("the NetBox object must NOT be released while the lease is still held, got %v", got)
	}
	items, err := corrosion.DrainSyncQueue(ctx, s.db, "orphan", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Key != "id-1" {
		t.Fatalf("want an orphan check enqueued for the address left behind, got %v", items)
	}
}

// TestReleaseAllUsesTheRecordedOwner pins that rollback tombstones the lease by
// the owner triple the CLAIM recorded, not by an owner the rollback assumes.
//
// ReleaseLease is owner-scoped and refuses a row whose (kind, host, name) it
// does not match. A rollback that hardcoded one claimant's owner would, for any
// other claimant, fail its tombstone, skip the NetBox delete by the safety rule
// above, and strand the address behind a lease nothing will ever reclaim — and
// it would do so silently, because a failed tombstone is only a warning.
func TestReleaseAllUsesTheRecordedOwner(t *testing.T) {
	const (
		mac    = "52:54:00:dd:ee:ff"
		subnet = "10.0.5.0/24"
	)

	t.Run("the recorded owner releases the lease", func(t *testing.T) {
		s, nb := newTestServerWithFakeNetBox(t)
		ctx := context.Background()

		// A claimant that is NOT a VM: host-scoped, different kind and name.
		ip, err := network.AllocateIPFor(ctx, s.db, "n", subnet, mac, "ct", "host-1", "ct-1")
		if err != nil {
			t.Fatalf("seed lease: %v", err)
		}

		cs := &claimSet{srv: s}
		cs.add(claimedAddr{
			Network: "n", IP: ip, MAC: mac,
			OwnerKind: "ct", OwnerHost: "host-1", Name: "ct-1",
			NetBoxID: 41, Identity: "id-1",
		})

		cs.releaseAll(ctx)

		rows, err := s.db.Query(ctx,
			`SELECT ip FROM ip_allocations WHERE network = 'n' AND ip = ? AND deleted_at IS NULL`, ip)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Fatalf("rollback must tombstone the lease held by ct/host-1/ct-1 for %s, it is still live", ip)
		}
		if got := nb.Released(); len(got) != 1 || got[0] != 41 {
			t.Fatalf("rollback must release the NetBox object once the lease is gone, got %v", got)
		}
	})

	t.Run("a mismatched owner releases nothing", func(t *testing.T) {
		s, nb := newTestServerWithFakeNetBox(t)
		ctx := context.Background()

		ip, err := network.AllocateIPFor(ctx, s.db, "n", subnet, mac, "ct", "host-1", "ct-1")
		if err != nil {
			t.Fatalf("seed lease: %v", err)
		}

		// The owner triple the old hardcoded rollback would have used.
		cs := &claimSet{srv: s}
		cs.add(claimedAddr{
			Network: "n", IP: ip, MAC: mac,
			OwnerKind: "vm", OwnerHost: "", Name: "ct-1",
			NetBoxID: 41, Identity: "id-1",
		})

		cs.releaseAll(ctx)

		rows, err := s.db.Query(ctx,
			`SELECT ip FROM ip_allocations WHERE network = 'n' AND ip = ? AND deleted_at IS NULL`, ip)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("a mismatched owner must NOT tombstone someone else's lease for %s", ip)
		}
		if got := nb.Released(); len(got) != 0 {
			t.Fatalf("the NetBox object must NOT be released while the lease is still live, got %v", got)
		}
		items, err := corrosion.DrainSyncQueue(ctx, s.db, "orphan", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 || items[0].Key != "id-1" {
			t.Fatalf("want an orphan check enqueued for the address left behind, got %v", items)
		}
	})
}
