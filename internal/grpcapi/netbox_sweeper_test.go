package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// TestSweeperParseIdentityRoundTrips pins parseIdentity as the exact inverse of
// netbox.Identity for a REAL MAC.
//
// The hazard is specific: a MAC contains colons, so a four-way split on ":"
// silently truncates "52:54:00:aa:bb:cc" to "52". Every proof would then ask
// about a MAC no NIC has, no host would ever report holding it, and the sweeper
// would delete live addresses with a complete, confident, entirely wrong proof.
func TestSweeperParseIdentityRoundTrips(t *testing.T) {
	const (
		fp   = "abcdef0123456789"
		uuid = "6f1b0c2e-0000-4000-8000-0000000000aa"
		mac  = "52:54:00:aa:bb:cc"
	)
	gotFP, gotUUID, gotMAC, ok := parseIdentity(netbox.Identity(fp, uuid, mac))
	if !ok {
		t.Fatal("a well-formed identity must parse")
	}
	if gotFP != fp || gotUUID != uuid || gotMAC != mac {
		t.Fatalf("parseIdentity = (%q, %q, %q), want (%q, %q, %q)",
			gotFP, gotUUID, gotMAC, fp, uuid, mac)
	}
}

// TestSweeperParseIdentityRejectsMalformed pins the refusals. Each rejected
// shape would otherwise be treated as a candidate under SOME fingerprint, and a
// candidate is the first step toward a delete.
func TestSweeperParseIdentityRejectsMalformed(t *testing.T) {
	for _, raw := range []string{
		"",
		"lv",
		"lv:fp",
		"lv:fp:uuid",              // no MAC at all
		"lv:fp:uuid:",             // empty MAC
		"lv::uuid:52:54:00:a:b:c", // empty fingerprint
		"lv:fp::52:54:00:a:b:c",   // empty uuid
		"xx:fp:uuid:52:54:00",     // not ours
		"someone-else",
	} {
		if _, _, _, ok := parseIdentity(raw); ok {
			t.Errorf("parseIdentity(%q) accepted a malformed identity", raw)
		}
	}
}

// TestSweeperBareAddressForms covers the reduction from NetBox's prefixed form
// to the bare host address local rows store. An address that reduced wrongly
// would match no lease, and "no lease" is the sweeper's licence to delete.
func TestSweeperBareAddressForms(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"10.0.5.100/24", "10.0.5.100", true},
		{"10.0.5.100", "10.0.5.100", true},
		{"10.0.5.100/33", "10.0.5.100", true}, // nonsense length, real host half
		{"2001:db8::5/64", "2001:db8::5", true},
		{"not-an-address/24", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := bareAddress(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("bareAddress(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestSweeperGraceTreatsUnknownAgeAsTooYoung pins the fail-closed reading of a
// missing creation timestamp. "I do not know how old this is" must never become
// "old enough to delete".
func TestSweeperGraceTreatsUnknownAgeAsTooYoung(t *testing.T) {
	cutoff := time.Now().UTC().Add(-orphanGrace)
	if olderThan(time.Time{}, cutoff) {
		t.Fatal("an object of unknown age must never be treated as past the grace window")
	}
	if olderThan(cutoff.Add(time.Minute), cutoff) {
		t.Fatal("an object created after the cutoff is inside the grace window")
	}
	if !olderThan(cutoff.Add(-time.Minute), cutoff) {
		t.Fatal("an object created before the cutoff is past the grace window")
	}
}

// TestSweeperGraceIsInertOnANetBox3DateOnlyCreated pins the two halves together
// on the version of NetBox that serves the coarse timestamp.
//
// 3.x serializes `created` as a DATE. Parsed as midnight UTC it is not merely
// imprecise, it is systematically EARLY: against a 30-minute grace window every
// object created after 00:30 UTC reads as already past it, so the window that
// keeps the sweeper off an address a create is still claiming would be open for
// nearly the whole day — the sweeper could reclaim an address seconds after it
// was issued. Refusing the layout leaves Created zero and olderThan false, so on
// 3.x the sweeper reclaims nothing and the addresses are freed by hand.
//
// Asserted through the REAL client decode, not parseCreated: the field is
// unexported to this package, and what matters is the value the sweeper's own
// input carries.
func TestSweeperGraceIsInertOnANetBox3DateOnlyCreated(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A NetBox 3.x list response: a date, no time.
		_, _ = w.Write([]byte(
			`{"results":[{"id":41,"address":"10.0.5.100/24","created":"` +
				time.Now().UTC().Format("2006-01-02") + `"}],"next":""}`))
	}))
	t.Cleanup(httpSrv.Close)

	tokenPath := filepath.Join(t.TempDir(), "netbox-token")
	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	client, err := netbox.New(netbox.Config{BaseURL: httpSrv.URL, TokenPath: tokenPath, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("netbox.New: %v", err)
	}

	ips, err := client.ListIPsByPrefix(context.Background(), "10.0.5.0/24", 3)
	if err != nil {
		t.Fatalf("ListIPsByPrefix: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("want one address, got %d", len(ips))
	}
	if !ips[0].Created.IsZero() {
		t.Fatalf("a date-only `created` must decode to the zero time (age unknown), got %v", ips[0].Created)
	}
	if olderThan(ips[0].Created, time.Now().UTC().Add(-orphanGrace)) {
		t.Fatal("an object whose age NetBox did not report must never pass the grace window")
	}
}

// TestSweeperSameHostSetIsOrderSensitiveOnSortedInput pins the membership
// comparison. Both samples come out of closedRuntimeProofSet sorted, so a
// positional compare is exact — and a set that differs anywhere must not
// compare equal, because the difference is a host the proof never asked.
func TestSweeperSameHostSetDetectsEveryDifference(t *testing.T) {
	base := []string{"a", "b", "c"}
	if !sameHostSet(base, []string{"a", "b", "c"}) {
		t.Fatal("identical sets must compare equal")
	}
	for _, other := range [][]string{
		{"a", "b"},
		{"a", "b", "c", "d"},
		{"a", "b", "d"},
		nil,
	} {
		if sameHostSet(base, other) {
			t.Errorf("sameHostSet(%v, %v) = true, want false", base, other)
		}
	}
}

// TestSweeperSkipReasonIsBounded pins that the metric label comes from the
// closed set, never from the error text. The reason strings name addresses and
// hosts; a Prometheus label built from them is unbounded cardinality, which is
// a cluster-wide memory bug rather than a diagnostic.
func TestSweeperSkipReasonIsBounded(t *testing.T) {
	err := skipf(skipHostHolds, "host %s still claims the address", "node-7")
	if got := skipReason(err); got != skipHostHolds {
		t.Fatalf("skipReason = %q, want %q", got, skipHostHolds)
	}
	if msg := err.Error(); msg != "host node-7 still claims the address" {
		t.Fatalf("the full reason must survive for the log line, got %q", msg)
	}
	if got := skipReason(errors.New("something else")); got != "error" {
		t.Fatalf("skipReason of a plain error = %q, want \"error\"", got)
	}
}

// ── the orphan-check queue ──────────────────────────────────────────────────

// The queue fixture. The identity is built from the test cluster's REAL
// fingerprint, because handleOrphanCheck drops anything stamped with another
// cluster's — an identity hardcoded here would make every scenario vacuous.
const (
	queuePrefixID = 7
	queueVRF      = 3
	queueSubnet   = "10.0.5.0/24"
	queueNetwork  = "bound"
	queueCIDR     = "10.0.5.150/24"
	queueNetBoxID = 41
	queueUUID     = "6f1b0c2e-0000-4000-8000-0000000000aa"
	queueMAC      = "52:54:00:0a:0b:0c"
)

// fakeNetBoxQueue answers the identity lookup drainOrphanChecks makes, and
// records every DELETE. Deletes are RECORDED rather than refused so a test can
// tell "nothing was deleted" apart from "the delete was attempted and failed" —
// only the first is the property these scenarios assert.
type fakeNetBoxQueue struct {
	mu       sync.Mutex
	identity string
	deleted  []int
}

func (f *fakeNetBoxQueue) Deleted() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.deleted...)
}

func (f *fakeNetBoxQueue) handler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("cf_"+netbox.IdentityField) != f.identity {
			_, _ = w.Write([]byte(`{"results":[]}`))
			return
		}
		_, _ = fmt.Fprintf(w,
			`{"results":[{"id":%d,"address":%q,"vrf":{"id":%d},"custom_fields":{%q:%q}}]}`,
			queueNetBoxID, queueCIDR, queueVRF, netbox.IdentityField, f.identity)
	case http.MethodDelete:
		f.mu.Lock()
		f.deleted = append(f.deleted, queueNetBoxID)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "fakeNetBoxQueue: unsupported method "+r.Method, http.StatusMethodNotAllowed)
	}
}

// newOrphanQueueServer builds a server whose sync queue holds exactly ONE
// orphan check — the item a failed create-compensation leaves behind —
// resolvable against a real binding through the real *netbox.Client.
func newOrphanQueueServer(t *testing.T) (*Server, *fakeNetBoxQueue) {
	t.Helper()
	ctx := context.Background()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// ClusterFingerprint derives the scope from the CA cert, so there has to be
	// a cluster row before an identity means anything at all.
	if err := db.Execute(ctx,
		`INSERT INTO cluster (id, name, domain, ca_cert, created_at, updated_at)
		 VALUES ('default', 'test', 'test.local', 'test-ca-cert', ?, ?)`,
		db.NowWall(), db.NowTS()); err != nil {
		t.Fatalf("seed cluster row: %v", err)
	}
	fp, err := corrosion.ClusterFingerprint(ctx, db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}

	nb := &fakeNetBoxQueue{identity: netbox.Identity(fp, queueUUID, queueMAC)}
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

	if ok, err := corrosion.ClaimBinding(ctx, db, corrosion.BindingRecord{
		PrefixID:           queuePrefixID,
		Network:            queueNetwork,
		ObservedCIDR:       queueSubnet,
		VRFID:              queueVRF,
		ClusterFingerprint: fp,
	}); err != nil || !ok {
		t.Fatalf("ClaimBinding: ok=%v err=%v", ok, err)
	}
	if err := corrosion.EnqueueSync(ctx, db, "orphan", nb.identity, "check"); err != nil {
		t.Fatalf("EnqueueSync: %v", err)
	}
	return &Server{hostName: "test-host", db: db, netbox: client}, nb
}

// hideLeaseTable makes every read of ip_allocations fail.
//
// It RENAMES the table: SQLite has no BEFORE SELECT trigger, so a read cannot be
// intercepted, and a missing table is the only way to produce the error a
// corrupt or unavailable ip_allocations yields. Same seam the fleet harness uses
// for fencing_log.
func hideLeaseTable(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	if err := s.db.Execute(ctx,
		`ALTER TABLE ip_allocations RENAME TO ip_allocations_hidden_by_test`); err != nil {
		t.Fatalf("hide ip_allocations: %v", err)
	}
	t.Cleanup(func() {
		if err := s.db.Execute(ctx,
			`ALTER TABLE ip_allocations_hidden_by_test RENAME TO ip_allocations`); err != nil {
			t.Logf("restore ip_allocations: %v", err)
		}
	})
}

func queueItems(t *testing.T, s *Server) []corrosion.QueueItem {
	t.Helper()
	items, err := corrosion.DrainSyncQueue(context.Background(), s.db, "orphan", 10)
	if err != nil {
		t.Fatalf("DrainSyncQueue: %v", err)
	}
	return items
}

// TestOrphanCheckKeptQueuedWhenLeaseReadFails pins that a FAILED lease read
// leaves the item queued.
//
// The stuck-lease check is the whole reason this queue exists: it is the only
// place the cluster ever learns that a compensating release never finished
// locally. Acking on a transient DB error discards that signal permanently —
// the periodic candidate pass skips any address a live lease references, so
// nothing else ever looks at it again — and the address stays leaked in both
// systems with no counter, no log line, and no way back.
func TestOrphanCheckKeptQueuedWhenLeaseReadFails(t *testing.T) {
	s, nb := newOrphanQueueServer(t)
	hideLeaseTable(t, s)

	s.drainOrphanChecks(context.Background())

	items := queueItems(t, s)
	if len(items) != 1 {
		t.Fatalf("an unreadable lease table must leave the orphan check queued, %d items remain", len(items))
	}
	if items[0].Attempts != 1 {
		t.Fatalf("attempts = %d, want 1 — an item retried without being counted can never be retired",
			items[0].Attempts)
	}
	if got := nb.Deleted(); len(got) != 0 {
		t.Fatalf("nothing may be deleted when the lease read failed, deleted %v", got)
	}
}

// TestOrphanCheckGivesUpAfterTenAttempts pins the other end of that retry: an
// item nothing can ever resolve is retired rather than re-attempted on every
// pass for the life of the cluster. It is retired LOUDLY (an ERROR naming the
// identity), because the address behind it is then reachable only by hand.
func TestOrphanCheckGivesUpAfterTenAttempts(t *testing.T) {
	s, nb := newOrphanQueueServer(t)
	ctx := context.Background()
	hideLeaseTable(t, s)

	// One attempt short of the cap, so THIS pass is the one that gives up.
	if err := s.db.Execute(ctx,
		`UPDATE netbox_sync_queue SET attempts = ?, updated_at = ?`,
		orphanCheckMaxAttempts-1, s.db.NowTS()); err != nil {
		t.Fatalf("seed attempts: %v", err)
	}

	s.drainOrphanChecks(ctx)

	if items := queueItems(t, s); len(items) != 0 {
		t.Fatalf("an item that has failed %d times must be retired, %d still queued",
			orphanCheckMaxAttempts, len(items))
	}
	if got := nb.Deleted(); len(got) != 0 {
		t.Fatalf("giving up must delete nothing, deleted %v", got)
	}
}

// ── the leader lease ────────────────────────────────────────────────────────

// leaseServer is a Server with an initialised schema and nothing else — the
// lease predicate reads one table and needs no NetBox, no cluster row and no
// fingerprint.
func leaseServer(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{db: db, hostName: "lease-host"}
}

// seedLease writes the `netbox` leader_election row verbatim, so a test can
// place an expiry the acquire path would never produce.
func seedLease(t *testing.T, s *Server, holder string, expires time.Time) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`INSERT OR REPLACE INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES (?, ?, ?, ?)`,
		netBoxLeaseKey, holder,
		expires.UTC().Format(time.RFC3339), s.db.NowTS()); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
}

// TestHoldsLeaderLeaseFalseWhenExpired is the reason this predicate reads
// expires_at at all.
//
// A lease is not ours because our name is still in the row — it is ours until
// the TTL runs out. Nothing obliges a peer to overwrite the row the instant we
// expire (it may be busy, unreachable, or simply not yet at its tick), so the
// stale row keeps naming us for as long as no one else writes. A holder-only
// predicate reads that as "still leader" forever, and the sweeper's per-batch
// re-validation — and the five-step orphan proof's re-check before a
// destructive delete — go on resting on a lease no other node would honour.
func TestHoldsLeaderLeaseFalseWhenExpired(t *testing.T) {
	s := leaseServer(t)
	seedLease(t, s, s.hostName, time.Now().Add(-time.Minute))

	if s.holdsLeaderLease(context.Background()) {
		t.Fatal("an EXPIRED lease still naming this host must not read as held — " +
			"the holder is checked but the TTL is not")
	}
}

// TestHoldsLeaderLeaseTrueWhenHeldAndFresh is the other side: the expiry check
// must not make the predicate say no to a lease this node genuinely holds, or
// every sweep would abort at its first batch boundary.
func TestHoldsLeaderLeaseTrueWhenHeldAndFresh(t *testing.T) {
	s := leaseServer(t)
	seedLease(t, s, s.hostName, time.Now().Add(2*time.Minute))

	if !s.holdsLeaderLease(context.Background()) {
		t.Fatal("a lease held by this host with a future expiry must read as held")
	}
}

// TestHoldsLeaderLeaseFailsClosed pins the fail-closed branches. Each is a
// state a real cluster can produce — a peer took the lease, the row is absent
// before any node has acquired, a mixed-version or hand-edited row carries an
// empty or malformed expires_at — and every one of them must read as "not
// ours", because a lease we cannot PROVE we hold is one we do not hold.
func TestHoldsLeaderLeaseFailsClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("no row at all", func(t *testing.T) {
		s := leaseServer(t)
		if s.holdsLeaderLease(ctx) {
			t.Fatal("an absent lease row must not read as held")
		}
	})

	t.Run("held by a peer", func(t *testing.T) {
		s := leaseServer(t)
		seedLease(t, s, "other-host", time.Now().Add(2*time.Minute))
		if s.holdsLeaderLease(ctx) {
			t.Fatal("a lease held by a peer must not read as held")
		}
	})

	t.Run("unparseable expiry", func(t *testing.T) {
		s := leaseServer(t)
		seedLease(t, s, s.hostName, time.Now().Add(2*time.Minute))
		if err := s.db.Execute(ctx,
			`UPDATE leader_election SET expires_at = 'not-a-timestamp' WHERE key = ?`,
			netBoxLeaseKey); err != nil {
			t.Fatalf("corrupt expiry: %v", err)
		}
		if s.holdsLeaderLease(ctx) {
			t.Fatal("an unparseable expires_at must not read as held")
		}
	})

	t.Run("empty expiry", func(t *testing.T) {
		s := leaseServer(t)
		seedLease(t, s, s.hostName, time.Now().Add(2*time.Minute))
		if err := s.db.Execute(ctx,
			`UPDATE leader_election SET expires_at = '' WHERE key = ?`,
			netBoxLeaseKey); err != nil {
			t.Fatalf("blank expiry: %v", err)
		}
		if s.holdsLeaderLease(ctx) {
			t.Fatal("a missing expires_at must not read as held")
		}
	})
}

// TestAcquireNetBoxLeaseStillSucceeds guards the interaction between the new
// predicate and the acquire path: acquireNetBoxLease returns holdsLeaderLease,
// so an expiry format the writer produces and the reader cannot parse would
// make the sweeper unable to ever take its own lease.
func TestAcquireNetBoxLeaseStillSucceeds(t *testing.T) {
	s := leaseServer(t)
	if !s.acquireNetBoxLease(context.Background(), time.Minute) {
		t.Fatal("a node acquiring an unheld lease must read it back as held — " +
			"the acquire path's expires_at format and the read-back's parse disagree")
	}
}
