package fleet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// The orphan fixture. The address sits in the fake's distinctive .100+ band, so
// it could only have come from NetBox, and well clear of anything a claim in
// these scenarios would hand out.
const (
	orphanPrefixID = 7
	orphanVRF      = 3
	orphanSubnet   = "10.0.5.0/24"
	orphanNetwork  = "bound"
	orphanIP       = "10.0.5.150"
	orphanCIDR     = "10.0.5.150/24"
	orphanMAC      = "52:54:00:0a:0b:0c"
	orphanUUID     = "6f1b0c2e-0000-4000-8000-0000000000aa"
)

// orphanAge is how far in the past a seeded orphan is stamped: comfortably past
// the sweeper's 30-minute grace, so the grace is not what any of these
// scenarios accidentally turn on.
const orphanAge = 24 * time.Hour

// boundClusterWithOrphan builds a NetBox-bound fleet holding exactly ONE
// leaked address: a real cluster identity, no local lease, no VM, no NIC row
// anywhere. That is the only shape the sweeper is ever allowed to reclaim, so
// every scenario starts from a genuinely reclaimable address and then breaks
// one part of the proof.
func boundClusterWithOrphan(t *testing.T, nodes int) (*NetBoxFake, *Cluster) {
	t.Helper()
	return boundClusterWithOrphanAged(t, nodes, time.Now().UTC().Add(-orphanAge))
}

// boundClusterWithOrphanAged is boundClusterWithOrphan with an explicit
// creation time for the leaked address, so the grace window can be exercised.
func boundClusterWithOrphanAged(t *testing.T, nodes int, created time.Time) (*NetBoxFake, *Cluster) {
	t.Helper()
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(orphanPrefixID, orphanSubnet, orphanVRF, true)

	c := NewClusterWithNetBox(t, nodes, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	mustCreateBoundNetwork(t, c, c.Nodes[0], orphanNetwork, orphanSubnet, orphanPrefixID)

	// The identity has to carry THIS cluster's fingerprint. An orphan stamped
	// with any other value is another cluster's address, which the sweeper must
	// never touch — so hardcoding one would make every scenario here vacuous.
	nb.SeedIP(orphanCIDR, orphanVRF, orphanIdentity(t, c.Nodes[0]), created)
	return nb, c
}

// orphanIdentity is the fixture's identity under this cluster's fingerprint.
func orphanIdentity(t *testing.T, n *Node) string {
	t.Helper()
	fp, err := corrosion.ClusterFingerprint(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("ClusterFingerprint on %s: %v", n.Name, err)
	}
	return netbox.Identity(fp, orphanUUID, orphanMAC)
}

// mustSweep runs one sweep pass on n. A pass NEVER errors on a refused
// reclamation — every refusal is a logged skip — so an error here means the
// sweep itself broke, which is worth failing on.
func mustSweep(t *testing.T, n *Node) {
	t.Helper()
	if err := n.Server.SweepOrphansOnce(context.Background()); err != nil {
		t.Fatalf("SweepOrphansOnce on %s: %v", n.Name, err)
	}
}

// insertLiveLease writes the ip_allocations row a live claim leaves behind.
func insertLiveLease(t *testing.T, n *Node, network, ip, mac string) {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES (?, ?, ?, ?, 'vm', '', ?, ?)`,
		network, ip, mac, "holder", n.DB.NowWall(), n.DB.NowTS()); err != nil {
		t.Fatalf("insert lease %s/%s on %s: %v", network, ip, n.Name, err)
	}
}

// pendingQueueItems counts un-acked netbox_sync_queue rows.
func pendingQueueItems(t *testing.T, n *Node) int {
	t.Helper()
	items, err := corrosion.DrainSyncQueue(context.Background(), n.DB, 100)
	if err != nil {
		t.Fatalf("DrainSyncQueue on %s: %v", n.Name, err)
	}
	return len(items)
}

// stealNetBoxLease writes the sweeper's leader lease over to another holder,
// unguarded — the state a genuine leadership handover leaves behind.
func stealNetBoxLease(t *testing.T, n *Node, holder string) {
	t.Helper()
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := n.DB.Execute(context.Background(),
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('netbox', ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET holder = excluded.holder,
		   expires_at = excluded.expires_at, updated_at = excluded.updated_at`,
		holder, expires, n.DB.NowTS()); err != nil {
		t.Fatalf("steal netbox lease on %s: %v", n.Name, err)
	}
}

// sweepMetrics records the sweeper's counters so a scenario can assert on a
// signal that reaches nothing else — a stuck lease produces no deletion and no
// error, only this counter and a log line.
type sweepMetrics struct {
	mu          sync.Mutex
	apiErrors   int
	skipped     []string
	reclaimed   int
	stuckLeases int
}

func newSweepMetrics() *sweepMetrics { return &sweepMetrics{} }

func (m *sweepMetrics) IncAPIError(netbox.ErrClass) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.apiErrors++
}

func (m *sweepMetrics) IncSweepSkipped(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.skipped = append(m.skipped, reason)
}

func (m *sweepMetrics) IncOrphansReclaimed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reclaimed++
}

func (m *sweepMetrics) IncStuckLease() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stuckLeases++
}

func (m *sweepMetrics) stuck() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stuckLeases
}
