// Harness pieces the orphan-sweeper scenarios need: taking one node down,
// bringing one back, writing a row that exists on exactly one node, and
// breaking a specific READ.
//
// Each of these models something the sweeper's safety argument depends on, and
// each is here rather than in a test file because it needs Cluster/Node state.

package fleet

import (
	"context"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// ── reachability overlay ────────────────────────────────────────────────────

// reachSet is the set of peers the fleet declares currently REACHABLE.
//
// It exists because nothing in the in-process fleet populates health.Checker's
// peer table: the probe loop is never started, so HealthyPeers is permanently
// empty and every host reads as "not currently up". That default is the safe
// one for the sweeper (an unreachable host is only excluded with fence
// evidence on top), but it leaves no way to model the case that matters most —
// a fenced host that came BACK, whose live state must override the operator's
// stale attestation.
type reachSet struct {
	mu    sync.Mutex
	names map[string]bool
}

func newReachSet() *reachSet { return &reachSet{names: map[string]bool{}} }

func (r *reachSet) add(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names[name] = true
}

func (r *reachSet) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.names))
	for n := range r.names {
		out = append(out, n)
	}
	return out
}

// fleetGate is a health.Checker with the reachability overlay unioned into
// HealthyPeers. Every other gate decision is the checker's own, unchanged — the
// overlay is empty unless a scenario calls Rejoin, so wiring it everywhere
// leaves every existing scenario byte-for-byte as it was.
type fleetGate struct {
	*health.Checker
	reach *reachSet
}

func (g *fleetGate) HealthyPeers(ctx context.Context) []string {
	out := g.Checker.HealthyPeers(ctx)
	seen := map[string]bool{}
	for _, h := range out {
		seen[h] = true
	}
	for _, h := range g.reach.list() {
		if !seen[h] {
			out = append(out, h)
		}
	}
	return out
}

// Rejoin declares this node reachable again to every node's gate.
//
// It is the counterpart to a fence confirmation: the attestation says "this
// host is down", and a rejoin is what makes that attestation stale. The sweeper
// must then go back to ASKING this host rather than assuming it away.
func (n *Node) Rejoin() { n.cluster.reach.add(n.Name) }

// ── taking a node down ──────────────────────────────────────────────────────

// Stop takes one daemon off the network: its gRPC server stops serving and its
// listener closes, so a peer's dial fails at the transport, exactly as a
// powered-off or segmented host does. The node's DB stays open, because
// Cluster.Stop still has to close it and because a scenario may want to inspect
// it afterwards. Idempotent — Cluster.Stop runs over every node regardless.
func (n *Node) Stop() {
	if n.selfConn != nil {
		_ = n.selfConn.Close()
		n.selfConn = nil
	}
	if n.GRPCSrv != nil {
		n.GRPCSrv.Stop()
	}
	if n.Listener != nil {
		_ = n.Listener.Close()
	}
}

// ── a row that exists on exactly one node ───────────────────────────────────

// InsertLocalNICRow writes a vm_nics row into THIS node's database only.
//
// It is the peer-only row the whole per-host proof exists for. No stub is
// involved: the fleet harness deliberately does not run the replicator's
// background push loop (peers are discovered via gossip, which the in-process
// fleet does not join), so a write here reaches no other node until a scenario
// explicitly drives anti-entropy — and this one never does. The leader's own
// database therefore cannot see this NIC, which is precisely the asymmetry
// replication lag produces in production.
func (n *Node) InsertLocalNICRow(t *testing.T, vmName, mac, ip string) {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`INSERT INTO vm_nics (vm_name, id, network_name, model, mac, ordinal, ip, updated_at)
		 VALUES (?, ?, ?, 'virtio', ?, 0, ?, ?)`,
		vmName, "nic-0", "bound", mac, ip, n.DB.NowTS()); err != nil {
		t.Fatalf("insert local vm_nics row on %s: %v", n.Name, err)
	}
}

// ── breaking one specific read ──────────────────────────────────────────────

// FailFencingLogRead makes every SELECT against this node's fencing_log fail.
//
// It RENAMES the table rather than installing a trigger: SQLite has no BEFORE
// SELECT trigger, so a read cannot be intercepted, and a missing table is the
// only way to produce the error a corrupt or unavailable fencing_log yields.
// The rename is reversed on cleanup so nothing leaks into another scenario
// sharing the process.
func (n *Node) FailFencingLogRead(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := n.DB.Execute(ctx,
		`ALTER TABLE fencing_log RENAME TO fencing_log_hidden_by_test`); err != nil {
		t.Fatalf("hide fencing_log on %s: %v", n.Name, err)
	}
	t.Cleanup(func() {
		if err := n.DB.Execute(ctx,
			`ALTER TABLE fencing_log_hidden_by_test RENAME TO fencing_log`); err != nil {
			t.Logf("restore fencing_log on %s: %v", n.Name, err)
		}
	})
}

// ── sweeper seams ───────────────────────────────────────────────────────────

// OnProofCollected installs the hook the sweeper runs between its two
// eligible-host samples.
func (n *Node) OnProofCollected(fn func()) { n.Server.SetOnProofCollected(fn) }

// AddHostRow registers a brand-new host in every node's database. Called from
// OnProofCollected, it is a member joining DURING proof collection — a host the
// proof never asked and therefore cannot speak for.
func (c *Cluster) AddHostRow(t *testing.T, name string) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		if err := corrosion.InsertHost(ctx, n.DB, corrosion.HostRecord{
			Name:    name,
			Address: "127.0.0.1",
			// A port nothing listens on. The host joins AFTER the proofs are
			// gathered, so the second sample is where it shows up — either as a
			// member the closure cannot reach or as a set that no longer matches
			// the first. Both abort the reclamation, so it needs no daemon.
			GRPCPort:      1,
			SSHUser:       "root",
			SSHPort:       22,
			State:         "active",
			FenceStrategy: "best-effort",
			CPUTotal:      64,
			MemTotal:      262144,
		}); err != nil {
			t.Fatalf("insert host row %q on %s: %v", name, n.Name, err)
		}
	}
}
