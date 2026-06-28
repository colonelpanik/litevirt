package fleet

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/lxc"
)

// fleetCtRuntime is a fake lxc.Runtime for the fleet harness: there is no LXC on
// the box, so we model the runtime as an in-memory name→state map and record the
// CreateOpts a recreate passes (so a test can prove networking was rebuilt from
// the create_spec). Only Create/Start/State/Delete carry behaviour; the rest are
// no-ops sufficient to satisfy the interface.
type fleetCtRuntime struct {
	mu      sync.Mutex
	created map[string]lxc.CreateOpts
	state   map[string]lxc.State
}

func newFleetCtRuntime() *fleetCtRuntime {
	return &fleetCtRuntime{created: map[string]lxc.CreateOpts{}, state: map[string]lxc.State{}}
}

func (r *fleetCtRuntime) Create(_ context.Context, opts lxc.CreateOpts) (*lxc.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.created[opts.Name] = opts
	r.state[opts.Name] = lxc.StateStopped
	return &lxc.Container{Name: opts.Name, State: lxc.StateStopped, Image: opts.Template}, nil
}

func (r *fleetCtRuntime) Start(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.state[name]; !ok {
		return fmt.Errorf("no such container %q", name)
	}
	r.state[name] = lxc.StateRunning
	return nil
}

func (r *fleetCtRuntime) State(_ context.Context, name string) (lxc.State, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.state[name]; ok {
		return s, nil
	}
	return lxc.StateUnknown, nil // not present here → recreate proceeds
}

func (r *fleetCtRuntime) Delete(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.state, name)
	delete(r.created, name)
	return nil
}

// snapshot returns the recorded create opts + live state for a container.
func (r *fleetCtRuntime) snapshot(name string) (lxc.CreateOpts, lxc.State, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.state[name]
	return r.created[name], s, ok
}

// Remaining lxc.Runtime methods are no-ops for this scenario.
func (r *fleetCtRuntime) Stop(context.Context, string, int) error             { return nil }
func (r *fleetCtRuntime) Exec(context.Context, string, []string) (lxc.ExecResult, error) {
	return lxc.ExecResult{}, nil
}
func (r *fleetCtRuntime) IP(context.Context, string) (string, error)      { return "", nil }
func (r *fleetCtRuntime) List(context.Context) ([]string, error)          { return nil, nil }
func (r *fleetCtRuntime) Freeze(context.Context, string) error            { return nil }
func (r *fleetCtRuntime) Unfreeze(context.Context, string) error          { return nil }
func (r *fleetCtRuntime) RootFSPath(string) (string, error)               { return "", nil }
func (r *fleetCtRuntime) ExportContainer(context.Context, string, io.Writer) error { return nil }
func (r *fleetCtRuntime) ImportContainer(context.Context, string, io.Reader) error { return nil }
func (r *fleetCtRuntime) RevertContainer(context.Context, string, io.Reader) error { return nil }
func (r *fleetCtRuntime) CloneContainer(context.Context, string, string) error     { return nil }
func (r *fleetCtRuntime) Stats(context.Context, string) (lxc.ContainerStats, error) {
	return lxc.ContainerStats{}, nil
}

// converge runs one bidirectional anti-entropy repair between a and b over the
// REAL StreamStateDump → MergeStateBytesLWW path (the production convergence
// mechanism), so a relocation written on one survivor propagates to the other.
func converge(t *testing.T, c *Cluster, a, b *Node) {
	t.Helper()
	blob, err := peerPull(c, a, b) // a pulls b's dump
	if err != nil {
		t.Fatalf("converge pull %s←%s: %v", a.Name, b.Name, err)
	}
	a.DB.MergeStateBytesLWW(blob)
	blob, err = peerPull(c, b, a) // b pulls a's dump
	if err != nil {
		t.Fatalf("converge pull %s←%s: %v", b.Name, a.Name, err)
	}
	b.DB.MergeStateBytesLWW(blob)
}

// TestFleet_ChaosContainerRelocationUnderNodeKill is the end-to-end chaos drill
// PR #57 needed: a relocatable container lives on a node, that node is KILLED
// (partitioned away + a fresh quorum reports it down), the REAL failover
// coordinator on a survivor fences it and re-homes the container, the REAL
// container reconciler on the chosen survivor recreates it (rebuilding managed
// networking from the persisted create_spec), and the relocation replicates over
// the real anti-entropy path. It then asserts CONTAINER + CLUSTER + DB + AUDIT are
// all consistent afterward: exactly one live copy on a survivor (source
// tombstoned everywhere), the victim no longer active, both survivor DBs
// converged, and the per-host audit chain intact. Only the LXC runtime is faked
// (no LXC on the box); everything else is the production code path.
func TestFleet_ChaosContainerRelocationUnderNodeKill(t *testing.T) {
	c := New(t, Options{Nodes: 3}) // independent DBs → exercises real replication
	ctx := context.Background()
	victim, survA, survB := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")
	now := time.Now().UTC()

	// A relocatable container "web" lives on the victim, with litevirt-managed
	// networking recorded in its create_spec (v34) — the state a bare image-recreate
	// must faithfully rebuild.
	spec := corrosion.ContainerCreateSpec{
		Template: "download", Distro: "alpine", Release: "3.19", Arch: "amd64",
		Networks: []corrosion.ContainerNetwork{{Name: "eth0", Bridge: "br-test", IP: "10.9.9.9", MAC: "52:54:00:12:34:56"}},
	}
	if err := corrosion.UpsertContainer(ctx, survA.DB, corrosion.ContainerRecord{
		HostName: victim.Name, Name: "web", State: "running", Image: "alpine:3.19",
		CPULimit: 1, MemMiB: 256, OnHostFailure: "image-recreate",
		CreateSpec: corrosion.EncodeCreateSpec(spec),
	}); err != nil {
		t.Fatalf("seed container: %v", err)
	}
	converge(t, c, survA, survB) // start the cluster converged

	// ── KILL the victim: sever its replication + a fresh quorum reports it down. ──
	c.Partition(victim, survA)
	c.Partition(victim, survB)
	seedHealth(t, survA, []string{survA.Name, survB.Name}, victim.Name, 5, now.Format(time.RFC3339))

	var fences atomic.Int32
	coord := failover.NewCoordinator(survA.Name, survA.DB)
	coord.Now = func() time.Time { return now }
	coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences.Add(1)
		return fence.Result{Method: "fleet-test", Success: true}
	})
	// Restorer left nil → exercises the image-recreate relocation tier (tier-1).
	coord.RunOnce(ctx)

	if fences.Load() != 1 {
		t.Fatalf("expected exactly one fence of the killed victim, got %d", fences.Load())
	}
	if h, _ := corrosion.GetHost(ctx, survA.DB, victim.Name); h == nil || h.State == "active" {
		t.Fatalf("killed victim must not remain active, got %+v", h)
	}

	// The coordinator re-keyed "web" to a survivor as pending+relocate-recreate.
	target := relocatedTarget(t, ctx, survA.DB, "web", []string{survA.Name, survB.Name})

	// Converge so the chosen target's own DB carries the pending row, then run the
	// REAL container reconciler there against a fake runtime.
	converge(t, c, survA, survB)
	rt := newFleetCtRuntime()
	health.NewContainerChecker(target, c.Node(target).DB, rt).SweepOnce(ctx)
	converge(t, c, survA, survB) // propagate the recreate result back

	// ── VERIFY: container + cluster + DB + audit are all consistent. ──
	for _, n := range []*Node{survA, survB} {
		if r, _ := corrosion.GetContainer(ctx, n.DB, victim.Name, "web"); r != nil {
			t.Fatalf("%s: the killed victim's web row must be tombstoned, got %+v", n.Name, r)
		}
		got, _ := corrosion.GetContainer(ctx, n.DB, target, "web")
		if got == nil || got.State != "running" {
			t.Fatalf("%s: web should be running on %s after relocation, got %+v", n.Name, target, got)
		}
		if got != nil && got.StateDetail != "" {
			t.Fatalf("%s: relocate marker not cleared on web, detail=%q", n.Name, got.StateDetail)
		}
		// No second live copy anywhere (the other survivor must not own it).
		other := survA.Name
		if target == survA.Name {
			other = survB.Name
		}
		if r, _ := corrosion.GetContainer(ctx, n.DB, other, "web"); r != nil {
			t.Fatalf("%s: web must exist on exactly one host; also found a copy on %s", n.Name, other)
		}
		if _, badID, err := corrosion.VerifyAuditChain(ctx, n.DB); err != nil || badID != "" {
			t.Fatalf("%s: audit chain broken (badID=%q err=%v)", n.Name, badID, err)
		}
	}
	if n := rowCount(t, survA, `SELECT count(*) AS n FROM audit_log WHERE action='ct.relocate.recreate' AND target='web'`); n == 0 {
		t.Fatal("expected a ct.relocate.recreate audit row for web")
	}

	// The container REALLY materialized on the target's runtime, with managed
	// networking reconstructed from the create_spec (the PR #57 fidelity fix).
	opts, st, ok := rt.snapshot("web")
	if !ok || st != lxc.StateRunning {
		t.Fatalf("web not running on the target runtime (present=%v state=%v)", ok, st)
	}
	if len(opts.Network) != 1 || opts.Network[0].Bridge != "br-test" || opts.Network[0].IP != "10.9.9.9" {
		t.Fatalf("recreate did not rebuild managed networking from create_spec: %+v", opts.Network)
	}
}

// relocatedTarget finds the survivor the coordinator re-keyed name to
// (state=pending, detail=relocate-recreate), failing if it isn't exactly one.
func relocatedTarget(t *testing.T, ctx context.Context, db *corrosion.Client, name string, survivors []string) string {
	t.Helper()
	var found []string
	for _, s := range survivors {
		if r, _ := corrosion.GetContainer(ctx, db, s, name); r != nil &&
			r.State == "pending" && r.StateDetail == corrosion.ContainerRelocateRecreateDetail {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one relocate-recreate target for %q, got %v", name, found)
	}
	return found[0]
}
