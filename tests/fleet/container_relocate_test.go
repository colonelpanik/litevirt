package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
)

// Host-loss relocation is the other genuinely multi-node container path: when a
// host is fenced, its containers' rootfs died with it, so the coordinator
// re-homes what it can rebuild (a re-pullable image) and refuses to touch what
// it cannot (coordinator.go:1338).
//
// The refusals are the part worth pinning. A container whose data cannot be
// recovered must be left VISIBLE for an operator rather than silently recreated
// empty or dropped — and a same-name container already running on the survivor
// must never be clobbered by the relocation of an unrelated one (container
// names are keyed (host_name, name), not cluster-unique).

// fenceVictim marks victim as failed by quorum and runs one coordinator cycle on
// coordNode, returning how many times the fencer fired.
//
// The health rows must be RFC3339: the coordinator's freshness gate compares
// against an RFC3339 cutoff, and SQLite's space-separated datetime('now') sorts
// before any 'T'-separated stamp, so such a row reads as permanently stale and
// never reaches quorum (see failover_test.go).
func fenceVictim(t *testing.T, c *Cluster, coordNode, victim *Node, observers ...*Node) int {
	t.Helper()
	ctx := context.Background()
	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, o := range observers {
		if err := coordNode.DB.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', 5, NULL, ?)`,
			o.Name, victim.Name, nowRFC); err != nil {
			t.Fatalf("insert health from %s: %v", o.Name, err)
		}
	}
	fences := 0
	coord := failover.NewCoordinator(coordNode.Name, coordNode.DB)
	coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "fleet-test", Success: true}
	})
	coord.RunOnce(ctx)
	return fences
}

// putContainer writes a container row directly onto host n. Relocation reads
// cluster state, not the local runtime, so a row is the whole fixture.
func putContainer(t *testing.T, n *Node, name, image, onHostFailure string) {
	t.Helper()
	if err := corrosion.UpsertContainer(context.Background(), n.DB, corrosion.ContainerRecord{
		HostName: n.Name, Name: name, Image: image, State: "running",
		OnHostFailure: onHostFailure,
	}); err != nil {
		t.Fatalf("seed container %s on %s: %v", name, n.Name, err)
	}
}

// findContainer locates the live row for name across every host, returning the
// owning host ("" if no live row exists anywhere).
func findContainer(t *testing.T, c *Cluster, name string) (string, *corrosion.ContainerRecord) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		rec, err := corrosion.GetContainer(ctx, c.Nodes[0].DB, n.Name, name)
		if err != nil {
			t.Fatalf("read container %s on %s: %v", name, n.Name, err)
		}
		if rec != nil {
			return n.Name, rec
		}
	}
	return "", nil
}

// TestContainerRelocate_RehomesRepullableAndPreservesTheRest drives one fencing
// cycle over three containers that differ only in what relocation is allowed to
// do with them, and pins all three outcomes at once — a relocation pass that
// treated them alike would fail here whichever way it erred.
func TestContainerRelocate_RehomesRepullableAndPreservesTheRest(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	// Re-pullable image + opted in → must be re-homed onto a survivor.
	putContainer(t, victim, "ct-repullable", "docker.io/library/alpine:3.19", "image-recreate")
	// No image to re-pull: its rootfs died with the host. Must be SKIPPED, not
	// recreated empty — recreating would look like a successful failover while
	// silently discarding the container's data.
	putContainer(t, victim, "ct-stateful", "", "image-recreate")
	// Opted out entirely → relocation must not touch it.
	putContainer(t, victim, "ct-optout", "docker.io/library/alpine:3.19", "none")

	if got := fenceVictim(t, c, a, victim, a, b); got != 1 {
		t.Fatalf("fencer fired %d times, want 1 — without a fence there is no relocation pass and this proves nothing", got)
	}
	if vrec, _ := corrosion.GetHost(context.Background(), a.DB, victim.Name); vrec == nil || vrec.State == "active" {
		t.Fatalf("victim host is still active after fencing: %+v", vrec)
	}

	// Re-pullable: re-keyed onto a survivor, pending recreate.
	host, rec := findContainer(t, c, "ct-repullable")
	if rec == nil {
		t.Fatal("ct-repullable vanished — a relocatable container must never be lost")
	}
	if host == victim.Name {
		t.Errorf("ct-repullable is still owned by the fenced host %s", victim.Name)
	}
	if rec.StateDetail != corrosion.ContainerRelocateRecreateDetail {
		t.Errorf("ct-repullable detail = %q, want %q so the target's reconciler recreates it",
			rec.StateDetail, corrosion.ContainerRelocateRecreateDetail)
	}

	// Stateful: left on the fenced host, marked terminal for operator recovery.
	host, rec = findContainer(t, c, "ct-stateful")
	if rec == nil {
		t.Fatal("ct-stateful vanished — an unrecoverable container must stay visible, not disappear")
	}
	if host != victim.Name {
		t.Errorf("ct-stateful was re-homed to %s despite having no re-pullable image — its data is gone and this hides that", host)
	}
	if rec.StateDetail != corrosion.ContainerRelocateSkippedDetail {
		t.Errorf("ct-stateful detail = %q, want %q", rec.StateDetail, corrosion.ContainerRelocateSkippedDetail)
	}

	// Opted out: untouched.
	host, rec = findContainer(t, c, "ct-optout")
	if rec == nil {
		t.Fatal("ct-optout vanished")
	}
	if host != victim.Name {
		t.Errorf("ct-optout moved to %s despite on_host_failure=none", host)
	}
	if rec.StateDetail == corrosion.ContainerRelocateSkippedDetail ||
		rec.StateDetail == corrosion.ContainerRelocateRecreateDetail {
		t.Errorf("ct-optout was processed by relocation (detail %q) despite opting out", rec.StateDetail)
	}
}

// TestContainerRelocate_DoesNotClobberASameNameContainerOnTheSurvivor: names are
// unique per (host, name), so the only survivor may already run an UNRELATED
// container of the same name. Re-keying onto it would overwrite that row —
// destroying a healthy container to rescue a dead one.
//
// Two independent layers prevent this: the coordinator skips a colliding target
// (pickContainerTarget → targetHasLiveContainer), and corrosion.
// RelocateContainerWithToken refuses to re-key onto a live row before deleting
// the source. Mutation-verified: disabling EITHER one alone leaves this test
// green — it only goes red when both are removed, at which point the survivor's
// row really is overwritten. So a single-guard mutation surviving here is
// defence in depth, not a weak assertion.
func TestContainerRelocate_DoesNotClobberASameNameContainerOnTheSurvivor(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	a, spare, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	const name = "ct-samename"

	// Three nodes are needed for a fencing quorum (liveHosts/2+1), but the
	// scenario needs exactly ONE relocation candidate — otherwise the coordinator
	// simply picks the uncontended host and the collision is never reached. Parking
	// the spare out of "active" keeps it counting as an observer while removing it
	// from healthyHosts.
	if err := corrosion.UpdateHostState(ctx, a.DB, spare.Name, "maintenance"); err != nil {
		t.Fatalf("park the spare host: %v", err)
	}

	// The survivor's own container — healthy, and nothing to do with the victim's.
	putContainer(t, a, name, "docker.io/library/nginx:1.25", "none")
	if err := corrosion.SetContainerStateDetail(ctx, a.DB, a.Name, name, "running", "survivor-original"); err != nil {
		t.Fatalf("mark the survivor's container: %v", err)
	}
	// The fenced host's same-named container, opted in to relocation.
	putContainer(t, victim, name, "docker.io/library/alpine:3.19", "image-recreate")

	if got := fenceVictim(t, c, a, victim, a, spare); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}

	// The survivor's container must be exactly as it was.
	surv, err := corrosion.GetContainer(ctx, a.DB, a.Name, name)
	if err != nil || surv == nil {
		t.Fatalf("survivor's own container: rec=%v err=%v — relocation destroyed an unrelated healthy container", surv, err)
	}
	if surv.Image != "docker.io/library/nginx:1.25" || surv.StateDetail != "survivor-original" {
		t.Fatalf("survivor's container was overwritten by the relocation: image=%q detail=%q",
			surv.Image, surv.StateDetail)
	}

	// And the victim's copy is left intact rather than silently dropped.
	//
	// Note it is DEFERRED, not terminally skipped: with every candidate
	// colliding, pickContainerTarget returns "" and startRelocation returns
	// before marking anything (coordinator.go:1418-1421), so a later tick
	// retries — which is what you want if the collision is transient. The
	// terminal relocate-skipped marker belongs to the non-repullable case.
	vrec, err := corrosion.GetContainer(ctx, a.DB, victim.Name, name)
	if err != nil {
		t.Fatalf("read the victim's container: %v", err)
	}
	if vrec == nil {
		t.Fatal("the victim's container was deleted with nowhere to go — it must stay visible for operator recovery")
	}
	if vrec.StateDetail == corrosion.ContainerRelocateRecreateDetail {
		t.Error("the victim's container was marked for recreate onto a host that already runs that name")
	}
	if vrec.Image != "docker.io/library/alpine:3.19" {
		t.Errorf("victim's container image = %q, want it unchanged", vrec.Image)
	}
}
