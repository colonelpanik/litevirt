// Fleet scenarios for DELEGATED project-quota admission (F2 second half).
//
// Reserve-then-verify makes two concurrent admissions pick a winner, but only once
// both reservations are VISIBLE to both deciders. Corrosion is eventually consistent,
// so two nodes that have not yet exchanged rows each see only their own claim and
// both admit — together exceeding a quota neither request individually broke.
//
// That failure is structurally unreachable from a single-package test: it needs two
// daemons with genuinely separate replicas, deciding at the same time, over real
// gRPC. This harness gives exactly that — nothing converges between two nodes unless
// a scenario explicitly pulls, so the lag window can be held open for as long as the
// assertion needs instead of being raced against a timer.

package fleet

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// seedTenantQuota creates a project with a vCPU quota on every node, so each one's
// view of the LIMIT agrees. Only the USAGE is allowed to diverge — that divergence is
// the thing under test.
func seedTenantQuota(t *testing.T, c *Cluster, project string, vcpuLimit int) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		if err := corrosion.InsertProject(ctx, n.DB, corrosion.ProjectRecord{Name: project}); err != nil {
			t.Fatalf("InsertProject on %s: %v", n.Name, err)
		}
		if err := corrosion.UpsertProjectQuota(ctx, n.DB, corrosion.ProjectQuotaRecord{
			ProjectName: project, VCPULimit: vcpuLimit,
		}); err != nil {
			t.Fatalf("UpsertProjectQuota on %s: %v", n.Name, err)
		}
	}
}

// seedProjectAuthority establishes holder as the project's admission authority on
// EVERY node's replica.
//
// Authority is sticky and minted once, long before the concurrent creates that
// matter; seeding it directly reflects that steady state rather than racing the
// initial claim. The initial claim itself has its own narrow split-brain window (two
// nodes that cannot see each other both mint epoch 1, and LWW picks a winner when
// they converge) — a separate, self-healing concern, and not what these scenarios
// are about.
func seedProjectAuthority(t *testing.T, c *Cluster, project string, holder *Node) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		applied, err := corrosion.ClaimInitialProjectAuthority(ctx, n.DB, project, holder.Name)
		if err != nil || !applied {
			t.Fatalf("ClaimInitialProjectAuthority on %s: applied=%v err=%v", n.Name, applied, err)
		}
	}
	for _, n := range c.Nodes {
		cur, ok, err := corrosion.CurrentProjectAuthority(ctx, n.DB, project)
		if err != nil || !ok || cur.Holder != holder.Name {
			t.Fatalf("%s sees authority holder %q (ok=%v err=%v), want %q", n.Name, cur.Holder, ok, err, holder.Name)
		}
	}
}

// latchProjectAuthority turns the delegation kill-switch on everywhere and drives the
// cluster latch. The token is advertised only while the flag is on, so this also
// proves the config-uniformity requirement is satisfiable.
func latchProjectAuthority(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		n.Server.SetProjectAuthorityEnforce(true)
	}
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.ProjectAuthorityV1) {
			t.Fatalf("%s: project_authority_v1 failed to latch with the config flag on everywhere", n.Name)
		}
	}
}

// roomyHosts sizes every host well beyond what these scenarios ask of it, so a
// refusal can only have come from the PROJECT quota. A host-capacity refusal would
// otherwise pass the same assertion for entirely the wrong reason.
func roomyHosts(t *testing.T, c *Cluster) {
	t.Helper()
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}
}

// runProjectVM is runVM with a tenancy bucket, since project quota is what these
// scenarios turn on.
func runProjectVM(t *testing.T, c *Cluster, at *Node, name, pinHost string, cpu, memMiB int32, project string) (*pb.VM, error) {
	t.Helper()
	spec := &pb.VMSpec{Name: name, Cpu: cpu, MemoryMib: memMiB, Project: project}
	if pinHost != "" {
		spec.Placement = &pb.PlacementSpec{Host: pinHost}
	}
	return c.SelfClient(at).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: spec})
}

// TestFleet_ProjectAuthority_SecondNodeCannotAdmitPastTheQuota is the scenario the
// whole mechanism exists for.
//
// Two nodes, one project with a 4 vCPU quota, and two 4 vCPU creates entering
// DIFFERENT daemons whose replicas have not exchanged a thing. Deciding locally, each
// node sees an empty project and admits; the project ends up at 8 vCPU against a
// limit of 4. Routed through one decider, the second request is refused.
//
// Note that this holds whichever node holds authority. When the holder is the OTHER
// node it sees the first VM's row directly; when the holder is the node that made the
// first grant, it sees nothing of the winner's VM yet and relies on the settle grace
// keeping that released lease counted. Both are exercised below.
func TestFleet_ProjectAuthority_SecondNodeCannotAdmitPastTheQuota(t *testing.T) {
	for _, holderIdx := range []int{0, 1} {
		holderIdx := holderIdx
		name := "holder_is_the_first_admitter"
		if holderIdx == 1 {
			name = "holder_is_the_second_admitter"
		}
		t.Run(name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2})
			defer c.Stop()
			gates := gateAll(t, c)
			roomyHosts(t, c)
			seedTenantQuota(t, c, "tenant", 4)
			seedProjectAuthority(t, c, "tenant", c.Nodes[holderIdx])
			latchProjectAuthority(t, c, gates)

			n1, n2 := c.Nodes[0], c.Nodes[1]

			if _, err := runProjectVM(t, c, n1, "vm-a", n1.Name, 4, 1024, "tenant"); err != nil {
				t.Fatalf("first create must be admitted (it fits the quota exactly): %v", err)
			}
			// Deliberately NO convergence here: n2's replica has never seen vm-a. This
			// is the exact state in which local admission over-admits.
			_, err := runProjectVM(t, c, n2, "vm-b", n2.Name, 4, 1024, "tenant")
			if status.Code(err) != codes.ResourceExhausted {
				t.Fatalf("second create returned %v (code %s), want ResourceExhausted — "+
					"the project's 4 vCPU quota was already fully spent by vm-a",
					err, status.Code(err))
			}
		})
	}
}

// TestFleet_ProjectAuthority_DisabledStillOverAdmits pins the bug this closes, so the
// scenario above cannot quietly become vacuous.
//
// With delegation off, both creates are admitted and the project lands at double its
// quota. If this ever starts refusing, the test above stopped proving anything about
// delegation and started passing for some other reason.
func TestFleet_ProjectAuthority_DisabledStillOverAdmits(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	gateAll(t, c)
	roomyHosts(t, c)
	seedTenantQuota(t, c, "tenant", 4)
	seedProjectAuthority(t, c, "tenant", c.Nodes[0])
	// Flag deliberately left off — no latch, no delegation.

	n1, n2 := c.Nodes[0], c.Nodes[1]
	if _, err := runProjectVM(t, c, n1, "vm-a", n1.Name, 4, 1024, "tenant"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := runProjectVM(t, c, n2, "vm-b", n2.Name, 4, 1024, "tenant"); err != nil {
		t.Fatalf("without delegation the second create is expected to slip through "+
			"(that is the bug); it was refused instead: %v", err)
	}
}

// TestFleet_ProjectAuthority_UnreachableHolderRefuses pins the availability trade the
// operator is making when they enable this.
//
// A holder that cannot be reached REFUSES the admission. Falling back to the local
// view would be precisely the behavior delegation removes, and it would reappear
// exactly when the network is least trustworthy — so the failure is closed, loudly,
// and named as Unavailable rather than disguised as a quota refusal.
func TestFleet_ProjectAuthority_UnreachableHolderRefuses(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	gates := gateAll(t, c)
	roomyHosts(t, c)
	seedTenantQuota(t, c, "tenant", 8)
	seedProjectAuthority(t, c, "tenant", c.Nodes[0])
	latchProjectAuthority(t, c, gates)

	n1, n2 := c.Nodes[0], c.Nodes[1]
	c.Partition(n1, n2)
	defer c.Heal(n1, n2)

	_, err := runProjectVM(t, c, n2, "vm-b", n2.Name, 2, 1024, "tenant")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("create with an unreachable authority holder returned %v (code %s), "+
			"want Unavailable — a partition must not silently fall back to the local view",
			err, status.Code(err))
	}
}

// TestFleet_ProjectAuthority_BootstrapsWithoutWaitingForReplication covers the very
// first admission of a project, which has no authority record anywhere yet.
//
// The minting node writes the claim to ITS replica, so the node it names as holder
// does not have that row when the delegated request arrives a moment later. Waiting
// for replication would fail every project's first create. Instead both sides DERIVE
// the initial holder from membership, so the holder confirms the claim independently
// rather than taking the caller's word for it.
//
// Nothing is seeded here on purpose: authority is minted by the code path under test,
// and the assertion is simply that a create works at all.
func TestFleet_ProjectAuthority_BootstrapsWithoutWaitingForReplication(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	defer c.Stop()
	gates := gateAll(t, c)
	roomyHosts(t, c)
	seedTenantQuota(t, c, "tenant", 8)
	latchProjectAuthority(t, c, gates)

	// Enter at each node in turn. Whichever one derivation picks as holder, at least
	// one of these is a genuine cross-node delegation into a node that has never seen
	// the authority row.
	for i, n := range c.Nodes {
		name := "boot-vm-" + string(rune('a'+i))
		if _, err := runProjectVM(t, c, n, name, n.Name, 1, 512, "tenant"); err != nil {
			t.Fatalf("create entering %s failed on a project with no replicated authority record: %v — "+
				"the holder must confirm the derived claim itself instead of waiting for replication", n.Name, err)
		}
	}

	// And every node must have landed on the SAME holder; disagreement here means two
	// deciders, which is the state the mechanism exists to prevent.
	ctx := context.Background()
	var first string
	for _, n := range c.Nodes {
		cur, ok, err := corrosion.CurrentProjectAuthority(ctx, n.DB, "tenant")
		if err != nil || !ok {
			t.Fatalf("%s has no authority record after admitting: ok=%v err=%v", n.Name, ok, err)
		}
		if first == "" {
			first = cur.Holder
		} else if cur.Holder != first {
			t.Errorf("%s thinks %q holds the project but another node thinks %q — two holders at one epoch",
				n.Name, cur.Holder, first)
		}
	}
}

// TestFleet_ProjectAuthority_HolderGrantsWithinQuota guards the other direction: the
// single decider must still ADMIT what genuinely fits. A mechanism that refuses
// everything would pass every scenario above.
func TestFleet_ProjectAuthority_HolderGrantsWithinQuota(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	gates := gateAll(t, c)
	roomyHosts(t, c)
	seedTenantQuota(t, c, "tenant", 8)
	seedProjectAuthority(t, c, "tenant", c.Nodes[0])
	latchProjectAuthority(t, c, gates)

	n1, n2 := c.Nodes[0], c.Nodes[1]
	if _, err := runProjectVM(t, c, n1, "vm-a", n1.Name, 4, 1024, "tenant"); err != nil {
		t.Fatalf("first create (4 of 8 vCPU): %v", err)
	}
	// Delegated across the wire from the non-holder, and it fits.
	if _, err := runProjectVM(t, c, n2, "vm-b", n2.Name, 4, 1024, "tenant"); err != nil {
		t.Fatalf("second create (the remaining 4 of 8 vCPU) was refused: %v", err)
	}
}
