// Fleet scenarios for the LEASE DISCIPLINE of the re-key's adoption tail.
//
// rekeyBinding opens with a rule about itself: "The lease before ANY write, the
// suspend below included." The address-rewrite loop keeps it literally — it
// calls lease.check before EVERY SetIPIdentity, so a lease lost for any reason
// stops the rewrite at the very next object rather than at the next renewal.
//
// The adoption the re-key gained sits after that loop and can issue up to 256
// NetBox POSTs of its own, against a lease whose TTL is one minute. Without the
// same discipline it re-proved nothing across the whole of it, and the
// UpsertBinding that RESUMES the binding was then separated from its last proof
// by all of them — which is the one write that must never rest on a lease this
// node stopped holding, because it is what makes a half-rewritten cluster live
// again.
//
// Both scenarios steal the lease from INSIDE a claim, which is the only way to
// land a handover in the middle of the adoption rather than between passes.

package fleet

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// stealLeaseDuringClaim makes the fake steal the `netbox` leader lease the FIRST
// time an address is claimed, then let that claim (and every later one) proceed
// normally.
//
// Unguarded, exactly as a genuine leadership handover leaves the row, and
// written from the fake's own goroutine — so it records its error instead of
// failing the test from there.
func stealLeaseDuringClaim(nb *NetBoxFake, n *Node, holder string) func() error {
	var (
		once    sync.Once
		mu      sync.Mutex
		stolen  bool
		stealer error
	)
	nb.SetOnClaimSpecific(func(string) error {
		once.Do(func() {
			expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			err := n.DB.Execute(context.Background(),
				`INSERT INTO leader_election (key, holder, expires_at, updated_at)
				 VALUES ('netbox', ?, ?, ?)
				 ON CONFLICT(key) DO UPDATE SET holder = excluded.holder,
				   expires_at = excluded.expires_at, updated_at = excluded.updated_at`,
				holder, expires, n.DB.NowTS())
			mu.Lock()
			defer mu.Unlock()
			stolen, stealer = err == nil, err
		})
		return nil
	})
	return func() error {
		mu.Lock()
		defer mu.Unlock()
		if !stolen {
			if stealer != nil {
				return stealer
			}
			return errNoClaimReached
		}
		return nil
	}
}

// errNoClaimReached marks a scenario that never reached a claim at all — the
// shape where every assertion below would hold vacuously.
var errNoClaimReached = errNoClaim{}

type errNoClaim struct{}

func (errNoClaim) Error() string {
	return "no address claim was ever made, so the lease was never stolen mid-adoption"
}

// aSuspendedBindingOwingAdoption leaves the cluster with a bound, SUSPENDED
// binding and `len(ips)` addresses still owed, built entirely from real RPCs:
// guests hold the addresses, the bind's adoption is refused on the LOWEST one
// (adoption runs in address order, so the pass stops before adopting any), and
// the refusal is then cleared.
func aSuspendedBindingOwingAdoption(t *testing.T, nb *NetBoxFake, c *Cluster, n *Node, ips ...string) {
	t.Helper()

	mustCreateUnboundNetwork(t, c, n, adoptNetName, adoptSubnet)
	for i, ip := range ips {
		mustCreateVMHoldingIP(t, c, n, vmNameForIP(i), adoptNetName, ip)
	}
	nb.SetOnClaimSpecific(func(address string) error {
		if strings.HasPrefix(address, ips[0]+"/") {
			return errRefusedByNetBox
		}
		return nil
	})
	if err := relink(c, n, t); err == nil {
		t.Fatal("precondition: the bind's adoption had to fail, leaving the binding suspended")
	}
	nb.SetOnClaimSpecific(nil)

	b := bindingFor(t, n)
	if b == nil || !b.Suspended {
		t.Fatalf("precondition: the binding must be suspended with adoption owed, got %+v", b)
	}
	for _, ip := range ips {
		if lease := leaseFor(t, n, adoptNetName, ip); lease != nil {
			t.Fatalf("precondition: %s must still be owed, got lease %+v", ip, lease)
		}
	}
}

func vmNameForIP(i int) string {
	return []string{"guest-a", "guest-b", "guest-c"}[i]
}

// TestFleetRekeyAdoptionReProvesTheLeaseBeforeEachClaim.
//
// Two addresses are owed. The lease is stolen from inside the FIRST claim, so
// the first one lands and the check before the SECOND must stop the pass. A
// re-key that re-proved nothing would go on POSTing under a lease another node
// holds — alongside whatever that node started doing with it.
func TestFleetRekeyAdoptionReProvesTheLeaseBeforeEachClaim(t *testing.T) {
	nb, c, n := adoptCluster(t)
	aSuspendedBindingOwingAdoption(t, nb, c, n, adoptFirstIP, adoptSecondIP)

	stealCheck := stealLeaseDuringClaim(nb, n, "another-node")
	postsBefore := nb.AddressPOSTs()

	err := rekey(c, n, adoptNetName)

	if serr := stealCheck(); serr != nil {
		t.Fatalf("the scenario never stole the lease mid-adoption: %v", serr)
	}
	if err == nil {
		t.Fatal("the re-key's adoption ran to completion under a lease this node had lost")
	}
	if !strings.Contains(err.Error(), "another-node") {
		t.Fatalf("the failure must name the node that now holds the lease, got: %v", err)
	}
	// EXACTLY one POST: the claim that carried the steal. A second one is the
	// bug — a write issued after the lease was demonstrably gone.
	if got := nb.AddressPOSTs() - postsBefore; got != 1 {
		t.Fatalf("the adoption made %d address POSTs after losing the lease, want 1 "+
			"(the one that carried the steal)", got)
	}
	if lease := leaseFor(t, n, adoptNetName, adoptFirstIP); lease == nil {
		t.Fatalf("the first address should have adopted before the steal")
	}
	if lease := leaseFor(t, n, adoptNetName, adoptSecondIP); lease != nil {
		t.Fatalf("%s was adopted after the lease was lost, got %+v", adoptSecondIP, lease)
	}
	if b := bindingFor(t, n); b == nil || !b.Suspended {
		t.Fatalf("a re-key that stopped on a lost lease must leave the binding suspended, got %+v", b)
	}
}

// TestFleetRekeyReProvesTheLeaseBeforeResumingAfterAdoption is the other half,
// and the more dangerous one.
//
// ONE address is owed, and the steal rides its claim — so the adoption FINISHES
// and the very next thing the tail does is the UpsertBinding that resumes the
// binding. Resuming is what makes a re-keyed cluster live again; a resume
// written under a lease this node lost is a live binding whose rewrite another
// node may be halfway through undoing.
func TestFleetRekeyReProvesTheLeaseBeforeResumingAfterAdoption(t *testing.T) {
	nb, c, n := adoptCluster(t)
	aSuspendedBindingOwingAdoption(t, nb, c, n, adoptFirstIP)

	stealCheck := stealLeaseDuringClaim(nb, n, "another-node")

	err := rekey(c, n, adoptNetName)

	if serr := stealCheck(); serr != nil {
		t.Fatalf("the scenario never stole the lease mid-adoption: %v", serr)
	}
	if err == nil {
		t.Fatal("the re-key RESUMED the binding under a lease this node had lost")
	}
	if !strings.Contains(err.Error(), "another-node") {
		t.Fatalf("the failure must name the node that now holds the lease, got: %v", err)
	}
	// The adoption itself DID finish — that is what makes this the resume's
	// property and not the loop's.
	if lease := leaseFor(t, n, adoptNetName, adoptFirstIP); lease == nil || lease.NetBoxIPID == 0 {
		t.Fatalf("the owed address should have been adopted before the resume, got %+v", lease)
	}
	if b := bindingFor(t, n); b == nil || !b.Suspended {
		t.Fatalf("the binding must STAY SUSPENDED: the resume may not rest on a lost lease, got %+v", b)
	}

	// And the recovery path works: with the lease back, the same command
	// finishes — so this cannot pass against a re-key that refuses everything.
	stealNetBoxLease(t, n, n.Name)
	nb.SetOnClaimSpecific(nil)
	mustRekey(t, c, n, adoptNetName)
	if b := bindingFor(t, n); b == nil || b.Suspended {
		t.Fatalf("a re-key holding the lease must resume the binding, got %+v", b)
	}
	// The already-adopted address costs nothing on the re-run.
	if _, err := c.SelfClient(n).ListVMs(context.Background(), &pb.ListVMsRequest{}); err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
}
