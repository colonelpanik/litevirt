package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/network"
)

// claimedAddr is one address claimed from NetBox during a create, held so it can
// be compensated if any later step fails.
type claimedAddr struct {
	Network string
	IP      string
	MAC     string
	// OwnerKind, OwnerHost and Name are the owner triple of the LOCAL
	// ip_allocations lease this claim persisted, and are what releaseAll
	// tombstones it by. ReleaseLease is owner-scoped and refuses a row it does
	// not match, so the triple has to travel with the claim rather than be
	// assumed by the rollback — a claimant with a different owner would
	// otherwise fail its tombstone silently and strand the address.
	//
	// An empty Name means the claim never got as far as a local lease, so there
	// is nothing local to undo.
	OwnerKind string
	OwnerHost string
	Name      string
	Identity  string
	NetBoxID  int
}

// claimSet accumulates the claims one create has taken.
//
// A NetBox claim is a synchronous remote side-effect and cannot join the local
// atomic batch the container path uses, so compensation is explicit.
type claimSet struct {
	srv   *Server
	items []claimedAddr
}

func (c *claimSet) add(a claimedAddr) { c.items = append(c.items, a) }
func (c *claimSet) empty() bool       { return len(c.items) == 0 }

// releaseAll compensates every claim. A release that itself fails leaves an
// address nothing references, so it is enqueued for the sweeper rather than
// dropped — otherwise it is stranded until a human notices.
func (c *claimSet) releaseAll(ctx context.Context) {
	for _, a := range c.items {
		// The LOCAL lease goes first, and a failure to tombstone it stops the
		// remote delete — the same order and the same reason as
		// netboxAllocator.Release. Freeing the address in NetBox while litevirt
		// still holds the lease lets another system take an address litevirt
		// believes is its own; the reverse order only risks an address the
		// orphan sweep can reclaim. A claim that never persisted a lease
		// (Name empty) has nothing local to undo.
		if a.Name != "" {
			if err := network.ReleaseLease(ctx, c.srv.db, a.Network, a.IP, a.MAC, a.OwnerKind, a.OwnerHost, a.Name); err != nil {
				slog.Warn("netbox: local lease tombstone failed during rollback; NetBox delete skipped",
					"address", a.IP, "owner", a.Name, "error", err)
				if eerr := c.srv.enqueueOrphanCheck(ctx, a.Identity); eerr != nil {
					slog.Error("netbox: could not enqueue orphan check — address may be stranded",
						"identity", a.Identity, "error", eerr)
				}
				continue
			}
		}
		if a.NetBoxID == 0 {
			continue
		}
		var releaseErr error
		if c.srv.netbox == nil {
			// A non-zero NetBoxID with no wired client is a programming error (a
			// server that claimed an address without a client could not exist),
			// but panicking mid-rollback is the worst place to discover that.
			// Treat it exactly like a failed release.
			releaseErr = fmt.Errorf("netbox client not wired")
		} else {
			releaseErr = c.srv.netbox.ReleaseIP(ctx, a.NetBoxID)
		}
		if releaseErr != nil {
			slog.Warn("netbox: compensating release failed; enqueueing orphan check",
				"address", a.IP, "netbox_id", a.NetBoxID, "error", releaseErr)
			if eerr := c.srv.enqueueOrphanCheck(ctx, a.Identity); eerr != nil {
				slog.Error("netbox: could not enqueue orphan check — address may be stranded",
					"identity", a.Identity, "error", eerr)
			}
		}
	}
	c.items = nil
}

// enqueueOrphanChecks names every claim in the set for the orphan sweep WITHOUT
// releasing any of them.
//
// This is the compensation-could-not-complete case: the addresses must STAY
// held, because a row that survived an incomplete rollback still names them, and
// freeing an address something still points at is the one outcome the release
// ordering exists to prevent. But a claim nothing will ever come back for is a
// stuck lease, and a stuck lease whose only trace is a log line is invisible.
// Naming each one hands it to the sweep's stuck-lease surfacing, which reports
// exactly this shape: an identity whose local lease is still live with nothing
// driving it forward.
//
// The set is emptied afterwards exactly as releaseAll empties it: this is the
// terminal disposition of every claim in it, so a second caller must not be able
// to enqueue the same identities again (or, worse, release addresses this
// disposition deliberately kept).
func (c *claimSet) enqueueOrphanChecks(ctx context.Context) {
	for _, a := range c.items {
		if a.Identity == "" {
			continue // never got as far as an identity; there is nothing to name
		}
		if eerr := c.srv.enqueueOrphanCheck(ctx, a.Identity); eerr != nil {
			slog.Error("netbox: could not enqueue orphan check for a retained claim — the address may stay stuck until the next full sweep",
				"identity", a.Identity, "error", eerr)
		}
	}
	c.items = nil
}

// enqueueOrphanCheck records that an identity may name an unreferenced NetBox
// object. The full sweep is what resolves it; this only shortens the latency.
func (s *Server) enqueueOrphanCheck(ctx context.Context, identity string) error {
	return corrosion.EnqueueSync(ctx, s.db, "orphan", identity, "check")
}

// vmSpecUUID reads the incarnation uuid out of a stored VM spec — the middle
// component of every netbox.Identity this package builds.
//
// A missing uuid is an ERROR, not an empty string: the uuid is what makes an
// identity incarnation-unique, and an identity built without one names nothing.
// Claiming under it would tag a NetBox object no later lookup could find, and
// enqueueing it would only send the sweeper after an object that does not exist.
func vmSpecUUID(vmSpec string) (string, error) {
	var sp struct {
		Uuid string `json:"uuid"`
	}
	if err := json.Unmarshal([]byte(vmSpec), &sp); err != nil {
		return "", fmt.Errorf("parse VM spec for its uuid: %w", err)
	}
	if sp.Uuid == "" {
		return "", fmt.Errorf("VM record carries no uuid")
	}
	return sp.Uuid, nil
}

// nicIdentity builds the NetBox identity ONE NIC of vm claims under: the cluster
// fingerprint + the VM's incarnation uuid + the NIC's mac, exactly as the claim
// paths build it. An identity built any other way names nothing.
func (s *Server) nicIdentity(ctx context.Context, vm *corrosion.VMRecord, mac string) (string, error) {
	fp, ferr := corrosion.ClusterFingerprint(ctx, s.db)
	if ferr != nil {
		return "", fmt.Errorf("cluster fingerprint: %w", ferr)
	}
	vmUUID, uerr := vmSpecUUID(vm.Spec)
	if uerr != nil {
		return "", uerr
	}
	return netbox.Identity(fp, vmUUID, mac), nil
}

// enqueueNICOrphanCheck hands ONE NIC's now-unreferenced NetBox object to the
// orphan sweep. Best effort by construction: every caller has already made the
// LOCAL half durable, so the full sweep is the backstop and a failure here costs
// latency, never correctness — which is why it logs rather than returning.
func (s *Server) enqueueNICOrphanCheck(ctx context.Context, vm *corrosion.VMRecord, nic corrosion.NICRecord) {
	identity, err := s.nicIdentity(ctx, vm, nic.MAC)
	if err != nil {
		slog.Error("netbox: could not build the identity for an orphan check — address may be stranded until the next full sweep",
			"vm", vm.Name, "network", nic.NetworkName, "ip", nic.IP, "error", err)
		return
	}
	if eerr := s.enqueueOrphanCheck(ctx, identity); eerr != nil {
		slog.Error("netbox: could not enqueue orphan check — address may be stranded until the next full sweep",
			"identity", identity, "error", eerr)
	}
}

// releaseOneNICLease gives back EXACTLY one NIC's address, and is the single
// implementation behind BOTH per-NIC releases: DeleteVM's loop over every NIC a
// VM holds, and a hot-detach of the one NIC that is going away. They were
// near-verbatim copies of each other, which is the shape where a fix to one
// silently misses the other.
//
// Keyed on the lease's own (network, ip) primary key, never on (network,
// vm_name): a VM can hold several leases, and a bulk release would free the
// addresses of the NICs that are staying. The LEASE decides whether there is
// anything to release — read owner-scoped, so a foreign row sharing this
// (network, ip) reads back as nil rather than as a row this VM may not retire.
//
// The error return is what the caller SURFACES. A release that failed means
// either the lease is still live (litevirt still holds the address, and the
// operator has to know) or ownership moved underneath — never something to
// swallow.
func (s *Server) releaseOneNICLease(ctx context.Context, vm *corrosion.VMRecord, nic corrosion.NICRecord) error {
	if nic.IP == "" {
		return nil // never addressed — nothing to give back
	}
	lease, lerr := corrosion.GetLeaseByIPForOwner(ctx, s.db, nic.NetworkName, nic.IP, "vm", "", vm.Name)
	if lerr != nil {
		return fmt.Errorf("read lease %s on %s: %w", nic.IP, nic.NetworkName, lerr)
	}
	if lease == nil {
		// No LIVE lease. Either this NIC never allocated one, or an EARLIER
		// release already tombstoned it and then failed its remote half — the one
		// state a re-run cannot finish, because the local row it would prove
		// ownership with is already gone.
		//
		// On a bound network that second case leaves a NetBox object nothing
		// references, which is precisely what the orphan sweep exists for, so
		// name it rather than let it wait for a full sweep. On an unbound network
		// (or one whose binding cannot be resolved) there is no remote authority
		// and nothing to name, and no identity is built — the cluster fingerprint
		// is a read, and the ordinary case must not gain one.
		alloc, _, aerr := s.allocatorFor(ctx, "vm", nic.NetworkName)
		if aerr != nil || alloc == nil {
			return nil
		}
		s.enqueueNICOrphanCheck(ctx, vm, nic)
		return nil
	}

	alloc, _, aerr := s.allocatorFor(ctx, "vm", nic.NetworkName)
	if aerr != nil {
		// A suspended or misconfigured binding must not block a delete or make a
		// NIC undetachable — the workload is going away either way, and a VM that
		// cannot be deleted at all (or a NIC that can never come off) is strictly
		// worse. But skipping the release outright burns the address in BOTH
		// systems: the row is removed while this lease stays LIVE under an owner
		// that no longer exists, and a live lease is exactly what the orphan sweep
		// must never touch (that invariant is what protects a running guest's
		// address), while the guarded upsert in netboxAllocator.persist refuses to
		// reuse a live row even after an operator frees the address in NetBox by
		// hand.
		//
		// So tombstone the LOCAL half directly. The allocator is only needed for
		// the remote half; the local half is a plain owner-scoped write, and
		// owner-scoping still makes it fail loudly if ownership moved.
		slog.Warn("netbox: no allocator for network, releasing the lease locally",
			"vm", vm.Name, "network", nic.NetworkName, "ip", nic.IP, "error", aerr)
		if rerr := network.ReleaseLease(ctx, s.db, nic.NetworkName, nic.IP, nic.MAC, "vm", "", vm.Name); rerr != nil {
			// Same treatment as any other release failure: the lease is still
			// live, so the caller has to know litevirt still holds the address.
			// Nothing destructive has run, so a retry re-runs this.
			return fmt.Errorf("tombstone lease %s on %s: %w", nic.IP, nic.NetworkName, rerr)
		}
		if lease.NetBoxIPID == 0 {
			return nil // a builtin lease: no remote object to hand over
		}
		// The remote object is now UNREFERENCED, which is precisely the case the
		// orphan sweep already handles correctly. Name it so it does not wait for
		// a full sweep to notice.
		//
		// A failure here is logged, not surfaced: the local tombstone already
		// landed, so a re-run would find no lease and could never reach this point
		// again — reporting it as retryable would be a lie, and the full sweep
		// remains the backstop either way.
		s.enqueueNICOrphanCheck(ctx, vm, nic)
		return nil
	}
	if alloc == nil {
		// An UNBOUND network. VMs have never allocated there, so the live lease
		// read above cannot be one of ours to give back; leave it exactly as
		// today's code does rather than newly tombstoning a row this path has
		// never owned.
		return nil
	}

	// The ordinary release: local tombstone then remote delete, in that order,
	// inside the allocator.
	return alloc.Release(ctx, network.ReleaseRequest{
		Network:    nic.NetworkName,
		IP:         nic.IP,
		MAC:        nic.MAC,
		OwnerKind:  "vm",
		OwnerHost:  "", // VM names are cluster-global
		Name:       vm.Name,
		NetBoxIPID: lease.NetBoxIPID,
	})
}
