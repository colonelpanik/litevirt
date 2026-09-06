package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// claimedAddr is one address claimed from NetBox during a create, held so it can
// be compensated if any later step fails.
type claimedAddr struct {
	Network string
	IP      string
	MAC     string
	// VMName is the owner of the LOCAL ip_allocations lease this claim
	// persisted, and is what releaseAll tombstones it by. Empty means the claim
	// never got as far as a local lease, so there is nothing local to undo.
	VMName   string
	Identity string
	NetBoxID int
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
		// (VMName empty) has nothing local to undo.
		if a.VMName != "" {
			if err := network.ReleaseLease(ctx, c.srv.db, a.Network, a.IP, a.MAC, "vm", "", a.VMName); err != nil {
				slog.Warn("netbox: local lease tombstone failed during rollback; NetBox delete skipped",
					"address", a.IP, "vm", a.VMName, "error", err)
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

// enqueueOrphanCheck records that an identity may name an unreferenced NetBox
// object. The full sweep is what resolves it; this only shortens the latency.
func (s *Server) enqueueOrphanCheck(ctx context.Context, identity string) error {
	return corrosion.EnqueueSync(ctx, s.db, "orphan", identity, "check")
}
