package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// claimedAddr is one address claimed from NetBox during a create, held so it can
// be compensated if any later step fails.
type claimedAddr struct {
	Network  string
	IP       string
	MAC      string
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
