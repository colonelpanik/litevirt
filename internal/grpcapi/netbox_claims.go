package grpcapi

import (
	"context"
	"encoding/json"
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
