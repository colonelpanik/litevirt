package network

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ReserveContainerIP claims (network, ip) for a container WITHOUT stealing it.
// It succeeds (reserved=true) only when the address is FREE, TOMBSTONED (a
// released lease — resurrected), or already held by THIS exact owner
// (ct, host, ctName) — an idempotent re-reserve. It deliberately does NOT
// "transfer" a live lease held by a same-named container on ANOTHER host: v36
// makes CT names per-host, so that may be a different workload — we can't prove
// it's ours, so we never overwrite it (the read-back returns reserved=false and
// the caller degrades to a blank IP). Cross-host lease MOVES are done explicitly
// by the mover, which knows the full prior owner.
func ReserveContainerIP(ctx context.Context, db *corrosion.Client, network, ip, mac, host, ctName string) (bool, error) {
	now := db.NowTS()
	allocAt := time.Now().UTC().Format(time.RFC3339)
	// Resurrect a tombstone, or idempotently refresh OUR OWN live lease; never
	// touch a live lease owned by anyone else (the guarded UPDATE no-ops, which
	// the read-back detects).
	if err := db.Execute(ctx,
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES (?, ?, ?, ?, 'ct', ?, ?, ?)
		 ON CONFLICT(network, ip) DO UPDATE SET
		   mac = excluded.mac, vm_name = excluded.vm_name, owner_kind = excluded.owner_kind,
		   owner_host = excluded.owner_host, updated_at = excluded.updated_at, deleted_at = NULL
		 WHERE ip_allocations.deleted_at IS NOT NULL
		    OR (ip_allocations.owner_kind = 'ct'
		        AND ip_allocations.vm_name = excluded.vm_name
		        AND ip_allocations.owner_host = excluded.owner_host)`,
		network, ip, mac, ctName, host, allocAt, now); err != nil {
		return false, err
	}
	return ipLeaseHeldBy(ctx, db, network, ip, "ct", host, ctName)
}

// ReleaseContainerLeases tombstones ALL of a container's IPAM leases on a host
// (across every network), without needing the interface rows. Used to roll back a
// failed create and as the delete cascade.
func ReleaseContainerLeases(ctx context.Context, db *corrosion.Client, host, ctName string) error {
	now := db.NowTS()
	return db.Execute(ctx,
		`UPDATE ip_allocations SET deleted_at = ?, updated_at = ?
		 WHERE owner_kind = 'ct' AND owner_host = ? AND vm_name = ? AND deleted_at IS NULL`,
		now, now, host, ctName)
}

// ReserveContainerNICs re-reserves the IPs of a re-homed container's managed
// interface rows on this host (restore). It runs AFTER the rows are written. For
// each NIC with an IP it conditionally reserves the address; if it can't (held by
// another workload), the row's IP is BLANKED (we never assert an address we don't
// own) and it's counted as unreserved so the caller can refuse to start the
// container (its imported on-disk config still names that IP — booting it would
// cause the conflict the DB is avoiding). Best-effort on errors; returns the
// number of NICs left unreserved + the first error.
func ReserveContainerNICs(ctx context.Context, db *corrosion.Client, host, ctName string, ifaces []corrosion.ContainerInterfaceRecord) (unreserved int, firstErr error) {
	for _, ifc := range ifaces {
		if ifc.IP == "" {
			continue
		}
		reserved, err := ReserveContainerIP(ctx, db, ifc.NetworkName, ifc.IP, ifc.MAC, host, ctName)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			unreserved++
			continue
		}
		if !reserved {
			slog.Warn("container rebuild: IP held by another workload; blanking NIC (will be re-discovered)",
				"ct", ctName, "host", host, "network", ifc.NetworkName, "ip", ifc.IP)
			unreserved++
			if e := corrosion.UpdateContainerInterfaceIP(ctx, db, host, ctName, ifc.Ordinal, ""); e != nil && firstErr == nil {
				firstErr = e
			}
		}
	}
	return unreserved, firstErr
}
