package network

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ReserveContainerIP claims (network, ip) for a container WITHOUT stealing it
// from an unrelated workload. It succeeds (reserved=true) when the address is
// free or already held by THIS container (same name + kind, any host — i.e. a
// re-home), transferring owner_host to this host. When a DIFFERENT workload holds
// it, the lease is left untouched and reserved=false, so the caller can degrade
// (blank IP) rather than silently overwrite ownership.
func ReserveContainerIP(ctx context.Context, db *corrosion.Client, network, ip, mac, host, ctName string) (bool, error) {
	now := db.NowTS()
	allocAt := time.Now().UTC().Format(time.RFC3339)
	// ON CONFLICT … DO UPDATE … WHERE same-owner: the guarded UPDATE only fires
	// when the existing lease is THIS container's, so it never steals; on a
	// mismatch it's a no-op (no error), which the read-back below detects.
	if err := db.Execute(ctx,
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES (?, ?, ?, ?, 'ct', ?, ?, ?)
		 ON CONFLICT(network, ip) DO UPDATE SET
		   owner_host = excluded.owner_host,
		   mac        = excluded.mac,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL
		 WHERE ip_allocations.owner_kind = 'ct' AND ip_allocations.vm_name = excluded.vm_name`,
		network, ip, mac, ctName, host, allocAt, now); err != nil {
		return false, err
	}
	al, err := GetAllocationFor(ctx, db, network, "ct", host, ctName)
	if err != nil {
		return false, err
	}
	return al != nil && al.IP == ip, nil
}

// ReserveContainerNICs re-reserves the IPs of a re-homed container's managed
// interface rows on this host (restore / migrate / relocate). It must run AFTER
// the rows are written. For each NIC with an IP it conditionally reserves the
// address; if another workload holds it, the row's IP is blanked (so we never
// assert an address we don't own — it's re-discovered later). Best-effort:
// returns the first error for logging but always processes every NIC.
func ReserveContainerNICs(ctx context.Context, db *corrosion.Client, host, ctName string, ifaces []corrosion.ContainerInterfaceRecord) error {
	var firstErr error
	for _, ifc := range ifaces {
		if ifc.IP == "" {
			continue
		}
		reserved, err := ReserveContainerIP(ctx, db, ifc.NetworkName, ifc.IP, ifc.MAC, host, ctName)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !reserved {
			slog.Warn("container rebuild: IP held by another workload; blanking NIC (will be re-discovered)",
				"ct", ctName, "host", host, "network", ifc.NetworkName, "ip", ifc.IP)
			if e := corrosion.UpdateContainerInterfaceIP(ctx, db, host, ctName, ifc.Ordinal, ""); e != nil && firstErr == nil {
				firstErr = e
			}
		}
	}
	return firstErr
}
