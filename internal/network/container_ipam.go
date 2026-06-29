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

// TransferContainerLeases re-homes ALL of a container's live IPAM leases from
// fromHost to toHost (owner_host: fromHost→toHost), keyed on the FULL prior owner
// (ct, fromHost, ctName) so it's precise — never touches a same-named container
// on a third host. The mover (migrate) uses it for an explicit cross-host handoff,
// which ReserveContainerIP deliberately won't infer. Returns the number of leases
// moved so the caller can assert the handoff was complete (every held lease).
//
// allocated_at is RESET to now on the new owner: the orphan-lease GC keys off the
// lease's age, so a transferred lease (which keeps its original, possibly old,
// timestamp) must restart its age clock on the target — otherwise the target's GC
// could immediately reclaim it in the brief window before the migrated container
// row is visible there.
func TransferContainerLeases(ctx context.Context, db *corrosion.Client, fromHost, toHost, ctName string) (int64, error) {
	now := db.NowTS()
	allocAt := time.Now().UTC().Format(time.RFC3339)
	return db.ExecuteRows(ctx,
		`UPDATE ip_allocations SET owner_host = ?, allocated_at = ?, updated_at = ?
		 WHERE owner_kind = 'ct' AND owner_host = ? AND vm_name = ? AND deleted_at IS NULL`,
		toHost, allocAt, now, fromHost, ctName)
}

// ContainerLeasesOwnedBy reports whether (ct, host, ctName) owns the live IPAM
// lease for EVERY non-empty IP among ifaces — the per-NIC handoff invariant the
// migrate finaliser checks both BEFORE and AFTER the lease transfer. A managed NIC
// whose IP has no live lease, or whose lease is held by another owner, makes it
// return false. This is stricter than counting leases: a count can't catch a
// container_interfaces / create-spec NIC whose IP was never (or is no longer)
// backed by a source lease — exactly the case where the target, skipping
// re-reservation on a verified migrate, would otherwise start an unowned/
// conflicting address.
func ContainerLeasesOwnedBy(ctx context.Context, db *corrosion.Client, host, ctName string, ifaces []corrosion.ContainerInterfaceRecord) (bool, error) {
	for _, ifc := range ifaces {
		if ifc.IP == "" {
			continue
		}
		ok, err := ipLeaseHeldBy(ctx, db, ifc.NetworkName, ifc.IP, "ct", host, ctName)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// ReleaseOrphanContainerLeases tombstones CT leases on host whose owner has no
// live container row AND that are older than minAge — i.e. leases stranded by a
// daemon crash between allocating a lease and persisting the container row. The
// age guard keeps it from racing an in-flight create (which holds the name lock
// and finishes in seconds). Returns how many it released.
func ReleaseOrphanContainerLeases(ctx context.Context, db *corrosion.Client, host string, live map[string]bool, minAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-minAge).UTC().Format(time.RFC3339)
	rows, err := db.Query(ctx,
		`SELECT DISTINCT vm_name FROM ip_allocations
		 WHERE owner_kind = 'ct' AND owner_host = ? AND deleted_at IS NULL AND allocated_at < ?`,
		host, cutoff)
	if err != nil {
		return 0, err
	}
	released := 0
	for _, r := range rows {
		name := r.String("vm_name")
		if live[name] {
			continue
		}
		if err := ReleaseContainerLeases(ctx, db, host, name); err != nil {
			return released, err
		}
		slog.Warn("released orphan container IPAM lease (no live container row)", "host", host, "ct", name)
		released++
	}
	return released, nil
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
