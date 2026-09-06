package corrosion

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/randid"
)

// BindingRecord is one litevirt network bound to one NetBox prefix.
type BindingRecord struct {
	Network            string
	PrefixID           int
	ObservedCIDR       string
	VRFID              int
	ClusterFingerprint string
	Suspended          bool
	SuspendReason      string
}

// ClaimBinding inserts a binding ONLY if the prefix is unbound, then confirms
// by read-back. Returns false when another network already holds the prefix.
//
// A read-then-upsert is not enough: two concurrent binds both see nil from
// GetBindingByPrefix, both upsert, and the second silently steals the prefix
// from the first. A conflict clause that cannot touch a LIVE row, plus the
// read-back, makes the first writer win.
//
// The conflict target is the prefix_id PRIMARY KEY, which a TOMBSTONED row
// still occupies — so a released prefix (DeleteBinding) would conflict forever
// and read back nil. The guarded DO UPDATE resurrects a tombstone and only a
// tombstone: `WHERE netbox_bindings.deleted_at IS NOT NULL` leaves a live row
// untouched, exactly as DO NOTHING did. Same shape as the reclaim guard in
// internal/network/ipam.go's AllocateIPFor.
func ClaimBinding(ctx context.Context, c *Client, r BindingRecord) (bool, error) {
	if err := c.Execute(ctx,
		`INSERT INTO netbox_bindings
		   (prefix_id, network, observed_cidr, vrf_id, cluster_fingerprint,
		    suspended, suspend_reason, validated_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 0, '', ?, ?, ?)
		 ON CONFLICT(prefix_id) DO UPDATE SET
		   network = excluded.network,
		   observed_cidr = excluded.observed_cidr,
		   vrf_id = excluded.vrf_id,
		   cluster_fingerprint = excluded.cluster_fingerprint,
		   suspended = 0,
		   suspend_reason = '',
		   validated_at = excluded.validated_at,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL
		 WHERE netbox_bindings.deleted_at IS NOT NULL`,
		r.PrefixID, r.Network, r.ObservedCIDR, r.VRFID, r.ClusterFingerprint,
		c.NowWall(), c.NowWall(), c.NowTS()); err != nil {
		return false, fmt.Errorf("claim binding: %w", err)
	}
	got, err := GetBindingByPrefix(ctx, c, r.PrefixID)
	if err != nil {
		return false, err
	}
	if got == nil {
		return false, fmt.Errorf("binding for prefix %d vanished after insert", r.PrefixID)
	}
	return got.Network == r.Network, nil
}

// UpsertBinding rewrites an EXISTING binding — used by revalidation and re-key,
// never to create one. Use ClaimBinding for a new bind. It refuses (returns an
// error) when no row exists for the prefix, rather than silently creating one
// — a silent create would bypass ClaimBinding's uniqueness read-back.
func UpsertBinding(ctx context.Context, c *Client, r BindingRecord) error {
	susp := 0
	if r.Suspended {
		susp = 1
	}
	n, err := c.ExecuteRows(ctx,
		`UPDATE netbox_bindings SET
		   network = ?,
		   observed_cidr = ?,
		   vrf_id = ?,
		   cluster_fingerprint = ?,
		   suspended = ?,
		   suspend_reason = ?,
		   validated_at = ?,
		   updated_at = ?,
		   deleted_at = NULL
		 WHERE prefix_id = ?`,
		r.Network, r.ObservedCIDR, r.VRFID, r.ClusterFingerprint,
		susp, r.SuspendReason, c.NowWall(), c.NowTS(), r.PrefixID)
	if err != nil {
		return fmt.Errorf("update binding: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("binding for prefix %d does not exist; use ClaimBinding", r.PrefixID)
	}
	return nil
}

// SuspendBinding marks a binding unusable for NEW allocations. Running VMs are
// untouched — suspension is about refusing further claims, not about disturbing
// workloads that already hold an address.
func SuspendBinding(ctx context.Context, c *Client, prefixID int, reason string) error {
	return c.Execute(ctx,
		`UPDATE netbox_bindings SET suspended = 1, suspend_reason = ?, updated_at = ?
		 WHERE prefix_id = ?`,
		reason, c.NowTS(), prefixID)
}

// DeleteBinding RELEASES a prefix: the network behind the binding is gone (or
// never landed), so nothing may keep holding the NetBox prefix. It tombstones
// rather than hard-deletes, because a hard DELETE does not replicate as an LWW
// row — and the tombstone is what ClaimBinding reclaims when the prefix is
// bound again. Releasing an already-released (or never-created) binding is a
// no-op, so a compensating caller can retry it.
func DeleteBinding(ctx context.Context, c *Client, prefixID int) error {
	if err := c.Execute(ctx,
		`UPDATE netbox_bindings SET deleted_at = ?, updated_at = ?
		 WHERE prefix_id = ? AND deleted_at IS NULL`,
		c.NowWall(), c.NowTS(), prefixID); err != nil {
		return fmt.Errorf("delete binding for prefix %d: %w", prefixID, err)
	}
	return nil
}

const bindingCols = `prefix_id, network, observed_cidr, vrf_id, cluster_fingerprint,
	 COALESCE(suspended, 0) AS suspended, COALESCE(suspend_reason, '') AS suspend_reason`

func scanBinding(r Row) BindingRecord {
	return BindingRecord{
		PrefixID:           r.Int("prefix_id"),
		Network:            r.String("network"),
		ObservedCIDR:       r.String("observed_cidr"),
		VRFID:              r.Int("vrf_id"),
		ClusterFingerprint: r.String("cluster_fingerprint"),
		Suspended:          r.Int("suspended") == 1,
		SuspendReason:      r.String("suspend_reason"),
	}
}

// GetBindingByPrefix reads the binding for a NetBox prefix, or nil.
func GetBindingByPrefix(ctx context.Context, c *Client, prefixID int) (*BindingRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+bindingCols+` FROM netbox_bindings WHERE prefix_id = ? AND deleted_at IS NULL`,
		prefixID)
	if err != nil {
		return nil, fmt.Errorf("query binding by prefix: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	b := scanBinding(rows[0])
	return &b, nil
}

// GetBindingByNetwork reads the binding for a litevirt network, or nil.
func GetBindingByNetwork(ctx context.Context, c *Client, network string) (*BindingRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+bindingCols+` FROM netbox_bindings WHERE network = ? AND deleted_at IS NULL`,
		network)
	if err != nil {
		return nil, fmt.Errorf("query binding by network: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	b := scanBinding(rows[0])
	return &b, nil
}

// ListBindings returns every live binding.
func ListBindings(ctx context.Context, c *Client) ([]BindingRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+bindingCols+` FROM netbox_bindings WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	out := make([]BindingRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, scanBinding(r))
	}
	return out, nil
}

// QueueItem is one pending sync/orphan-check unit.
type QueueItem struct {
	ID       string
	Kind     string
	Key      string
	Op       string
	Attempts int
}

// EnqueueSync records work for the reconciler. The queue is a LATENCY
// optimisation only — the full sweep is what makes the mirror correct — so
// callers log an enqueue failure and continue rather than failing the operation.
func EnqueueSync(ctx context.Context, c *Client, kind, key, op string) error {
	id := randid.New()
	return c.Execute(ctx,
		`INSERT INTO netbox_sync_queue (id, kind, key, op, attempts, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 0, ?, ?)`,
		id, kind, key, op, c.NowWall(), c.NowTS())
}

// DrainSyncQueue reads up to limit pending items.
func DrainSyncQueue(ctx context.Context, c *Client, limit int) ([]QueueItem, error) {
	rows, err := c.Query(ctx,
		`SELECT id, kind, key, op, COALESCE(attempts, 0) AS attempts
		 FROM netbox_sync_queue WHERE deleted_at IS NULL ORDER BY created_at LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("drain sync queue: %w", err)
	}
	out := make([]QueueItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, QueueItem{
			ID: r.String("id"), Kind: r.String("kind"),
			Key: r.String("key"), Op: r.String("op"), Attempts: r.Int("attempts"),
		})
	}
	return out, nil
}

// AckSyncItem tombstones a completed item.
func AckSyncItem(ctx context.Context, c *Client, id string) error {
	return c.Execute(ctx,
		`UPDATE netbox_sync_queue SET deleted_at = ?, updated_at = ? WHERE id = ?`,
		c.NowWall(), c.NowTS(), id)
}

// LeaseRecord is one ip_allocations row with its NetBox join keys.
type LeaseRecord struct {
	Network      string
	IP           string
	MAC          string
	NetBoxIPID   int
	NetBoxPrefix int
}

// GetLeaseByIPForOwner reads one lease by its (network, ip) PRIMARY KEY, scoped
// to the owner that must hold it, or nil.
//
// Keyed on the ADDRESS, because a release has to name the exact row it is
// retiring and an owner-keyed read cannot distinguish two NICs of one workload.
// The owner triple is a PREDICATE on top of that key, matching ReleaseLease's:
// a read that returned a FOREIGN lease sharing (network, ip) would hand the
// caller a row it may not retire, and the owner-scoped release would then refuse
// it — turning someone else's address into a workload that cannot be deleted.
// Returning nil instead lets the caller treat it as "not ours, nothing to do".
//
// The NetBox columns are nullable — every pre-v51 lease has them empty — so they
// are COALESCEd, and a builtin lease reads back as id 0, which is what tells a
// release there is no remote object to delete.
func GetLeaseByIPForOwner(ctx context.Context, c *Client, network, ip, ownerKind, ownerHost, name string) (*LeaseRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT network, ip, mac,
		        COALESCE(netbox_ip_id, 0) AS netbox_ip_id,
		        COALESCE(netbox_prefix_id, 0) AS netbox_prefix_id
		 FROM ip_allocations
		 WHERE network = ? AND ip = ? AND vm_name = ?
		   AND owner_kind = ? AND owner_host = ? AND deleted_at IS NULL`,
		network, ip, name, ownerKind, ownerHost)
	if err != nil {
		return nil, fmt.Errorf("query lease: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &LeaseRecord{
		Network:      r.String("network"),
		IP:           r.String("ip"),
		MAC:          r.String("mac"),
		NetBoxIPID:   r.Int("netbox_ip_id"),
		NetBoxPrefix: r.Int("netbox_prefix_id"),
	}, nil
}

// LeaseExistsByIP reports whether ANY live lease references (network, ip).
//
// Deliberately owner-BLIND, unlike GetLeaseByIPForOwner. The orphan sweeper asks
// a different question: not "may I retire this owner's row?" but "does litevirt
// still believe this address is taken?". A lease whose owner triple no longer
// matches anything is exactly the half-finished state a crashed release leaves —
// and it is still a lease, still standing between the sweeper and an address a
// guest may be using. Scoping this read to an owner would hide those rows and
// let the sweeper free an address the cluster still holds.
func LeaseExistsByIP(ctx context.Context, c *Client, network, ip string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT 1 AS hit FROM ip_allocations
		 WHERE network = ? AND ip = ? AND deleted_at IS NULL`,
		network, ip)
	if err != nil {
		return false, fmt.Errorf("query lease by ip: %w", err)
	}
	return len(rows) > 0, nil
}
