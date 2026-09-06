package corrosion

import (
	"context"
	"fmt"
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
// from the first. DO NOTHING plus a read-back makes the first writer win.
func ClaimBinding(ctx context.Context, c *Client, r BindingRecord) (bool, error) {
	if err := c.Execute(ctx,
		`INSERT INTO netbox_bindings
		   (prefix_id, network, observed_cidr, vrf_id, cluster_fingerprint,
		    suspended, suspend_reason, validated_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 0, '', ?, ?, ?)
		 ON CONFLICT(prefix_id) DO NOTHING`,
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
