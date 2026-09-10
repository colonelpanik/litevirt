package corrosion

import (
	"context"
	"fmt"
	"time"
)

// netbox_host_config is the per-host publication of the NetBox configuration a
// node cannot latch: the `virtualization.cluster` name it resolves.
//
// WHY A TABLE AND NOT A COLUMN ON `hosts`. `hosts.capacity_policy_hash` is the
// obvious precedent — a per-host published config fingerprint on the node's own
// row — but a new column on `hosts` costs something a new table does not. A
// receiver refuses a whole table dump whose column set it does not recognise
// (sync.go, "skipping dump table with unexpected columns"), so during the window
// where one node has migrated and another has not, a `hosts` column makes peers
// discard the entire `hosts` dump — the table whose divergence takes the control
// plane with it. A table absent on the older peer is simply a table it does not
// have. The publication is host-owned either way: host_name is the PK and only
// that host writes its row, exactly like host_networks.
//
// WHY THE NAME AND NOT A HASH. capacity_policy_hash hashes because an admission
// policy is a compound structure with no useful short rendering. A cluster name
// already IS a short human string, and the health condition it feeds has to name
// both values — an operator cannot correct a disagreement they cannot read, and
// two differing hashes say only that something differs.

// PublishNetBoxHostConfig records the NetBox cluster name `host` resolves.
//
// WRITE-IF-CHANGED. This runs on every mirror pass on every node, forever. An
// unconditional upsert would restamp updated_at — the LWW key — on a row nothing
// changed, churning replication and giving a genuine concurrent write something
// to tie against. SetHostLabel and reconcileHostAddress take this shape for the
// same reason.
func PublishNetBoxHostConfig(ctx context.Context, c *Client, host, clusterName string) error {
	if host == "" {
		return fmt.Errorf("publishing a NetBox host config requires a host name")
	}
	rows, err := c.Query(ctx,
		`SELECT netbox_cluster FROM netbox_host_config WHERE host_name = ? AND deleted_at IS NULL`,
		host)
	if err != nil {
		return fmt.Errorf("read published NetBox config for %s: %w", host, err)
	}
	if len(rows) == 1 && rows[0].String("netbox_cluster") == clusterName {
		return nil
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO netbox_host_config (host_name, netbox_cluster, created_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(host_name) DO UPDATE SET
			netbox_cluster = excluded.netbox_cluster,
			updated_at     = excluded.updated_at,
			deleted_at     = NULL`,
		host, clusterName, time.Now().UTC().Format(time.RFC3339), now)
}

// ListNetBoxHostConfig returns every host's published NetBox cluster name.
//
// Every host, not the live ones: which hosts count is the CALLER's rule, and it
// differs by caller (the mirror counts only hosts it can currently see, so a
// fenced node's stale value cannot block mirroring forever). Filtering here
// would put that decision somewhere no caller can see it.
func ListNetBoxHostConfig(ctx context.Context, c *Client) (map[string]string, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, netbox_cluster FROM netbox_host_config WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("list published NetBox host configs: %w", err)
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.String("host_name")] = r.String("netbox_cluster")
	}
	return out, nil
}
