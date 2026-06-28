package corrosion

import "context"

// HostRuntimeUsage is a per-host runtime-telemetry sample the placement engine
// reads to score the DiskIOPS/NetBW dimensions.
type HostRuntimeUsage struct {
	HostName string
	DiskIOPS int64 // aggregate disk IOPS (read+write ops/sec) across the host's domains
	NetMbps  int64 // aggregate network throughput (rx+tx) in megabits/sec
}

// UpsertHostRuntimeUsage records THIS host's current runtime telemetry. It uses
// ExecuteDeferred (telemetry isn't instant-critical — replicates on the next
// periodic tick) and NowTS for the LWW updated_at; deleted_at is left untouched.
func UpsertHostRuntimeUsage(ctx context.Context, c *Client, hostName string, diskIOPS, netMbps int64) error {
	return c.ExecuteDeferred(ctx,
		`INSERT INTO host_runtime_usage (host_name, disk_iops, net_mbps, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(host_name) DO UPDATE SET
		   disk_iops = excluded.disk_iops,
		   net_mbps = excluded.net_mbps,
		   updated_at = excluded.updated_at`,
		hostName, diskIOPS, netMbps, c.NowTS())
}

// ListHostRuntimeUsage returns live per-host runtime telemetry keyed by host name.
func ListHostRuntimeUsage(ctx context.Context, c *Client) (map[string]HostRuntimeUsage, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, disk_iops, net_mbps FROM host_runtime_usage WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]HostRuntimeUsage, len(rows))
	for _, r := range rows {
		out[r.String("host_name")] = HostRuntimeUsage{
			HostName: r.String("host_name"),
			DiskIOPS: r.Int64("disk_iops"),
			NetMbps:  r.Int64("net_mbps"),
		}
	}
	return out, nil
}
