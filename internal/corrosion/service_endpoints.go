package corrosion

import (
	"context"
	"fmt"
	"time"
)

// ServiceEndpoint is one (service_name, ip, region) triple. The DNS
// server queries this table on every lookup and round-robins the
// returned rows so a multi-region service surfaces as a single name
// without an external anycast IP.
type ServiceEndpoint struct {
	ServiceName string
	IP          string
	Region      string
	Weight      int
}

// UpsertServiceEndpoint creates or updates the (service_name, ip) row.
// Region defaults to "default" when empty; weight defaults to 1.
func UpsertServiceEndpoint(ctx context.Context, c *Client, e ServiceEndpoint) error {
	if e.ServiceName == "" || e.IP == "" {
		return fmt.Errorf("service_name and ip required")
	}
	if e.Region == "" {
		e.Region = "default"
	}
	if e.Weight <= 0 {
		e.Weight = 1
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT INTO service_endpoints (service_name, ip, region, weight, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(service_name, ip) DO UPDATE SET
		   region     = excluded.region,
		   weight     = excluded.weight,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		e.ServiceName, e.IP, e.Region, e.Weight, now, now)
}

// ListServiceEndpoints returns all non-deleted endpoints. If serviceName
// is non-empty, the result is filtered to that service.
func ListServiceEndpoints(ctx context.Context, c *Client, serviceName string) ([]ServiceEndpoint, error) {
	q := `SELECT service_name, ip, region, weight
	      FROM service_endpoints
	      WHERE deleted_at IS NULL`
	args := []interface{}{}
	if serviceName != "" {
		q += " AND service_name = ?"
		args = append(args, serviceName)
	}
	q += " ORDER BY service_name, ip"
	rows, err := c.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list service_endpoints: %w", err)
	}
	out := make([]ServiceEndpoint, 0, len(rows))
	for _, r := range rows {
		w := r.Int("weight")
		if w <= 0 {
			w = 1
		}
		out = append(out, ServiceEndpoint{
			ServiceName: r.String("service_name"),
			IP:          r.String("ip"),
			Region:      r.String("region"),
			Weight:      w,
		})
	}
	return out, nil
}

// DeleteServiceEndpoint soft-deletes a (service_name, ip) row.
func DeleteServiceEndpoint(ctx context.Context, c *Client, serviceName, ip string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE service_endpoints SET deleted_at = ?, updated_at = ?
		 WHERE service_name = ? AND ip = ?`,
		now, now, serviceName, ip)
}
