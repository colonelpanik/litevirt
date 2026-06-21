package corrosion

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// VMEventRecord is one row of the vm_events table — a durable, replicated,
// append-only record of a per-VM operational event (lifecycle transition,
// backup outcome, etc.). Unlike audit_log it carries no hash chain and is
// prunable (see PruneVMEvents).
type VMEventRecord struct {
	ID       string
	VMName   string
	HostName string
	Type     string // e.g. "backup.failed", "vm.started"
	Result   string // "ok" | "error"
	Severity string // "info" | "warn" | "error"
	Detail   string
	Username string
	TS       string // RFC3339Nano UTC; empty = now at insert
}

// InsertVMEvent appends one event. Idempotent on ID (INSERT OR IGNORE) so a row
// that arrives via Crescent replication isn't double-inserted. ts gets
// nanosecond precision so same-second events on one VM still sort
// deterministically.
func InsertVMEvent(ctx context.Context, c *Client, r VMEventRecord) error {
	if r.ID == "" {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return fmt.Errorf("vm_event id: %w", err)
		}
		r.ID = hex.EncodeToString(b[:])
	}
	if r.TS == "" {
		r.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if r.Result == "" {
		r.Result = "ok"
	}
	if r.Severity == "" {
		r.Severity = "info"
	}
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO vm_events
		   (id, vm_name, host_name, type, result, severity, detail, username, ts)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.VMName, r.HostName, r.Type, r.Result, r.Severity, r.Detail, r.Username, r.TS)
}

// ListVMEvents returns a VM's events newest-first, capped at limit (default 100,
// max 1000). When since is non-empty (RFC3339) only events at/after it are
// returned.
func ListVMEvents(ctx context.Context, c *Client, vmName string, limit int, since string) ([]VMEventRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	// Empty vmName = cluster-wide (the /activity log); a name filters to one VM.
	sql := `SELECT id, vm_name, host_name, type, result, severity, detail, username, ts
		FROM vm_events`
	var args []interface{}
	var where []string
	if vmName != "" {
		where = append(where, "vm_name = ?")
		args = append(args, vmName)
	}
	if since != "" {
		where = append(where, "ts >= ?")
		args = append(args, since)
	}
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY ts DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := c.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("list vm_events: %w", err)
	}
	out := make([]VMEventRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, VMEventRecord{
			ID: r.String("id"), VMName: r.String("vm_name"), HostName: r.String("host_name"),
			Type: r.String("type"), Result: r.String("result"), Severity: r.String("severity"),
			Detail: r.String("detail"), Username: r.String("username"), TS: r.String("ts"),
		})
	}
	return out, nil
}

// PruneVMEvents enforces retention on THIS host's own rows (host_name =
// hostName) so every daemon prunes only what it wrote — idempotent, bounded,
// and needs no cluster lease. The DELETEs replicate, so each host's old rows
// are eventually removed everywhere. Three sweeps:
//   - info/success events older than infoDays
//   - error events older than errDays (kept longer — rare + high-value)
//   - a per-VM newest-N cap (maxPerVM) backstop against a flapping VM
//
// A sweep with a non-positive bound is skipped.
func PruneVMEvents(ctx context.Context, c *Client, hostName string, infoDays, errDays, maxPerVM int) error {
	now := time.Now().UTC()
	if infoDays > 0 {
		cutoff := now.AddDate(0, 0, -infoDays).Format(time.RFC3339Nano)
		if err := c.Execute(ctx,
			`DELETE FROM vm_events WHERE host_name = ? AND result != 'error' AND ts < ?`,
			hostName, cutoff); err != nil {
			return fmt.Errorf("prune info: %w", err)
		}
	}
	if errDays > 0 {
		cutoff := now.AddDate(0, 0, -errDays).Format(time.RFC3339Nano)
		if err := c.Execute(ctx,
			`DELETE FROM vm_events WHERE host_name = ? AND result = 'error' AND ts < ?`,
			hostName, cutoff); err != nil {
			return fmt.Errorf("prune errors: %w", err)
		}
	}
	if maxPerVM > 0 {
		if err := c.Execute(ctx,
			`DELETE FROM vm_events WHERE id IN (
			   SELECT id FROM (
			     SELECT id, ROW_NUMBER() OVER (PARTITION BY vm_name ORDER BY ts DESC, id DESC) AS rn
			     FROM vm_events WHERE host_name = ?
			   ) WHERE rn > ?
			 )`,
			hostName, maxPerVM); err != nil {
			return fmt.Errorf("prune per-vm cap: %w", err)
		}
	}
	return nil
}
