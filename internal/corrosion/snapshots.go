package corrosion

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// SnapshotRecord represents a stored snapshot.
type SnapshotRecord struct {
	ID        string
	VMName    string
	HostName  string
	Name      string
	State     string
	SizeBytes int64
	CreatedAt string

	// Live/RAM snapshots (#3). Type is "disk" (external disk-only, default) or
	// "memory" (also captured guest RAM). VMStatePath/VMStateBytes describe the
	// saved RAM image for memory snapshots.
	Type         string
	VMStatePath  string
	VMStateBytes int64
}

// InsertSnapshot records a new snapshot.
func InsertSnapshot(ctx context.Context, c *Client, s SnapshotRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	if s.Type == "" {
		s.Type = "disk"
	}
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO snapshots (id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.VMName, s.HostName, s.Name, s.State, s.SizeBytes, s.Type, s.VMStatePath, s.VMStateBytes, now, now,
	)
}

// ListSnapshots returns all snapshots for a VM.
func ListSnapshots(ctx context.Context, c *Client, vmName string) ([]SnapshotRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at
		 FROM snapshots WHERE vm_name = ? AND deleted_at IS NULL ORDER BY created_at`,
		vmName)
	if err != nil {
		return nil, err
	}

	snaps := make([]SnapshotRecord, len(rows))
	for i, r := range rows {
		snaps[i] = scanSnapshot(r)
	}
	return snaps, nil
}

// GetSnapshot returns one snapshot by (vm, name), or (nil, nil) if absent.
// Used by restore/delete so they can branch on snapshot type and reach the
// recorded vmstate path.
func GetSnapshot(ctx context.Context, c *Client, vmName, snapshotName string) (*SnapshotRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at
		 FROM snapshots WHERE vm_name = ? AND name = ? AND deleted_at IS NULL LIMIT 1`,
		vmName, snapshotName)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	s := scanSnapshot(rows[0])
	return &s, nil
}

func scanSnapshot(r Row) SnapshotRecord {
	typ := r.String("type")
	if typ == "" {
		typ = "disk"
	}
	return SnapshotRecord{
		ID:           r.String("id"),
		VMName:       r.String("vm_name"),
		HostName:     r.String("host_name"),
		Name:         r.String("name"),
		State:        r.String("state"),
		SizeBytes:    r.Int64("size_bytes"),
		Type:         typ,
		VMStatePath:  r.String("vmstate_path"),
		VMStateBytes: r.Int64("vmstate_size_bytes"),
		CreatedAt:    r.String("created_at"),
	}
}

// DeleteSnapshot tombstones a snapshot record.
func DeleteSnapshot(ctx context.Context, c *Client, vmName, snapshotName string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE snapshots SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND name = ?`,
		now, now, vmName, snapshotName,
	)
}
