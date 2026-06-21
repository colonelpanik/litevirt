package corrosion

import (
	"context"
	"time"
)

// RestartState tracks restart attempts for a VM within a sliding window.
type RestartState struct {
	VMName       string
	AttemptCount int
	WindowStart  time.Time
	LastRestart  time.Time
}

// GetRestartState returns the restart tracking state for a VM, or nil if none exists.
func GetRestartState(ctx context.Context, c *Client, vmName string) (*RestartState, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, attempt_count, window_start, last_restart
		 FROM vm_restarts WHERE vm_name = ?`, vmName)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	ws, _ := time.Parse(time.RFC3339, r.String("window_start"))
	lr, _ := time.Parse(time.RFC3339, r.String("last_restart"))
	return &RestartState{
		VMName:       r.String("vm_name"),
		AttemptCount: r.Int("attempt_count"),
		WindowStart:  ws,
		LastRestart:  lr,
	}, nil
}

// IncrementRestart records a restart attempt for a VM.
func IncrementRestart(ctx context.Context, c *Client, vmName string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT INTO vm_restarts (vm_name, attempt_count, window_start, last_restart, updated_at)
		 VALUES (?, 1, ?, ?, ?)
		 ON CONFLICT(vm_name) DO UPDATE SET
		   attempt_count = vm_restarts.attempt_count + 1,
		   last_restart = excluded.last_restart,
		   updated_at = excluded.updated_at`,
		vmName, now, now, now,
	)
}

// ResetRestartState resets the restart counter for a VM (e.g. when the window expires).
func ResetRestartState(ctx context.Context, c *Client, vmName string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT INTO vm_restarts (vm_name, attempt_count, window_start, last_restart, updated_at)
		 VALUES (?, 0, ?, NULL, ?)
		 ON CONFLICT(vm_name) DO UPDATE SET
		   attempt_count = 0,
		   window_start = excluded.window_start,
		   last_restart = NULL,
		   updated_at = excluded.updated_at`,
		vmName, now, now,
	)
}

// DeleteRestartState removes the restart tracking for a VM.
func DeleteRestartState(ctx context.Context, c *Client, vmName string) error {
	return c.Execute(ctx, `DELETE FROM vm_restarts WHERE vm_name = ?`, vmName)
}
