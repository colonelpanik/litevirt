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

// ── container_restarts (schema v24) ─────────────────────────────────────────
// Mirrors the vm_restarts helpers above, keyed by (host_name, name) since a
// container's identity is host-local (unlike a globally-unique VM name).

// ContainerRestartState tracks restart attempts for a container within a window.
type ContainerRestartState struct {
	HostName     string
	Name         string
	AttemptCount int
	WindowStart  time.Time
	LastRestart  time.Time
}

// GetContainerRestartState returns the restart tracking for a container, or nil.
func GetContainerRestartState(ctx context.Context, c *Client, hostName, name string) (*ContainerRestartState, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, name, attempt_count, window_start, last_restart
		 FROM container_restarts WHERE host_name = ? AND name = ?`, hostName, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	ws, _ := time.Parse(time.RFC3339, r.String("window_start"))
	lr, _ := time.Parse(time.RFC3339, r.String("last_restart"))
	return &ContainerRestartState{
		HostName:     r.String("host_name"),
		Name:         r.String("name"),
		AttemptCount: r.Int("attempt_count"),
		WindowStart:  ws,
		LastRestart:  lr,
	}, nil
}

// IncrementContainerRestart records a restart attempt for a container.
func IncrementContainerRestart(ctx context.Context, c *Client, hostName, name string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT INTO container_restarts (host_name, name, attempt_count, window_start, last_restart, updated_at)
		 VALUES (?, ?, 1, ?, ?, ?)
		 ON CONFLICT(host_name, name) DO UPDATE SET
		   attempt_count = container_restarts.attempt_count + 1,
		   last_restart = excluded.last_restart,
		   updated_at = excluded.updated_at`,
		hostName, name, now, now, now,
	)
}

// ResetContainerRestartState resets the restart counter (e.g. window expiry).
func ResetContainerRestartState(ctx context.Context, c *Client, hostName, name string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT INTO container_restarts (host_name, name, attempt_count, window_start, last_restart, updated_at)
		 VALUES (?, ?, 0, ?, NULL, ?)
		 ON CONFLICT(host_name, name) DO UPDATE SET
		   attempt_count = 0,
		   window_start = excluded.window_start,
		   last_restart = NULL,
		   updated_at = excluded.updated_at`,
		hostName, name, now, now,
	)
}

// DeleteContainerRestartState removes the restart tracking for a container.
func DeleteContainerRestartState(ctx context.Context, c *Client, hostName, name string) error {
	return c.Execute(ctx, `DELETE FROM container_restarts WHERE host_name = ? AND name = ?`, hostName, name)
}
