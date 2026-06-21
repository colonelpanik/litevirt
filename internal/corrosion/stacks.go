package corrosion

import (
	"context"
	"time"
)

// StackRecord represents a deployed compose stack.
type StackRecord struct {
	Name        string
	ComposeHash string
	ComposeYAML string
	State       string
	CreatedAt   string
	UpdatedAt   string
}

// UpsertStack creates or updates a stack record.
func UpsertStack(ctx context.Context, c *Client, s StackRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   compose_hash = excluded.compose_hash,
		   compose_yaml = excluded.compose_yaml,
		   state        = excluded.state,
		   updated_at   = excluded.updated_at,
		   deleted_at   = NULL`,
		s.Name, s.ComposeHash, s.ComposeYAML, s.State, now, now,
	)
}

// GetStack returns a stack by name, or nil if not found.
func GetStack(ctx context.Context, c *Client, name string) (*StackRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, compose_hash, compose_yaml, state, created_at, updated_at
		 FROM stacks WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &StackRecord{
		Name:        r.String("name"),
		ComposeHash: r.String("compose_hash"),
		ComposeYAML: r.String("compose_yaml"),
		State:       r.String("state"),
		CreatedAt:   r.String("created_at"),
		UpdatedAt:   r.String("updated_at"),
	}, nil
}

// ListStacks returns all active stacks.
func ListStacks(ctx context.Context, c *Client) ([]StackRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, compose_hash, compose_yaml, state, created_at, updated_at
		 FROM stacks WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	stacks := make([]StackRecord, len(rows))
	for i, r := range rows {
		stacks[i] = StackRecord{
			Name:        r.String("name"),
			ComposeHash: r.String("compose_hash"),
			ComposeYAML: r.String("compose_yaml"),
			State:       r.String("state"),
			CreatedAt:   r.String("created_at"),
			UpdatedAt:   r.String("updated_at"),
		}
	}
	return stacks, nil
}

// SetStackState updates the state column of a stack (e.g. "active" → "deleting").
func SetStackState(ctx context.Context, c *Client, name, state string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE stacks SET state = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
		state, now, name,
	)
}

// ListDeletingStacks returns stacks that are mid-deletion (state = 'deleting').
func ListDeletingStacks(ctx context.Context, c *Client) ([]StackRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, compose_hash, compose_yaml, state, created_at, updated_at
		 FROM stacks WHERE state = 'deleting' AND deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	stacks := make([]StackRecord, len(rows))
	for i, r := range rows {
		stacks[i] = StackRecord{
			Name:        r.String("name"),
			ComposeHash: r.String("compose_hash"),
			ComposeYAML: r.String("compose_yaml"),
			State:       r.String("state"),
			CreatedAt:   r.String("created_at"),
			UpdatedAt:   r.String("updated_at"),
		}
	}
	return stacks, nil
}

// DeleteStackRecord tombstones a stack.
func DeleteStackRecord(ctx context.Context, c *Client, name string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE stacks SET deleted_at = ?, updated_at = ?, state = 'deleted' WHERE name = ?`,
		now, now, name,
	)
}
