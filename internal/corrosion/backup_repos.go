package corrosion

import (
	"context"
	"time"
)

// BackupRepo is a logical backup-repo name → on-disk path mapping, registered
// at runtime (e.g. from a compose `backup-repos:` block) and CRDT-replicated so
// every host can resolve the name. Daemon config `backup_repos:` is the static
// alternative and takes precedence in the resolver.
type BackupRepo struct {
	Name      string
	Path      string
	StackName string
}

// UpsertBackupRepo registers (or updates) a named repo path.
func UpsertBackupRepo(ctx context.Context, c *Client, r BackupRepo) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT INTO backup_repos (name, path, stack_name, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(name) DO UPDATE SET path = excluded.path,
		   stack_name = excluded.stack_name, updated_at = excluded.updated_at, deleted_at = NULL`,
		r.Name, r.Path, r.StackName, now, now,
	)
}

// GetBackupRepoPath resolves a repo name to its path, or "" if unregistered.
func GetBackupRepoPath(ctx context.Context, c *Client, name string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT path FROM backup_repos WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].String("path"), nil
}

// ListBackupRepos returns every live registered repo.
func ListBackupRepos(ctx context.Context, c *Client) ([]BackupRepo, error) {
	rows, err := c.Query(ctx,
		`SELECT name, path, stack_name FROM backup_repos WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := make([]BackupRepo, len(rows))
	for i, r := range rows {
		out[i] = BackupRepo{Name: r.String("name"), Path: r.String("path"), StackName: r.String("stack_name")}
	}
	return out, nil
}

// DeleteStackBackupRepos tombstones the repos a compose stack registered.
func DeleteStackBackupRepos(ctx context.Context, c *Client, stack string) error {
	if stack == "" {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE backup_repos SET deleted_at = ?, updated_at = ? WHERE stack_name = ? AND deleted_at IS NULL`,
		now, now, stack)
}
