package grpcapi

import (
	"context"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
)

// SetBackupRepos records the daemon's configured repo-name → path map so the
// RPC handlers can resolve a request's repo_path the same way the scheduler
// does. Called once at daemon startup.
func (s *Server) SetBackupRepos(repos map[string]string) { s.backupRepos = repos }

// resolveBackupRepoPath maps a request's repo_path to a concrete on-disk repo
// path under a consistent policy: a registered repo NAME (daemon config or a
// cluster-registered compose repo) is allowed for any caller; a custom absolute
// path is admin-only (it can read/write anywhere on the host). An unknown,
// non-absolute value is rejected. This keeps pbsstore.Open off arbitrary
// operator-chosen paths.
func (s *Server) resolveBackupRepoPath(ctx context.Context, repoPath string) (string, error) {
	if repoPath == "" {
		return "", status.Error(codes.InvalidArgument, "repo_path required")
	}
	if p, ok := s.backupRepos[repoPath]; ok {
		return p, nil
	}
	if s.db != nil {
		if p, err := corrosion.GetBackupRepoPath(ctx, s.db, repoPath); err == nil && p != "" {
			return p, nil
		}
	}
	if filepath.IsAbs(repoPath) {
		if err := RequireRole(ctx, "admin"); err != nil {
			return "", status.Error(codes.PermissionDenied,
				"a custom absolute repo_path requires the admin role; otherwise reference a registered backup repo by name")
		}
		return repoPath, nil
	}
	return "", status.Errorf(codes.NotFound, "unknown backup repo %q (register it or pass an absolute path as admin)", repoPath)
}

// resolveRestoreTarget resolves a restore/replicate destination path under a
// consistent policy: a bare filename (or relative path) is validated and
// contained under defaultDir; a custom absolute path is admin-only. The result
// is always a path it is safe to create + finalize via lstat/temp/rename.
func (s *Server) resolveRestoreTarget(ctx context.Context, targetPath, defaultDir string) (string, error) {
	if targetPath == "" {
		return "", status.Error(codes.InvalidArgument, "target_path required")
	}
	if filepath.IsAbs(targetPath) {
		if err := RequireRole(ctx, "admin"); err != nil {
			return "", status.Error(codes.PermissionDenied,
				"a custom absolute target_path requires the admin role; otherwise pass a bare filename to write under the pool")
		}
		return targetPath, nil
	}
	// Relative: must be a BARE filename (no separators) — don't silently turn
	// "subdir/disk.qcow2" into "disk.qcow2"; reject it so the contract is clear.
	if targetPath != filepath.Base(targetPath) {
		return "", status.Error(codes.InvalidArgument,
			"target_path must be a bare filename (no path separators), or an absolute path (admin only)")
	}
	if err := safename.ValidateName(targetPath); err != nil {
		return "", status.Errorf(codes.InvalidArgument, "target_path: %v", err)
	}
	return safename.SafeJoin(defaultDir, targetPath)
}

// finalizeRestoreFile refuses to write through a symlink already at dst (an
// admin-chosen absolute target could otherwise be redirected). The caller
// creates content at a temp path and renames it to dst; os.Rename replaces a
// symlink at dst atomically rather than following it, but we still reject a
// pre-existing symlink so a planted link is never silently honored.
func refuseSymlinkTarget(dst string) error {
	if fi, err := os.Lstat(dst); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return status.Errorf(codes.FailedPrecondition, "destination %q is a symlink", dst)
	}
	return nil
}
