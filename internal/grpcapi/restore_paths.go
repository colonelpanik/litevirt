package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// restoreAuthDecision resolves which project a restore is authorized against
// and returns it for downstream use (e.g. forcing it onto the restored record).
//
// The manifest's embedded project is AUTHORITATIVE — it is the project the
// backup belongs to. The live row (if the name currently exists) is only a
// fallback for legacy manifests that carry no project. Crucially, if the
// manifest's project differs from a current same-named resource's project
// (project A reused a name from project B), the restore would let one tenant
// read/write across the boundary, so it requires admin. When neither the
// manifest nor a live row yields a project, it also requires admin.
func (s *Server) restoreAuthDecision(ctx context.Context, manifestProject, liveProject string, liveExists bool) (string, error) {
	switch {
	case manifestProject != "":
		// Backup's own project wins. A mismatch with a current same-named
		// resource is a name-reuse cross-tenant hazard → admin only.
		if liveExists && tenancy.NormalizeProject(manifestProject) != tenancy.NormalizeProject(liveProject) {
			if err := RequireRole(ctx, "admin"); err != nil {
				return "", status.Error(codes.PermissionDenied,
					"the backup's project differs from the current resource's project (name reuse); restore requires the admin role")
			}
		}
		return manifestProject, nil
	case liveExists:
		// Legacy manifest with no embedded project: scope to the live row.
		return liveProject, nil
	default:
		// No manifest project and no live row → can't scope; require admin.
		if err := RequireRole(ctx, "admin"); err != nil {
			return "", status.Error(codes.PermissionDenied,
				"cannot determine the backup's project (no embedded spec, no live resource); restore requires the admin role")
		}
		return tenancy.Default, nil
	}
}

// authorizeVMRestore enforces backup.restore on the project a VM backup belongs
// to (manifest-derived, with the name-reuse / undeterminable cases gated on
// admin — see restoreAuthDecision).
func (s *Server) authorizeVMRestore(ctx context.Context, vmName string, m *pbsstore.Manifest) (string, error) {
	liveProject, liveExists := "", false
	if vm, _ := corrosion.GetVM(ctx, s.db, vmName); vm != nil {
		liveProject, liveExists = vm.Project, true
	}
	project, err := s.restoreAuthDecision(ctx, manifestVMProject(m), liveProject, liveExists)
	if err != nil {
		return "", err
	}
	if err := s.RequirePerm(ctx, vmRBACPathFor(project, vmName), "backup.restore", "operator"); err != nil {
		return "", err
	}
	return project, nil
}

// authorizeContainerRestore is the container analogue; it returns the resolved
// project so the rebuilt row lands in the backup's project (when authorized),
// never the unauthenticated manifest-claimed project blindly.
func (s *Server) authorizeContainerRestore(ctx context.Context, name string, m *pbsstore.Manifest) (string, error) {
	liveProject, liveExists := "", false
	if rec, _ := corrosion.GetContainer(ctx, s.db, s.hostName, name); rec != nil {
		liveProject, liveExists = rec.Project, true
	}
	project, err := s.restoreAuthDecision(ctx, manifestContainerProject(m), liveProject, liveExists)
	if err != nil {
		return "", err
	}
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, name), "backup.restore", "operator"); err != nil {
		return "", err
	}
	return project, nil
}

// manifestVMProject returns the project embedded in a VM backup manifest's spec
// ("" when absent — a legacy manifest).
func manifestVMProject(m *pbsstore.Manifest) string {
	if m != nil && m.VMSpecJSON != "" {
		var spec pb.VMSpec
		if json.Unmarshal([]byte(m.VMSpecJSON), &spec) == nil {
			return spec.Project
		}
	}
	return ""
}

func manifestContainerProject(m *pbsstore.Manifest) string {
	if m != nil && m.ContainerSpecJSON != "" {
		var spec containerBackupSpec
		if json.Unmarshal([]byte(m.ContainerSpecJSON), &spec) == nil {
			return spec.Project
		}
	}
	return ""
}

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
