package gitops

import (
	"context"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGitOps_DifferShortCircuitsNoOp confirms that when the Differ
// reports 0 mutations for a changed file, Reconcile doesn't call
// Deployer — even though the file's bytes changed. This is the
// whitespace-only / comment-only no-op the short-circuit
// asks for.
func TestGitOps_DifferShortCircuitsNoOp(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	remote, work := initRemoteRepo(t)
	mkfile(t, filepath.Join(work, "stack-a", "compose.yaml"), "name: stack-a\n")
	mustRun(t, work, "git", "add", "-A")
	mustRun(t, work, "git", "commit", "-m", "init")
	mustRun(t, work, "git", "push", "origin", "main")

	var deployCalls atomic.Int32
	deployer := func(ctx context.Context, path, body string) error {
		deployCalls.Add(1)
		return nil
	}
	// Differ always reports 0 mutations → controller must skip.
	differ := func(ctx context.Context, path, body string) (int, error) {
		return 0, nil
	}
	var (
		notifMu     sync.Mutex
		lastStatus  CommitStatus
		notifyCalls atomic.Int32
	)
	notifier := func(ctx context.Context, s CommitStatus) {
		notifMu.Lock()
		defer notifMu.Unlock()
		lastStatus = s
		notifyCalls.Add(1)
	}

	ctrl, err := New(Config{
		RepoURL: remote, Branch: "main",
		LocalDir:     filepath.Join(t.TempDir(), "wd"),
		ComposeGlob:  "**/compose.yaml",
		PollInterval: 24 * time.Hour,
		WebhookBind:  "",
		Deployer:     deployer,
		Differ:       differ,
		Notifier:     notifier,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := ctrl.ensureClone(ctx); err != nil {
		t.Fatalf("ensureClone: %v", err)
	}
	ctrl.Reconcile(ctx)

	if got := deployCalls.Load(); got != 0 {
		t.Errorf("Differ said no-op; Deployer should NOT have been called (got %d)", got)
	}
	if notifyCalls.Load() != 1 {
		t.Errorf("expected exactly one notifier call, got %d", notifyCalls.Load())
	}
	notifMu.Lock()
	defer notifMu.Unlock()
	if lastStatus.Total != 1 || len(lastStatus.Skipped) != 1 {
		t.Errorf("status mismatch: %+v", lastStatus)
	}
}

// TestGitOps_DifferErrorFallsThrough proves a Differ failure doesn't
// block the reconcile — the controller still calls Deployer because
// a flaky diff shouldn't strand legitimate changes.
func TestGitOps_DifferErrorFallsThrough(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	remote, work := initRemoteRepo(t)
	mkfile(t, filepath.Join(work, "stack-a", "compose.yaml"), "name: stack-a\n")
	mustRun(t, work, "git", "add", "-A")
	mustRun(t, work, "git", "commit", "-m", "init")
	mustRun(t, work, "git", "push", "origin", "main")

	var deployed atomic.Int32
	deployer := func(ctx context.Context, path, body string) error {
		deployed.Add(1)
		return nil
	}
	differ := func(ctx context.Context, path, body string) (int, error) {
		return 0, context.DeadlineExceeded
	}

	ctrl, _ := New(Config{
		RepoURL: remote, Branch: "main",
		LocalDir:     filepath.Join(t.TempDir(), "wd"),
		ComposeGlob:  "**/compose.yaml",
		PollInterval: 24 * time.Hour,
		Deployer:     deployer,
		Differ:       differ,
	})
	ctx := context.Background()
	if err := ctrl.ensureClone(ctx); err != nil {
		t.Fatalf("ensureClone: %v", err)
	}
	ctrl.Reconcile(ctx)

	if deployed.Load() != 1 {
		t.Errorf("Differ error should not block Deploy; got %d deploys", deployed.Load())
	}
}
