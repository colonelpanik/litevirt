package gitops

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// initRemoteRepo builds a tiny bare git repo with one commit in a
// tempdir and returns its URL (file:///… path). Cheap fixture; uses
// the real `git` binary because the controller does too.
func initRemoteRepo(t *testing.T) (remoteURL, workTree string) {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, "remote.git")
	work := filepath.Join(root, "scratch")

	mustRun(t, "", "git", "init", "--bare", "--initial-branch=main", bare)
	mustRun(t, "", "git", "clone", bare, work)
	// Author so git commit doesn't refuse.
	mustRun(t, work, "git", "config", "user.email", "fleet@example.com")
	mustRun(t, work, "git", "config", "user.name", "fleet")
	return "file://" + bare, work
}

func mustRun(t *testing.T, cwd string, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func TestGitOps_BootstrapDeploysAllComposes(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	remote, work := initRemoteRepo(t)

	// Seed two compose files and push.
	mkfile(t, filepath.Join(work, "stack-a", "compose.yaml"), "name: stack-a\n")
	mkfile(t, filepath.Join(work, "stack-b", "compose.yaml"), "name: stack-b\n")
	mustRun(t, work, "git", "add", "-A")
	mustRun(t, work, "git", "commit", "-m", "init")
	mustRun(t, work, "git", "push", "origin", "main")

	var (
		mu       sync.Mutex
		deployed []string
	)
	deployer := func(ctx context.Context, path, body string) error {
		mu.Lock()
		defer mu.Unlock()
		deployed = append(deployed, path)
		return nil
	}

	ctrl, err := New(Config{
		RepoURL:      remote,
		Branch:       "main",
		LocalDir:     filepath.Join(t.TempDir(), "wd"),
		ComposeGlob:  "**/compose.yaml",
		PollInterval: 24 * time.Hour, // we drive Reconcile directly
		WebhookBind:  "",             // disable webhook listener
		Deployer:     deployer,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := ctrl.ensureClone(ctx); err != nil {
		t.Fatalf("ensureClone: %v", err)
	}
	ctrl.Reconcile(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(deployed) != 2 {
		t.Fatalf("expected 2 deploys, got %d (%v)", len(deployed), deployed)
	}
	want := map[string]bool{"stack-a/compose.yaml": false, "stack-b/compose.yaml": false}
	for _, p := range deployed {
		if _, ok := want[p]; !ok {
			t.Errorf("unexpected deploy path %q", p)
			continue
		}
		want[p] = true
	}
	for p, seen := range want {
		if !seen {
			t.Errorf("missed deploy %q", p)
		}
	}
}

func TestGitOps_OnlyChangedComposesDeployOnSecondCycle(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	remote, work := initRemoteRepo(t)
	mkfile(t, filepath.Join(work, "stack-a", "compose.yaml"), "name: stack-a\n")
	mkfile(t, filepath.Join(work, "stack-b", "compose.yaml"), "name: stack-b\n")
	mustRun(t, work, "git", "add", "-A")
	mustRun(t, work, "git", "commit", "-m", "init")
	mustRun(t, work, "git", "push", "origin", "main")

	var (
		mu       sync.Mutex
		deployed []string
	)
	deployer := func(ctx context.Context, path, body string) error {
		mu.Lock()
		defer mu.Unlock()
		deployed = append(deployed, path)
		return nil
	}
	ctrl, err := New(Config{
		RepoURL:      remote,
		Branch:       "main",
		LocalDir:     filepath.Join(t.TempDir(), "wd"),
		ComposeGlob:  "**/compose.yaml",
		PollInterval: 24 * time.Hour,
		WebhookBind:  "",
		Deployer:     deployer,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := ctrl.ensureClone(ctx); err != nil {
		t.Fatalf("ensureClone: %v", err)
	}
	ctrl.Reconcile(ctx) // bootstrap: 2 deploys
	mu.Lock()
	bootstrapCount := len(deployed)
	mu.Unlock()
	if bootstrapCount != 2 {
		t.Fatalf("bootstrap should fire 2 deploys, got %d", bootstrapCount)
	}

	// Push a change to ONE compose file.
	mkfile(t, filepath.Join(work, "stack-a", "compose.yaml"), "name: stack-a-v2\n")
	mustRun(t, work, "git", "add", "-A")
	mustRun(t, work, "git", "commit", "-m", "tweak stack-a")
	mustRun(t, work, "git", "push", "origin", "main")

	ctrl.Reconcile(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(deployed) != 3 {
		t.Fatalf("second cycle should add 1 deploy, total now %d (%v)", len(deployed), deployed)
	}
	if deployed[2] != "stack-a/compose.yaml" {
		t.Errorf("expected stack-a/compose.yaml on second cycle, got %q", deployed[2])
	}
}

func TestGitOps_NoChangesIsNoop(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	remote, work := initRemoteRepo(t)
	mkfile(t, filepath.Join(work, "stack-a", "compose.yaml"), "name: stack-a\n")
	mustRun(t, work, "git", "add", "-A")
	mustRun(t, work, "git", "commit", "-m", "init")
	mustRun(t, work, "git", "push", "origin", "main")

	var called int
	deployer := func(ctx context.Context, path, body string) error {
		called++
		return nil
	}
	ctrl, _ := New(Config{
		RepoURL: remote, Branch: "main",
		LocalDir:     filepath.Join(t.TempDir(), "wd"),
		ComposeGlob:  "**/compose.yaml",
		PollInterval: 24 * time.Hour,
		WebhookBind:  "",
		Deployer:     deployer,
	})
	ctx := context.Background()
	if err := ctrl.ensureClone(ctx); err != nil {
		t.Fatalf("ensureClone: %v", err)
	}
	ctrl.Reconcile(ctx)
	if called != 1 {
		t.Fatalf("bootstrap should fire 1 deploy, got %d", called)
	}
	// Subsequent reconciles with no remote changes must be no-ops.
	ctrl.Reconcile(ctx)
	ctrl.Reconcile(ctx)
	if called != 1 {
		t.Errorf("expected 1 total deploy (no remote change), got %d", called)
	}
}

func TestMatchComposeGlob(t *testing.T) {
	cases := []struct {
		path, pattern string
		want          bool
	}{
		{"stacks/web/compose.yaml", "**/compose.yaml", true},
		{"compose.yaml", "**/compose.yaml", true},
		{"a/b/c/compose.yaml", "**/compose.yaml", true},
		{"stacks/web/notes.md", "**/compose.yaml", false},
		{"stacks/web/compose.yaml", "stacks/*/compose.yaml", true},
		{"deep/stacks/web/compose.yaml", "stacks/*/compose.yaml", false},
	}
	for _, tc := range cases {
		if got := matchComposeGlob(tc.path, tc.pattern); got != tc.want {
			t.Errorf("matchComposeGlob(%q, %q) = %v, want %v", tc.path, tc.pattern, got, tc.want)
		}
	}
}

func mkfile(t *testing.T, path, body string) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := exec.Command("mkdir", "-p", dir).Run(); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := exec.Command("sh", "-c", "echo "+sqEscape(body)+" > "+path).Run(); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func sqEscape(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
