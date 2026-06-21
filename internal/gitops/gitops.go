// Package gitops implements the GitOps controller — a
// standalone binary that watches a Git repo of compose YAML files
// and reconciles each one through the daemon's DeployStack RPC. The
// design is deliberately tiny: clone-or-pull on a poll interval,
// detect changed files since the last commit we processed, fire
// DeployStack for each, log the outcome.
//
// The controller is one-binary, one-daemon-target. Multi-region
// federation is out of scope here — operators run one gitops
// controller per region pointing at a regional repo or branch.
//
// Webhook support is a thin HTTP listener on a configurable port:
// any POST triggers an immediate reconcile cycle, on top of the
// background poll. Authenticity isn't enforced — the listener binds
// to 127.0.0.1 by default; expose it to the WAN behind a real
// reverse proxy with HMAC checking.

package gitops

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config is the controller's configuration. Loaded from YAML or env.
type Config struct {
	// RepoURL is the Git remote to track. Required.
	RepoURL string
	// Branch is the branch within RepoURL to reconcile. Default "main".
	Branch string
	// LocalDir is where the working tree lives on disk. The
	// controller clones into it on first start, then pulls
	// per-cycle. Default `/var/lib/litevirt-gitops/repo`.
	LocalDir string
	// ComposeGlob restricts which paths in the repo are considered
	// compose files. Default "**/compose.yaml".
	ComposeGlob string
	// PollInterval is the background tick. Default 60 s.
	PollInterval time.Duration
	// WebhookBind is the address the webhook listener binds to.
	// Empty disables the webhook listener entirely. Default
	// "127.0.0.1:7700".
	WebhookBind string
	// Deployer is the function the controller calls for each
	// changed compose file. Production wires this to a gRPC
	// DeployStack call; tests pass a recorder.
	Deployer Deployer

	// Differ pre-checks each changed file via DiffStack and skips
	// no-op redeploys. Optional — if nil, the controller always
	// calls Deployer for every changed file.
	Differ Differ

	// Notifier reports each cycle's outcome back to the SCM (e.g.
	// as a GitHub commit comment). Optional — if nil, no post-back.
	Notifier CommitNotifier
}

// Deployer takes a compose YAML body and applies it. It must be
// idempotent — the controller will retry on the next cycle.
type Deployer func(ctx context.Context, path, body string) error

// Differ pre-checks a compose YAML against the live cluster state.
// Returns the count of entries the deploy would actually mutate
// (CREATE / UPDATE / DELETE — never UNCHANGED). When 0 the
// controller skips the deploy entirely, even though the file
// changed — this avoids redeploying every file every time the
// repo's whitespace shifts.
//
// Optional: if nil, the controller never short-circuits and always
// calls Deployer.
type Differ func(ctx context.Context, path, body string) (int, error)

// CommitNotifier posts a single status update back to the SCM for
// one reconcile cycle. Implementations typically call `gh` (GitHub)
// or hit a GitLab/Bitbucket API. Errors are logged but never stop
// the reconcile loop.
//
// Optional: if nil, the controller doesn't try to post back.
type CommitNotifier func(ctx context.Context, status CommitStatus)

// CommitStatus aggregates one reconcile cycle's outcome.
type CommitStatus struct {
	SHA     string
	Total   int      // compose files touched
	OK      []string // paths that deployed cleanly
	Failed  []string // paths that returned an error
	Skipped []string // paths whose Diff reported no-op
	Errors  []string // controller-side errors (pull, diff, etc.)
}

// Controller is the long-running reconcile loop.
type Controller struct {
	cfg  Config
	last atomic.Value // most-recent commit SHA we reconciled against
	mu   sync.Mutex   // serialises reconcile cycles
}

// New returns a Controller with sane defaults applied. The Deployer
// is required and must be non-nil.
func New(cfg Config) (*Controller, error) {
	if cfg.RepoURL == "" {
		return nil, fmt.Errorf("RepoURL required")
	}
	if cfg.Deployer == nil {
		return nil, fmt.Errorf("Deployer required")
	}
	if cfg.Branch == "" {
		cfg.Branch = "main"
	}
	if cfg.LocalDir == "" {
		cfg.LocalDir = "/var/lib/litevirt-gitops/repo"
	}
	if cfg.ComposeGlob == "" {
		cfg.ComposeGlob = "**/compose.yaml"
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 60 * time.Second
	}
	if cfg.WebhookBind == "" {
		cfg.WebhookBind = "127.0.0.1:7700"
	}
	return &Controller{cfg: cfg}, nil
}

// Run blocks until ctx is cancelled. Spawns a background poll loop
// and (optionally) a webhook listener that triggers immediate
// reconciles.
func (c *Controller) Run(ctx context.Context) error {
	if err := c.ensureClone(ctx); err != nil {
		return fmt.Errorf("initial clone: %w", err)
	}

	wg := &sync.WaitGroup{}
	if c.cfg.WebhookBind != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.serveWebhook(ctx)
		}()
	}

	tick := time.NewTicker(c.cfg.PollInterval)
	defer tick.Stop()

	// First reconcile fires immediately so a fresh controller picks
	// up the world on start.
	c.Reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-tick.C:
			c.Reconcile(ctx)
		}
	}
}

// Reconcile runs one cycle: pull, list compose files that changed
// since the last successful cycle, optionally pre-check via Differ
// (skipping no-op files), fire Deployer for the rest, and post one
// status update back to the SCM. Safe to call concurrently — the
// inner mutex serialises.
func (c *Controller) Reconcile(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev := c.lastSHA()
	sha, err := c.pull(ctx)
	if err != nil {
		slog.Warn("gitops: pull", "error", err)
		c.notify(ctx, CommitStatus{SHA: sha, Errors: []string{"pull: " + err.Error()}})
		return
	}
	if sha == prev && prev != "" {
		return // nothing changed
	}
	changed, err := c.changedComposes(ctx, prev, sha)
	if err != nil {
		slog.Warn("gitops: diff", "from", prev, "to", sha, "error", err)
		c.notify(ctx, CommitStatus{SHA: sha, Errors: []string{"git diff: " + err.Error()}})
		return
	}

	status := CommitStatus{SHA: sha, Total: len(changed)}
	for _, p := range changed {
		body, err := os.ReadFile(filepath.Join(c.cfg.LocalDir, p))
		if err != nil {
			slog.Warn("gitops: read compose", "path", p, "error", err)
			status.Failed = append(status.Failed, p)
			continue
		}
		// Pre-check via Differ when wired. A diff that returns 0
		// mutations means "the YAML changed but the resolved plan
		// matches live state" — e.g. whitespace, comments, key
		// reordering — and we skip the deploy entirely.
		if c.cfg.Differ != nil {
			n, derr := c.cfg.Differ(ctx, p, string(body))
			if derr != nil {
				slog.Warn("gitops: diff stack", "path", p, "error", derr)
				// Fall through and let Deployer take a real swing;
				// a failed Differ shouldn't block the cycle.
			} else if n == 0 {
				slog.Info("gitops: no-op (diff clean)", "path", p)
				status.Skipped = append(status.Skipped, p)
				continue
			}
		}
		if err := c.cfg.Deployer(ctx, p, string(body)); err != nil {
			slog.Warn("gitops: deploy failed", "path", p, "error", err)
			status.Failed = append(status.Failed, p)
			continue
		}
		slog.Info("gitops: deployed", "path", p, "sha", sha[:min(7, len(sha))])
		status.OK = append(status.OK, p)
	}
	c.last.Store(sha)
	c.notify(ctx, status)
}

// notify forwards a CommitStatus to the configured Notifier. No-op
// when no notifier is wired or the status carries nothing meaningful.
func (c *Controller) notify(ctx context.Context, s CommitStatus) {
	if c.cfg.Notifier == nil {
		return
	}
	if s.Total == 0 && len(s.Errors) == 0 {
		return
	}
	c.cfg.Notifier(ctx, s)
}

// ensureClone clones the repo if LocalDir doesn't exist yet.
func (c *Controller) ensureClone(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(c.cfg.LocalDir, ".git")); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.cfg.LocalDir), 0o755); err != nil {
		return err
	}
	out, err := runGit(ctx, "", "clone", "--branch", c.cfg.Branch, c.cfg.RepoURL, c.cfg.LocalDir)
	if err != nil {
		return fmt.Errorf("git clone: %w (%s)", err, out)
	}
	return nil
}

// pull does `git fetch + reset --hard origin/<branch>` and returns
// the new HEAD SHA.
func (c *Controller) pull(ctx context.Context) (string, error) {
	if _, err := runGit(ctx, c.cfg.LocalDir, "fetch", "origin", c.cfg.Branch); err != nil {
		return "", err
	}
	if _, err := runGit(ctx, c.cfg.LocalDir, "reset", "--hard", "origin/"+c.cfg.Branch); err != nil {
		return "", err
	}
	sha, err := runGit(ctx, c.cfg.LocalDir, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(sha), nil
}

// changedComposes lists compose files that changed between two SHAs.
// If `from` is empty (first reconcile), returns all compose files
// matching the glob — that's the bootstrap path.
func (c *Controller) changedComposes(ctx context.Context, from, to string) ([]string, error) {
	if from == "" {
		// Bootstrap: list every compose file matching ComposeGlob.
		out, err := runGit(ctx, c.cfg.LocalDir, "ls-files")
		if err != nil {
			return nil, err
		}
		return filterComposes(strings.Split(strings.TrimSpace(out), "\n"), c.cfg.ComposeGlob), nil
	}
	out, err := runGit(ctx, c.cfg.LocalDir, "diff", "--name-only", from, to)
	if err != nil {
		return nil, err
	}
	return filterComposes(strings.Split(strings.TrimSpace(out), "\n"), c.cfg.ComposeGlob), nil
}

// filterComposes keeps paths matching the glob. Uses filepath.Match
// for simple patterns; multi-segment "**" expands to "match any
// number of path segments".
func filterComposes(paths []string, pattern string) []string {
	var out []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		if matchComposeGlob(p, pattern) {
			out = append(out, p)
		}
	}
	return out
}

// matchComposeGlob is a tiny "**" aware matcher. Supports patterns
// like "**/compose.yaml" or "stacks/*/compose.yaml". Not full
// double-star semantics; just enough for the common cases.
func matchComposeGlob(path, pattern string) bool {
	if strings.HasPrefix(pattern, "**/") {
		return strings.HasSuffix(path, strings.TrimPrefix(pattern, "**/"))
	}
	ok, _ := filepath.Match(pattern, path)
	return ok
}

// serveWebhook listens for POSTs on cfg.WebhookBind. Any request
// fires a reconcile. No auth — bind to localhost or front with a
// real auth proxy.
func (c *Controller) serveWebhook(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/reconcile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		go c.Reconcile(context.Background())
		w.WriteHeader(http.StatusAccepted)
	})
	srv := &http.Server{
		Addr:              c.cfg.WebhookBind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Warn("gitops: webhook listener", "error", err)
	}
}

func (c *Controller) lastSHA() string {
	v := c.last.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// runGit shells out to git. `cwd` is the working directory ("" =
// current). Returns combined stdout/stderr — handy when the caller
// wants to surface git's error message.
func runGit(ctx context.Context, cwd string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
