package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/gitops"
)

// newGitopsCmd is the GitOps reconcile loop, folded in from the former
// standalone `litevirt-gitops` binary so litevirt ships as a single binary
// (like `daemon` and `schema-migrate`). It watches a Git repo of compose YAMLs
// and, on every push (or `--poll` tick), diffs each changed file against the
// cluster and deploys it. Auth to the daemon reuses the `lv` gRPC dialer —
// set LV_HOST / LV_TOKEN, or rely on the per-user CLI cert.
func newGitopsCmd() *cobra.Command {
	var (
		repoURL     string
		branch      string
		localDir    string
		composeGlob string
		poll        time.Duration
		webhook     string
	)
	cmd := &cobra.Command{
		Use:   "gitops --repo <url> [flags]",
		Short: "Reconcile a Git repo of compose YAMLs into the cluster (GitOps controller)",
		Long: "Run the GitOps reconcile loop: clone --repo, and on every push (or --poll\n" +
			"tick) diff each changed compose file against the cluster and deploy it.\n" +
			"Auth to the daemon uses the same dialer as the CLI (LV_HOST / LV_TOKEN).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if repoURL == "" {
				return fmt.Errorf("--repo is required")
			}

			ctx, cancel := signal.NotifyContext(context.Background(),
				syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			// Deployer applies one compose file by streaming DeployStack and
			// surfacing the last error, if any.
			deployer := func(ctx context.Context, path, body string) error {
				client, closer, err := cli.Connect(ctx)
				if err != nil {
					return fmt.Errorf("dial daemon: %w", err)
				}
				defer closer()
				stream, err := client.DeployStack(ctx, &pb.DeployStackRequest{
					ComposeYaml: body,
				})
				if err != nil {
					return fmt.Errorf("DeployStack: %w", err)
				}
				for {
					p, err := stream.Recv()
					if err != nil {
						if err.Error() == "EOF" {
							return nil
						}
						return fmt.Errorf("stream: %w", err)
					}
					if p.Error != "" {
						return fmt.Errorf("deploy: %s", p.Error)
					}
				}
			}

			// Differ short-circuits no-op cycles: it returns the number of
			// mutation-bearing entries from DiffStack (UNCHANGED rows excluded),
			// so a whitespace-only repo bump doesn't redeploy.
			differ := func(ctx context.Context, path, body string) (int, error) {
				client, closer, err := cli.Connect(ctx)
				if err != nil {
					return 0, fmt.Errorf("dial daemon: %w", err)
				}
				defer closer()
				resp, err := client.DiffStack(ctx, &pb.DiffStackRequest{ComposeYaml: body})
				if err != nil {
					return 0, fmt.Errorf("DiffStack: %w", err)
				}
				muts := 0
				for _, e := range resp.Entries {
					if e.Operation != pb.DiffOp_DIFF_UNCHANGED {
						muts++
					}
				}
				return muts, nil
			}

			ctrl, err := gitops.New(gitops.Config{
				RepoURL:      repoURL,
				Branch:       branch,
				LocalDir:     localDir,
				ComposeGlob:  composeGlob,
				PollInterval: poll,
				WebhookBind:  webhook,
				Deployer:     deployer,
				Differ:       differ,
				Notifier:     newGHCommitNotifier(),
			})
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}

			slog.Info("litevirt gitops starting",
				"repo", repoURL, "branch", branch,
				"local_dir", localDir, "poll", poll, "webhook", webhook)
			return ctrl.Run(ctx)
		},
	}
	f := cmd.Flags()
	f.StringVar(&repoURL, "repo", "", "Git remote URL (required)")
	f.StringVar(&branch, "branch", "main", "Git branch to track")
	f.StringVar(&localDir, "local-dir", "/var/lib/litevirt-gitops/repo", "working tree location")
	f.StringVar(&composeGlob, "compose-glob", "**/compose.yaml", "path glob for compose files inside the repo")
	f.DurationVar(&poll, "poll", 60*time.Second, "polling interval (0s disables polling)")
	f.StringVar(&webhook, "webhook-bind", "127.0.0.1:7700", "address for the reconcile webhook listener (empty = disabled)")
	return cmd
}

// newGHCommitNotifier returns a gitops.CommitNotifier that posts a one-line
// status as a GitHub commit comment via the `gh` CLI. If `gh` isn't on PATH or
// the repo isn't a GitHub remote, it falls back to a structured slog event so
// the reconcile cycle still has an observable outcome.
func newGHCommitNotifier() gitops.CommitNotifier {
	_, ghErr := exec.LookPath("gh")
	useGH := ghErr == nil
	return func(ctx context.Context, s gitops.CommitStatus) {
		body := formatCommitStatus(s)
		if !useGH {
			slog.Info("gitops status (gh not found)", "sha", s.SHA, "body", body)
			return
		}
		if s.SHA == "" {
			// Status with no SHA — usually a pre-pull error. Log it rather
			// than guessing at gh args.
			slog.Info("gitops status (no SHA)", "body", body)
			return
		}
		// `gh api /repos/:owner/:repo/commits/<sha>/comments` works for any
		// GitHub remote gh recognises. The cwd matters — gh picks the remote
		// from the current git repo.
		cmd := exec.CommandContext(ctx, "gh", "api",
			fmt.Sprintf("repos/{owner}/{repo}/commits/%s/comments", s.SHA),
			"-f", "body="+body)
		out, err := cmd.CombinedOutput()
		if err != nil {
			slog.Warn("gitops: gh post failed", "sha", s.SHA, "error", err, "out", string(out))
			return
		}
		slog.Info("gitops: posted commit comment", "sha", s.SHA)
	}
}

// formatCommitStatus renders a CommitStatus as a markdown blob fit for a GitHub
// comment: one useful summary line plus per-path breakdowns when relevant.
func formatCommitStatus(s gitops.CommitStatus) string {
	var b strings.Builder
	short := s.SHA
	if len(short) > 7 {
		short = short[:7]
	}
	switch {
	case len(s.Errors) > 0:
		fmt.Fprintf(&b, "🛑 litevirt-gitops cycle %s failed\n\n", short)
		for _, e := range s.Errors {
			fmt.Fprintf(&b, "- %s\n", e)
		}
	case len(s.Failed) == 0 && len(s.OK) == 0 && len(s.Skipped) == s.Total:
		fmt.Fprintf(&b, "✅ litevirt-gitops cycle %s: no-op (all %d files skipped — no semantic diff)\n",
			short, s.Total)
	case len(s.Failed) == 0:
		fmt.Fprintf(&b, "✅ litevirt-gitops cycle %s: %d deployed, %d skipped\n",
			short, len(s.OK), len(s.Skipped))
	default:
		fmt.Fprintf(&b, "⚠️ litevirt-gitops cycle %s: %d deployed, %d failed, %d skipped\n",
			short, len(s.OK), len(s.Failed), len(s.Skipped))
	}
	if len(s.OK) > 0 {
		fmt.Fprintf(&b, "\n**Deployed**\n")
		for _, p := range s.OK {
			fmt.Fprintf(&b, "- `%s`\n", p)
		}
	}
	if len(s.Failed) > 0 {
		fmt.Fprintf(&b, "\n**Failed**\n")
		for _, p := range s.Failed {
			fmt.Fprintf(&b, "- `%s`\n", p)
		}
	}
	return b.String()
}
