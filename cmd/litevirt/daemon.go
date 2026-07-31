package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/litevirt/litevirt/internal/daemon"
	"github.com/litevirt/litevirt/internal/systemdunit"
)

// newDaemonCmd runs the litevirt daemon (server). systemd's ExecStart is
// `/usr/local/bin/litevirt daemon`.
func newDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Run the litevirt daemon (server)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon()
		},
	}
}

// execFn is a seam over syscall.Exec so tests can assert what env the
// re-exec is invoked with.
var execFn = syscall.Exec

// reExecSelf replaces the running process with the current binary, passing
// pristineEnv — the env snapshot taken before obs.Setup mutated it — instead
// of the live os.Environ(). systemd's Environment= is not re-read on an
// in-place execve (same PID), so this is the only way the re-exec'd daemon
// starts from a clean env rather than accumulated OTEL_* pollution and
// scrubbed credentials (findings 1 & 2).
func reExecSelf(pristineEnv []string) error {
	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}
	return execFn(binary, os.Args, pristineEnv)
}

// runDaemon is the daemon entrypoint (formerly cmd/litevirtd/main). On an
// upgrade the daemon's Run returns ErrReExec and we self-replace via
// syscall.Exec — os.Args is ["litevirt","daemon",…], so the re-exec'd process
// re-enters daemon mode.
func runDaemon() error {
	slog.Info("starting litevirt daemon", "version", version, "commit", commit)

	// Snapshot the env before obs.Setup (inside daemon.New/d.Run) mutates it,
	// so a self-upgrade re-exec carries systemd's original env, not obs's
	// scrubbed/accumulated one.
	pristineEnv := os.Environ()

	cfg, err := daemon.LoadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	cfg.Version = version

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// SIGHUP and SIGPIPE must not reach the runtime's die-from-signal path.
	// systemd classes death by either as a CLEAN exit, so Restart=on-failure
	// would not restart us and the node would sit down indefinitely. Installed
	// after the shutdown context so it stops with it. See drainIgnoredSignals.
	drainIgnoredSignals(ctx)

	d, err := daemon.New(cfg)
	if err != nil {
		return fmt.Errorf("initializing daemon: %w", err)
	}

	if err := d.Run(ctx); err != nil {
		if err == daemon.ErrReExec {
			slog.Info("re-execing new binary")
			if execErr := reExecSelf(pristineEnv); execErr != nil {
				return fmt.Errorf("re-exec failed: %w", execErr)
			}
		}
		// An uninstall has already deleted the unit files and this binary.
		// Returning an error here would exit 1 — a FAILURE — and under
		// Restart=always systemd would try to restart a unit with nothing left
		// to run. Exit with the status the unit's RestartPreventExitStatus
		// names instead, which tells systemd this ending was intended.
		if err == daemon.ErrUninstalled {
			slog.Info("uninstalled; exiting without restart")
			os.Exit(systemdunit.UninstallExitCode)
		}
		return fmt.Errorf("daemon error: %w", err)
	}
	return nil
}
