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

// runDaemon is the daemon entrypoint (formerly cmd/litevirtd/main). On an
// upgrade the daemon's Run returns ErrReExec and we self-replace via
// syscall.Exec — os.Args is ["litevirt","daemon",…], so the re-exec'd process
// re-enters daemon mode.
func runDaemon() error {
	slog.Info("starting litevirt daemon", "version", version, "commit", commit)

	cfg, err := daemon.LoadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	cfg.Version = version

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	d, err := daemon.New(cfg)
	if err != nil {
		return fmt.Errorf("initializing daemon: %w", err)
	}

	if err := d.Run(ctx); err != nil {
		if err == daemon.ErrReExec {
			slog.Info("re-execing new binary")
			binary, _ := os.Executable()
			if execErr := syscall.Exec(binary, os.Args, os.Environ()); execErr != nil {
				return fmt.Errorf("re-exec failed: %w", execErr)
			}
		}
		return fmt.Errorf("daemon error: %w", err)
	}
	return nil
}
