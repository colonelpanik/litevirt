package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/mcpserver"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/grpclog"
)

var runMCPServer = func(ctx context.Context, opts mcpserver.Options) error {
	s, err := mcpserver.New(ctx, opts)
	if err != nil {
		return fmt.Errorf("start litevirt MCP server: %w", err)
	}
	defer s.Close()
	return s.Run(ctx)
}

func newMCPCmd() *cobra.Command {
	var allowWrite bool
	var timeout time.Duration
	var maxListItems int
	var toolPrefix string

	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run a Model Context Protocol server for litevirt",
		Long: `Run a stdio Model Context Protocol server for litevirt.

The server uses the same LV_HOST, LV_TOKEN, and litevirt config/PKI resolution as
the normal CLI. It is intended to run on a node or bastion that can reach the
litevirt daemon. stdout is reserved for MCP JSON-RPC; diagnostics go to stderr.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("LV_MCP_ALLOW_WRITE") == "1" {
				allowWrite = true
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			slog.SetDefault(logger)
			grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, os.Stderr, os.Stderr))

			ctx := cmd.Context()
			return runMCPServer(ctx, mcpserver.Options{
				Name:         "litevirt",
				Version:      version,
				AllowWrite:   allowWrite,
				Timeout:      timeout,
				MaxListItems: maxListItems,
				ToolPrefix:   toolPrefix,
				Logger:       logger,
				Connect:      cli.Connect,
			})
		},
	}
	cmd.Flags().BoolVar(&allowWrite, "allow-write", false, "expose reversible write tools; also enabled by LV_MCP_ALLOW_WRITE=1")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "per-RPC timeout")
	cmd.Flags().IntVar(&maxListItems, "max-list-items", 100, "maximum list items returned by tools/resources")
	cmd.Flags().StringVar(&toolPrefix, "tool-prefix", "litevirt_", "prefix for MCP tool names")
	return cmd
}
