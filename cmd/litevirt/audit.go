package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect / verify / export the cluster audit log",
	}
	cmd.AddCommand(
		newAuditLsCmd(),
		newAuditVerifyCmd(),
		newAuditExportCmd(),
	)
	return cmd
}

func newAuditLsCmd() *cobra.Command {
	var limit int32
	var target, action, user, since string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "Show audit log (most recent first)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListAuditLog(ctx, &pb.ListAuditLogRequest{
					Limit:  limit,
					Target: target,
					Action: action,
					User:   user,
					Since:  since,
				})
				if err != nil {
					return fmt.Errorf("list audit log: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "TIMESTAMP\tUSER\tHOST\tACTION\tTARGET\tDETAIL\tRESULT")
				for _, e := range resp.Entries {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						e.Timestamp, e.Username, e.HostName,
						e.Action, e.Target, e.Detail, e.Result,
					)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().Int32Var(&limit, "limit", 50, "Maximum number of entries to return")
	cmd.Flags().StringVar(&target, "target", "", "filter by exact target path")
	cmd.Flags().StringVar(&action, "action", "", "filter by action; trailing * is a prefix glob (e.g. sg.*)")
	cmd.Flags().StringVar(&user, "user", "", "filter by username")
	cmd.Flags().StringVar(&since, "since", "", "filter to entries at/after this RFC3339 timestamp")
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Replay the audit hash chain and report any tampering",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.VerifyAuditChain(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("verify audit chain: %w", err)
				}
				if resp.Error != "" {
					return fmt.Errorf("verify error: %s", resp.Error)
				}
				if resp.BrokenAtId != "" {
					return fmt.Errorf("audit chain broken at row %s (after %d rows verified)",
						resp.BrokenAtId, resp.RowsChecked)
				}
				fmt.Printf("audit chain intact: %d rows verified\n", resp.RowsChecked)
				return nil
			})
		},
	}
}

func newAuditExportCmd() *cobra.Command {
	var since, until, outPath string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the audit log as a WORM-suitable JSON blob",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ExportAuditChain(ctx, &pb.ExportAuditChainRequest{
					Since: since, Until: until,
				})
				if err != nil {
					return fmt.Errorf("export audit chain: %w", err)
				}
				if outPath == "" || outPath == "-" {
					fmt.Println(resp.Json)
				} else {
					if err := os.WriteFile(outPath, []byte(resp.Json), 0o600); err != nil {
						return fmt.Errorf("write %s: %w", outPath, err)
					}
					fmt.Fprintf(os.Stderr, "wrote %d rows to %s\n", resp.RowCount, outPath)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "filter from this RFC3339 timestamp (inclusive)")
	cmd.Flags().StringVar(&until, "until", "", "filter up to this RFC3339 timestamp (inclusive)")
	cmd.Flags().StringVar(&outPath, "out", "", "write to file (default: stdout)")
	return cmd
}
