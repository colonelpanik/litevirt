package main

import (
	"context"
	"fmt"
	"io"
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
				return reportAuditVerify(os.Stdout, resp)
			})
		},
	}
}

// reportAuditVerify prints the verify result and returns an error — which
// main.go turns into exit 1 — only when the log shows interference.
//
// The two outcomes are kept visually separate on purpose. An unsigned row is
// what every cluster looks like before signing was switched on, and an operator
// who reads "3 rows unsigned" as "you have been hacked" learns to ignore this
// command; by the time it reports a real forgery they will scroll past it.
// So the clean paths are one line each, and a finding gets a headline plus
// every affected row spelled out rather than a count they would have to chase.
func reportAuditVerify(w io.Writer, resp *pb.VerifyAuditChainResponse) error {
	if !resp.Tampered {
		switch {
		case resp.UnsignedRows > 0:
			fmt.Fprintf(w, "audit chain intact: %d rows verified (%d predate tamper-evidence and are chain-checked only)\n",
				resp.RowsChecked, resp.UnsignedRows)
		default:
			fmt.Fprintf(w, "audit chain intact: %d rows verified, all signed\n", resp.RowsChecked)
		}
		// Neither of these says a row is wrong — one is a missing keyring, the
		// other a row that never carried a host — but both mean part of the log
		// went unchecked, so they are never swallowed into a clean line.
		if resp.UnverifiableRows > 0 {
			fmt.Fprintf(w, "  note: %d signed rows could not be checked (no keyring available to this daemon)\n", resp.UnverifiableRows)
		}
		if resp.UnattributedRows > 0 {
			fmt.Fprintf(w, "  note: %d rows carry no host name and belong to no sub-chain\n", resp.UnattributedRows)
		}
		return nil
	}

	fmt.Fprintf(w, "AUDIT CHAIN TAMPERED — %d rows checked\n", resp.RowsChecked)
	if resp.BrokenAtId != "" {
		fmt.Fprintf(w, "\nhash mismatch (row content does not match its recorded hash):\n  %s\n", resp.BrokenAtId)
	}
	for _, g := range []struct {
		title string
		rows  []string
	}{
		{"bad signature (edited by someone without the host's key):", resp.BadSignature},
		{"unknown key (no trustworthy published certificate for the signer):", resp.UnknownKeyId},
		{"sequence gap (rows deleted from a host's chain):", resp.SeqGaps},
		{"laundered (row blanked its own hash to fake a chain reset):", resp.Laundered},
		{"retired key used (signed after the key was rotated out):", resp.RetiredKeyUse},
		{"chain head mismatch (a row covered by a signed head was rewritten):", resp.HeadMismatch},
		{"unsigned after signed (a host that had begun signing produced an unsigned row):", resp.UnsignedAfterSigned},
		{"never adopted (a host declares its rows are signed but cannot sign):", resp.NeverAdopted},
	} {
		if len(g.rows) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", g.title)
		for _, row := range g.rows {
			fmt.Fprintf(w, "  %s\n", row)
		}
	}
	if len(resp.TruncatedHosts) > 0 {
		fmt.Fprintf(w, "\ntruncated (signed chain head attests to more rows than exist):\n")
		for _, h := range resp.TruncatedHosts {
			fmt.Fprintf(w, "  %s\n", h)
		}
	}
	// Printed last and only here, so they read as context for the findings
	// above rather than as findings of their own.
	if resp.UnsignedRows > 0 || resp.UnverifiableRows > 0 || resp.UnattributedRows > 0 {
		fmt.Fprintf(w, "\nnot tampering, for context: %d unsigned (predate tamper-evidence), %d unverifiable (no keyring), %d unattributed (no host)\n",
			resp.UnsignedRows, resp.UnverifiableRows, resp.UnattributedRows)
	}
	return fmt.Errorf("audit chain verification failed: the log shows evidence of tampering")
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
