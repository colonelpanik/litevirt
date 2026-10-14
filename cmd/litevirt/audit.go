package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auditexport"
	"github.com/litevirt/litevirt/internal/corrosion"
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
	var target, action, user, since, until string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "Show audit log (most recent first)",
		RunE: func(cmd *cobra.Command, args []string) error {
			since, until, err := resolveTimeBounds(since, until)
			if err != nil {
				return err
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListAuditLog(ctx, &pb.ListAuditLogRequest{
					Limit:  limit,
					Target: target,
					Action: action,
					User:   user,
					Since:  since,
					Until:  until,
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
	cmd.Flags().StringVar(&since, "since", "", "filter to entries at/after this time (RFC3339, a date like 2026-06-01, or a duration ago like 24h)")
	cmd.Flags().StringVar(&until, "until", "", "filter up to this time, inclusive of the whole unit it names (RFC3339, a date, or a duration ago)")
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
// main.go turns into exit 1 — when the log shows interference OR when part of it
// could not be checked at all.
//
// THREE outcomes, kept visually separate on purpose, because collapsing them is
// how this command stops being read. An unsigned row is what every cluster looks
// like before signing was switched on, and an operator who reads "3 rows
// unsigned" as "you have been hacked" learns to ignore the output; by the time it
// reports a real forgery they will scroll past it. So the clean path is one line,
// and a finding gets a headline plus every affected row spelled out rather than a
// count they would have to chase.
//
// The middle outcome — "could not verify" — exists because its one finding is
// forgeable. Any peer can plant a certificate row naming any host and manufacture
// a `never adopted`, so reporting that as TAMPERED handed anyone who could reach
// the cluster a permanent false accusation against a host that had done nothing.
// It still fails the command: a key nobody can read is precisely the state an
// attacker arranges, and it must not read as a pass. It just does not claim to
// know that anyone interfered, because the row it read cannot tell it that.
//
// The two other uncheckable things stay NOTES on the clean path, and the reason
// is the same one this whole split exists for: unverifiable rows are the ordinary
// state of a node mid-rollout, and unattributed rows are legacy data nothing can
// fix. Failing on either would page somebody on a healthy cluster.
func reportAuditVerify(w io.Writer, resp *pb.VerifyAuditChainResponse) error {
	if !resp.Tampered {
		// The headline states the OUTCOME, so it must not say "intact" on a run that
		// exits 1. It did: the unverified path printed the clean line first and
		// contradicted itself four lines later, which is fine for someone reading the
		// whole output and wrong for the far more common cases — an operator scanning
		// the first line, or a CI job grepping for "intact".
		switch {
		case resp.Unverified:
			fmt.Fprintf(w, "audit chain NOT FULLY VERIFIED: %d rows checked", resp.RowsChecked)
			if resp.UnsignedRows > 0 {
				fmt.Fprintf(w, " (%d predate tamper-evidence and are chain-checked only)", resp.UnsignedRows)
			}
			fmt.Fprintln(w)
		case resp.UnsignedRows > 0:
			fmt.Fprintf(w, "audit chain intact: %d rows verified (%d predate tamper-evidence and are chain-checked only)\n",
				resp.RowsChecked, resp.UnsignedRows)
		default:
			fmt.Fprintf(w, "audit chain intact: %d rows verified, all signed\n", resp.RowsChecked)
		}
		// A row that never carried a host belongs to no sub-chain and cannot be
		// checked — but nothing writes one any more and every cluster with history
		// has some, so it is a note rather than a failure.
		if resp.UnattributedRows > 0 {
			fmt.Fprintf(w, "  note: %d rows carry no host name and belong to no sub-chain\n", resp.UnattributedRows)
		}
		if resp.UnverifiableRows > 0 {
			fmt.Fprintf(w, "  note: %d signed rows could not be checked (no keyring available to this daemon)\n",
				resp.UnverifiableRows)
		}
		if !resp.Unverified {
			return nil
		}

		fmt.Fprintf(w, "\nPART OF THIS LOG COULD NOT BE VERIFIED\n")
		reportAmbiguousRows(w, resp)
		if len(resp.NeverAdopted) == 0 {
			if len(resp.AmbiguousRows) > 0 {
				return fmt.Errorf("audit chain verification incomplete: rows whose hash does not determine their content")
			}
			fmt.Fprintln(w, "\nthe daemon reported an unverified audit condition; inspect its logs and health findings")
			return fmt.Errorf("audit chain verification incomplete")
		}
		fmt.Fprintf(w, "\nhosts declaring signed rows that cannot sign:\n")
		for _, h := range resp.NeverAdopted {
			fmt.Fprintf(w, "  %s\n", h)
		}
		fmt.Fprintf(w, "\nEither the host cannot read its signing key — fix it and restart, or run\n"+
			"`lv host rotate-audit-key <host>` — or the certificate was published by\n"+
			"someone else, since any peer can write that row. A certificate naming a host\n"+
			"is not proof the host published it, which is why this is NOT reported as\n"+
			"tampering. Retire the key from the CA holder (`lv host retire-audit-key\n"+
			"<host>`) to close it out; only the CA can.\n")
		return fmt.Errorf("audit chain verification incomplete: a host declares signed rows it cannot sign")
	}

	forkOnly := resp.Forked && len(resp.BadSignature) == 0 && len(resp.UnknownKeyId) == 0 &&
		len(resp.Laundered) == 0 && len(resp.RetiredKeyUse) == 0 && len(resp.HeadMismatch) == 0 &&
		len(resp.UnsignedAfterSigned) == 0 && len(resp.OrphanedRows) == 0 && len(resp.TruncatedHosts) == 0
	if forkOnly {
		// Nothing found says a row was edited, deleted or forged: a second chain was
		// opened under a host name that already had one. It still fails the command.
		// The daemon's verdict is not trusted alone: any tamper finding listed
		// below keeps the TAMPERED headline.
		fmt.Fprintf(w, "AUDIT CHAIN FORKED — %d rows checked (no edited, deleted or forged row found)\n", resp.RowsChecked)
	} else {
		fmt.Fprintf(w, "AUDIT CHAIN TAMPERED — %d rows checked\n", resp.RowsChecked)
	}
	if resp.BrokenAtId != "" {
		fmt.Fprintf(w, "\n%s\n  %s\n", brokenLinkHeading(resp.BrokenAtKind), resp.BrokenAtId)
	}
	for _, g := range []struct {
		title string
		rows  []string
	}{
		{"bad signature (edited by someone without the host's key):", resp.BadSignature},
		{"unknown key (no trustworthy published certificate for the signer):", resp.UnknownKeyId},
		{"sequence break (rows deleted from a host's chain, or a repeated seq — a forked chain):", resp.SeqGaps},
		{"laundered (row blanked its own hash to fake a chain reset):", resp.Laundered},
		{"retired key used (signed after the key was rotated out):", resp.RetiredKeyUse},
		{"chain head mismatch (a row covered by a signed head was rewritten):", resp.HeadMismatch},
		{"unsigned after signed (a host that had begun signing produced an unsigned row):", resp.UnsignedAfterSigned},
		{"orphaned (on a forked host, the row before it was deleted or rewritten, or it was renumbered or relinked; no seq gap shows it):", resp.OrphanedRows},
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
	if resp.UnsignedRows > 0 || resp.UnverifiableRows > 0 || resp.UnattributedRows > 0 ||
		len(resp.NeverAdopted) > 0 {
		fmt.Fprintf(w, "\nnot tampering, for context: %d unsigned (predate tamper-evidence), %d unverifiable (no keyring), %d unattributed (no host)\n",
			resp.UnsignedRows, resp.UnverifiableRows, resp.UnattributedRows)
		for _, h := range resp.NeverAdopted {
			fmt.Fprintf(w, "  could not be verified either way (any peer can publish this row): %s\n", h)
		}
	}
	reportAmbiguousRows(w, resp)
	if forkOnly {
		return fmt.Errorf("audit chain verification failed: the log holds a forked chain")
	}
	return fmt.Errorf("audit chain verification failed: the log shows evidence of tampering")
}

// resolveTimeBounds turns --since/--until as typed into the fixed-width UTC
// stamps the daemon stores, before anything is sent.
//
// The daemon parses bounds itself, but a daemon older than that compares
// whatever it is sent to its stamps as TEXT. A fixed-width UTC stamp is the one
// form that comparison gets right, so resolving here makes `--since 24h`, an
// offset or a date correct against a node not yet upgraded too. It also pins a
// relative bound to one instant for every page of an export.
func resolveTimeBounds(since, until string) (string, string, error) {
	w, err := corrosion.ParseTimeWindow(since, until, time.Now())
	if err != nil {
		return "", "", fmt.Errorf("--%w", err)
	}
	s, u := w.Bounds()
	return s, u, nil
}

// brokenLinkHeading names the first broken link by what the daemon found it to
// be. Every kind is a finding and fails the command; the heading only stops a
// forked chain — a row that hashes correctly but opens a second chain for its
// host — from reading as an edited row, which is what sent the lab 1
// investigation looking for tampering that had not happened.
func brokenLinkHeading(kind string) string {
	switch kind {
	case "forked":
		return "forked chain (the row hashes correctly but starts a second chain — empty prev_hash — " +
			"for a host that already has one; see the duplicate seqs under sequence break):"
	case "unlinked":
		return "broken link (the row hashes correctly against its own prev_hash, but it does not link to " +
			"the row before it — a row between them was deleted or rewritten, or the chain branched):"
	default:
		// "content", and a daemon older than broken_at_kind, which sends none.
		return "hash mismatch (row content does not match its recorded hash):"
	}
}

// reportAmbiguousRows lists rows with a NUL byte in a hashed field. The content
// hash is collision-free only over NUL-free rows, so for these the hash and the
// signature say nothing about WHICH content was written. Not tampering — an
// older build wrote such rows verbatim — and not clean either.
func reportAmbiguousRows(w io.Writer, resp *pb.VerifyAuditChainResponse) {
	if len(resp.AmbiguousRows) == 0 {
		return
	}
	fmt.Fprintf(w, "\nrows whose hash does not determine their content (a NUL byte in a field):\n")
	for _, r := range resp.AmbiguousRows {
		fmt.Fprintf(w, "  %s\n", strings.ReplaceAll(r, "\x00", "␀"))
	}
	fmt.Fprintf(w, "\nA current daemon never writes such a row; it came from an older build or a\n"+
		"direct write to the table. Its signature would verify a different row equally\n"+
		"well, so treat its content as unconfirmed.\n")
}

func newAuditExportCmd() *cobra.Command {
	var since, until, outPath string
	var allowGaps bool
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the audit log as a WORM-suitable JSON blob",
		RunE: func(cmd *cobra.Command, args []string) error {
			since, until, err := resolveTimeBounds(since, until)
			if err != nil {
				return err
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return writeAuditExport(ctx, func(ctx context.Context, cursor string) (*pb.ExportAuditChainResponse, error) {
					return c.ExportAuditChain(ctx, &pb.ExportAuditChainRequest{
						Since: since, Until: until, Cursor: cursor,
					})
				}, outPath, allowGaps, os.Stdout, os.Stderr)
			})
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "filter from this time, inclusive (RFC3339, a date like 2026-06-01, or a duration ago like 24h)")
	cmd.Flags().StringVar(&until, "until", "", "filter up to this time, inclusive of the whole unit it names (RFC3339, a date, or a duration ago)")
	cmd.Flags().StringVar(&outPath, "out", "", "write to file (default: stdout)")
	cmd.Flags().BoolVar(&allowGaps, "allow-gaps", false,
		"export a chain with seq gaps (rows missing from a host's chain), listing them under seq_gaps, instead of refusing; for investigation, not attestation")
	return cmd
}

// writeAuditExport walks the export and writes the one document to outPath, or
// to stdout when outPath is empty or "-".
//
// The server pages, and a per-page file would be useless for the job the docs
// give this command: a verifier needs one artifact whose rows are contiguous,
// and a chain split across files can only be checked by reassembling it anyway.
// The pages are therefore written to a spool file as they arrive — the chain
// has no size bound, so it is never held in memory — and the spool becomes the
// output only once the whole walk has succeeded. A refused export leaves no
// file at outPath and writes nothing to stdout.
func writeAuditExport(ctx context.Context, fetch auditexport.FetchPage, outPath string, allowGaps bool, stdout, stderr io.Writer) error {
	toStdout := outPath == "" || outPath == "-"
	dir, pattern := "", "lv-audit-export-*.json"
	if !toStdout {
		// Beside the target, so the final rename stays on one filesystem.
		dir, pattern = filepath.Dir(outPath), "."+filepath.Base(outPath)+".partial-*"
	}
	spool, err := os.CreateTemp(dir, pattern) // mode 0600
	if err != nil {
		return fmt.Errorf("create export spool: %w", err)
	}
	keep := false
	defer func() {
		_ = spool.Close()
		if !keep {
			_ = os.Remove(spool.Name())
		}
	}()

	bw := bufio.NewWriter(spool)
	total, err := auditexport.Write(ctx, fetch, bw, auditexport.Options{AllowGaps: allowGaps})
	if err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("write export spool: %w", err)
	}

	if toStdout {
		if _, err := spool.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("read export spool: %w", err)
		}
		if _, err := io.Copy(stdout, spool); err != nil {
			return fmt.Errorf("write export: %w", err)
		}
		_, err := fmt.Fprintln(stdout)
		return err
	}
	if err := spool.Sync(); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	if err := os.Rename(spool.Name(), outPath); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	keep = true
	fmt.Fprintf(stderr, "wrote %d rows to %s\n", total, outPath)
	return nil
}
