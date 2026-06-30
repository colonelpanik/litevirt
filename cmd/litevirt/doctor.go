package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newDoctorCmd groups read-only cluster-health diagnostics.
func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Read-only cluster diagnostics",
	}
	cmd.AddCommand(newDoctorDivergenceCmd())
	return cmd
}

func newDoctorDivergenceCmd() *cobra.Command {
	var jsonOut, includeSensitive bool
	var tables []string
	cmd := &cobra.Command{
		Use:   "divergence",
		Short: "Report replicated rows that diverge across cluster nodes",
		Long: `Scan every active node and report rows of replicated state that disagree
across nodes, plus cluster-wide semantic-invariant violations (e.g. the same
container name live on two hosts). Read-only — it never writes or merges state.

Divergences are reported only when they persist across two samples (an in-flight
replication delta is filtered out). --include-sensitive also scans secret-bearing
tables over the peer-mTLS lane, reporting only keyed HMAC labels (never plaintext).

Run this BEFORE any remediation that changes merge behavior — convergence
destroys the per-node evidence.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				rep, err := c.DiagnoseDivergence(ctx, &pb.DiagnoseDivergenceRequest{
					IncludeSensitive: includeSensitive,
					Tables:           tables,
				})
				if err != nil {
					return fmt.Errorf("diagnose divergence: %w", err)
				}
				if jsonOut {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(rep)
				}
				renderDivergenceReport(rep)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the full report as JSON")
	cmd.Flags().BoolVar(&includeSensitive, "include-sensitive", false, "also scan secret-bearing tables (HMAC labels only)")
	cmd.Flags().StringSliceVar(&tables, "table", nil, "restrict to these tables (repeatable)")
	return cmd
}

func renderDivergenceReport(rep *pb.DivergenceReport) {
	fmt.Printf("scanned %d node(s): %s\n", len(rep.GetNodesScanned()), strings.Join(rep.GetNodesScanned(), ", "))
	if u := rep.GetNodesUnreachable(); len(u) > 0 {
		fmt.Printf("UNREACHABLE (not scanned): %s\n", strings.Join(u, ", "))
	}
	if su := rep.GetSensitiveUnreachable(); len(su) > 0 {
		fmt.Printf("SENSITIVE LANE PARTIAL (secret tables NOT scanned on): %s\n", strings.Join(su, ", "))
	}
	fmt.Printf("samples: %d   stable: %t\n", rep.GetSamples(), rep.GetStable())
	if !rep.GetStable() {
		fmt.Println("WARNING: cluster was not quiescent across the scan — a stuck_different may be replication backlog; re-run when settled.")
	}

	if len(rep.GetRows()) == 0 && len(rep.GetViolations()) == 0 {
		fmt.Println("\nno divergence detected.")
		return
	}

	if rows := rep.GetRows(); len(rows) > 0 {
		fmt.Printf("\nDiverging rows (%d):\n", len(rows))
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "TABLE\tPK\tCLASS\tPER-NODE (host=updated_at/hash)")
		for _, r := range rows {
			parts := make([]string, 0, len(r.GetPerNode()))
			for _, m := range r.GetPerNode() {
				h := shortHash(m.GetRowHash())
				marker := ""
				if m.GetDeleted() {
					marker = " (deleted)"
				}
				parts = append(parts, fmt.Sprintf("%s=%s/%s%s", m.GetHost(), m.GetUpdatedAt(), h, marker))
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.GetTable(), r.GetPk(), r.GetClass(), strings.Join(parts, "  "))
		}
		_ = w.Flush()
	}

	if vs := rep.GetViolations(); len(vs) > 0 {
		fmt.Printf("\nSemantic-invariant violations (%d):\n", len(vs))
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "KIND\tKEY\tHOSTS\tDETAIL")
		for _, v := range vs {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", v.GetKind(), v.GetKey(), strings.Join(v.GetHosts(), ","), v.GetDetail())
		}
		_ = w.Flush()
	}
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
