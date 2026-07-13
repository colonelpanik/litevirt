package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Cluster management",
	}
	cmd.AddCommand(
		newClusterDigestCmd(),
		newClusterConvergeCmd(),
	)
	return cmd
}

// lv cluster digest — per-table state digest for EVERY host, aggregated server-side (the
// connected host fans GetStateDigest/GetSensitiveStateDigest out to its peers), so it works
// from a single connection.
func newClusterDigestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "digest",
		Short: "Show per-table state digest for every host",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				dig, err := c.GetClusterStateDigest(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("cluster digest: %w", err)
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "HOST\tTABLE\tROWS\tHASH\tTIES\n")
				for _, h := range dig.GetHosts() {
					for _, t := range h.GetTables() {
						if t.GetCount() == 0 && t.GetUnresolvedTies() == 0 {
							continue
						}
						ties := ""
						if t.GetUnresolvedTies() > 0 {
							ties = fmt.Sprintf("%d", t.GetUnresolvedTies())
						}
						fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", h.GetHostName(), t.GetName(), t.GetCount(), t.GetHash(), ties)
					}
				}
				w.Flush()
				printCoverageGaps(dig)
				return nil
			})
		},
	}
}

// lv cluster converge — kick an immediate anti-entropy pass and verify cross-host convergence.
func newClusterConvergeCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:     "converge",
		Aliases: []string{"sync"},
		Short:   "Kick an immediate anti-entropy pass and report cross-host convergence",
		Long: `Cluster state converges automatically via anti-entropy (roughly once a minute) plus
WAL replication. This command ACCELERATES that (kick a pass now instead of waiting) and
VERIFIES it (report per-table digest convergence across hosts). It does not merge or repair
state by itself.

  --all   relay the kick to every active peer as well (default: only the connected host)

Divergence caused by a deliberate safety fault — unresolved equal-timestamp LWW ties, which
anti-entropy will NOT auto-merge — is labelled as such; resolve those with
'lv doctor repair-owner', not by re-running this. For a row-level scan use 'lv doctor divergence'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.CalledAs() == "sync" {
				fmt.Fprintln(os.Stderr, "note: `lv cluster sync` is deprecated — use `lv cluster converge`")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				tr, err := c.TriggerAntiEntropy(ctx, &pb.TriggerAntiEntropyRequest{All: all})
				if err != nil {
					return fmt.Errorf("trigger anti-entropy: %w", err)
				}
				printTriggerSummary(tr)
				dig, err := c.GetClusterStateDigest(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("cluster digest: %w", err)
				}
				printConvergence(dig)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "relay the anti-entropy kick to every active peer")
	return cmd
}

func printTriggerSummary(tr *pb.TriggerAntiEntropyResponse) {
	line := func(label string, hosts []string) {
		if len(hosts) > 0 {
			fmt.Printf("  %-12s %s\n", label+":", strings.Join(hosts, ", "))
		}
	}
	fmt.Println("Anti-entropy pass:")
	line("triggered", tr.GetTriggered())
	line("debounced", tr.GetDebounced()) // ran too recently — a pass is already fresh
	line("unreachable", tr.GetUnreachable())
	line("older-binary", tr.GetUnsupported())
}

// printConvergence groups the per-host digests by table and reports each table's convergence,
// distinguishing real drift from deliberate safety-fault ties. Converged tables are summarized,
// not listed.
func printConvergence(dig *pb.ClusterStateDigestResponse) {
	type cell struct {
		hash string
	}
	tables := map[string]map[string]cell{} // table -> host -> cell
	ties := map[string]int32{}             // table -> total unresolved ties across hosts
	var order []string
	for _, h := range dig.GetHosts() {
		for _, t := range h.GetTables() {
			if _, ok := tables[t.GetName()]; !ok {
				tables[t.GetName()] = map[string]cell{}
				order = append(order, t.GetName())
			}
			tables[t.GetName()][h.GetHostName()] = cell{hash: t.GetHash()}
			ties[t.GetName()] += t.GetUnresolvedTies()
		}
	}
	sort.Strings(order)

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "\nTABLE\tSTATUS\tDETAIL\n")
	converged := 0
	for _, name := range order {
		hosts := tables[name]
		hashes := map[string]bool{}
		for _, c := range hosts {
			hashes[c.hash] = true
		}
		switch {
		case len(hashes) <= 1:
			converged++
		case ties[name] > 0:
			fmt.Fprintf(w, "%s\tSAFETY-FAULT\t%d unresolved tie(s) — deliberate; run `lv doctor repair-owner`\n", name, ties[name])
		default:
			fmt.Fprintf(w, "%s\tDIVERGENT\thashes differ across %d hosts (drift)\n", name, len(hosts))
		}
	}
	w.Flush()
	fmt.Printf("\n%d/%d table(s) converged across %d reporting host(s).\n", converged, len(order), len(dig.GetHosts()))
	printCoverageGaps(dig)
}

func printCoverageGaps(dig *pb.ClusterStateDigestResponse) {
	if len(dig.GetUnreachable()) > 0 {
		fmt.Printf("⚠ unreachable (state NOT verified): %s\n", strings.Join(dig.GetUnreachable(), ", "))
	}
	if len(dig.GetUnsupported()) > 0 {
		fmt.Printf("⚠ older binary (no cluster-digest RPC): %s\n", strings.Join(dig.GetUnsupported(), ", "))
	}
}
