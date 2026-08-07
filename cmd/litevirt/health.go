package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// silentExitError carries an exit code without a printable message. The root
// command recognizes it and exits with the code, printing NOTHING — a health
// report that ends "overall: CRITICAL" must not be followed by a generic
// "Error: exit status 2" line that buries the report it annotates.
type silentExitError struct{ code int }

func (e silentExitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// exitCodeOf returns (code, true) when err carries a silent typed exit.
func exitCodeOf(err error) (int, bool) {
	var se silentExitError
	if errors.As(err, &se) {
		return se.code, true
	}
	return 0, false
}

// healthExitCode maps the overall state to the scriptable contract:
// 0 healthy · 1 degraded or unknown · 2 critical.
func healthExitCode(overall string) int {
	switch overall {
	case "HEALTHY":
		return 0
	case "CRITICAL":
		return 2
	default: // DEGRADED, UNKNOWN, or anything unrecognized
		return 1
	}
}

func newHealthCmd() *cobra.Command {
	var includeResolved bool
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Show cluster health: conditions, coverage, connectivity",
		Long: `Show the cluster's health: the overall state, every active condition with its
lifecycle and involved hosts, evaluator coverage, and peer connectivity.

Exit code: 0 healthy · 1 degraded or unknown · 2 critical.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{IncludeResolved: includeResolved})
				if err != nil {
					return fmt.Errorf("get cluster health: %w", err)
				}
				printClusterHealth(resp)
				if code := healthExitCode(resp.GetOverall()); code != 0 {
					return silentExitError{code: code}
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&includeResolved, "resolved", false, "include recently-resolved conditions (30-day history)")
	return cmd
}

func printClusterHealth(h *pb.ClusterHealth) {
	fmt.Printf("overall: %s\n", h.GetOverall())

	if conds := h.GetConditions(); len(conds) > 0 {
		fmt.Println("\nconditions:")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  SEVERITY\tLIFECYCLE\tCODE\tSUBJECT\tHOSTS\tSINCE")
		for _, c := range conds {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s/%s\t%s\t%s\n",
				c.GetSeverity(), c.GetLifecycle(), c.GetCode(),
				c.GetSubjectKind(), c.GetSubjectId(),
				strings.Join(c.GetHosts(), ","), c.GetFirstSeen())
		}
		w.Flush()
	}

	if evs := h.GetEvaluators(); len(evs) > 0 {
		fmt.Println("\nevaluators:")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  EVALUATOR\tCOVERAGE\tLAST SCAN\tDETAIL")
		for _, e := range evs {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", e.GetEvaluator(), e.GetCoverage(), e.GetLastScan(), e.GetDetail())
		}
		w.Flush()
	}

	if edges := h.GetConnectivity(); len(edges) > 0 {
		fmt.Println("\nconnectivity:")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  OBSERVER\tTARGET\tSTATUS\tFAILURES")
		for _, e := range edges {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%d\n", e.GetObserver(), e.GetTarget(), e.GetStatus(), e.GetConsecutiveFailures())
		}
		w.Flush()
	}

	if caps := h.GetCapacity(); len(caps) > 0 {
		fmt.Println("\ncapacity:")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  HOST\tEFFECTIVE\tDB\tEXTRA\tCOMPLETE\tDETAIL")
		for _, c := range caps {
			fmt.Fprintf(w, "  %s\t%dc/%dMiB\t%dc/%dMiB\t%dc/%dMiB\t%v\t%s\n",
				c.GetHostName(),
				c.GetEffectiveCpu(), c.GetEffectiveMemMib(),
				c.GetDbCpu(), c.GetDbMemMib(),
				c.GetExtraCpu(), c.GetExtraMemMib(),
				c.GetComplete(), c.GetDetail())
		}
		w.Flush()
	}
}
