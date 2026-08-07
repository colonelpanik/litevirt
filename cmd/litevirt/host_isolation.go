package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newHostIsolateCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "isolate <host>",
		Short: "Record a host as isolated — the cluster refuses its replication until reseeded",
		Long: `Record, in cluster state, that <host>'s local state was produced outside the
cluster's current compatibility regime. Every peer then REFUSES that host's
mutation pushes and will not merge from it, until 'lv host reseed' replaces its
state and verifies convergence.

Run this against a HEALTHY peer: the observation must come from someone other
than the suspect, which is the whole reason the epoch lives in cluster state
rather than a file on the isolated node. Admin-gated and audited.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				st, err := c.IsolateHost(ctx, &pb.IsolateHostRequest{Name: args[0], Reason: reason})
				if err != nil {
					return fmt.Errorf("isolate: %w", err)
				}
				fmt.Printf("%s isolated at epoch %d (%s) — its replication is refused until `lv host reseed %s`\n",
					st.GetHostName(), st.GetIsolationEpoch(), st.GetIsolationReason(), st.GetHostName())
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "manual", "rolled_back_latch | manual | schema_forward")
	return cmd
}

func newHostReseedCmd() *cobra.Command {
	var source string
	cmd := &cobra.Command{
		Use:   "reseed <host>",
		Short: "Replace an isolated host's replicated state from a healthy peer and end its quarantine",
		Long: `Drive an isolated host back into the cluster: it discards its replicated state,
pulls a full state dump from a healthy peer, and VERIFIES convergence. Only a
verified reseed ends the quarantine — a partial one leaves the host isolated,
because half a reseed is worse than none.

Run this against a HEALTHY peer (not the isolated host): the epoch clear is
peer-written, and an isolated node's own writes are refused, so a self-driven
reseed would succeed into a cluster that never hears about it.

The host must not be running workloads — drain it first. Reseed discards
replicated state, which must never happen under a live VM. Admin-gated, audited.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ReseedHost(ctx, &pb.ReseedHostRequest{Name: args[0], Source: source})
				if err != nil {
					return fmt.Errorf("reseed: %w", err)
				}
				fmt.Printf("%s reseeded from %s: %d tables converged, isolation epoch %d cleared\n",
					resp.GetHostName(), resp.GetSource(), resp.GetTablesConverged(), resp.GetClearedEpoch())
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&source, "source", "", "healthy peer to reseed from (default: any healthy peer)")
	return cmd
}
