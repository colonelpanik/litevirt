package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newRebalanceCmd assembles the `lv rebalance` group: list / run / approve /
// reject for the placement rebalancer.
func newRebalanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rebalance",
		Short: "Inspect and act on rebalance proposals",
	}
	cmd.AddCommand(
		newRebalanceListCmd(),
		newRebalanceRunCmd(),
		newRebalanceApproveCmd(),
		newRebalanceRejectCmd(),
	)
	return cmd
}

func newRebalanceListCmd() *cobra.Command {
	var statusFilter string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List pending and recent rebalance proposals",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(context.Background(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListRebalanceProposals(ctx,
					&pb.ListRebalanceProposalsRequest{StatusFilter: statusFilter})
				if err != nil {
					return fmt.Errorf("list: %w", err)
				}
				if len(resp.Proposals) == 0 {
					fmt.Println("(no proposals)")
					return nil
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "ID\tVM\tFROM → TO\tPOLICY\tGAIN%\tSTATUS\tDETAIL")
				for _, p := range resp.Proposals {
					fmt.Fprintf(w, "%s\t%s\t%s → %s\t%s\t%.1f\t%s\t%s\n",
						p.Id, p.VmName, p.SrcHost, p.DstHost, p.Policy,
						p.ExpectedGain, p.Status, p.Detail,
					)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&statusFilter, "status", "",
		"Filter by status (pending, approved, applying, applied, failed, rejected, expired)")
	return cmd
}

func newRebalanceRunCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Trigger a single rebalance evaluation cycle now",
		Long: `Forces an immediate rebalance evaluation. Without --dry-run, the
engine still respects each VM's resolved rebalance.mode (so VMs with mode=off
or mode=on-demand are still skipped). With --dry-run, all proposals are
recorded as pending regardless of mode.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(context.Background(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.RunRebalance(ctx,
					&pb.RunRebalanceRequest{DryRun: dryRun})
				if err != nil {
					return fmt.Errorf("run: %w", err)
				}
				fmt.Printf("Emitted %d new proposal(s).\n", resp.ProposalsEmitted)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Force dry-run regardless of per-VM mode")
	return cmd
}

func newRebalanceApproveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "approve <proposal-id>",
		Short: "Approve a proposal; the leader's executor then live-migrates it",
		Long: `Approve a rebalance proposal. The leader node's rebalance executor
then claims it (approved → applying), live-migrates the VM, and records the
result (applied / failed) — subject to the cluster rebalance budget. Track
progress with 'lv rebalance list'.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(context.Background(), func(ctx context.Context, c pb.LiteVirtClient) error {
				p, err := c.ApproveRebalanceProposal(ctx,
					&pb.ApproveRebalanceProposalRequest{Id: args[0]})
				if err != nil {
					return fmt.Errorf("approve: %w", err)
				}
				fmt.Printf("Proposal %s approved (%s → %s for %s); executor will apply it shortly.\n",
					p.Id, p.SrcHost, p.DstHost, p.VmName)
				return nil
			})
		},
	}
}

func newRebalanceRejectCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "reject <proposal-id>",
		Short: "Reject a pending proposal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(context.Background(), func(ctx context.Context, c pb.LiteVirtClient) error {
				p, err := c.RejectRebalanceProposal(ctx,
					&pb.RejectRebalanceProposalRequest{Id: args[0], Reason: reason})
				if err != nil {
					return fmt.Errorf("reject: %w", err)
				}
				fmt.Printf("Proposal %s rejected (%s).\n", p.Id, p.Detail)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Optional rejection reason recorded in the proposal")
	return cmd
}
