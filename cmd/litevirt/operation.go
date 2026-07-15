package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newOperationCmd is the F1 admin recovery surface for an in-flight operation
// wedged on a VM's mutation barrier (active_operation_id). `show` inspects it;
// `abort` force-clears the barrier so the VM is mutable again.
func newOperationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "operation",
		Short: "Inspect and recover in-flight VM operations",
	}
	cmd.AddCommand(newOperationShowCmd(), newOperationAbortCmd())
	return cmd
}

func newOperationShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <vm>",
		Short: "Show the operation holding a VM's mutation barrier",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetVMOperation(ctx, &pb.GetVMOperationRequest{VmName: args[0]})
				if err != nil {
					return fmt.Errorf("get operation: %w", err)
				}
				if !resp.HasActive {
					fmt.Printf("%s: no in-flight operation\n", args[0])
					return nil
				}
				fmt.Printf("VM:              %s\n", args[0])
				fmt.Printf("Operation:       %s (%s)\n", resp.OperationId, resp.OperationKind)
				fmt.Printf("State:           %s\n", resp.CurrentState)
				if resp.Faulted {
					fmt.Printf("  ⚠ SAFETY FAULT: conflicting terminal states recorded\n")
				}
				if resp.HeaderMissing {
					fmt.Printf("  ⚠ barrier points at a missing operation header\n")
				}
				fmt.Printf("Owner epoch:     %d\nSpec generation: %d\n", resp.VmOwnerEpoch, resp.SpecGeneration)
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "STEP\tEPOCH\tRECORDED")
				for _, st := range resp.Steps {
					fmt.Fprintf(w, "%s\t%d\t%s\n", st.StepName, st.OwnerEpoch, st.CreatedAt)
				}
				return w.Flush()
			})
		},
	}
}

func newOperationAbortCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "abort <vm>",
		Short: "Force-clear a wedged operation's mutation barrier (admin recovery)",
		Long: `Force-clear the operation holding a VM's mutation barrier so the VM can be
mutated again. This is a deliberate recovery action for a wedged operation — it
clears the barrier only via the exact owner/generation compare-and-swap (a stale
or superseded operation can't clear a newer one). Requires --force.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				return fmt.Errorf("--force is required to abort an operation")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.AbortVMOperation(ctx, &pb.AbortVMOperationRequest{VmName: args[0], Force: true})
				if err != nil {
					return fmt.Errorf("abort operation: %w", err)
				}
				if !resp.Aborted {
					fmt.Printf("not aborted: %s\n", resp.Detail)
					return nil
				}
				fmt.Printf("aborted operation %s on %s\n", resp.PreviousOperationId, args[0])
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Confirm the destructive abort")
	return cmd
}
