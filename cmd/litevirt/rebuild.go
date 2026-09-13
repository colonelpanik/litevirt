package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newRebuildCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rebuild <vm>",
		Short: "Destroy and recreate a VM from its stored spec",
		Long:  "Rebuilds a VM preserving its IP and MAC allocations. Useful for recovering from corrupted disk state.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.RebuildVM(ctx, &pb.RebuildVMRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("rebuild: %w", err)
				}
				fmt.Printf("VM %s rebuilt on host %s (state: %s)\n", vm.Name, vm.HostName, vm.State)
				return nil
			})
		},
	}
}

func newCutoverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cutover <vm>",
		Short: "Complete a snapshot-and-replace update",
		Long: `Replaces the original VM with the -next candidate created during a
snapshot-and-replace update.

A RUNNING candidate is briefly interrupted. libvirt has no operation that moves a
live domain to another name, so the candidate is stopped, redefined under the
original's name and started again.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				next := args[0] + "-next"
				// Say so up front when it applies, rather than leaving an operator
				// to discover the restart from a monitoring alert. A lookup failure
				// is not worth failing the cutover over — the server does its own.
				if cand, lerr := c.InspectVM(ctx, &pb.InspectVMRequest{Name: next}); lerr == nil &&
					cand.State == pb.VMState_VM_RUNNING {
					fmt.Printf("%s is running; it will be stopped and restarted as %s "+
						"(libvirt cannot rename a live domain).\n", next, args[0])
				}
				vm, err := c.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: args[0]})
				if err != nil {
					return fmt.Errorf("cutover: %w", err)
				}
				fmt.Printf("Cutover complete: VM %s is now running on %s\n", vm.Name, vm.HostName)
				return nil
			})
		},
	}
}
