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
		Long:  "Replaces the original VM with the -next candidate created during a snapshot-and-replace update.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
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
