package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newSetMemoryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-memory <vm> <mib>",
		Short: "Set a VM's live memory balloon target (MiB)",
		Long: "Adjust the running memory balloon target for a VM. The target must lie " +
			"within the VM's [--min-mem, --max-mem] band. For a running VM the virtio " +
			"balloon is driven live; the value is also persisted to libvirt config.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mib, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid memory %q: %w", args[1], err)
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: args[0], TargetMib: int32(mib)})
				if err != nil {
					return fmt.Errorf("set memory: %w", err)
				}
				fmt.Printf("VM %s memory balloon target set to %d MiB\n", vm.Name, mib)
				return nil
			})
		},
	}
}
