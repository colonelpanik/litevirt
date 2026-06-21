package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newUpdateCmd() *cobra.Command {
	var (
		cpu        int32
		memory     int32
		cpuMode    string
		disableVNC bool
	)
	cmd := &cobra.Command{
		Use:   "update <vm>",
		Short: "Update VM resources (CPU, memory, CPU mode, VNC)",
		Long:  "Update a stopped VM's CPU count, memory, CPU mode, or VNC setting.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("cpu") && !cmd.Flags().Changed("memory") && !cmd.Flags().Changed("cpu-mode") && !cmd.Flags().Changed("disable-vnc") {
				return fmt.Errorf("at least one of --cpu, --memory, --cpu-mode, or --disable-vnc must be specified")
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.UpdateVM(ctx, &pb.UpdateVMRequest{
					Name:       args[0],
					Cpu:        cpu,
					MemoryMib:  memory,
					CpuMode:    cpuMode,
					DisableVnc: disableVNC,
				})
				if err != nil {
					return fmt.Errorf("update VM: %w", err)
				}
				fmt.Printf("VM %s updated (cpu: %d, memory: %d MiB, state: %s)\n",
					vm.Name, vm.CpuActual, vm.MemActualMib, vm.State)
				return nil
			})
		},
	}
	cmd.Flags().Int32Var(&cpu, "cpu", 0, "Number of vCPUs (0 = no change)")
	cmd.Flags().Int32Var(&memory, "memory", 0, "Memory in MiB (0 = no change)")
	cmd.Flags().StringVar(&cpuMode, "cpu-mode", "", "CPU mode (host-passthrough, host-model, custom)")
	cmd.Flags().BoolVar(&disableVNC, "disable-vnc", false, "Disable VNC access")
	return cmd
}
