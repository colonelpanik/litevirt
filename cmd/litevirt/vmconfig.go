package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newVMConfigCmd() *cobra.Command {
	var (
		ip        string
		network   string
		bootOrder string
	)

	cmd := &cobra.Command{
		Use:   "config <vm>",
		Short: "Update VM configuration (IP, boot order)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]

			if ip == "" && bootOrder == "" {
				return fmt.Errorf("at least one of --ip or --boot must be specified")
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				var vm *pb.VM
				var err error

				if ip != "" {
					vm, err = c.SetVMIP(ctx, &pb.SetVMIPRequest{
						Name:        vmName,
						Ip:          ip,
						NetworkName: network,
					})
					if err != nil {
						return fmt.Errorf("set VM IP: %w", err)
					}
					fmt.Printf("VM %s IP set to %s on network %s\n", vm.Name, ip, network)
				}

				if bootOrder != "" {
					vm, err = c.SetBootOrder(ctx, &pb.SetBootOrderRequest{
						Name:      vmName,
						BootOrder: bootOrder,
					})
					if err != nil {
						return fmt.Errorf("set boot order: %w", err)
					}
					fmt.Printf("VM %s boot order set to %s\n", vm.Name, bootOrder)
				}

				if vm != nil {
					fmt.Printf("VM %s state: %s\n", vm.Name, vm.State)
				}

				return nil
			})
		},
	}

	cmd.Flags().StringVar(&ip, "ip", "", "IP address to assign to the VM interface")
	cmd.Flags().StringVar(&network, "network", "production", "Network name for the IP assignment")
	cmd.Flags().StringVar(&bootOrder, "boot", "", "Boot order (disk|cdrom|network)")

	return cmd
}
