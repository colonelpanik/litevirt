package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newMappingCmd manages cluster-wide resource mappings (#14): named aliases for
// equivalent passthrough devices across hosts, so a VM requesting a device by
// mapping name can run on / migrate to any host registered under that mapping.
func newMappingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mapping",
		Short: "Manage cluster-wide device resource mappings",
	}
	cmd.AddCommand(
		newMappingCreateCmd(),
		newMappingLsCmd(),
		newMappingRmCmd(),
		newMappingAddDeviceCmd(),
		newMappingRmDeviceCmd(),
	)
	return cmd
}

func newMappingCreateCmd() *cobra.Command {
	var desc string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a resource mapping",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				m, err := c.CreateResourceMapping(ctx, &pb.CreateResourceMappingRequest{Name: args[0], Description: desc})
				if err != nil {
					return fmt.Errorf("create mapping: %w", err)
				}
				fmt.Printf("Resource mapping %q created\n", m.Name)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&desc, "description", "", "human-friendly description")
	return cmd
}

func newMappingLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List resource mappings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListResourceMappings(ctx, &pb.ListResourceMappingsRequest{})
				if err != nil {
					return fmt.Errorf("list mappings: %w", err)
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "MAPPING\tHOST\tADDRESS\tVENDOR\tDEVICE\tDESCRIPTION\n")
				for _, m := range resp.Mappings {
					if len(m.Devices) == 0 {
						fmt.Fprintf(w, "%s\t-\t-\t-\t-\t%s\n", m.Name, m.Description)
						continue
					}
					for _, d := range m.Devices {
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", m.Name, d.HostName, d.Address, d.Vendor, d.Device, m.Description)
					}
				}
				return w.Flush()
			})
		},
	}
}

func newMappingRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a resource mapping",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteResourceMapping(ctx, &pb.DeleteResourceMappingRequest{Name: args[0]}); err != nil {
					return fmt.Errorf("delete mapping: %w", err)
				}
				fmt.Printf("Resource mapping %q deleted\n", args[0])
				return nil
			})
		},
	}
}

func newMappingAddDeviceCmd() *cobra.Command {
	var host, vendor, device string
	cmd := &cobra.Command{
		Use:   "add-device <mapping> <pci-address>",
		Short: "Register a host's device under a mapping",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				m, err := c.AddMappingDevice(ctx, &pb.AddMappingDeviceRequest{
					Mapping: args[0], Host: host, Address: args[1], Vendor: vendor, Device: device,
				})
				if err != nil {
					return fmt.Errorf("add mapping device: %w", err)
				}
				fmt.Printf("Mapping %q now has %d device(s)\n", m.Name, len(m.Devices))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "host the device is on (default: the daemon you connect to)")
	cmd.Flags().StringVar(&vendor, "vendor", "", "optional PCI vendor ID")
	cmd.Flags().StringVar(&device, "device", "", "optional device ID / name")
	return cmd
}

func newMappingRmDeviceCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "rm-device <mapping> <pci-address>",
		Short: "Remove a host's device from a mapping",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.RemoveMappingDevice(ctx, &pb.RemoveMappingDeviceRequest{
					Mapping: args[0], Host: host, Address: args[1],
				}); err != nil {
					return fmt.Errorf("remove mapping device: %w", err)
				}
				fmt.Printf("Device %s removed from mapping %q\n", args[1], args[0])
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "host the device is on (default: the daemon you connect to)")
	return cmd
}
