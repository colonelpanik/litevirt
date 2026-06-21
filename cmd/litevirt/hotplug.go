package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newAttachDiskCmd() *cobra.Command {
	var (
		size string
		bus  string
	)
	cmd := &cobra.Command{
		Use:   "attach-disk <vm> <disk-name>",
		Short: "Hot-attach a disk to a running VM",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.AttachDevice(ctx, &pb.AttachDeviceRequest{
					VmName: args[0],
					Disk:   &pb.DiskSpec{Name: args[1], Size: size, Bus: bus},
				})
				if err != nil {
					return fmt.Errorf("attach disk: %w", err)
				}

				fmt.Printf("Disk %q attached to VM %s\n", args[1], vm.Name)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&size, "size", "20G", "Disk size (e.g. 20G, 1T)")
	cmd.Flags().StringVar(&bus, "bus", "virtio", "Disk bus (virtio, scsi, sata)")
	return cmd
}

func newDetachDiskCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detach-disk <vm> <disk-name>",
		Short: "Hot-detach a disk from a running VM",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.DetachDevice(ctx, &pb.DetachDeviceRequest{
					VmName:   args[0],
					DiskName: args[1],
				})
				if err != nil {
					return fmt.Errorf("detach disk: %w", err)
				}

				fmt.Printf("Disk %q detached from VM %s\n", args[1], vm.Name)
				return nil
			})
		},
	}
}

func newAttachNicCmd() *cobra.Command {
	var (
		model string
		mac   string
	)
	cmd := &cobra.Command{
		Use:   "attach-nic <vm> <network>",
		Short: "Hot-attach a NIC to a running VM",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.AttachDevice(ctx, &pb.AttachDeviceRequest{
					VmName: args[0],
					Nic:    &pb.NetworkAttachment{Name: args[1], Model: model, Mac: mac},
				})
				if err != nil {
					return fmt.Errorf("attach NIC: %w", err)
				}

				fmt.Printf("NIC attached to VM %s on network %q\n", vm.Name, args[1])
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&model, "model", "virtio", "NIC model (virtio, e1000)")
	cmd.Flags().StringVar(&mac, "mac", "", "MAC address (auto-generated if empty)")
	return cmd
}

func newDetachNicCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detach-nic <vm> <mac>",
		Short: "Hot-detach a NIC from a running VM by MAC address",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.DetachDevice(ctx, &pb.DetachDeviceRequest{
					VmName: args[0],
					NicMac: args[1],
				})
				if err != nil {
					return fmt.Errorf("detach NIC: %w", err)
				}

				fmt.Printf("NIC %s detached from VM %s\n", args[1], vm.Name)
				return nil
			})
		},
	}
}

func newAttachPciCmd() *cobra.Command {
	var (
		devType string
		vendor  string
		count   int32
		sriov   bool
	)
	cmd := &cobra.Command{
		Use:   "attach-pci <vm>",
		Short: "Hot-attach a PCI device to a running VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.AttachDevice(ctx, &pb.AttachDeviceRequest{
					VmName: args[0],
					PciDevice: &pb.DeviceSpec{
						Type:   devType,
						Vendor: vendor,
						Count:  count,
						Sriov:  sriov,
					},
				})
				if err != nil {
					return fmt.Errorf("attach PCI device: %w", err)
				}

				fmt.Printf("PCI device attached to VM %s\n", vm.Name)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&devType, "type", "gpu", "Device type (gpu, network, nvme)")
	cmd.Flags().StringVar(&vendor, "vendor", "", "PCI vendor ID (e.g. 10de)")
	cmd.Flags().Int32Var(&count, "count", 1, "Number of devices to attach")
	cmd.Flags().BoolVar(&sriov, "sriov", false, "Request SR-IOV VF instead of PF")
	return cmd
}

func newDetachPciCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detach-pci <vm> <pci-address>",
		Short: "Hot-detach a PCI device from a running VM",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.DetachDevice(ctx, &pb.DetachDeviceRequest{
					VmName:     args[0],
					PciAddress: args[1],
				})
				if err != nil {
					return fmt.Errorf("detach PCI device: %w", err)
				}

				fmt.Printf("PCI device %s detached from VM %s\n", args[1], vm.Name)
				return nil
			})
		},
	}
}

func newResizeDiskCmd() *cobra.Command {
	var disk string
	cmd := &cobra.Command{
		Use:   "resize-disk <vm> --disk <name> --size <size>",
		Short: "Expand a VM disk to a new size",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			size, _ := cmd.Flags().GetString("size")
			if size == "" {
				return fmt.Errorf("--size is required")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.ResizeDisk(ctx, &pb.ResizeDiskRequest{
					VmName:   args[0],
					DiskName: disk,
					Size:     size,
				})
				if err != nil {
					return fmt.Errorf("resize disk: %w", err)
				}

				fmt.Printf("Disk %q on VM %s resized to %s\n", disk, vm.Name, size)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&disk, "disk", "root", "Disk name to resize")
	cmd.Flags().String("size", "", "New total disk size (e.g. 40G, 1T)")
	_ = cmd.MarkFlagRequired("size")
	return cmd
}
