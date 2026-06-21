package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newSnapshotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Manage VM snapshots",
	}
	cmd.AddCommand(
		newSnapshotCreateCmd(),
		newSnapshotLsCmd(),
		newSnapshotRestoreCmd(),
		newSnapshotRmCmd(),
	)
	return cmd
}

func newSnapshotCreateCmd() *cobra.Command {
	var withMemory bool
	cmd := &cobra.Command{
		Use:   "create <vm> <name>",
		Short: "Create a snapshot of a VM",
		Long: "Create a snapshot of a VM. By default this is a disk-only snapshot; " +
			"--memory also captures guest RAM/CPU state so a restore lands the running " +
			"VM at the exact snapshot instant (falls back to disk-only for a stopped VM).",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]
			snapName := args[1]

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				snap, err := c.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{
					VmName:     vmName,
					Name:       snapName,
					WithMemory: withMemory,
				})
				if err != nil {
					return fmt.Errorf("create snapshot: %w", err)
				}

				kind := snap.Type
				if kind == "" {
					kind = "disk"
				}
				fmt.Printf("Snapshot %q (%s) created for VM %s (state: %s)\n", snap.Name, kind, snap.VmName, snap.State)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&withMemory, "memory", false, "also capture guest RAM/CPU state (live snapshot)")
	return cmd
}

func newSnapshotLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls <vm>",
		Short: "List snapshots of a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListSnapshots(ctx, &pb.ListSnapshotsRequest{
					VmName: vmName,
				})
				if err != nil {
					return fmt.Errorf("list snapshots: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "ID\tNAME\tTYPE\tSTATE\tSIZE\tCREATED\n")
				for _, snap := range resp.Snapshots {
					created := ""
					if snap.CreatedAt != nil {
						created = snap.CreatedAt.AsTime().Format("2006-01-02 15:04:05")
					}
					kind := snap.Type
					if kind == "" {
						kind = "disk"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
						snap.Id,
						snap.Name,
						kind,
						snap.State,
						formatBytes(snap.SizeBytes),
						created,
					)
				}
				return w.Flush()
			})
		},
	}
}

func newSnapshotRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore <vm> <name>",
		Short: "Restore a VM to a snapshot",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]
			snapName := args[1]

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{
					VmName:       vmName,
					SnapshotName: snapName,
				})
				if err != nil {
					return fmt.Errorf("restore snapshot: %w", err)
				}

				fmt.Printf("VM %s restored from snapshot %q (state: %s)\n", vm.Name, snapName, vm.State)
				return nil
			})
		},
	}
}

func newSnapshotRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <vm> <name>",
		Short: "Delete a snapshot",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]
			snapName := args[1]

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{
					VmName:       vmName,
					SnapshotName: snapName,
				})
				if err != nil {
					return fmt.Errorf("delete snapshot: %w", err)
				}

				fmt.Printf("Snapshot %q deleted from VM %s\n", snapName, vmName)
				return nil
			})
		},
	}
}
