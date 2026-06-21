package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newUninstallCmd() *cobra.Command {
	var confirmed bool
	var keepData bool

	cmd := &cobra.Command{
		Use:   "uninstall <hostname>",
		Short: "Remove litevirt from a host",
		Long: `Uninstall litevirt from a cluster host.

Stops the daemon, removes the binary, config, PKI, and optionally
all VM data (images, disks, state). The host is NOT removed from
cluster state — run 'lv host rm' first if the cluster is still active.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			if !confirmed {
				fmt.Fprintf(os.Stderr, "This will remove litevirt from %s.\n", hostName)
				if !keepData {
					fmt.Fprintf(os.Stderr, "All VM data (images, disks) will be DELETED.\n")
					fmt.Fprintf(os.Stderr, "Use --keep-data to preserve /var/lib/litevirt.\n")
				}
				fmt.Fprintf(os.Stderr, "Re-run with --confirmed to proceed.\n")
				return fmt.Errorf("uninstall requires --confirmed")
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				fmt.Printf("Uninstalling litevirt from %s...\n", hostName)
				resp, err := c.UninstallHost(ctx, &pb.UninstallHostRequest{
					KeepData:   keepData,
					TargetHost: hostName,
				})
				if err != nil {
					return fmt.Errorf("uninstall: %w", err)
				}

				fmt.Printf("\nlitevirt removed from %s (status: %s)\n", resp.HostName, resp.Status)
				if keepData {
					fmt.Println("  VM data preserved at /var/lib/litevirt")
				}
				return nil
			})
		},
	}

	cmd.Flags().BoolVar(&confirmed, "confirmed", false, "Confirm uninstall")
	cmd.Flags().BoolVar(&keepData, "keep-data", false, "Preserve /var/lib/litevirt (images, disks)")

	return cmd
}
