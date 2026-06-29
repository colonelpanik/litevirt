package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newPoolCmd is 's CLI surface. Lets an operator add or
// remove a storage backend at runtime instead of editing /etc/litevirt/
// config.yaml and restarting the daemon.
func newPoolCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pool",
		Short: "Manage storage pools (local | dir | nfs | iscsi | ceph | zfs | btrfs | lvm-thin)",
	}
	cmd.AddCommand(
		newPoolCreateCmd(),
		newPoolListCmd(),
		newPoolInspectCmd(),
		newPoolDeleteCmd(),
	)
	return cmd
}

func newPoolCreateCmd() *cobra.Command {
	var driver, source, target, host, project string
	var opts []string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Register and prepare a storage pool",
		Long: `Register a new storage pool. The daemon runs the driver's Prepare()
hook (mount NFS, log into iSCSI, …) before persisting the row, so a
mount failure is surfaced immediately instead of at first VM create.

Options are key=value pairs; pass --option multiple times.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				parsedOpts, err := parsePoolOptions(opts)
				if err != nil {
					return err
				}
				resp, err := c.CreateStoragePool(ctx, &pb.CreateStoragePoolRequest{
					Name:    args[0],
					Driver:  driver,
					Source:  source,
					Target:  target,
					Options: parsedOpts,
					Host:    host,
					Project: project,
				})
				if err != nil {
					return fmt.Errorf("create pool: %w", err)
				}
				fmt.Printf("pool %s created on %s (driver=%s)\n",
					resp.Pool.Name, resp.Pool.Host, resp.Pool.Driver)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&driver, "driver", "", "driver (required: local|dir|nfs|iscsi|ceph|zfs|btrfs|lvm-thin)")
	cmd.Flags().StringVar(&source, "source", "", "driver-specific source (e.g. server:/export, ceph pool name)")
	cmd.Flags().StringVar(&target, "target", "", "local mount/path override")
	cmd.Flags().StringSliceVar(&opts, "option", nil, "driver-specific option (key=value; repeatable)")
	cmd.Flags().StringVar(&host, "host", "", "target host (default: caller's local host)")
	cmd.Flags().StringVar(&project, "project", "", "Owning project (empty = global/shared, usable by all projects)")
	_ = cmd.MarkFlagRequired("driver")
	return cmd
}

func newPoolListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List storage pools across the cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListStoragePools(ctx, &pb.ListStoragePoolsRequest{})
				if err != nil {
					return fmt.Errorf("list pools: %w", err)
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "HOST\tNAME\tDRIVER\tSOURCE\tTARGET\tSTATE")
				for _, p := range resp.Pools {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
						p.Host, p.Name, p.Driver, p.Source, p.Target, p.State)
				}
				return w.Flush()
			})
		},
	}
}

func newPoolInspectCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "inspect <name>",
		Short: "Show full details for one pool",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetStoragePool(ctx, &pb.GetStoragePoolRequest{
					Name: args[0], Host: host,
				})
				if err != nil {
					return fmt.Errorf("get pool: %w", err)
				}
				p := resp.Pool
				fmt.Printf("Name:        %s\n", p.Name)
				fmt.Printf("Host:        %s\n", p.Host)
				fmt.Printf("Driver:      %s\n", p.Driver)
				fmt.Printf("Source:      %s\n", p.Source)
				fmt.Printf("Target:      %s\n", p.Target)
				fmt.Printf("State:       %s\n", p.State)
				fmt.Printf("Total:       %d bytes\n", p.TotalBytes)
				fmt.Printf("Used:        %d bytes\n", p.UsedBytes)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "target host (default: caller's local host)")
	return cmd
}

func newPoolDeleteCmd() *cobra.Command {
	var host string
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Soft-delete a storage pool from the inventory",
		Long: `Remove a pool from cluster state. The delete is REFUSED when VM disks
or active backup/replication schedules still reference the pool —
pass --force to override. The driver is then asked to tear down
(unmount NFS, log out of iSCSI) on a best-effort basis; a teardown
failure does not block the row delete.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteStoragePool(ctx, &pb.DeleteStoragePoolRequest{
					Name: args[0], Host: host, Force: force,
				}); err != nil {
					return fmt.Errorf("delete pool: %w", err)
				}
				fmt.Printf("pool %s deleted\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "target host (default: caller's local host)")
	cmd.Flags().BoolVar(&force, "force", false, "delete even if VM disks or active schedules still reference the pool")
	return cmd
}

// parsePoolOptions turns ["key=value", "k2=v2"] into a map. Bad rows
// fail loudly so an operator typo doesn't silently drop an NFS flag.
func parsePoolOptions(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(raw))
	keys := make([]string, 0, len(raw))
	for _, kv := range raw {
		i := strings.IndexByte(kv, '=')
		if i <= 0 || i == len(kv)-1 {
			return nil, fmt.Errorf("--option %q: want key=value", kv)
		}
		k, v := kv[:i], kv[i+1:]
		out[k] = v
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return out, nil
}
