// federation CLI — `lv region ls`, `lv region status`,
// `lv region migrate <vm> <target-host>`. Surfaces the federation
// engine in `internal/region/` over the gRPC RPCs added in 2.5.

package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newRegionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "region",
		Short: "Inspect and operate on regions (federation)",
	}
	cmd.AddCommand(
		newRegionListCmd(),
		newRegionStatusCmd(),
		newRegionMigrateCmd(),
		newRegionAnycastCmd(),
	)
	return cmd
}

func newRegionListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List the distinct regions in the cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListRegions(ctx, &pb.ListRegionsRequest{})
				if err != nil {
					return fmt.Errorf("list regions: %w", err)
				}
				for _, r := range resp.Regions {
					fmt.Println(r)
				}
				return nil
			})
		},
	}
}

func newRegionStatusCmd() *cobra.Command {
	var only string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show host + VM rollups per region",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.RegionStatus(ctx, &pb.RegionStatusRequest{Region: only})
				if err != nil {
					return fmt.Errorf("region status: %w", err)
				}
				fmt.Printf("%-20s %-6s %-7s %-5s %s\n", "REGION", "HOSTS", "ACTIVE", "VMS", "LAST UPDATED")
				for _, st := range resp.Statuses {
					fmt.Printf("%-20s %-6d %-7d %-5d %s\n",
						st.Name, st.HostCount, st.ActiveHosts, st.VmCount, defaultStr(st.LastUpdated, "-"))
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&only, "region", "", "show only this region")
	return cmd
}

func newRegionMigrateCmd() *cobra.Command {
	var live, includeDisks bool
	var targetPool string
	cmd := &cobra.Command{
		Use:   "migrate <vm> <target-host>",
		Short: "Migrate a VM to a host in a different region",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.CrossRegionMigrate(ctx, &pb.CrossRegionMigrateRequest{
					VmName:       args[0],
					TargetHost:   args[1],
					Live:         live,
					IncludeDisks: includeDisks,
					TargetPool:   targetPool,
				})
				if err != nil {
					return fmt.Errorf("cross-region migrate: %w", err)
				}
				for {
					p, err := stream.Recv()
					if err != nil {
						// io.EOF marks end-of-stream which is success.
						if err.Error() == "EOF" {
							return nil
						}
						return fmt.Errorf("migrate stream: %w", err)
					}
					if p.Status != "" {
						fmt.Printf("[%s] %s\n", p.Phase, p.Status)
					}
					if p.Error != "" {
						return fmt.Errorf("%s", p.Error)
					}
				}
			})
		},
	}
	cmd.Flags().BoolVar(&live, "live", true, "use live migration (memory-pre-copy)")
	cmd.Flags().BoolVar(&includeDisks, "with-storage", false, "replicate disks to target_pool before migrating memory")
	cmd.Flags().StringVar(&targetPool, "target-pool", "",
		"target storage pool name (required with --with-storage); must be reachable from the source host")
	return cmd
}

func newRegionAnycastCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "anycast",
		Short: "Manage DNS round-robin service endpoints",
	}
	cmd.AddCommand(
		newAnycastAddCmd(),
		newAnycastListCmd(),
		newAnycastRmCmd(),
	)
	return cmd
}

func newAnycastAddCmd() *cobra.Command {
	var serviceName, ip, region string
	var weight int32
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add or replace a service endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				ep, err := c.UpsertServiceEndpoint(ctx, &pb.UpsertServiceEndpointRequest{
					ServiceName: serviceName, Ip: ip, Region: region, Weight: weight,
				})
				if err != nil {
					return fmt.Errorf("upsert endpoint: %w", err)
				}
				fmt.Printf("registered %s → %s (region=%s, weight=%d)\n",
					ep.ServiceName, ep.Ip, ep.Region, ep.Weight)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&serviceName, "name", "", "service DNS name (e.g. api.litevirt.local)")
	cmd.Flags().StringVar(&ip, "ip", "", "endpoint IP")
	cmd.Flags().StringVar(&region, "region", "", "region label (default: \"default\")")
	cmd.Flags().Int32Var(&weight, "weight", 1, "round-robin weight (default 1)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("ip")
	return cmd
}

func newAnycastListCmd() *cobra.Command {
	var only string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List service endpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListServiceEndpoints(ctx, &pb.ListServiceEndpointsRequest{
					ServiceName: only,
				})
				if err != nil {
					return fmt.Errorf("list endpoints: %w", err)
				}
				fmt.Printf("%-32s %-16s %-12s %s\n", "SERVICE", "IP", "REGION", "WEIGHT")
				for _, e := range resp.Endpoints {
					fmt.Printf("%-32s %-16s %-12s %d\n", e.ServiceName, e.Ip, e.Region, e.Weight)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&only, "name", "", "filter to a single service")
	return cmd
}

func newAnycastRmCmd() *cobra.Command {
	var serviceName, ip string
	cmd := &cobra.Command{
		Use:   "rm",
		Short: "Remove a service endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteServiceEndpoint(ctx, &pb.DeleteServiceEndpointRequest{
					ServiceName: serviceName, Ip: ip,
				}); err != nil {
					return fmt.Errorf("delete endpoint: %w", err)
				}
				fmt.Printf("removed %s → %s\n", serviceName, ip)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&serviceName, "name", "", "service DNS name")
	cmd.Flags().StringVar(&ip, "ip", "", "endpoint IP")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("ip")
	return cmd
}
