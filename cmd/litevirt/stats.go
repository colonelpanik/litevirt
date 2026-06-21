package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newStatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats <vm>",
		Short: "Show live resource stats for a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				s, err := c.GetVMStats(ctx, &pb.GetVMStatsRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("get VM stats: %w", err)
				}

				fmt.Printf("VM: %s\n", s.Name)
				fmt.Printf("CPU:      %.1f%%\n", s.CpuPct)
				fmt.Printf("Memory:   %s / %s (%.0f%%)\n",
					formatBytes(s.MemRssBytes), formatBytes(s.MemTotalBytes),
					safePct(s.MemRssBytes, s.MemTotalBytes))
				fmt.Printf("Disk I/O: %s read / %s written\n",
					formatBytes(s.DiskRdBytes), formatBytes(s.DiskWrBytes))
				fmt.Printf("Net I/O:  %s rx / %s tx\n",
					formatBytes(s.NetRxBytes), formatBytes(s.NetTxBytes))
				return nil
			})
		},
	}
}

func newHostStatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats <host>",
		Short: "Show live resource stats for a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				s, err := c.GetHostStats(ctx, &pb.GetHostStatsRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("get host stats: %w", err)
				}

				fmt.Printf("Host: %s\n", s.HostName)
				fmt.Printf("CPU:    %.1f%%\n", s.CpuPct)
				fmt.Printf("Memory: %s / %s (%.0f%%)\n",
					formatBytes(s.MemUsedBytes), formatBytes(s.MemTotalBytes),
					safePct(s.MemUsedBytes, s.MemTotalBytes))
				fmt.Printf("Disk I/O: %s read / %s written\n",
					formatBytes(s.DiskRdBytes), formatBytes(s.DiskWrBytes))
				fmt.Println()

				if len(s.VmStats) > 0 {
					w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
					fmt.Fprintln(w, "VM\tCPU %\tMEM RSS\tDISK RD\tDISK WR\tNET RX\tNET TX")
					for _, vm := range s.VmStats {
						fmt.Fprintf(w, "%s\t%.1f\t%s\t%s\t%s\t%s\t%s\n",
							vm.Name, vm.CpuPct,
							formatBytes(vm.MemRssBytes),
							formatBytes(vm.DiskRdBytes), formatBytes(vm.DiskWrBytes),
							formatBytes(vm.NetRxBytes), formatBytes(vm.NetTxBytes),
						)
					}
					w.Flush()
				}
				return nil
			})
		},
	}
}

func safePct(used, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}
