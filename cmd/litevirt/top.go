package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newTopCmd() *cobra.Command {
	var interval time.Duration

	cmd := &cobra.Command{
		Use:   "top",
		Short: "Live cluster resource dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
				defer signal.Stop(sigCh)

				ticker := time.NewTicker(interval)
				defer ticker.Stop()

				// Initial render
				if err := renderTop(cmd, c); err != nil {
					return err
				}

				for {
					select {
					case <-sigCh:
						return nil
					case <-ctx.Done():
						return nil
					case <-ticker.C:
						if err := renderTop(cmd, c); err != nil {
							return err
						}
					}
				}
			})
		},
	}

	cmd.Flags().DurationVar(&interval, "interval", 3*time.Second, "Refresh interval")
	return cmd
}

func renderTop(cmd *cobra.Command, c pb.LiteVirtClient) error {
	cs, err := c.GetClusterStatus(cmd.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	// ANSI clear screen + move cursor home
	fmt.Print("\033[2J\033[H")

	fmt.Printf("litevirt top   %s\n\n", time.Now().Format("15:04:05"))
	fmt.Printf("Cluster: %-20s  Hosts: %d/%d active   VMs: %d running / %d total\n\n",
		cs.ClusterName, cs.HostsActive, cs.HostsTotal, cs.VmsRunning, cs.VmsTotal)

	w := io.Writer(os.Stdout)
	fmt.Fprintf(w, "%-20s  %-6s  %-10s  %-10s  %-8s  %s\n",
		"HOST", "STATE", "CPU", "MEM (MiB)", "VMs", "ADDRESS")
	fmt.Fprintln(w, strings.Repeat("─", 72))

	for _, h := range cs.Hosts {
		cpuBar := resourceBar(int(h.CpuUsed), int(h.CpuTotal), 10)
		memBar := resourceBar(int(h.MemUsedMib), int(h.MemTotalMib), 10)
		fmt.Fprintf(w, "%-20s  %-6s  %s %-4d  %s %-6d  %-8d  %s\n",
			h.Name,
			hostStateShort(h.State),
			cpuBar, h.CpuUsed,
			memBar, h.MemUsedMib,
			h.VmCount,
			h.Address,
		)
	}
	return nil
}

func resourceBar(used, total, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filled := used * width / total
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func hostStateShort(s pb.HostState) string {
	switch s {
	case pb.HostState_HOST_ACTIVE:
		return "active"
	case pb.HostState_HOST_DRAINING:
		return "drain"
	case pb.HostState_HOST_MAINTENANCE:
		return "maint"
	case pb.HostState_HOST_SUSPECT:
		return "susp"
	case pb.HostState_HOST_OFFLINE:
		return "OFFLN"
	default:
		return "?"
	}
}
