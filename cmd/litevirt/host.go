package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

func newHostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Manage cluster hosts",
	}

	cmd.AddCommand(
		newHostInitCmd(),
		newHostAddCmd(),
		newHostLsCmd(),
		newHostInspectCmd(),
		newHostDrainCmd(),
		newHostShutdownWorkloadsCmd(),
		newHostUndrainCmd(),
		newHostRmCmd(),
		newHostLabelCmd(),
		newHostFenceCmd(),
		newHostFenceConfirmCmd(),
		newHostConfigCmd(),
		newHostRescanCmd(),
		newHostDevicesCmd(),
		newHostUpgradeCmd(),
		newHostPreflightUpgradeCmd(),
		newHostStatsCmd(),
		newHostCephCmd(),
	)

	return cmd
}

func newHostInitCmd() *cobra.Command {
	var name string
	var local bool
	cmd := &cobra.Command{
		Use:   "init [user@host]",
		Short: "Bootstrap first cluster host",
		Long: `Bootstrap the first host in a litevirt cluster.

For remote hosts:   lv host init root@10.0.50.10 --name host-a
For localhost:      lv host init --local --name node-1`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if local {
				return cli.HostInitLocal(cmd.Context(), name)
			}
			if len(args) == 0 {
				return fmt.Errorf("SSH target required (or use --local for standalone setup)")
			}
			return cli.HostInit(cmd.Context(), args[0], name)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Host name (required)")
	cmd.Flags().BoolVar(&local, "local", false, "Initialize on localhost (no SSH)")
	cmd.MarkFlagRequired("name")
	return cmd
}

func newHostAddCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "add <user@host>",
		Short: "Add host to existing cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Query existing cluster hosts to get gossip peer addresses.
			// Best-effort: if we can't reach a daemon, proceed with no peers.
			var peerAddrs []string
			c, closer, err := cli.Connect(cmd.Context())
			if err == nil {
				resp, err := c.ListHosts(cmd.Context(), nil)
				if err == nil {
					for _, h := range resp.Hosts {
						if h.Address != "" {
							peerAddrs = append(peerAddrs, fmt.Sprintf("%s:7946", h.Address))
						}
					}
				}
				closer()
			}
			return cli.HostAdd(cmd.Context(), args[0], name, peerAddrs)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Host name (required)")
	cmd.MarkFlagRequired("name")
	return cmd
}

func newHostLsCmd() *cobra.Command {
	var namesOnly bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List cluster hosts",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListHosts(ctx, nil)
				if err != nil {
					return fmt.Errorf("list hosts: %w", err)
				}

				// --names prints one bare host name per line (no header), for
				// shell loops like `for h in $(lv host ls --names); do …`.
				if namesOnly {
					for _, h := range resp.Hosts {
						fmt.Println(h.Name)
					}
					return nil
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "NAME\tADDRESS\tSTATE\tCPU\tMEMORY\tVMs\tVERSION\n")
				for _, h := range resp.Hosts {
					ver := h.Version
					if ver == "" {
						ver = "-"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%d/%d\t%d/%d MiB\t%d\t%s\n",
						h.Name, h.Address, h.State,
						h.CpuUsed, h.CpuTotal,
						h.MemUsedMib, h.MemTotalMib,
						h.VmCount, ver,
					)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().BoolVar(&namesOnly, "names", false, "print only host names, one per line (for scripting)")
	return cmd
}

func newHostInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <host>",
		Short: "Show host details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.PrintHostInspect(ctx, c, args[0])
			})
		},
	}
}

func newHostDrainCmd() *cobra.Command {
	var parallel int
	cmd := &cobra.Command{
		Use:   "drain <host>",
		Short: "Migrate all VMs off a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.DrainHost(ctx, &pb.DrainHostRequest{
					Name:     args[0],
					Parallel: int32(parallel),
				})
				if err != nil {
					return fmt.Errorf("drain: %w", err)
				}

				for {
					p, err := stream.Recv()
					if err != nil {
						break
					}
					if p.Error != "" {
						fmt.Fprintf(os.Stderr, "  %s → %s [%s] ERROR: %s\n",
							p.VmName, p.TargetHost, p.Strategy, p.Error)
					} else {
						fmt.Printf("  %s → %s [%s] %s\n",
							p.VmName, p.TargetHost, p.Strategy, p.Status)
					}
				}

				fmt.Printf("Host %s drained.\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&parallel, "parallel", 2, "Number of parallel migrations")
	return cmd
}

func newHostShutdownWorkloadsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shutdown-workloads <host>",
		Short: "Gracefully stop a host's VMs in reverse startup order (honors stop-delay)",
		Long: `Stop every running VM on a host in REVERSE startup order (highest
startup_order first), pausing each VM's stop_delay_sec before the next.

This is an explicit operator action for ordered host shutdown — it is NOT run on
a normal daemon restart/upgrade (those keep VMs running). Each VM's ACPI
stop_timeout_sec is honored.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.ShutdownHostWorkloads(ctx, &pb.ShutdownHostWorkloadsRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("shutdown-workloads: %w", err)
				}
				for {
					p, err := stream.Recv()
					if err != nil {
						break
					}
					if p.Error != "" {
						fmt.Fprintf(os.Stderr, "  %s [%s] ERROR: %s\n", p.VmName, p.Status, p.Error)
					} else {
						fmt.Printf("  %s [%s]\n", p.VmName, p.Status)
					}
				}
				fmt.Printf("Host %s workloads shut down.\n", args[0])
				return nil
			})
		},
	}
	return cmd
}

func newHostUndrainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "undrain <host>",
		Short: "Return host to active scheduling",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				h, err := c.UndrainHost(ctx, &pb.UndrainHostRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("undrain: %w", err)
				}
				fmt.Printf("Host %s is now %s.\n", h.Name, h.State)
				return nil
			})
		},
	}
}

func newHostRmCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "rm <host>",
		Short: "Remove host from cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.RemoveHost(ctx, &pb.RemoveHostRequest{
					Name:  args[0],
					Force: force,
				})
				if err != nil {
					return fmt.Errorf("remove host: %w", err)
				}
				fmt.Printf("Host %s removed from cluster.\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Force removal even if VMs exist")
	return cmd
}

func newHostLabelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "label",
		Short: "Manage host labels",
	}
	cmd.AddCommand(
		newHostLabelSetCmd(),
		newHostLabelRmCmd(),
		newHostLabelLsCmd(),
	)
	return cmd
}

func newHostLabelSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <host> <key=value>...",
		Short: "Set labels on a host",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				labels := make(map[string]string)
				for _, kv := range args[1:] {
					parts := splitKeyValue(kv)
					if parts == nil {
						return fmt.Errorf("invalid label %q (expected key=value)", kv)
					}
					labels[parts[0]] = parts[1]
				}

				h, err := c.SetHostLabels(ctx, &pb.SetHostLabelsRequest{
					Name:   args[0],
					Labels: labels,
				})
				if err != nil {
					return fmt.Errorf("set labels: %w", err)
				}
				fmt.Printf("Host %s labels updated.\n", h.Name)
				printLabels(h.Labels)
				return nil
			})
		},
	}
}

func newHostLabelRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <host> <key>...",
		Short: "Remove labels from a host",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				h, err := c.SetHostLabels(ctx, &pb.SetHostLabelsRequest{
					Name:   args[0],
					Remove: args[1:],
				})
				if err != nil {
					return fmt.Errorf("remove labels: %w", err)
				}
				fmt.Printf("Host %s labels updated.\n", h.Name)
				printLabels(h.Labels)
				return nil
			})
		},
	}
}

func newHostLabelLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls <host>",
		Short: "List labels on a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				h, err := c.InspectHost(ctx, &pb.InspectHostRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("inspect host: %w", err)
				}
				printLabels(h.Labels)
				return nil
			})
		},
	}
}

func splitKeyValue(s string) []string {
	for i, c := range s {
		if c == '=' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return nil
}

func printLabels(labels map[string]string) {
	if len(labels) == 0 {
		fmt.Println("(no labels)")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tVALUE")
	for k, v := range labels {
		fmt.Fprintf(w, "%s\t%s\n", k, v)
	}
	w.Flush()
}

func newHostFenceCmd() *cobra.Command {
	var confirmed bool
	cmd := &cobra.Command{
		Use:   "fence <host>",
		Short: "Manually fence a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				result, err := c.FenceHost(ctx, &pb.FenceHostRequest{
					Name:      args[0],
					Confirmed: confirmed,
				})
				if err != nil {
					return fmt.Errorf("fence: %w", err)
				}
				fmt.Printf("Host %s: method=%s result=%s detail=%s\n",
					result.HostName, result.Method, result.Result, result.Detail)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&confirmed, "confirmed", false, "Confirm fencing")
	return cmd
}

// newHostFenceConfirmCmd records that the operator has manually powered off
// a host whose FenceStrategy is "manual". Without this confirmation, the
// failover coordinator's split-brain guard refuses to reschedule the host's
// VMs.
func newHostFenceConfirmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fence-confirm <host>",
		Short: "Confirm a manual fence so VMs may be rescheduled",
		Long: `Record that an operator has powered the host off externally.

Use this after FenceStrategy=manual hosts that the coordinator has flagged as
needing manual intervention. Without this confirmation the coordinator will
NOT reschedule the host's VMs, to prevent split-brain on shared storage.

The host MUST be physically off (or otherwise demonstrably not running its
workloads) before running this command.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				result, err := c.FenceHost(ctx, &pb.FenceHostRequest{
					Name:              args[0],
					Confirmed:         true,
					ConfirmManualOnly: true,
				})
				if err != nil {
					return fmt.Errorf("fence-confirm: %w", err)
				}
				fmt.Printf("Host %s: method=%s result=%s detail=%s\n",
					result.HostName, result.Method, result.Result, result.Detail)
				return nil
			})
		},
	}
}

func newHostConfigCmd() *cobra.Command {
	var fenceStrategy, ipmiAddr, ipmiUser, ipmiPass, watchdogDev, role, region string

	cmd := &cobra.Command{
		Use:   "config <host>",
		Short: "Configure host settings (fencing, IPMI, watchdog, role, region)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				h, err := c.ConfigureHost(ctx, &pb.ConfigureHostRequest{
					Name:          args[0],
					FenceStrategy: fenceStrategy,
					IpmiAddress:   ipmiAddr,
					IpmiUser:      ipmiUser,
					IpmiPass:      ipmiPass,
					WatchdogDev:   watchdogDev,
					Role:          role,
					Region:        region,
				})
				if err != nil {
					return fmt.Errorf("configure host: %w", err)
				}
				fmt.Printf("Host %s configured.\n", h.Name)
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&fenceStrategy, "fence-strategy", "", "Fencing strategy (ssh, ipmi, watchdog)")
	cmd.Flags().StringVar(&ipmiAddr, "ipmi-address", "", "IPMI BMC address")
	cmd.Flags().StringVar(&ipmiUser, "ipmi-user", "", "IPMI username")
	cmd.Flags().StringVar(&ipmiPass, "ipmi-pass", "", "IPMI password")
	cmd.Flags().StringVar(&watchdogDev, "watchdog-dev", "", "Watchdog device path")
	cmd.Flags().StringVar(&role, "role", "",
		"Role: 'worker' (run VMs + vote) or 'witness' (vote-only tiebreaker for even-N clusters). Host must have no VMs to be promoted to witness.")
	cmd.Flags().StringVar(&region, "region", "",
		"Region label (failure domain — DC, rack, AZ). Default 'default'. Used by `lv region status` and cross-region migration.")

	return cmd
}

func newHostRescanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rescan [host]",
		Short: "Rescan PCI devices on a host",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				name := ""
				if len(args) > 0 {
					name = args[0]
				}

				resp, err := c.RescanHost(ctx, &pb.RescanHostRequest{Name: name})
				if err != nil {
					return fmt.Errorf("rescan: %w", err)
				}

				fmt.Printf("PCI rescan complete: %d added, %d removed, %d total\n",
					resp.Added, resp.Removed, resp.Total)
				return nil
			})
		},
	}
}

func newHostUpgradeCmd() *cobra.Command {
	var binaryPath string
	var yes bool
	var force bool
	var noPreStage bool
	cmd := &cobra.Command{
		Use:   "upgrade [host-name...]",
		Short: "Roll out a new litevirtd binary to cluster hosts",
		Long: `Performs a rolling upgrade of litevirtd across cluster hosts.

For each target host: copy binary → swap → restart → verify.
VMs, HAProxy, and keepalived all survive daemon restarts.

A pre-flight check inspects the host for in-flight migrations, leader-lease
holdings, replication backlog, and clock skew. The upgrade aborts on
"block" findings unless --force is passed (warnings are logged either way).

  lv host upgrade                           # all outdated hosts, with preflight
  lv host upgrade host-b host-c             # specific hosts
  lv host upgrade --binary ./bin/litevirtd  # use a local binary
  lv host upgrade --force                   # skip preflight blocks
  lv host preflight-upgrade <host>          # check without upgrading`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.HostUpgrade(ctx, c, cli.UpgradeOpts{
					BinaryPath: binaryPath,
					HostNames:  args,
					Yes:        yes,
					Force:      force,
					NoPreStage: noPreStage,
				})
			})
		},
	}
	cmd.Flags().StringVar(&binaryPath, "binary", "/usr/local/bin/litevirt", "Path to litevirtd binary to distribute")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().BoolVar(&force, "force", false, "Skip preflight blocks (warnings still printed)")
	cmd.Flags().BoolVar(&noPreStage, "no-prestage", false, "Skip the cluster-wide schema pre-stage pass (not recommended for multi-version upgrades)")
	return cmd
}

// newHostPreflightUpgradeCmd reports preflight findings without triggering
// the actual upgrade. Operators can run this before scheduling maintenance.
func newHostPreflightUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "preflight-upgrade <host>",
		Short: "Report preflight findings for an upgrade without performing it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.PreflightUpgrade(ctx,
					&pb.PreflightUpgradeRequest{TargetHost: args[0]})
				if err != nil {
					return fmt.Errorf("preflight: %w", err)
				}
				if len(resp.Findings) == 0 {
					fmt.Printf("Host %s: no findings, upgrade is safe.\n", resp.Host)
					return nil
				}
				fmt.Printf("Host %s preflight findings:\n", resp.Host)
				for _, f := range resp.Findings {
					fmt.Printf("  [%s] %s: %s\n", f.Severity, f.Code, f.Message)
				}
				if !resp.Ok {
					return fmt.Errorf("upgrade blocked by %d finding(s)", countBlockingCLI(resp.Findings))
				}
				return nil
			})
		},
	}
}

func countBlockingCLI(findings []*pb.PreflightFinding) int {
	n := 0
	for _, f := range findings {
		if f.Severity == "block" {
			n++
		}
	}
	return n
}

func newHostDevicesCmd() *cobra.Command {
	var typeFilter string
	cmd := &cobra.Command{
		Use:   "devices <host>",
		Short: "List PCI devices on a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListHostDevices(ctx, &pb.ListHostDevicesRequest{
					Name:       args[0],
					TypeFilter: typeFilter,
				})
				if err != nil {
					return fmt.Errorf("list devices: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "ADDRESS\tTYPE\tVENDOR\tDEVICE\tDRIVER\tIOMMU\tVM")
				for _, d := range resp.Devices {
					vm := d.VmName
					if vm == "" {
						vm = "-"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
						d.Address, d.Type, d.VendorId, d.DeviceId,
						d.Driver, d.IommuGroup, vm)
				}
				w.Flush()
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&typeFilter, "type", "", "Filter by device type (gpu, network, nvme, infiniband)")
	return cmd
}
