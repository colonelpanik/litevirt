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
		newHostRotateAuditKeyCmd(),
		newHostRetireAuditKeyCmd(),
	)

	return cmd
}

func newHostInitCmd() *cobra.Command {
	var name string
	var local bool
	var address string
	cmd := &cobra.Command{
		Use:   "init [user@host]",
		Short: "Bootstrap first cluster host",
		Long: `Bootstrap the first host in a litevirt cluster.

For remote hosts:   lv host init root@10.0.50.10 --name host-a
For localhost:      lv host init --local --name node-1 --address 10.77.0.11

With --local, --address is what peers will dial. It goes into the host certificate,
so leaving it wrong means every peer handshake fails with "certificate is valid for
127.0.0.1, not <addr>". It defaults to the default-route source IP, which is the
wrong interface on a multi-homed host — pass the same value you will put in
advertise_address.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if local {
				return cli.HostInitLocal(cmd.Context(), name, address)
			}
			if len(args) == 0 {
				return fmt.Errorf("SSH target required (or use --local for standalone setup)")
			}
			return cli.HostInit(cmd.Context(), args[0], name)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Host name (required)")
	cmd.Flags().BoolVar(&local, "local", false, "Initialize on localhost (no SSH)")
	cmd.Flags().StringVar(&address, "address", "",
		"with --local, the IP peers will dial this host on; it goes in the host "+
			"certificate. Defaults to the default-route source IP, which is wrong on a "+
			"multi-homed host — use the same value you will set as advertise_address")
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
			// Query existing cluster hosts to get gossip peer addresses. This was
			// best-effort and silent, which meant an unreachable daemon produced an
			// empty peer list and a node provisioned with nowhere to join. HostAdd
			// refuses an empty list now, so the only job here is to say WHY it is
			// empty rather than leaving the operator to guess.
			var peerAddrs []string
			c, closer, err := cli.Connect(cmd.Context())
			if err != nil {
				return fmt.Errorf("cannot reach a cluster daemon to read the existing hosts, "+
					"whose addresses become %s's gossip peers: %w", name, err)
			}
			resp, lerr := c.ListHosts(cmd.Context(), nil)
			closer()
			if lerr != nil {
				return fmt.Errorf("cannot list the existing cluster hosts, whose addresses "+
					"become %s's gossip peers: %w", name, lerr)
			}
			for _, h := range resp.Hosts {
				if h.Address != "" {
					peerAddrs = append(peerAddrs, fmt.Sprintf("%s:7946", h.Address))
				}
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
	var cpuOvercommit, memOvercommit float64
	var cpuReserve, memReserveMiB int

	cmd := &cobra.Command{
		Use:   "config <host>",
		Short: "Configure host settings (fencing, IPMI, watchdog, role, region)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				out := &pb.ConfigureHostRequest{
					Name:          args[0],
					FenceStrategy: fenceStrategy,
					IpmiAddress:   ipmiAddr,
					IpmiUser:      ipmiUser,
					IpmiPass:      ipmiPass,
					WatchdogDev:   watchdogDev,
					Role:          role,
					Region:        region,
				}
				// Send capacity overrides only when the operator actually passed the
				// flag: an omitted numeric flag is 0, which for a reserve is a REAL
				// value ("hand guests everything"), so silence has to mean silence.
				if cmd.Flags().Changed("cpu-overcommit") {
					out.CpuOvercommit = &cpuOvercommit
				}
				if cmd.Flags().Changed("mem-overcommit") {
					out.MemOvercommit = &memOvercommit
				}
				if cmd.Flags().Changed("cpu-reserve") {
					v := int32(cpuReserve)
					out.CpuReserve = &v
				}
				if cmd.Flags().Changed("mem-reserve") {
					v := int32(memReserveMiB)
					out.MemReserveMib = &v
				}
				h, err := c.ConfigureHost(ctx, out)
				if err != nil {
					return fmt.Errorf("configure host: %w", err)
				}
				fmt.Printf("Host %s configured.\n", h.Name)
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&fenceStrategy, "fence-strategy", "",
		"Fencing strategy: ssh | ipmi | watchdog | manual | best-effort. 'manual' never powers the host off — it records the intent and waits for `lv host fence-confirm`.")
	cmd.Flags().StringVar(&ipmiAddr, "ipmi-address", "", "IPMI BMC address")
	cmd.Flags().StringVar(&ipmiUser, "ipmi-user", "", "IPMI username")
	cmd.Flags().StringVar(&ipmiPass, "ipmi-pass", "", "IPMI password")
	cmd.Flags().StringVar(&watchdogDev, "watchdog-dev", "", "Watchdog device path")
	cmd.Flags().StringVar(&role, "role", "",
		"Role: 'worker' (run VMs + vote) or 'witness' (vote-only tiebreaker for even-N clusters). Host must have no VMs to be promoted to witness.")
	cmd.Flags().StringVar(&region, "region", "",
		"Region label (failure domain — DC, rack, AZ). Default 'default'. Used by `lv region status` and cross-region migration.")
	cmd.Flags().Float64Var(&cpuOvercommit, "cpu-overcommit", 0,
		"vCPU oversubscription ratio for this host (0 = inherit the cluster default). vCPU is time-sliced, so >1 is normal.")
	cmd.Flags().Float64Var(&memOvercommit, "mem-overcommit", 0,
		"Memory oversubscription ratio for this host (0 = inherit). Raise above 1 only with ballooning/KSM/swap to back it.")
	cmd.Flags().IntVar(&cpuReserve, "cpu-reserve", 0,
		"vCPUs held back for the host itself (negative = inherit the cluster default).")
	cmd.Flags().IntVar(&memReserveMiB, "mem-reserve", 0,
		"MiB held back for the host itself (negative = inherit). 0 means hand guests every last MiB — the host gets no headroom.")

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

// newHostRotateAuditKeyCmd replaces the key a host signs audit rows with. It
// is SSH + a restart, not an RPC: only the host holds its new private key, so
// only the host can sign the chain head that seals what the old key wrote.
func newHostRotateAuditKeyCmd() *cobra.Command {
	var sshTarget string
	cmd := &cobra.Command{
		Use:   "rotate-audit-key <host>",
		Short: "Replace a host's audit signing key",
		Long: `Mint a new audit signing certificate for a host and install it.

Run this when the host's signing key may have been exposed — notably on any node
provisioned before the fix that pushed /etc/litevirt/pki/host.key mode 0644.
Tightening the mode does not undo a copy someone already took.

Must run from the node that holds the cluster CA private key (the one that ran
'lv host init'): there is no CSR flow, so nowhere else can sign a certificate.

The host's TLS identity (host.crt / host.key) is NOT touched — peer mTLS and
qemu+tls:// live migration are unaffected. The target's daemon is restarted,
because the signing keyring is loaded once at boot.

  lv host rotate-audit-key host-b
  lv host rotate-audit-key host-b --ssh root@10.0.50.11`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.HostRotateAuditKey(cmd.Context(), args[0], sshTarget)
		},
	}
	cmd.Flags().StringVar(&sshTarget, "ssh", "",
		"SSH target for the host (default root@<host>) — needed when the litevirt host name is not the address you reach it on")
	return cmd
}

// newHostRetireAuditKeyCmd ends a host's audit signing contract when the host
// cannot end it itself.
//
// The daemon signs its own retirement whenever enforcement.audit_signature is
// turned off, so an ordinary rollback needs no command at all. This is for a
// host that has lost its key, is gone, or is being decommissioned.
func newHostRetireAuditKeyCmd() *cobra.Command {
	var atSeq int64
	var force bool
	cmd := &cobra.Command{
		Use:   "retire-audit-key <host>",
		Short: "Retire a host's audit signing key on its behalf",
		Long: `End a host's audit signing contract when the host cannot end it itself.

Publishing a signing certificate declares that a host's audit rows are signed
from that point on. A host that stops signing while that declaration stands has
every unsigned row reported as tampering on every node — which is correct when
someone took its key away, and wrong when the machine is simply gone.

You do not need this for a normal rollback: turning enforcement.audit_signature
off makes the daemon sign its own retirement on the next start. Use it when the
host cannot sign one — key lost or unreadable, machine destroyed, decommission.

Run it where the cluster CA private key is (the machine that ran 'lv host init'):
signing on another host's behalf means minting a certificate carrying that host's
name, which is exactly what holding the CA authorises. The signing happens
locally — the CA key is never sent to a node, and the daemon only verifies.

Rows the retired key signed stay verifiable forever — retirement is a validity
window, never a deletion.

The boundary is derived from replicated state, and the command refuses to run from
a node whose copy of the host's log a signed chain head says is behind: pinning a
boundary below rows the key legitimately signed cannot be undone. Use --at-seq only
when that refusal cannot be satisfied, because a head signed by the key you are
retiring can claim any sequence at all and cannot be withdrawn — a leaked key can
block this command indefinitely.

An --at-seq at or above what this node can already see is accepted; a lower one is
refused unless you add --force, because lowering the boundary is the direction that
cannot be walked back and a typo looks exactly like a decision.

  lv host retire-audit-key host-b
  lv host retire-audit-key host-b --at-seq 4210
  lv host retire-audit-key host-b --at-seq 100 --force   # key known to have leaked at row 100`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Changed(), not a zero check: 0 is a meaningful boundary — "this key
			// signed nothing valid" — and must not be indistinguishable from the flag
			// being absent.
			var at *int64
			if cmd.Flags().Changed("at-seq") {
				at = &atSeq
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.HostRetireAuditKey(ctx, c, args[0], at, force)
			})
		},
	}
	cmd.Flags().Int64Var(&atSeq, "at-seq", 0,
		"retire at this sequence instead of the one the cluster derives (bypasses the "+
			"lagging-replica refusal; a value below what the host really signed is permanent)")
	cmd.Flags().BoolVar(&force, "force", false,
		"with --at-seq, permit a boundary BELOW the one the cluster derives — the "+
			"unrecoverable direction, since rows above it become permanent findings")
	return cmd
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
