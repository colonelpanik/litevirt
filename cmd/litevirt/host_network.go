package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// lv host network — declarative host wiring (bridges, bonds, VLANs, NIC
// addressing) rendered by the OWNING host into one litevirt-managed netplan
// file behind a journaled apply-with-rollback. The flow is deliberately
// two-step: `set`/`rm` record intent, `plan` shows exactly what would change,
// `apply` runs it behind the connectivity confirm.
func newHostNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Configure host bridges, bonds, VLANs and NIC addressing (netplan-managed)",
	}
	cmd.AddCommand(
		newHostNetworkLsCmd(),
		newHostNetworkSetCmd(),
		newHostNetworkPlanCmd(),
		newHostNetworkApplyCmd(),
		newHostNetworkRmCmd(),
	)
	return cmd
}

func newHostNetworkLsCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List host network intents (cluster-wide by default)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListHostNetworks(ctx, &pb.ListHostNetworksRequest{HostName: host})
				if err != nil {
					return fmt.Errorf("list host networks: %w", err)
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "HOST\tNAME\tKIND\tMEMBERS\tSTATE\tGEN\tERROR\n")
				for _, n := range resp.Networks {
					detail := strings.Join(n.Members, ",")
					if n.Kind == "vlan" {
						detail = fmt.Sprintf("%s.%d", n.VlanLink, n.VlanId)
					}
					if detail == "" {
						detail = "-"
					}
					errCol := n.LastError
					if errCol == "" {
						errCol = "-"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
						n.HostName, n.Name, n.Kind, detail, n.State, n.Generation, errCol)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "only this host's intents")
	return cmd
}

func newHostNetworkSetCmd() *cobra.Command {
	var (
		host, kind, vlanLink            string
		members, addresses, nameservers []string
		gateway, gateway6               string
		bondMode, lacpRate, hashPolicy  string
		vlanID, mtu                     int
		dhcp4, dhcp6                    bool
	)
	cmd := &cobra.Command{
		Use:   "set <interface>",
		Short: "Record (or edit) one interface intent — nothing changes until apply",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("--host is required (the node whose wiring this describes)")
			}
			addressing := ""
			if dhcp4 || dhcp6 || len(addresses) > 0 || gateway != "" || gateway6 != "" || len(nameservers) > 0 {
				blob, err := json.Marshal(map[string]interface{}{
					"dhcp4": dhcp4, "dhcp6": dhcp6,
					"addresses": addresses, "gateway": gateway, "gateway6": gateway6,
					"nameservers": nameservers,
				})
				if err != nil {
					return err
				}
				addressing = string(blob)
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				n, err := c.UpsertHostNetwork(ctx, &pb.UpsertHostNetworkRequest{Network: &pb.HostNetwork{
					HostName: host, Name: args[0], Kind: kind,
					Members: members, VlanId: int32(vlanID), VlanLink: vlanLink,
					Addressing: addressing, Mtu: int32(mtu),
					BondMode: bondMode, LacpRate: lacpRate, HashPolicy: hashPolicy,
				}})
				if err != nil {
					return fmt.Errorf("record intent: %w", err)
				}
				fmt.Printf("Recorded %s/%s (%s), state %s — run `lv host network plan --host %s` then `apply`\n",
					n.HostName, n.Name, n.Kind, n.State, n.HostName)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "the host this interface belongs to (required)")
	cmd.Flags().StringVar(&kind, "kind", "bridge", "bridge | bond | vlan | ethernet")
	cmd.Flags().StringSliceVar(&members, "member", nil, "member interface (repeatable; bridge/bond)")
	cmd.Flags().IntVar(&vlanID, "vlan-id", 0, "VLAN id 1..4094 (kind=vlan)")
	cmd.Flags().StringVar(&vlanLink, "vlan-link", "", "parent interface (kind=vlan)")
	cmd.Flags().BoolVar(&dhcp4, "dhcp4", false, "enable DHCPv4")
	cmd.Flags().BoolVar(&dhcp6, "dhcp6", false, "enable DHCPv6")
	cmd.Flags().StringSliceVar(&addresses, "address", nil, "static address CIDR (repeatable, v4 or v6)")
	cmd.Flags().StringVar(&gateway, "gateway", "", "IPv4 default gateway")
	cmd.Flags().StringVar(&gateway6, "gateway6", "", "IPv6 default gateway")
	cmd.Flags().StringSliceVar(&nameservers, "nameserver", nil, "DNS server (repeatable)")
	cmd.Flags().IntVar(&mtu, "mtu", 0, "MTU (0 = default)")
	cmd.Flags().StringVar(&bondMode, "bond-mode", "", "bond mode (default active-backup; 802.3ad for LACP)")
	cmd.Flags().StringVar(&lacpRate, "lacp-rate", "", "LACP rate (slow|fast)")
	cmd.Flags().StringVar(&hashPolicy, "hash-policy", "", "bond transmit hash policy (e.g. layer3+4)")
	return cmd
}

func newHostNetworkPlanCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Show exactly what apply would change on a host (writes nothing)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("--host is required")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				p, err := c.PlanHostNetwork(ctx, &pb.PlanHostNetworkRequest{HostName: host})
				if err != nil {
					return fmt.Errorf("plan: %w", err)
				}
				if len(p.Conflicts) > 0 {
					fmt.Println("CONFLICTS (apply will refuse):")
					for iface, file := range p.Conflicts {
						fmt.Printf("  %s is already defined by %s\n", iface, file)
					}
				}
				if p.CutoffReason != "" {
					fmt.Printf("CUTOFF RISK: %s\n  apply will refuse without --force-interface %s\n",
						p.CutoffReason, p.ClusterInterface)
				}
				if p.NoOp {
					fmt.Println("No changes: the rendered configuration matches the file on the host.")
					return nil
				}
				fmt.Printf("--- current (%s)\n%s\n--- rendered\n%s", host, orEmptyFile(p.Current), p.Rendered)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "the host to plan (required)")
	return cmd
}

func orEmptyFile(s string) string {
	if s == "" {
		return "(no litevirt-managed netplan file yet)\n"
	}
	return s
}

func newHostNetworkApplyCmd() *cobra.Command {
	var host, forceInterface string
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Render and apply a host's intents behind the timed-rollback confirm",
		Long: "Applies the rendered netplan file on the host via `netplan try`: the change is\n" +
			"reverted — kernel-side, even if the daemon dies — unless the host confirms its own\n" +
			"connectivity (advertise address still assigned, own gRPC listener answering, prior\n" +
			"default gateway still reachable). A plan that touches the interface carrying the\n" +
			"cluster LAN refuses unless --force-interface NAMES that interface.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("--host is required")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.ApplyHostNetwork(ctx, &pb.ApplyHostNetworkRequest{
					HostName: host, ForceInterface: forceInterface,
				}); err != nil {
					return fmt.Errorf("apply: %w", err)
				}
				fmt.Printf("Applied and confirmed on %s\n", host)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "the host to apply (required)")
	cmd.Flags().StringVar(&forceInterface, "force-interface", "",
		"confirm touching the cluster-LAN interface by naming it (see plan output)")
	return cmd
}

func newHostNetworkRmCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "rm <interface>",
		Short: "Remove one interface intent (takes effect on the next apply)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("--host is required")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteHostNetwork(ctx, &pb.DeleteHostNetworkRequest{
					HostName: host, Name: args[0],
				}); err != nil {
					return fmt.Errorf("remove intent: %w", err)
				}
				fmt.Printf("Removed intent %s/%s — the interface goes away on the next `lv host network apply`\n",
					host, args[0])
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "the host owning the intent (required)")
	return cmd
}
