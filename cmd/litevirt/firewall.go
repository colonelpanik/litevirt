package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/firewall"
)

// newFirewallCmd shows the live nftables ruleset litevirt is managing,
// forces a reload from the daemon's reconciler, and manages the two non-NIC
// rule tiers (cluster / host), named ip sets, and the default-deny policy.
// (Per-NIC rules are managed via `lv sg`.)
func newFirewallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firewall",
		Short: "Inspect / reload / manage the litevirt distributed firewall",
	}
	cmd.AddCommand(
		newFirewallShowCmd(),
		newFirewallReloadCmd(),
		newFirewallClusterRuleCmd(),
		newFirewallHostRuleCmd(),
		newFirewallIPSetCmd(),
		newFirewallDefaultDenyCmd(),
	)
	return cmd
}

func newFirewallShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the current nftables ruleset for the litevirt-fw table",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := exec.CommandContext(cmd.Context(), "nft", "list", "table", "inet", firewall.TableName).CombinedOutput()
			if err != nil {
				return fmt.Errorf("nft list: %w: %s", err, string(out))
			}
			fmt.Print(string(out))
			return nil
		},
	}
}

func newFirewallReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Re-read security groups from cluster state and re-apply now",
		Long: `Forces the daemon's firewall reconciler to re-read security_groups +
sg_rules + vm_interfaces from Corrosion and atomically re-apply this
host's nftables ruleset. The reconciler still polls every 30s; this
command is for "I just changed a rule and want it live now".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				st, err := c.ReloadFirewall(ctx, &emptypb.Empty{})
				if err != nil {
					return err
				}
				fmt.Printf("Reloaded on %s\n", st.HostName)
				fmt.Printf("  rules total:    %d\n", st.RulesTotal)
				fmt.Printf("  security groups:%d\n", st.SecurityGroups)
				fmt.Printf("  NICs bound:     %d\n", st.NicsBound)
				if st.LastError != "" {
					fmt.Printf("  last error:     %s\n", st.LastError)
				}
				if st.LastAppliedAt != "" {
					fmt.Printf("  last applied:   %s\n", st.LastAppliedAt)
				}
				return nil
			})
		},
	}
}

// ruleFlags is the shared flag set for cluster-rule / host-rule add.
type ruleFlags struct {
	direction, proto, port, cidr, action, comment string
	priority                                      int
}

func (rf *ruleFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&rf.direction, "direction", "ingress", "ingress | egress")
	cmd.Flags().StringVar(&rf.proto, "proto", "all", "tcp | udp | icmp | all")
	cmd.Flags().StringVar(&rf.port, "port", "", "port or range (e.g. 80 or 8000-9000)")
	cmd.Flags().StringVar(&rf.cidr, "cidr", "", "source/dest CIDR or @ipset-name (default: any)")
	cmd.Flags().StringVar(&rf.action, "action", "accept", "accept | drop | reject")
	cmd.Flags().StringVar(&rf.comment, "comment", "", "human-readable note rendered on the rule")
	cmd.Flags().IntVar(&rf.priority, "priority", 100, "lower runs first")
}

func (rf *ruleFlags) pb() *pb.FirewallRule {
	return &pb.FirewallRule{
		Direction: rf.direction, Proto: rf.proto, Port: rf.port, Cidr: rf.cidr,
		Action: rf.action, Priority: int32(rf.priority), Comment: rf.comment,
	}
}

func printRules(rules []*pb.FirewallRule, withHost bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if withHost {
		fmt.Fprintln(w, "ID\tHOST\tDIR\tPROTO\tPORT\tCIDR\tACTION\tPRIO\tSTACK")
	} else {
		fmt.Fprintln(w, "ID\tDIR\tPROTO\tPORT\tCIDR\tACTION\tPRIO\tSTACK")
	}
	for _, r := range rules {
		if withHost {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				r.Id, r.HostName, r.Direction, r.Proto, r.Port, r.Cidr, r.Action, strconv.Itoa(int(r.Priority)), r.StackName)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				r.Id, r.Direction, r.Proto, r.Port, r.Cidr, r.Action, strconv.Itoa(int(r.Priority)), r.StackName)
		}
	}
	return w.Flush()
}

// ── cluster-rule ──

func newFirewallClusterRuleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cluster-rule", Short: "Manage cluster-tier rules (apply to every NIC on every host)"}

	var rf ruleFlags
	add := &cobra.Command{
		Use:   "add",
		Short: "Add a cluster-tier firewall rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				r, err := c.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: rf.pb()})
				if err != nil {
					return err
				}
				fmt.Printf("Added cluster rule %s\n", r.Id)
				return nil
			})
		},
	}
	rf.register(add)

	ls := &cobra.Command{
		Use:   "ls",
		Short: "List cluster-tier rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListClusterFirewallRules(ctx, &pb.ListClusterFirewallRulesRequest{})
				if err != nil {
					return err
				}
				return printRules(resp.Rules, false)
			})
		},
	}

	rm := &cobra.Command{
		Use:   "rm <id>",
		Short: "Remove a cluster-tier rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteClusterFirewallRule(ctx, &pb.DeleteClusterFirewallRuleRequest{Id: args[0]})
				if err == nil {
					fmt.Printf("Removed cluster rule %s\n", args[0])
				}
				return err
			})
		},
	}
	cmd.AddCommand(add, ls, rm)
	return cmd
}

// ── host-rule ──

func newFirewallHostRuleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "host-rule", Short: "Manage host-tier rules (apply to every NIC on one host)"}

	var rf ruleFlags
	var host string
	add := &cobra.Command{
		Use:   "add",
		Short: "Add a host-tier firewall rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("--host is required")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				rule := rf.pb()
				rule.HostName = host
				r, err := c.CreateHostFirewallRule(ctx, &pb.CreateHostFirewallRuleRequest{Rule: rule})
				if err != nil {
					return err
				}
				fmt.Printf("Added host rule %s on %s\n", r.Id, host)
				return nil
			})
		},
	}
	rf.register(add)
	add.Flags().StringVar(&host, "host", "", "host the rule applies to (required)")

	var lsHost string
	ls := &cobra.Command{
		Use:   "ls",
		Short: "List host-tier rules (optionally for one host)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListHostFirewallRules(ctx, &pb.ListHostFirewallRulesRequest{HostName: lsHost})
				if err != nil {
					return err
				}
				return printRules(resp.Rules, true)
			})
		},
	}
	ls.Flags().StringVar(&lsHost, "host", "", "filter to one host (default: all)")

	rm := &cobra.Command{
		Use:   "rm <id>",
		Short: "Remove a host-tier rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteHostFirewallRule(ctx, &pb.DeleteHostFirewallRuleRequest{Id: args[0]})
				if err == nil {
					fmt.Printf("Removed host rule %s\n", args[0])
				}
				return err
			})
		},
	}
	cmd.AddCommand(add, ls, rm)
	return cmd
}

// ── ipset ──

func newFirewallIPSetCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ipset", Short: "Manage named CIDR lists (reference with cidr=@<name>)"}

	var cidrs []string
	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Create a named ip set",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				s, err := c.CreateIpSet(ctx, &pb.CreateIpSetRequest{Name: args[0], Cidrs: cidrs})
				if err != nil {
					return err
				}
				fmt.Printf("Created ip set %s (%s)\n", s.Name, s.Id)
				return nil
			})
		},
	}
	add.Flags().StringArrayVar(&cidrs, "cidr", nil, "CIDR to include (repeatable)")

	ls := &cobra.Command{
		Use:   "ls",
		Short: "List ip sets",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListIpSets(ctx, &pb.ListIpSetsRequest{})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "ID\tNAME\tCIDRS\tSTACK")
				for _, s := range resp.Ipsets {
					cidrStr := ""
					for i, c := range s.Cidrs {
						if i > 0 {
							cidrStr += ","
						}
						cidrStr += c
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Id, s.Name, cidrStr, s.StackName)
				}
				return w.Flush()
			})
		},
	}

	rm := &cobra.Command{
		Use:   "rm <id>",
		Short: "Remove an ip set",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteIpSet(ctx, &pb.DeleteIpSetRequest{Id: args[0]})
				if err == nil {
					fmt.Printf("Removed ip set %s\n", args[0])
				}
				return err
			})
		},
	}
	cmd.AddCommand(add, ls, rm)
	return cmd
}

// ── default-deny ──

func newFirewallDefaultDenyCmd() *cobra.Command {
	var scope string
	cmd := &cobra.Command{
		Use:   "default-deny <on|off>",
		Short: "Set the default forward policy (deny = drop anything not explicitly accepted)",
		Long: `Sets the default-deny policy. With no --scope it sets the cluster-wide
default; pass --scope <host> to override one host. Reply traffic is always
allowed (conntrack established/related); the policy applies to new connections.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var deny bool
			switch args[0] {
			case "on", "true", "deny":
				deny = true
			case "off", "false", "accept":
				deny = false
			default:
				return fmt.Errorf("argument must be on|off")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.SetFirewallDefault(ctx, &pb.SetFirewallDefaultRequest{Scope: scope, DefaultDeny: deny})
				if err == nil {
					sc := scope
					if sc == "" {
						sc = "cluster"
					}
					fmt.Printf("default-deny=%v for %s\n", deny, sc)
				}
				return err
			})
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "", "host to scope the policy to (default: cluster-wide)")
	return cmd
}
