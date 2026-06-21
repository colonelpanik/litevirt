package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/daemon"
)

// newSGCmd groups security-group subcommands. These mutate the cluster
// state via Corrosion directly (matching the pattern used by other
// host-local maintenance commands like backup-repo). The reconciler on
// each host watches the same tables and re-applies its firewall plan
// when rules change — see internal/firewall/reconciler.go.
func newSGCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sg",
		Aliases: []string{"security-group"},
		Short:   "Manage security groups (distributed firewall)",
	}
	cmd.AddCommand(
		newSGCreateCmd(),
		newSGListCmd(),
		newSGDeleteCmd(),
		newSGRuleAddCmd(),
		newSGRuleListCmd(),
		newSGRuleRemoveCmd(),
		newSGBindCmd(),
	)
	return cmd
}

// newSGBindCmd attaches one or more security groups to a VM's NIC at
// runtime. The next firewall reconciler tick on the owning host
// rerenders nftables — or run `lv firewall reload` to force.
func newSGBindCmd() *cobra.Command {
	var network string
	var sgNames []string
	cmd := &cobra.Command{
		Use:   "bind <vm>",
		Short: "Bind security groups to a VM's NIC",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
					VmName: args[0], NetworkName: network, SecurityGroups: sgNames,
				}); err != nil {
					return err
				}
				fmt.Printf("Bound %v on %s/%s\n", sgNames, args[0], network)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&network, "network", "", "Compose network name (required; matches vm_interfaces.network_name)")
	cmd.Flags().StringSliceVar(&sgNames, "sg", nil, "Security group name (repeatable; empty list clears bindings)")
	cmd.MarkFlagRequired("network") //nolint:errcheck
	return cmd
}

// openClusterDB opens the local Corrosion database. Used by every sg
// subcommand because they all just CRUD into Corrosion.
func openClusterDB() (*corrosion.Client, error) {
	cfg, err := daemon.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("load config (must run on a litevirt node): %w", err)
	}
	return corrosion.NewLocalClient(cfg.DataDir, cfg.HostName)
}

func newSGCreateCmd() *cobra.Command {
	var stack string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a security group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openClusterDB()
			if err != nil {
				return err
			}
			defer db.Close()
			id, err := newID()
			if err != nil {
				return err
			}
			if err := corrosion.InsertSecurityGroup(cmd.Context(), db, corrosion.SecurityGroup{
				ID: id, Name: args[0], StackName: stack,
			}); err != nil {
				return err
			}
			fmt.Printf("Created security group %q (id=%s)\n", args[0], id)
			return nil
		},
	}
	cmd.Flags().StringVar(&stack, "stack", "", "Limit the SG to one stack (default: cluster-wide)")
	return cmd
}

func newSGListCmd() *cobra.Command {
	var stack string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List security groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openClusterDB()
			if err != nil {
				return err
			}
			defer db.Close()
			sgs, err := corrosion.ListSecurityGroups(cmd.Context(), db, stack)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tSTACK\tCREATED")
			for _, sg := range sgs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", sg.ID, sg.Name, sg.StackName, sg.CreatedAt)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&stack, "stack", "", "Filter to one stack")
	return cmd
}

func newSGDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>",
		Short: "Delete a security group (and its rules)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openClusterDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if err := corrosion.DeleteSGRules(cmd.Context(), db, args[0]); err != nil {
				return err
			}
			if err := corrosion.DeleteSecurityGroup(cmd.Context(), db, args[0]); err != nil {
				return err
			}
			fmt.Printf("Deleted security group %s\n", args[0])
			return nil
		},
	}
}

func newSGRuleAddCmd() *cobra.Command {
	var direction, proto, port, cidr, action string
	var priority int
	cmd := &cobra.Command{
		Use:   "rule-add <sg-id>",
		Short: "Add a rule to a security group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openClusterDB()
			if err != nil {
				return err
			}
			defer db.Close()
			id, err := newID()
			if err != nil {
				return err
			}
			if err := corrosion.InsertSGRule(cmd.Context(), db, corrosion.SGRule{
				ID: id, SGID: args[0],
				Direction: direction, Proto: proto, PortRange: port,
				CIDR: cidr, Action: action, Priority: priority,
			}); err != nil {
				return err
			}
			fmt.Printf("Added rule %s\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&direction, "direction", "ingress", "ingress | egress")
	cmd.Flags().StringVar(&proto, "proto", "all", "tcp | udp | icmp | all")
	cmd.Flags().StringVar(&port, "port", "", "port or range (e.g. 80 or 8000-9000)")
	cmd.Flags().StringVar(&cidr, "cidr", "", "source/dest CIDR or @ipset-name (default: any)")
	cmd.Flags().StringVar(&action, "action", "accept", "accept | drop | reject")
	cmd.Flags().IntVar(&priority, "priority", 100, "lower runs first")
	return cmd
}

func newSGRuleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rule-ls <sg-id>",
		Short: "List rules in a security group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openClusterDB()
			if err != nil {
				return err
			}
			defer db.Close()
			rules, err := corrosion.ListSGRules(cmd.Context(), db, args[0])
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tDIR\tPROTO\tPORT\tCIDR\tACTION\tPRIO")
			for _, r := range rules {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.ID, r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, strconv.Itoa(r.Priority))
			}
			return w.Flush()
		},
	}
}

func newSGRuleRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rule-rm <rule-id>",
		Short: "Remove a single rule from a security group (id from `sg rule-ls`)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openClusterDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if err := corrosion.DeleteSGRule(cmd.Context(), db, args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed rule %s\n", args[0])
			return nil
		},
	}
}

// newID returns a random hex id for SGs and rules. We use raw 8-byte
// random rather than UUIDs to keep ids short in CLI output.
func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
