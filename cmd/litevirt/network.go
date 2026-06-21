package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Manage networks",
	}
	cmd.AddCommand(
		newNetworkLsCmd(),
		newNetworkInspectCmd(),
		newNetworkCreateCmd(),
		newNetworkRmCmd(),
	)
	return cmd
}

func newNetworkLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List networks",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListNetworks(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("list networks: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "NAME\tTYPE\tINTERFACE\tSUBNET\tGATEWAY\tDHCP\tVNI\tSTACK\tVMS\n")
				for _, n := range resp.Networks {
					dhcp := ""
					if n.Dhcp {
						dhcp = "yes"
					}
					vni := ""
					if n.Vni > 0 {
						vni = fmt.Sprintf("%d", n.Vni)
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n",
						n.Name, n.Type, n.Iface, n.Subnet, n.Gateway,
						dhcp, vni, n.StackName, n.VmCount,
					)
				}
				return w.Flush()
			})
		},
	}
}

func newNetworkInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <name>",
		Short: "Show network details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				ni, err := c.GetNetwork(ctx, &pb.GetNetworkRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("get network: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "Name:\t%s\n", ni.Name)
				fmt.Fprintf(w, "Type:\t%s\n", ni.Type)
				fmt.Fprintf(w, "Interface:\t%s\n", ni.Iface)
				if ni.Subnet != "" {
					fmt.Fprintf(w, "Subnet:\t%s\n", ni.Subnet)
				}
				if ni.Gateway != "" {
					fmt.Fprintf(w, "Gateway:\t%s\n", ni.Gateway)
				}
				if ni.Dhcp {
					fmt.Fprintf(w, "DHCP:\tyes\n")
				}
				if ni.Vni > 0 {
					fmt.Fprintf(w, "VNI:\t%d\n", ni.Vni)
				}
				if ni.StackName != "" {
					fmt.Fprintf(w, "Stack:\t%s\n", ni.StackName)
				}
				fmt.Fprintf(w, "VMs:\t%d\n", ni.VmCount)
				return w.Flush()
			})
		},
	}
}

func newNetworkCreateCmd() *cobra.Command {
	var (
		ntype      string
		iface      string
		vlan       int
		vni        int
		underlay   string
		subnet     string
		dhcp       bool
		pf         string
		spoofCheck bool
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a network",
		Long: `Create a standalone network.

Examples:
  lv network create mgmt --type bridge --interface br-mgmt
  lv network create backend --type isolated --subnet 172.16.0.0/24 --dhcp
  lv network create overlay --type vxlan --vni 3000 --underlay eth0
  lv network create fast --type sriov --pf enp4s0f0 --vlan 100`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				ni, err := c.CreateNetwork(ctx, &pb.CreateNetworkRequest{
					Name:       args[0],
					Type:       ntype,
					Iface:      iface,
					Vlan:       int32(vlan),
					Vni:        int32(vni),
					Underlay:   underlay,
					Subnet:     subnet,
					Dhcp:       dhcp,
					Pf:         pf,
					SpoofCheck: spoofCheck,
				})
				if err != nil {
					return fmt.Errorf("create network: %w", err)
				}

				fmt.Printf("Network %s created (type=%s)\n", ni.Name, ni.Type)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&ntype, "type", "bridge", "Network type: bridge | vxlan | isolated | sriov")
	cmd.Flags().StringVar(&iface, "interface", "", "Bridge/interface name on host")
	cmd.Flags().IntVar(&vlan, "vlan", 0, "VLAN tag")
	cmd.Flags().IntVar(&vni, "vni", 0, "VXLAN VNI")
	cmd.Flags().StringVar(&underlay, "underlay", "", "Underlay interface for VXLAN")
	cmd.Flags().StringVar(&subnet, "subnet", "", "Subnet CIDR (e.g. 172.16.0.0/24)")
	cmd.Flags().BoolVar(&dhcp, "dhcp", false, "Enable DHCP on this network")
	cmd.Flags().StringVar(&pf, "pf", "", "SR-IOV physical function")
	cmd.Flags().BoolVar(&spoofCheck, "spoof-check", false, "Enable SR-IOV spoof checking")
	return cmd
}

func newNetworkRmCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:     "rm <name>",
		Aliases: []string{"delete"},
		Short:   "Delete a network",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{
					Name:  args[0],
					Force: force,
				})
				if err != nil {
					return fmt.Errorf("delete network: %w", err)
				}

				fmt.Printf("Network %s deleted\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Delete even if VMs are attached")
	return cmd
}
