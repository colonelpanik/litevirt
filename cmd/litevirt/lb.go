package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newLBCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lb",
		Short: "Manage load balancers",
	}
	cmd.AddCommand(
		newLBLsCmd(),
		newLBInspectCmd(),
		newLBCreateCmd(),
		newLBDeleteCmd(),
		newLBUpdateCmd(),
		newLBStatsCmd(),
		newLBDrainCmd(),
		newLBDisableCmd(),
		newLBEnableCmd(),
	)
	return cmd
}

func newLBLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List load balancers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListLoadBalancers(ctx, nil)
				if err != nil {
					return fmt.Errorf("list LBs: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "NAME\tVIP\tALGORITHM\tSTATE\tBACKENDS\tSTACK\n")
				for _, lb := range resp.Lbs {
					stack := lb.StackName
					if stack == "" {
						stack = "-"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
						lb.Name, lb.Vip, lb.Algorithm, lb.State, len(lb.Backends), stack)
				}
				return w.Flush()
			})
		},
	}
}

func newLBInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <name>",
		Short: "Show load balancer details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				lb, err := c.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("inspect LB: %w", err)
				}

				fmt.Printf("Name:       %s\n", lb.Name)
				if lb.StackName != "" {
					fmt.Printf("Stack:      %s\n", lb.StackName)
				}
				fmt.Printf("VIP:        %s\n", lb.Vip)
				fmt.Printf("Algorithm:  %s\n", lb.Algorithm)
				fmt.Printf("State:      %s\n", lb.State)
				if len(lb.LbHosts) > 0 {
					fmt.Printf("Hosts:      %s\n", strings.Join(lb.LbHosts, ", "))
				}
				if len(lb.Ports) > 0 {
					fmt.Printf("Ports:\n")
					for _, p := range lb.Ports {
						proto := p.Protocol
						if proto == "" {
							proto = "tcp"
						}
						fmt.Printf("  - %d -> %d/%s\n", p.Listen, p.Target, proto)
					}
				}
				fmt.Printf("Backends:   %d\n", len(lb.Backends))
				for _, b := range lb.Backends {
					name := b.VmName
					if name == "" {
						name = b.Address
					}
					fmt.Printf("  - %s %s [%s]\n", name, b.Address, b.Status)
				}
				return nil
			})
		},
	}
}

func newLBDisableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable <lb-name> --backend <vm-name>",
		Short: "Disable a backend (for maintenance)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			backend, _ := cmd.Flags().GetString("backend")
			if backend == "" {
				return fmt.Errorf("--backend required")
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DisableBackend(ctx, &pb.DisableBackendRequest{
					LbName:  args[0],
					Backend: backend,
				})
				if err != nil {
					return fmt.Errorf("disable backend: %w", err)
				}

				fmt.Printf("Backend %s disabled in LB %s\n", backend, args[0])
				return nil
			})
		},
	}
	cmd.Flags().String("backend", "", "Backend VM name")
	return cmd
}

func newLBEnableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable <lb-name> --backend <vm-name>",
		Short: "Re-enable a disabled backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			backend, _ := cmd.Flags().GetString("backend")
			if backend == "" {
				return fmt.Errorf("--backend required")
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.EnableBackend(ctx, &pb.EnableBackendRequest{
					LbName:  args[0],
					Backend: backend,
				})
				if err != nil {
					return fmt.Errorf("enable backend: %w", err)
				}

				fmt.Printf("Backend %s enabled in LB %s\n", backend, args[0])
				return nil
			})
		},
	}
	cmd.Flags().String("backend", "", "Backend VM name")
	return cmd
}

// parsePort parses "listen:target/protocol" (e.g. "80:8080/tcp") into an LBPort.
func parsePort(s string) (*pb.LBPort, error) {
	proto := "tcp"
	if idx := strings.Index(s, "/"); idx >= 0 {
		proto = s[idx+1:]
		s = s[:idx]
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port format %q (expected listen:target[/protocol])", s)
	}
	listen, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid listen port %q: %v", parts[0], err)
	}
	target, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid target port %q: %v", parts[1], err)
	}
	return &pb.LBPort{Listen: int32(listen), Target: int32(target), Protocol: proto}, nil
}

// parseBackend parses "name=address" into an LBBackendAddress.
func parseBackend(s string) (*pb.LBBackendAddress, error) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid backend format %q (expected name=address)", s)
	}
	return &pb.LBBackendAddress{Name: parts[0], Address: parts[1]}, nil
}

func newLBCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a standalone load balancer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vip, _ := cmd.Flags().GetString("vip")
			algorithm, _ := cmd.Flags().GetString("algorithm")
			portStrs, _ := cmd.Flags().GetStringSlice("port")
			hosts, _ := cmd.Flags().GetStringSlice("host")
			backendStrs, _ := cmd.Flags().GetStringSlice("backend")
			vmBackends, _ := cmd.Flags().GetStringSlice("vm-backend")

			if vip == "" {
				return fmt.Errorf("--vip required")
			}
			if len(portStrs) == 0 {
				return fmt.Errorf("at least one --port required")
			}

			var ports []*pb.LBPort
			for _, p := range portStrs {
				port, err := parsePort(p)
				if err != nil {
					return err
				}
				ports = append(ports, port)
			}

			var backends []*pb.LBBackendAddress
			for _, b := range backendStrs {
				be, err := parseBackend(b)
				if err != nil {
					return err
				}
				backends = append(backends, be)
			}

			if len(backends) == 0 && len(vmBackends) == 0 {
				return fmt.Errorf("at least one --backend or --vm-backend required")
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.CreateLoadBalancer(ctx, &pb.CreateLBRequest{
					Name:       args[0],
					Vip:        vip,
					Algorithm:  algorithm,
					Ports:      ports,
					Hosts:      hosts,
					Backends:   backends,
					VmBackends: vmBackends,
				})
				if err != nil {
					return fmt.Errorf("create LB: %w", err)
				}

				fmt.Printf("Created load balancer %s (VIP: %s, algorithm: %s, backends: %d)\n",
					resp.Name, resp.Vip, resp.Algorithm, len(resp.Backends))
				return nil
			})
		},
	}
	cmd.Flags().String("vip", "", "Virtual IP with CIDR (e.g. 10.0.100.50/24)")
	cmd.Flags().String("algorithm", "roundrobin", "Algorithm: roundrobin | leastconn | source")
	cmd.Flags().StringSlice("port", nil, "Port mapping listen:target[/protocol] (repeatable)")
	cmd.Flags().StringSlice("host", nil, "Host to run LB on (repeatable)")
	cmd.Flags().StringSlice("backend", nil, "Backend name=address (repeatable)")
	cmd.Flags().StringSlice("vm-backend", nil, "VM name to use as backend (repeatable)")
	return cmd
}

func newLBDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a load balancer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteLoadBalancer(ctx, &pb.DeleteLBRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("delete LB: %w", err)
				}

				fmt.Printf("Deleted load balancer %s\n", args[0])
				return nil
			})
		},
	}
}

func newLBUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update load balancer config (zero-downtime)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			algorithm, _ := cmd.Flags().GetString("algorithm")
			vip, _ := cmd.Flags().GetString("vip")
			addBackendStrs, _ := cmd.Flags().GetStringSlice("add-backend")
			removeBackends, _ := cmd.Flags().GetStringSlice("remove-backend")
			addVMBackends, _ := cmd.Flags().GetStringSlice("add-vm-backend")
			removeVMBackends, _ := cmd.Flags().GetStringSlice("remove-vm-backend")
			portStrs, _ := cmd.Flags().GetStringSlice("port")
			hosts, _ := cmd.Flags().GetStringSlice("host")

			var addBackends []*pb.LBBackendAddress
			for _, b := range addBackendStrs {
				be, err := parseBackend(b)
				if err != nil {
					return err
				}
				addBackends = append(addBackends, be)
			}

			var ports []*pb.LBPort
			for _, p := range portStrs {
				port, err := parsePort(p)
				if err != nil {
					return err
				}
				ports = append(ports, port)
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{
					Name:             args[0],
					Vip:              vip,
					Algorithm:        algorithm,
					Ports:            ports,
					Hosts:            hosts,
					AddBackends:      addBackends,
					RemoveBackends:   removeBackends,
					AddVmBackends:    addVMBackends,
					RemoveVmBackends: removeVMBackends,
				})
				if err != nil {
					return fmt.Errorf("update LB: %w", err)
				}

				fmt.Printf("Updated load balancer %s (VIP: %s, algorithm: %s, backends: %d)\n",
					resp.Name, resp.Vip, resp.Algorithm, len(resp.Backends))
				return nil
			})
		},
	}
	cmd.Flags().String("algorithm", "", "Change algorithm")
	cmd.Flags().String("vip", "", "Change VIP")
	cmd.Flags().StringSlice("add-backend", nil, "Add backend name=address (repeatable)")
	cmd.Flags().StringSlice("remove-backend", nil, "Remove backend by name (repeatable)")
	cmd.Flags().StringSlice("add-vm-backend", nil, "Add VM backend by name (repeatable)")
	cmd.Flags().StringSlice("remove-vm-backend", nil, "Remove VM backend by name (repeatable)")
	cmd.Flags().StringSlice("port", nil, "Replace ports listen:target[/protocol] (repeatable)")
	cmd.Flags().StringSlice("host", nil, "Replace hosts (repeatable)")
	return cmd
}

func newLBStatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats <name>",
		Short: "Show live backend metrics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.LBStats(ctx, &pb.LBStatsRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("lb stats: %w", err)
				}

				fmt.Printf("Load Balancer: %s\n\n", resp.Name)

				if len(resp.Frontends) > 0 {
					fmt.Println("Frontends:")
					w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
					fmt.Fprintf(w, "  SESSIONS\tTOTAL\tBYTES IN\tBYTES OUT\tRATE\n")
					for _, f := range resp.Frontends {
						fmt.Fprintf(w, "  %d\t%d\t%s\t%s\t%d/s\n",
							f.CurrentSessions, f.TotalSessions,
							formatBytes(f.BytesIn), formatBytes(f.BytesOut),
							f.RequestRate)
					}
					w.Flush()
					fmt.Println()
				}

				if len(resp.Backends) > 0 {
					fmt.Println("Backends:")
					w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
					fmt.Fprintf(w, "  NAME\tSTATUS\tSESSIONS\tTOTAL\tRATE\tBYTES IN\tBYTES OUT\tERR\tRESP(ms)\n")
					for _, b := range resp.Backends {
						fmt.Fprintf(w, "  %s\t%s\t%d\t%d\t%d/s\t%s\t%s\t%d\t%d\n",
							b.Name, b.Status,
							b.CurrentSessions, b.TotalSessions,
							b.RequestRate,
							formatBytes(b.BytesIn), formatBytes(b.BytesOut),
							b.ErrorConn+b.ErrorResp,
							b.AvgResponseMs)
					}
					w.Flush()
				}

				return nil
			})
		},
	}
}

func newLBDrainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drain <name> --backend <vm>",
		Short: "Graceful drain (finish existing connections)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			backend, _ := cmd.Flags().GetString("backend")
			if backend == "" {
				return fmt.Errorf("--backend required")
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.DrainBackend(ctx, &pb.DrainBackendRequest{
					LbName:  args[0],
					Backend: backend,
				})
				if err != nil {
					return fmt.Errorf("drain backend: %w", err)
				}

				fmt.Printf("Backend %s is %s (active connections: %d)\n",
					backend, resp.Status, resp.ActiveConnections)
				return nil
			})
		},
	}
	cmd.Flags().String("backend", "", "Backend name to drain")
	return cmd
}
