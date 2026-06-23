package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/lxc"
)

// newCTCmd groups container subcommands.: by default these
// route through the daemon's gRPC service so they work cluster-wide
// from any operator workstation. The `--local` flag forces the
// host-local lxc-* shell-out path — useful during host bootstrap when
// litevirtd isn't running yet.
func newCTCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ct",
		Aliases: []string{"container"},
		Short:   "Manage LXC / OCI containers across the cluster",
	}
	cmd.AddCommand(
		newCTCreateCmd(),
		newCTStartCmd(),
		newCTStopCmd(),
		newCTRmCmd(),
		newCTLsCmd(),
		newCTExecCmd(),
		newCTPullCmd(),
	)
	return cmd
}

func newCTCreateCmd() *cobra.Command {
	var distro, release, arch string
	var template, host, project string
	var cpu, memMiB int
	var useLocal bool
	var networks []string
	var restart, restartDelay, restartWin string
	var restartMax int32
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new container (does not start it)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			nics, err := parseCTNetworks(networks)
			if err != nil {
				return err
			}
			if useLocal {
				r := lxc.NewLxcRunner()
				c, err := r.Create(cmd.Context(), lxc.CreateOpts{
					Name: args[0], Template: template, Distro: distro, Release: release, Arch: arch,
					CPULimit: cpu, MemoryMiB: memMiB, Network: toLxcNICs(nics),
				})
				if err != nil {
					return err
				}
				fmt.Printf("Created %s (%s, local)\n", c.Name, c.State)
				return nil
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				req := &pb.CreateContainerRequest{
					HostName: host,
					Name:     args[0], Template: template,
					Distro: distro, Release: release, Arch: arch,
					Cpu: int32(cpu), MemoryMib: int32(memMiB), Networks: nics,
					Project: project,
				}
				if restart != "" && restart != "none" {
					req.Restart = &pb.RestartPolicy{
						Condition:   restart,
						MaxAttempts: restartMax,
						Delay:       restartDelay,
						Window:      restartWin,
					}
				}
				ct, err := c.CreateContainer(ctx, req)
				if err != nil {
					return err
				}
				fmt.Printf("Created %s on %s (%s)\n", ct.Name, ct.HostName, ct.State)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&template, "template", "download", "lxc-create template name (or rootfs path)")
	cmd.Flags().StringVar(&distro, "distro", "alpine", "Distribution for download template")
	cmd.Flags().StringVar(&release, "release", "3.21", "Release for download template (must be currently published on the LXC image server)")
	cmd.Flags().StringVar(&arch, "arch", "amd64", "Architecture for download template")
	cmd.Flags().IntVar(&cpu, "cpu", 0, "CPU shares (0 = unlimited)")
	cmd.Flags().IntVar(&memMiB, "memory", 0, "Memory cap MiB (0 = unlimited)")
	cmd.Flags().StringArrayVar(&networks, "network", nil, "Attach a NIC: bridge=<br>[,name=eth0][,ip=10.0.0.5/24][,mac=AA:BB:..] (repeatable; default: lxcbr0)")
	cmd.Flags().StringVar(&host, "host", "", "Target host (default: the daemon you're connected to)")
	cmd.Flags().StringVar(&project, "project", "", "Tenancy project (default: _default)")
	cmd.Flags().BoolVar(&useLocal, "local", false, "Use the host-local lxc-* runtime instead of gRPC")
	cmd.Flags().StringVar(&restart, "restart", "", "Auto-restart policy: none | on-failure | always (default none). An operator `lv ct stop` is never auto-restarted; any other stop is treated as unexpected (containers have no stop reason).")
	cmd.Flags().Int32Var(&restartMax, "restart-max-attempts", 0, "Max restart attempts within the window (0 = unlimited)")
	cmd.Flags().StringVar(&restartDelay, "restart-delay", "", "Delay between restart attempts (e.g. 5s; default 5s)")
	cmd.Flags().StringVar(&restartWin, "restart-window", "", "Attempt-count window (e.g. 1h; default 1h)")
	return cmd
}

// parseCTNetworks turns repeated `--network key=val,..` specs into the proto
// ContainerNetwork list. bridge is required; name/ip/mac are optional.
func parseCTNetworks(specs []string) ([]*pb.ContainerNetwork, error) {
	var out []*pb.ContainerNetwork
	for _, spec := range specs {
		n := &pb.ContainerNetwork{}
		for _, kv := range strings.Split(spec, ",") {
			kv = strings.TrimSpace(kv)
			if kv == "" {
				continue
			}
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return nil, fmt.Errorf("invalid --network %q: want comma-separated key=value pairs (bridge=,name=,ip=,mac=)", spec)
			}
			switch key := strings.TrimSpace(k); key {
			case "bridge", "br":
				n.Bridge = strings.TrimSpace(v)
			case "name", "nic":
				n.Name = strings.TrimSpace(v)
			case "ip":
				n.Ip = strings.TrimSpace(v)
			case "mac":
				n.Mac = strings.TrimSpace(v)
			default:
				return nil, fmt.Errorf("invalid --network key %q (want bridge|name|ip|mac)", key)
			}
		}
		if n.Bridge == "" {
			return nil, fmt.Errorf("--network %q: bridge is required", spec)
		}
		out = append(out, n)
	}
	return out, nil
}

func toLxcNICs(nics []*pb.ContainerNetwork) []lxc.NetworkAttach {
	var out []lxc.NetworkAttach
	for _, n := range nics {
		out = append(out, lxc.NetworkAttach{Name: n.Name, Bridge: n.Bridge, IP: n.Ip, MAC: n.Mac})
	}
	return out
}

func newCTStartCmd() *cobra.Command {
	var host string
	var useLocal bool
	cmd := &cobra.Command{
		Use:   "start <name>",
		Short: "Start a stopped container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if useLocal {
				return lxc.NewLxcRunner().Start(cmd.Context(), args[0])
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.StartContainer(ctx, &pb.StartContainerRequest{HostName: host, Name: args[0]})
				return err
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Target host")
	cmd.Flags().BoolVar(&useLocal, "local", false, "Use the host-local runtime")
	return cmd
}

func newCTStopCmd() *cobra.Command {
	var host string
	var useLocal bool
	var timeout int
	cmd := &cobra.Command{
		Use:   "stop <name>",
		Short: "Stop a running container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if useLocal {
				return lxc.NewLxcRunner().Stop(cmd.Context(), args[0], timeout)
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.StopContainer(ctx, &pb.StopContainerRequest{
					HostName: host, Name: args[0], TimeoutSec: int32(timeout),
				})
				return err
			})
		},
	}
	cmd.Flags().IntVar(&timeout, "timeout", 30, "Seconds to wait before SIGKILL")
	cmd.Flags().StringVar(&host, "host", "", "Target host")
	cmd.Flags().BoolVar(&useLocal, "local", false, "Use the host-local runtime")
	return cmd
}

func newCTRmCmd() *cobra.Command {
	var host string
	var useLocal bool
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a stopped container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if useLocal {
				return lxc.NewLxcRunner().Delete(cmd.Context(), args[0])
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteContainer(ctx, &pb.DeleteContainerRequest{HostName: host, Name: args[0]})
				return err
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Target host")
	cmd.Flags().BoolVar(&useLocal, "local", false, "Use the host-local runtime")
	return cmd
}

func newCTLsCmd() *cobra.Command {
	var host string
	var useLocal bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List containers (cluster-wide by default; --host to filter)",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			defer w.Flush()
			if useLocal {
				r := lxc.NewLxcRunner()
				names, err := r.List(cmd.Context())
				if err != nil {
					return err
				}
				fmt.Fprintln(w, "NAME\tSTATE")
				for _, n := range names {
					st, _ := r.State(cmd.Context(), n)
					fmt.Fprintf(w, "%s\t%s\n", n, st)
				}
				return nil
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListContainers(ctx, &pb.ListContainersRequest{HostName: host})
				if err != nil {
					return err
				}
				fmt.Fprintln(w, "HOST\tNAME\tSTATE\tIMAGE\tCPU\tMEM")
				for _, ct := range resp.Containers {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\n",
						ct.HostName, ct.Name, ct.State, ct.Image, ct.CpuLimit, ct.MemoryMib)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Filter by host (default: all)")
	cmd.Flags().BoolVar(&useLocal, "local", false, "List the host-local runtime's containers (no daemon)")
	return cmd
}

func newCTExecCmd() *cobra.Command {
	var host string
	var useLocal bool
	cmd := &cobra.Command{
		Use:   "exec <name> -- <cmd> [args...]",
		Short: "Run a command inside a container",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if useLocal {
				res, err := lxc.NewLxcRunner().Exec(cmd.Context(), args[0], args[1:])
				if err != nil {
					return err
				}
				os.Stdout.Write(res.Stdout)
				os.Stderr.Write(res.Stderr)
				os.Exit(res.ExitCode)
				return nil
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				res, err := c.ExecContainer(ctx, &pb.ExecContainerRequest{
					HostName: host, Name: args[0], Argv: args[1:],
				})
				if err != nil {
					return err
				}
				os.Stdout.Write(res.Stdout)
				os.Stderr.Write(res.Stderr)
				os.Exit(int(res.ExitCode))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Target host")
	cmd.Flags().BoolVar(&useLocal, "local", false, "Use the host-local runtime")
	return cmd
}

func newCTPullCmd() *cobra.Command {
	var host string
	var useLocal, passwordStdin bool
	var dest, tag, username, password string
	cmd := &cobra.Command{
		Use:   "pull <oci-image>",
		Short: "Pull an OCI image and unpack as a rootfs (requires skopeo + umoci)",
		Long: "Pull an OCI image and unpack it into a rootfs.\n" +
			"With no --username, the daemon resolves a stored registry credential\n" +
			"(per-user, then global; see `lv registry`). Pass --username for an\n" +
			"ad-hoc authenticated pull — under --local this is the only credential\n" +
			"source, since there is no daemon to resolve stored credentials.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if dest == "" {
				return fmt.Errorf("--dest is required")
			}
			var pw string
			if username != "" {
				p, err := readRegistryPassword(password, passwordStdin)
				if err != nil {
					return err
				}
				pw = p
			}
			if useLocal {
				return lxc.PullOCI(cmd.Context(), lxc.PullOCIOptions{
					Image: args[0], Dest: dest, Tag: tag, Username: username, Password: pw,
				})
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.PullOCIImage(ctx, &pb.PullOCIImageRequest{
					HostName: host, Image: args[0], Dest: dest, Tag: tag,
					Username: username, Password: pw,
				})
				return err
			})
		},
	}
	cmd.Flags().StringVar(&dest, "dest", "", "Destination rootfs directory")
	cmd.Flags().StringVar(&tag, "tag", "", "Override image tag")
	cmd.Flags().StringVar(&host, "host", "", "Target host")
	cmd.Flags().BoolVar(&useLocal, "local", false, "Use the host-local runtime")
	cmd.Flags().StringVarP(&username, "username", "u", "", "registry username for an ad-hoc authenticated pull")
	cmd.Flags().StringVar(&password, "password", "", "registry password/token (prefer --password-stdin)")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the registry password from stdin")
	return cmd
}

// keep emptypb used (gRPC-generated stubs reference it transitively)
var _ = emptypb.Empty{}
