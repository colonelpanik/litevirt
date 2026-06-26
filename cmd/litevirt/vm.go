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

func newRunCmd() *cobra.Command {
	var (
		name         string
		cpu          int32
		memory       int32
		minMemory    int32
		maxMemory    int32
		image        string
		disk         string
		host         string
		onboot       bool
		startupOrder int32
		startDelay   int32
		stopDelay    int32
		restart      string
		restartMax   int32
		restartDelay string
		restartWin   string
		secureBoot   bool
		tpm          bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Create and start a VM",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				spec := &pb.VMSpec{
					Name:          name,
					Image:         image,
					Cpu:           cpu,
					MemoryMib:     memory,
					MinMemoryMib:  minMemory,
					MaxMemoryMib:  maxMemory,
					Machine:       "q35",
					Firmware:      "uefi",
					GuestAgent:    true,
					Onboot:        onboot,
					StartupOrder:  startupOrder,
					StartDelaySec: startDelay,
					StopDelaySec:  stopDelay,
					SecureBoot:    secureBoot,
					Tpm:           tpm,
				}
				if disk != "" {
					spec.Disks = []*pb.DiskSpec{{Name: "root", Size: disk, Bus: "virtio"}}
				}
				if host != "" {
					spec.Placement = &pb.PlacementSpec{Host: host}
				}
				if restart != "" && restart != "none" {
					spec.Restart = &pb.RestartPolicy{
						Condition:   restart,
						MaxAttempts: restartMax,
						Delay:       restartDelay,
						Window:      restartWin,
					}
				}

				vm, err := c.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec})
				if err != nil {
					return fmt.Errorf("create VM: %w", err)
				}

				fmt.Printf("VM %s created on %s (state: %s)\n", vm.Name, vm.HostName, vm.State)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "VM name (required)")
	cmd.Flags().Int32Var(&cpu, "cpu", 2, "Number of vCPUs")
	cmd.Flags().Int32Var(&memory, "memory", 4096, "Memory in MiB (boot allocation)")
	cmd.Flags().Int32Var(&minMemory, "min-mem", 0, "Minimum memory in MiB the balloon may reclaim to (0 = none)")
	cmd.Flags().Int32Var(&maxMemory, "max-mem", 0, "Maximum memory in MiB the guest may balloon up to (0 = fixed at --memory)")
	cmd.Flags().StringVar(&image, "image", "", "Base image name")
	cmd.Flags().StringVar(&disk, "disk", "20G", "Root disk size")
	cmd.Flags().StringVar(&host, "host", "", "Target host")
	cmd.Flags().BoolVar(&onboot, "onboot", false, "Start this VM automatically when its host boots")
	cmd.Flags().Int32Var(&startupOrder, "startup-order", 0, "Autostart order (lower starts first)")
	cmd.Flags().Int32Var(&startDelay, "start-delay", 0, "Seconds to wait after starting this VM before the next")
	cmd.Flags().Int32Var(&stopDelay, "stop-delay", 0, "Seconds to wait after stopping this VM during ordered shutdown")
	cmd.Flags().StringVar(&restart, "restart", "", "Auto-restart policy: none | on-failure | always (default none). A clean guest shutdown or `lv stop` is never auto-restarted; only unexpected stops (crash/fence) are.")
	cmd.Flags().Int32Var(&restartMax, "restart-max-attempts", 0, "Max restart attempts within the window (0 = unlimited)")
	cmd.Flags().StringVar(&restartDelay, "restart-delay", "", "Delay between restart attempts (e.g. 5s; default 5s)")
	cmd.Flags().StringVar(&restartWin, "restart-window", "", "Attempt-count window (e.g. 1h; default 1h)")
	cmd.Flags().BoolVar(&secureBoot, "secure-boot", false, "Enable UEFI Secure Boot (q35; Windows 11 / signed-boot guests)")
	cmd.Flags().BoolVar(&tpm, "tpm", false, "Attach an emulated TPM 2.0 device (Windows 11 / BitLocker)")
	cmd.MarkFlagRequired("name")
	return cmd
}

func newLsCmd() *cobra.Command {
	var (
		stack string
		host  string
	)
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List VMs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListVMs(ctx, &pb.ListVMsRequest{
					StackName: stack,
					HostName:  host,
				})
				if err != nil {
					return fmt.Errorf("list VMs: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "NAME\tHOST\tSTATE\tCPU\tMEMORY\tIP\n")
				for _, vm := range resp.Vms {
					ip := "<unknown>"
					if len(vm.Interfaces) > 0 && vm.Interfaces[0].Ip != "" {
						ip = vm.Interfaces[0].Ip
					}
					// Templates show as "template" rather than their (always-stopped) state.
					state := fmt.Sprintf("%s", vm.State)
					if vm.IsTemplate {
						state = "template"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d MiB\t%s\n",
						vm.Name, vm.HostName, state,
						vm.CpuActual, vm.MemActualMib, ip,
					)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&stack, "stack", "", "Filter by stack")
	cmd.Flags().StringVar(&host, "host", "", "Filter by host")
	return cmd
}

func newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <vm>",
		Short: "Show VM details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.PrintVMInspect(ctx, c, args[0])
			})
		},
	}
}

func newStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start <vm>",
		Short: "Start a stopped VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.StartVM(ctx, &pb.StartVMRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("start VM: %w", err)
				}
				fmt.Printf("VM %s started (state: %s)\n", vm.Name, vm.State)
				return nil
			})
		},
	}
}

func newStopCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "stop <vm>",
		Short: "Stop a running VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.StopVM(ctx, &pb.StopVMRequest{
					Name:  args[0],
					Force: force,
				})
				if err != nil {
					return fmt.Errorf("stop VM: %w", err)
				}
				fmt.Printf("VM %s stopped (state: %s)\n", vm.Name, vm.State)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Force stop (destroy)")
	return cmd
}

func newRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart <vm>",
		Short: "Restart a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.RestartVM(ctx, &pb.RestartVMRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("restart VM: %w", err)
				}
				fmt.Printf("VM %s restarted (state: %s)\n", vm.Name, vm.State)
				return nil
			})
		},
	}
}

func newRmCmd() *cobra.Command {
	var keepDisks bool
	var force bool
	cmd := &cobra.Command{
		Use:   "rm <vm>",
		Short: "Delete a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				// Force-stop the VM first if --force is set and the VM is running.
				if force {
					c.StopVM(ctx, &pb.StopVMRequest{
						Name:  args[0],
						Force: true,
					})
					// Ignore error — VM may already be stopped or not found.
				}

				_, err := c.DeleteVM(ctx, &pb.DeleteVMRequest{
					Name:      args[0],
					KeepDisks: keepDisks,
				})
				if err != nil {
					return fmt.Errorf("delete VM: %w", err)
				}
				fmt.Printf("VM %s deleted\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&keepDisks, "keep-disks", false, "Keep disk files")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force-stop the VM before deleting")
	return cmd
}

func newConsoleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "console <vm>",
		Short: "Attach to VM serial console",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				fmt.Printf("Connecting to console of %s (press Ctrl+] to exit)...\n", vmName)
				return cli.StreamConsole(ctx, c, vmName)
			})
		},
	}
}

func newVNCCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "vnc <vm>",
		Short: "Fetch VNC address for a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.InspectVM(ctx, &pb.InspectVMRequest{Name: vmName})
				if err != nil {
					return fmt.Errorf("inspect VM: %w", err)
				}

				if vm.VncAddress == "" {
					return fmt.Errorf("VNC not available for %s (VM may not be running or VNC not enabled)", vmName)
				}
				fmt.Printf("VNC: %s\n", vm.VncAddress)
				return nil
			})
		},
	}
}

func newExecCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "exec <vm> <command> [args...]",
		Short: "Run a command inside a VM via guest agent",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]
			command := append([]string{args[1]}, args[2:]...)

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ExecVM(ctx, &pb.ExecVMRequest{
					Name:    vmName,
					Command: command,
				})
				if err != nil {
					return fmt.Errorf("exec: %w", err)
				}

				if len(resp.Stdout) > 0 {
					os.Stdout.Write(resp.Stdout)
				}
				if len(resp.Stderr) > 0 {
					os.Stderr.Write(resp.Stderr)
				}
				return nil
			})
		},
	}
	// Everything after <vm> is the guest command — stop cobra from parsing
	// flags meant for the guest (e.g. `lv exec vm uname -a` without needing
	// a `--` separator).
	c.Flags().SetInterspersed(false)
	return c
}
