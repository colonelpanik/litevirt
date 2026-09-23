package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

func newComposeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compose",
		Short: "Manage VM stacks via compose files",
	}
	cmd.AddCommand(
		newUpCmd(),
		newDownCmd(),
		newPsCmd(),
		newDiffCmd(),
		newStackLsCmd(),
		newExportCmd(),
	)
	return cmd
}

func newUpCmd() *cobra.Command {
	var (
		file string
		yes  bool
	)
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Deploy or update a stack from a compose file",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read raw YAML — needed for DeployStack RPC.
			yamlData, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read compose file: %w", err)
			}

			f, err := compose.ParseBytes(yamlData)
			if err != nil {
				return err
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				// Dry-run via DeployStack to get the plan from the server.
				dryStream, err := c.DeployStack(ctx, &pb.DeployStackRequest{
					ComposeYaml: string(yamlData),
					DryRun:      true,
				})
				if err != nil {
					return fmt.Errorf("deploy dry-run: %w", err)
				}

				var ops []compose.Op
				for {
					p, err := dryStream.Recv()
					if err != nil {
						if err.Error() != "EOF" {
							// Check if this is a real error (auth, network, etc.)
							// vs normal end-of-stream.
							st, ok := status.FromError(err)
							if ok && st.Code() != codes.OK {
								return fmt.Errorf("dry-run failed: %s", st.Message())
							}
						}
						break
					}
					ops = append(ops, compose.Op{
						Kind:   compose.OpKind(p.Phase),
						VMName: p.VmName,
						Detail: p.Detail,
					})
				}

				if len(ops) == 0 {
					fmt.Println("Nothing to do — stack is up to date.")
					return nil
				}

				// Print plan
				fmt.Printf("Stack %q:\n\n", f.Name)
				for _, op := range ops {
					switch op.Kind {
					case compose.OpCreate:
						fmt.Printf("  + %s\n", op.Detail)
					case compose.OpUpdate:
						fmt.Printf("  ~ %s\n", op.Detail)
					case compose.OpDelete:
						fmt.Printf("  - %s\n", op.Detail)
					case "network":
						fmt.Printf("  # %s\n", op.Detail)
					case "loadbalancer":
						fmt.Printf("  # %s\n", op.Detail)
					default:
						fmt.Printf("    %s\n", op.Detail)
					}
				}
				fmt.Println()

				if !yes {
					fmt.Print("Apply? [y/N] ")
					var ans string
					fmt.Scanln(&ans)
					if ans != "y" && ans != "Y" {
						fmt.Println("Aborted.")
						return nil
					}
				}

				// Execute via DeployStack RPC (handles VM creation, stack record, LB, etc.).
				stream, err := c.DeployStack(ctx, &pb.DeployStackRequest{
					ComposeYaml: string(yamlData),
				})
				if err != nil {
					return fmt.Errorf("deploy stack: %w", err)
				}

				var deployErr error
				for {
					p, err := stream.Recv()
					if err != nil {
						if st, ok := status.FromError(err); ok && st.Code() != codes.OK {
							deployErr = fmt.Errorf("deploy failed: %s", st.Message())
						}
						break
					}
					switch p.Phase {
					case "error":
						fmt.Fprintf(os.Stderr, "  error %s: %s\n", p.VmName, p.Error)
					case "done":
						fmt.Printf("  %s: done\n", p.VmName)
					default:
						fmt.Printf("  %s: %s\n", p.VmName, p.Detail)
					}
				}
				if deployErr != nil {
					return deployErr
				}

				fmt.Printf("\nStack %q deployed.\n", f.Name)
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "litevirt-compose.yaml", "Compose file path")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	return cmd
}

func newDownCmd() *cobra.Command {
	var (
		file      string
		stackName string
		yes       bool
	)
	cmd := &cobra.Command{
		Use:   "down",
		Short: "Tear down a stack",
		RunE: func(cmd *cobra.Command, args []string) error {
			var name string
			if cmd.Flags().Changed("name") {
				name = stackName
			} else {
				f, err := compose.Parse(file)
				if err != nil {
					return err
				}
				name = f.Name
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListVMs(ctx, &pb.ListVMsRequest{StackName: name})
				if err != nil {
					return fmt.Errorf("list VMs: %w", err)
				}

				if len(resp.Vms) == 0 {
					fmt.Printf("Stack %q has no running VMs — cleaning up stack record.\n", name)
				} else {
					fmt.Printf("Will delete %d VM(s) in stack %q:\n", len(resp.Vms), name)
				}
				for _, vm := range resp.Vms {
					fmt.Printf("  - %s (%s)\n", vm.Name, vm.State)
				}

				if !yes {
					fmt.Print("Confirm? [y/N] ")
					var ans string
					fmt.Scanln(&ans)
					if ans != "y" && ans != "Y" {
						fmt.Println("Aborted.")
						return nil
					}
				}

				// Use DeleteStack RPC which handles VM deletion, LB cleanup, and stack record removal.
				stream, err := c.DeleteStack(ctx, &pb.DeleteStackRequest{
					Name: name,
				})
				if err != nil {
					return fmt.Errorf("delete stack: %w", err)
				}

				var downErr error
				for {
					p, err := stream.Recv()
					if err != nil {
						if st, ok := status.FromError(err); ok && st.Code() != codes.OK {
							downErr = fmt.Errorf("delete failed: %s", st.Message())
						}
						break
					}
					switch p.Status {
					case "error":
						fmt.Fprintf(os.Stderr, "  error %s: %s\n", p.VmName, p.Error)
					case "deleted":
						fmt.Printf("  deleted %s\n", p.VmName)
					default:
						fmt.Printf("  %s: %s\n", p.VmName, p.Status)
					}
				}
				if downErr != nil {
					return downErr
				}

				fmt.Printf("Stack %q torn down.\n", name)
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "litevirt-compose.yaml", "Compose file path")
	cmd.Flags().StringVar(&stackName, "name", "", "Stack name (use instead of compose file)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	return cmd
}

func newPsCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "ps",
		Short: "List VMs in a stack",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := compose.Parse(file)
			if err != nil {
				return err
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListVMs(ctx, &pb.ListVMsRequest{StackName: f.Name})
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
					fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%dMiB\t%s\n",
						vm.Name, vm.HostName, vm.State,
						vm.CpuActual, vm.MemActualMib, ip)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "litevirt-compose.yaml", "Compose file path")
	return cmd
}

// composeVMState renders a VM state the way the daemon stores it ("error",
// "creating", …), which is what the planner's transient/error retry check
// matches on. The proto enum's String() is "VM_ERROR", which matched nothing,
// so an error-state VM read as unchanged in the diff while the server planned a
// retry (delete + recreate under the default strategy) for it.
func composeVMState(s pb.VMState) string {
	return strings.ToLower(strings.TrimPrefix(s.String(), "VM_"))
}

func newDiffCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show what lv compose up would change",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := compose.Parse(file)
			if err != nil {
				return err
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListVMs(ctx, &pb.ListVMsRequest{StackName: f.Name})
				if err != nil {
					return fmt.Errorf("list VMs: %w", err)
				}

				// ListVMs ships a PROJECTION of each spec (labels, uuid, machine,
				// cpu mode) — no image and no cloud-init. Diffing against the
				// projection made every VM of a cloud-init stack read as
				// "image →X cloud-init added", so the full spec comes from
				// InspectVM. A VM that cannot be inspected fails the diff rather
				// than being reported as changed.
				current := make([]compose.CurrentVM, 0, len(resp.Vms))
				for _, vm := range resp.Vms {
					full, err := c.InspectVM(ctx, &pb.InspectVMRequest{Name: vm.Name})
					if err != nil {
						return fmt.Errorf("inspect %s: %w", vm.Name, err)
					}
					cur := compose.CurrentVM{
						Name:     vm.Name,
						CPU:      int(vm.CpuActual),
						MemMiB:   int(vm.MemActualMib),
						State:    composeVMState(vm.State),
						HostName: vm.HostName,
						Spec:     full.Spec,
					}
					if full.Spec != nil {
						cur.Image = full.Spec.Image
						if ci := full.Spec.CloudInit; ci != nil {
							cur.CloudInitHash = compose.CloudInitHash(ci.Userdata, ci.Networkconfig)
						}
					}
					current = append(current, cur)
				}

				plan, err := compose.Build(f, current)
				if err != nil {
					return err
				}

				fmt.Println(plan.Summary())
				for _, op := range plan.Ops {
					switch op.Kind {
					case compose.OpCreate:
						fmt.Printf("  + %s\n", op.Detail)
					case compose.OpUpdate:
						fmt.Printf("  ~ %s\n", op.Detail)
					case compose.OpDelete:
						fmt.Printf("  - %s\n", op.Detail)
					case compose.OpNoChange:
						fmt.Printf("    %s\n", op.Detail)
					}
					if op.Warning != "" {
						fmt.Printf("    warning: %s\n", op.Warning)
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "litevirt-compose.yaml", "Compose file path")
	return cmd
}

func newStackLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all deployed stacks",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListStacks(ctx, nil)
				if err != nil {
					return fmt.Errorf("list stacks: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "NAME\tSTATE\tVMs\tRUNNING\tSTOPPED\tERROR\tCREATED")
				for _, s := range resp.Stacks {
					created := "-"
					if s.CreatedAt != nil {
						created = s.CreatedAt.AsTime().Format("2006-01-02 15:04")
					}
					fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
						s.Name, s.State, s.VmCount,
						s.Running, s.Stopped, s.Error,
						created,
					)
				}
				return w.Flush()
			})
		},
	}
}

func newExportCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "export <stack-name>",
		Short: "Export a stack's compose YAML",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ExportStack(ctx, &pb.ExportStackRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("export stack: %w", err)
				}

				if output != "" {
					if err := os.WriteFile(output, []byte(resp.ComposeYaml), 0644); err != nil {
						return fmt.Errorf("write file: %w", err)
					}
					fmt.Printf("Exported stack %q to %s\n", resp.Name, output)
					return nil
				}

				fmt.Print(resp.ComposeYaml)
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write YAML to file instead of stdout")
	return cmd
}
