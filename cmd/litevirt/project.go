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

// newProjectCmd is the tenancy surface. Single-tenant
// clusters never need this — the `_default` project is implicit
// and unbounded.
func newProjectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Manage projects (tenancy buckets)",
	}
	cmd.AddCommand(
		newProjectCreateCmd(),
		newProjectListCmd(),
		newProjectDeleteCmd(),
		newProjectQuotaCmd(),
		newProjectUsageCmd(),
	)
	return cmd
}

func newProjectCreateCmd() *cobra.Command {
	var display, parent string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a project (e.g. /acme/team-foo)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				p, err := c.CreateProject(ctx, &pb.CreateProjectRequest{
					Name: args[0], Display: display, ParentName: parent,
				})
				if err != nil {
					return fmt.Errorf("create project: %w", err)
				}
				fmt.Printf("project %s created\n", p.Name)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&display, "display", "", "human-readable label")
	cmd.Flags().StringVar(&parent, "parent", "", "parent project name (creates a child)")
	return cmd
}

func newProjectListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List projects",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListProjects(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("list projects: %w", err)
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "NAME\tDISPLAY\tPARENT\tCREATED")
				for _, p := range resp.Projects {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, p.Display, p.ParentName, p.CreatedAt)
				}
				return w.Flush()
			})
		},
	}
}

func newProjectDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a project (must be empty of VMs)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteProject(ctx, &pb.DeleteProjectRequest{Name: args[0]}); err != nil {
					return fmt.Errorf("delete project: %w", err)
				}
				fmt.Printf("project %s removed\n", args[0])
				return nil
			})
		},
	}
}

func newProjectQuotaCmd() *cobra.Command {
	var vcpu, mem, disk, nics, ips, backup int32
	cmd := &cobra.Command{
		Use:   "quota <name>",
		Short: "Set or view a project's quota (zero = unbounded)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				// If any limit flag was set, write; otherwise read.
				if cmd.Flags().Changed("vcpu") || cmd.Flags().Changed("mem") || cmd.Flags().Changed("disk") ||
					cmd.Flags().Changed("nics") || cmd.Flags().Changed("ips") || cmd.Flags().Changed("backup") {
					q, err := c.SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
						Quota: &pb.ProjectQuota{
							ProjectName: args[0], VcpuLimit: vcpu, MemMibLimit: mem,
							DiskGibLimit: disk, NicLimit: nics, PublicIpLimit: ips, BackupGibLimit: backup,
						},
					})
					if err != nil {
						return fmt.Errorf("set quota: %w", err)
					}
					printQuota(q)
					return nil
				}
				q, err := c.GetProjectQuota(ctx, &pb.GetProjectQuotaRequest{ProjectName: args[0]})
				if err != nil {
					return fmt.Errorf("get quota: %w", err)
				}
				printQuota(q)
				return nil
			})
		},
	}
	cmd.Flags().Int32Var(&vcpu, "vcpu", 0, "vCPU limit (0 = unbounded)")
	cmd.Flags().Int32Var(&mem, "mem", 0, "memory MiB limit (0 = unbounded)")
	cmd.Flags().Int32Var(&disk, "disk", 0, "disk GiB limit (0 = unbounded)")
	cmd.Flags().Int32Var(&nics, "nics", 0, "NIC count limit (0 = unbounded)")
	cmd.Flags().Int32Var(&ips, "ips", 0, "public IP limit (0 = unbounded)")
	cmd.Flags().Int32Var(&backup, "backup", 0, "backup GiB limit (0 = unbounded)")
	return cmd
}

func newProjectUsageCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "usage <name>",
		Short: "Show current resource usage for a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				u, err := c.GetProjectUsage(ctx, &pb.GetProjectUsageRequest{ProjectName: args[0]})
				if err != nil {
					return fmt.Errorf("get usage: %w", err)
				}
				fmt.Printf("project: %s\n", u.ProjectName)
				fmt.Printf("  vCPU used:   %d\n", u.VcpuUsed)
				fmt.Printf("  mem (MiB):   %d\n", u.MemMibUsed)
				fmt.Printf("  disk (GiB):  %d\n", u.DiskGibUsed)
				fmt.Printf("  NICs:        %d\n", u.NicUsed)
				fmt.Printf("  public IPs:  %d\n", u.PublicIpsUsed)
				fmt.Printf("  backup (GiB):%d\n", u.BackupGibUsed)
				fmt.Printf("  VM count:    %d\n", u.VmCount)
				return nil
			})
		},
	}
}

func printQuota(q *pb.ProjectQuota) {
	fmt.Printf("project: %s\n", q.ProjectName)
	fmt.Printf("  vCPU limit:       %d\n", q.VcpuLimit)
	fmt.Printf("  mem MiB limit:    %d\n", q.MemMibLimit)
	fmt.Printf("  disk GiB limit:   %d\n", q.DiskGibLimit)
	fmt.Printf("  NIC limit:        %d\n", q.NicLimit)
	fmt.Printf("  public IP limit:  %d\n", q.PublicIpLimit)
	fmt.Printf("  backup GiB limit: %d\n", q.BackupGibLimit)
}
