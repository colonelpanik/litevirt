package main

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newReplicationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replication",
		Short: "Scheduled volume replication + failover promotion",
	}
	cmd.AddCommand(
		newReplicationScheduleCmd(),
		newReplicationPromoteCmd(),
	)
	return cmd
}

func newReplicationScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage cron-driven replication schedules",
	}
	cmd.AddCommand(
		newReplicationScheduleAddCmd(),
		newReplicationScheduleListCmd(),
		newReplicationScheduleRmCmd(),
	)
	return cmd
}

func newReplicationScheduleAddCmd() *cobra.Command {
	var cron, targetPool, targetHost, scope, poolName, projectName string
	var keepReplicas int32
	var disabled, incremental, autoPromote bool
	cmd := &cobra.Command{
		Use:   "add <vm>",
		Short: "Add or replace a replication schedule for a VM",
		Long: `Replicate a VM's disk to target-pool on a cron schedule, keeping the newest
--keep point-in-time copies. The target is an explicit --target-host, a shared
pool (nfs/ceph/iscsi), or — when neither — an auto-selected healthy peer with
the pool.

--incremental transfers only dirty extents (raw replicas; full-copy fallback for
a stopped VM or old libvirt). --auto-promote lets failover bring up the freshest
replica if the VM's host is lost.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if scope == "" {
				scope = "vm"
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				s, err := c.CreateReplicationSchedule(ctx, &pb.CreateReplicationScheduleRequest{
					VmName: args[0], Cron: cron, TargetPool: targetPool, TargetHost: targetHost,
					KeepReplicas: keepReplicas, Enabled: !disabled, Scope: scope,
					PoolName: poolName, ProjectName: projectName,
					Incremental: incremental, AutoPromote: autoPromote,
				})
				if err != nil {
					return fmt.Errorf("create replication schedule: %w", err)
				}
				fmt.Printf("replication schedule %s → %s added (cron=%q, incremental=%v, auto-promote=%v, enabled=%v)\n",
					s.VmName, s.TargetPool, s.Cron, s.Incremental, s.AutoPromote, s.Enabled)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&cron, "cron", "", `5-field cron expression (e.g. "0 */4 * * *")`)
	cmd.Flags().StringVar(&targetPool, "target-pool", "", "destination storage pool")
	cmd.Flags().StringVar(&targetHost, "target-host", "", "explicit destination host (else shared-pool/auto peer)")
	cmd.Flags().Int32Var(&keepReplicas, "keep", 0, "keep N newest replicas (0 = keep all)")
	cmd.Flags().BoolVar(&incremental, "incremental", false, "transfer only dirty extents (raw replicas)")
	cmd.Flags().BoolVar(&autoPromote, "auto-promote", false, "failover may promote the freshest replica on host loss")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create the schedule disabled")
	cmd.Flags().StringVar(&scope, "scope", "vm", "schedule scope: vm | pool | cluster | project")
	cmd.Flags().StringVar(&poolName, "pool-name", "", "pool name (scope=pool)")
	cmd.Flags().StringVar(&projectName, "project-name", "", "project name (scope=project)")
	_ = cmd.MarkFlagRequired("cron")
	_ = cmd.MarkFlagRequired("target-pool")
	return cmd
}

func newReplicationScheduleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List configured replication schedules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListReplicationSchedules(ctx, &pb.ListReplicationSchedulesRequest{})
				if err != nil {
					return fmt.Errorf("list replication schedules: %w", err)
				}
				if len(resp.Schedules) == 0 {
					fmt.Println("(no replication schedules)")
					return nil
				}
				fmt.Printf("%-18s %-12s %-10s %-5s %-5s %-4s %-20s %s\n",
					"VM", "POOL", "HOST", "INCR", "AUTO", "KEEP", "LAST RUN", "LAST ERR")
				for _, s := range resp.Schedules {
					fmt.Printf("%-18s %-12s %-10s %-5v %-5v %-4d %-20s %s\n",
						s.VmName, s.TargetPool, defaultStr(s.TargetHost, "-"), s.Incremental, s.AutoPromote,
						s.KeepReplicas, defaultStr(s.LastRunAt, "-"), defaultStr(s.LastRunErr, "-"))
				}
				return nil
			})
		},
	}
}

func newReplicationScheduleRmCmd() *cobra.Command {
	var targetPool, scope, poolName, projectName string
	cmd := &cobra.Command{
		Use:   "rm <vm>",
		Short: "Remove a replication schedule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if scope == "" {
				scope = "vm"
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteReplicationSchedule(ctx, &pb.DeleteReplicationScheduleRequest{
					VmName: args[0], TargetPool: targetPool, Scope: scope,
					PoolName: poolName, ProjectName: projectName,
				}); err != nil {
					return fmt.Errorf("delete replication schedule: %w", err)
				}
				fmt.Printf("replication schedule %s → %s removed\n", args[0], targetPool)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&targetPool, "target-pool", "", "destination pool (required to disambiguate)")
	cmd.Flags().StringVar(&scope, "scope", "vm", "schedule scope")
	cmd.Flags().StringVar(&poolName, "pool-name", "", "pool name (scope=pool)")
	cmd.Flags().StringVar(&projectName, "project-name", "", "project name (scope=project)")
	_ = cmd.MarkFlagRequired("target-pool")
	return cmd
}

func newReplicationPromoteCmd() *cobra.Command {
	var pool, host, replica, newName string
	var force, noLocalize bool
	cmd := &cobra.Command{
		Use:   "promote <vm>",
		Short: "Bring up a VM from its replica (disaster recovery)",
		Long: `Promote a replica to a live VM. By default the newest replica of the VM's
root disk is located (from the VM's replication schedule, or --pool/--host),
copied into a self-contained live disk on the host holding it, and the VM is
defined + started there.

By default the original name is taken over (the host-loss case); pass --new-name
to bring it up alongside a still-running original. --force overrides the
split-brain guard. --no-localize boots off a fast overlay backed by the replica
instead of copying (pins the replica until you localize it).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.PromoteReplica(ctx, &pb.PromoteReplicaRequest{
					VmName: args[0], TargetPool: pool, TargetHost: host, Replica: replica,
					NewName: newName, Force: force, NoLocalize: noLocalize,
				})
				if err != nil {
					return err
				}
				for {
					p, rerr := stream.Recv()
					if rerr == io.EOF {
						return nil
					}
					if rerr != nil {
						return rerr
					}
					fmt.Printf("[%s] %s\n", p.Phase, p.Status)
				}
			})
		},
	}
	cmd.Flags().StringVar(&pool, "pool", "", "pool holding the replica (default: from the VM's replication schedule)")
	cmd.Flags().StringVar(&host, "host", "", "host holding the replica (default: auto-resolved)")
	cmd.Flags().StringVar(&replica, "replica", "", "exact replica filename (default: newest)")
	cmd.Flags().StringVar(&newName, "new-name", "", "promote under a new name (alongside the original)")
	cmd.Flags().BoolVar(&force, "force", false, "promote even if the original is on a healthy host")
	cmd.Flags().BoolVar(&noLocalize, "no-localize", false, "boot off an overlay backed by the replica (fast; pins it)")
	return cmd
}
