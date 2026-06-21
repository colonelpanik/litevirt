package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Backup and restore VMs",
	}
	cmd.AddCommand(
		newBackupCreateCmd(),
		newBackupRestoreCmd(),
		newBackupRepoCmd(),
		newBackupSnapshotCmd(),
		newBackupRestoreFromCmd(),
		newBackupRestoreLiveCmd(),
		newBackupScheduleCmd(),
	)
	return cmd
}

// newBackupScheduleCmd is the schedule surface — operators
// add/list/rm cron-driven schedules; the daemon scheduler ticks every
// minute and dispatches matching rows.
func newBackupScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage cron-driven backup schedules",
	}
	cmd.AddCommand(
		newBackupScheduleAddCmd(),
		newBackupScheduleListCmd(),
		newBackupScheduleRmCmd(),
	)
	return cmd
}

func newBackupScheduleAddCmd() *cobra.Command {
	var repo, cron, scope, poolName, projectName string
	var keepLast, keepDaily, keepWeekly, keepMonthly, keepYearly int32
	var disabled bool
	cmd := &cobra.Command{
		Use:   "add [vm]",
		Short: "Add or replace a backup schedule (per-VM, per-pool, per-project, or cluster-wide)",
		Long: `Schedules a backup on a cron. The default scope is a single VM (pass <vm>).
Use --pool to back up every VM whose disks live on a storage pool, --project for
every VM in a tenancy project, or --scope cluster for every VM in the cluster.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := ""
			if len(args) == 1 {
				vmName = args[0]
			}
			// Infer the scope from which target the operator supplied, unless
			// --scope was given explicitly.
			if scope == "" {
				switch {
				case poolName != "":
					scope = "pool"
				case projectName != "":
					scope = "project"
				case vmName != "":
					scope = "vm"
				default:
					return fmt.Errorf("specify a <vm>, --pool, --project, or --scope cluster")
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				req := &pb.CreateBackupScheduleRequest{
					VmName: vmName, Repo: repo, Cron: cron,
					Scope: scope, PoolName: poolName, ProjectName: projectName,
					KeepLast: keepLast, KeepDaily: keepDaily, KeepWeekly: keepWeekly,
					KeepMonthly: keepMonthly, KeepYearly: keepYearly,
					Enabled: !disabled,
				}
				s, err := c.CreateBackupSchedule(ctx, req)
				if err != nil {
					return fmt.Errorf("create schedule: %w", err)
				}
				fmt.Printf("schedule %s/%s added (scope=%s, cron=%q, enabled=%v)\n", s.VmName, s.Repo, s.Scope, s.Cron, s.Enabled)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "logical repo name (must match daemon backup_repos config)")
	cmd.Flags().StringVar(&cron, "cron", "", `5-field cron expression (e.g. "0 2 * * *")`)
	cmd.Flags().StringVar(&scope, "scope", "", "schedule scope: vm | pool | project | cluster (default: inferred)")
	cmd.Flags().StringVar(&poolName, "pool", "", "storage pool name (scope=pool)")
	cmd.Flags().StringVar(&projectName, "project", "", "tenancy project name (scope=project)")
	cmd.Flags().Int32Var(&keepLast, "keep-last", 0, "retention: keep N most-recent")
	cmd.Flags().Int32Var(&keepDaily, "keep-daily", 0, "retention: keep N daily")
	cmd.Flags().Int32Var(&keepWeekly, "keep-weekly", 0, "retention: keep N weekly")
	cmd.Flags().Int32Var(&keepMonthly, "keep-monthly", 0, "retention: keep N monthly")
	cmd.Flags().Int32Var(&keepYearly, "keep-yearly", 0, "retention: keep N yearly")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create the schedule disabled")
	_ = cmd.MarkFlagRequired("repo")
	_ = cmd.MarkFlagRequired("cron")
	return cmd
}

func newBackupScheduleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List configured backup schedules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListBackupSchedules(ctx, &pb.ListBackupSchedulesRequest{})
				if err != nil {
					return fmt.Errorf("list schedules: %w", err)
				}
				if len(resp.Schedules) == 0 {
					fmt.Println("(no schedules)")
					return nil
				}
				fmt.Printf("%-22s %-9s %-12s %-15s %-7s %-25s %s\n", "TARGET", "SCOPE", "REPO", "CRON", "ENABLED", "LAST RUN", "LAST ERR")
				for _, s := range resp.Schedules {
					fmt.Printf("%-22s %-9s %-12s %-15s %-7v %-25s %s\n",
						s.VmName, defaultStr(s.Scope, "vm"), s.Repo, s.Cron, s.Enabled, defaultStr(s.LastRunAt, "-"), defaultStr(s.LastRunErr, "-"))
				}
				return nil
			})
		},
	}
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func newBackupScheduleRmCmd() *cobra.Command {
	var repo, scope, poolName, projectName string
	cmd := &cobra.Command{
		Use:   "rm [vm]",
		Short: "Remove a backup schedule (per-VM, per-pool, per-project, or cluster-wide)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := ""
			if len(args) == 1 {
				vmName = args[0]
			}
			if scope == "" {
				switch {
				case poolName != "":
					scope = "pool"
				case projectName != "":
					scope = "project"
				case vmName != "":
					scope = "vm"
				default:
					return fmt.Errorf("specify a <vm>, --pool, --project, or --scope cluster")
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteBackupSchedule(ctx, &pb.DeleteBackupScheduleRequest{
					VmName: vmName, Repo: repo, Scope: scope, PoolName: poolName, ProjectName: projectName,
				}); err != nil {
					return fmt.Errorf("delete schedule: %w", err)
				}
				fmt.Printf("schedule removed (scope=%s, repo=%s)\n", scope, repo)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "logical repo name (required to disambiguate)")
	cmd.Flags().StringVar(&scope, "scope", "", "schedule scope: vm | pool | project | cluster (default: inferred)")
	cmd.Flags().StringVar(&poolName, "pool", "", "storage pool name (scope=pool)")
	cmd.Flags().StringVar(&projectName, "project", "", "tenancy project name (scope=project)")
	_ = cmd.MarkFlagRequired("repo")
	return cmd
}

// newBackupSnapshotCmd is the gRPC-driven push: streams a VM's disk
// into a host-local backup repo via the daemon.
func newBackupSnapshotCmd() *cobra.Command {
	var disk, repo, ts, quiesce string
	var incremental bool
	cmd := &cobra.Command{
		Use:   "snapshot <vm>",
		Short: "Push a VM's disk into a backup repo (PBS-equivalent dedup chunks)",
		Long: `Push a VM's disk into a backup repo as a content-addressed manifest.

--incremental looks up the most-recent manifest for this VM+disk in
the repo and reuses its chunk refs for clean regions. Requires a
parent manifest; the first --incremental push degrades to a full
backup. When the daemon has a libvirt dirty-bitmap provider wired,
the read I/O is skipped for clean regions too; without one, the
chunk store still dedups by content and the manifest chain stays
intact (but disk I/O is full).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if repo == "" {
				return fmt.Errorf("--repo is required")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.BackupSnapshot(ctx, &pb.BackupSnapshotRequest{
					VmName: args[0], DiskName: disk, RepoPath: repo,
					Timestamp: ts, Incremental: incremental, Quiesce: quiesce,
				})
				if err != nil {
					return err
				}
				for {
					p, err := stream.Recv()
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					switch p.Phase {
					case pb.BackupSnapshotProgress_DONE:
						fmt.Printf("[done] manifest=%s chunks=%d bytes=%d\n", p.ManifestTs, p.ChunksTotal, p.BytesProcessed)
						if p.BytesProcessed > 0 {
							pct := 100 * float64(p.BytesRead) / float64(p.BytesProcessed)
							fmt.Printf("       read %s of %s off disk (%.1f%%) — saved %s\n",
								formatBytes(p.BytesRead), formatBytes(p.BytesProcessed), pct,
								formatBytes(p.BytesProcessed-p.BytesRead))
						}
						return nil
					default:
						if p.Status != "" {
							fmt.Printf("[%s] %s\n", p.Phase, p.Status)
						} else {
							fmt.Printf("[%s] chunks=%d (deduped=%d) bytes=%d\n",
								p.Phase, p.ChunksTotal, p.ChunksDeduped, p.BytesProcessed)
						}
					}
				}
			})
		},
	}
	cmd.Flags().StringVar(&disk, "disk", "", "Disk name (default: root)")
	cmd.Flags().StringVar(&repo, "repo", "", "Backup repo path (host-local)")
	cmd.Flags().StringVar(&ts, "timestamp", "", "Override snapshot timestamp (RFC3339)")
	cmd.Flags().BoolVar(&incremental, "incremental", false, "Push only chunks changed since the most-recent manifest in this repo")
	cmd.Flags().StringVar(&quiesce, "quiesce", "auto", "In-guest fs-freeze for an app-consistent backup: auto (freeze if guest agent present) | off")
	return cmd
}

// newBackupRestoreFromCmd streams a manifest's chunks back into a
// target disk path. Distinct from `lv backup restore` (legacy) which
// uses the older full-disk RestoreVM RPC.
func newBackupRestoreFromCmd() *cobra.Command {
	var repo, vm, disk, ts, target string
	cmd := &cobra.Command{
		Use:   "restore-from",
		Short: "Restore a snapshot from a backup repo to a target disk path",
		RunE: func(cmd *cobra.Command, args []string) error {
			for name, val := range map[string]string{
				"--repo": repo, "--vm": vm, "--disk": disk, "--timestamp": ts, "--target-path": target,
			} {
				if val == "" {
					return fmt.Errorf("%s is required", name)
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.RestoreFromBackup(ctx, &pb.RestoreFromBackupRequest{
					RepoPath: repo, VmName: vm, DiskName: disk, Timestamp: ts, TargetPath: target,
				})
				if err != nil {
					return err
				}
				for {
					p, err := stream.Recv()
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					if p.Phase == pb.RestoreFromBackupProgress_DONE {
						fmt.Printf("[done] %d chunks, %d bytes restored to %s\n",
							p.ChunksDone, p.BytesWritten, target)
						return nil
					}
					fmt.Printf("[restore] %d/%d chunks (%d bytes)\n", p.ChunksDone, p.ChunksTotal, p.BytesWritten)
				}
			})
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "Backup repo path")
	cmd.Flags().StringVar(&vm, "vm", "", "VM name (matches manifest)")
	cmd.Flags().StringVar(&disk, "disk", "", "Disk name")
	cmd.Flags().StringVar(&ts, "timestamp", "", "Manifest timestamp (exact RFC3339)")
	cmd.Flags().StringVar(&target, "target-path", "", "Where to write the restored disk")
	return cmd
}

// newBackupRestoreLiveCmd opens a streaming RPC that spawns an NBD
// server backed by the manifest's chunk reader, creates a qcow2
// overlay at --target-path, and prints the resulting NBD URL +
// overlay path. The stream stays open so the NBD server keeps
// serving until the operator hits Ctrl+C (or another agent closes
// the gRPC stream).
//
// Workflow:
//
//	# Terminal 1 — start the live-restore source
//	lv backup restore-live --repo /srv/backup --vm vm1 \
//	    --disk root --timestamp 2026-05-11T10:00:00Z \
//	    --target-path /var/lib/libvirt/images/vm1-live.qcow2
//
//	# Terminal 2 — boot qemu/libvirt against the overlay path
//	virsh define vm1.xml && virsh start vm1
//
//	# Optional: pull the data local
//	virsh blockpull vm1 vda --wait
//
// Once blockpull completes, Ctrl+C terminal 1 — the NBD server
// stops and the overlay is fully self-contained.
func newBackupRestoreLiveCmd() *cobra.Command {
	var repo, vm, disk, ts, target, bind, newName string
	var autoStart, blockpull, fromExisting bool
	cmd := &cobra.Command{
		Use:   "restore-live",
		Short: "Serve a backup manifest as a live NBD source + qcow2 overlay",
		Long: `Spawn an NBD server backed by a manifest's chunk store and create a
qcow2 overlay backed by it. The VM can boot off the overlay
immediately; data migrates on-demand. Ctrl+C terminates the NBD
server when the operator has finished pulling data locally.

With --auto-start the daemon also defines and starts the VM against
the overlay (from the manifest's embedded spec, or --name for a
collision-avoiding rename). --blockpull then localizes the disk and
tears the NBD server down automatically when it completes.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			for name, val := range map[string]string{
				"--repo": repo, "--vm": vm, "--disk": disk, "--timestamp": ts, "--target-path": target,
			} {
				if val == "" {
					return fmt.Errorf("%s is required", name)
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.RestoreLive(ctx, &pb.RestoreLiveRequest{
					RepoPath: repo, VmName: vm, DiskName: disk, Timestamp: ts,
					TargetPath: target, BindAddr: bind,
					AutoStart: autoStart, NewName: newName,
					Blockpull: blockpull, FromExisting: fromExisting,
				})
				if err != nil {
					return err
				}
				for {
					p, err := stream.Recv()
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					if p.VmName != "" {
						fmt.Printf("[%s] %s (vm=%s)\n", p.Phase, p.Status, p.VmName)
					} else {
						fmt.Printf("[%s] %s\n", p.Phase, p.Status)
					}
					if p.NbdUrl != "" {
						fmt.Printf("    nbd_url=%s overlay=%s\n", p.NbdUrl, p.TargetPath)
					}
					if p.Phase == pb.RestoreLiveProgress_DONE || p.Phase == pb.RestoreLiveProgress_LOCALIZED {
						return nil
					}
				}
			})
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "Backup repo path")
	cmd.Flags().StringVar(&vm, "vm", "", "VM name (matches manifest)")
	cmd.Flags().StringVar(&disk, "disk", "", "Disk name")
	cmd.Flags().StringVar(&ts, "timestamp", "", "Manifest timestamp (exact RFC3339)")
	cmd.Flags().StringVar(&target, "target-path", "", "Where to write the qcow2 overlay")
	cmd.Flags().StringVar(&bind, "bind", "127.0.0.1:0", "NBD server bind addr (use 0.0.0.0:<port> for non-local qemu)")
	cmd.Flags().BoolVar(&autoStart, "auto-start", false, "Define and start the VM automatically against the overlay")
	cmd.Flags().StringVar(&newName, "name", "", "Rename the restored VM (avoids collision with the original)")
	cmd.Flags().BoolVar(&blockpull, "blockpull", false, "After start, localize the disk via blockpull then stop NBD")
	cmd.Flags().BoolVar(&fromExisting, "from-existing", false, "Fall back to an existing vms record for the spec")
	return cmd
}

func newBackupCreateCmd() *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:   "create <vm>",
		Short: "Export a VM's root disk to a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				// Default output filename.
				if outPath == "" {
					outPath = args[0] + ".qcow2"
				}

				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("create output file: %w", err)
				}
				defer f.Close()

				stream, err := c.BackupVM(ctx, &pb.BackupVMRequest{VmName: args[0]})
				if err != nil {
					return fmt.Errorf("backup: %w", err)
				}

				var written int64
				var checksum string
				for {
					chunk, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						return fmt.Errorf("recv: %w", err)
					}

					if len(chunk.Data) > 0 {
						n, wErr := f.Write(chunk.Data)
						if wErr != nil {
							return fmt.Errorf("write: %w", wErr)
						}
						written += int64(n)
						if chunk.TotalBytes > 0 {
							pct := float64(written) / float64(chunk.TotalBytes) * 100
							fmt.Printf("\r  backup: %.0f%%", pct)
						}
					}
					if chunk.Checksum != "" {
						checksum = chunk.Checksum
					}
				}

				fmt.Printf("\nBackup complete: %s (%d bytes", outPath, written)
				if checksum != "" {
					fmt.Printf(", %s", checksum)
				}
				fmt.Println(")")
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "Output file path (default: <vm>.qcow2)")
	return cmd
}

func newBackupRestoreCmd() *cobra.Command {
	var (
		name    string
		cpu     int32
		memMiB  int32
		network string
	)
	cmd := &cobra.Command{
		Use:   "restore <file>",
		Short: "Restore a VM from a backup file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				f, err := os.Open(args[0])
				if err != nil {
					return fmt.Errorf("open: %w", err)
				}
				defer f.Close()

				info, err := f.Stat()
				if err != nil {
					return fmt.Errorf("stat: %w", err)
				}

				stream, err := c.RestoreVM(ctx)
				if err != nil {
					return fmt.Errorf("restore: %w", err)
				}

				buf := make([]byte, 256*1024)
				var sent int64
				first := true

				for {
					n, readErr := f.Read(buf)
					if n > 0 {
						msg := &pb.RestoreVMRequest{Chunk: buf[:n]}
						if first {
							msg.Name = name
							msg.Cpu = cpu
							msg.MemoryMib = memMiB
							msg.Network = network
							first = false
						}
						if err := stream.Send(msg); err != nil {
							return fmt.Errorf("send: %w", err)
						}
						sent += int64(n)
						pct := float64(sent) / float64(info.Size()) * 100
						fmt.Printf("\r  restoring: %.0f%%", pct)
					}
					if readErr == io.EOF {
						break
					}
					if readErr != nil {
						return fmt.Errorf("read: %w", readErr)
					}
				}

				vm, err := stream.CloseAndRecv()
				if err != nil {
					return fmt.Errorf("restore: %w", err)
				}
				fmt.Printf("\nVM %s restored on %s (state: %s)\n",
					vm.Name, vm.HostName, vm.State)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "VM name (required)")
	cmd.Flags().Int32Var(&cpu, "cpu", 2, "CPU count")
	cmd.Flags().Int32Var(&memMiB, "memory", 4096, "Memory in MiB")
	cmd.Flags().StringVar(&network, "network", "", "Network bridge name (optional)")
	cmd.MarkFlagRequired("name")
	return cmd
}
