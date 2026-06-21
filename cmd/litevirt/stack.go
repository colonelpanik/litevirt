package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newStackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stack",
		Short: "Stack-level operations across all VMs of a stack",
	}
	cmd.AddCommand(newStackMigrateVolumesCmd())
	return cmd
}

func newStackMigrateVolumesCmd() *cobra.Command {
	var (
		to           string
		maps         []string
		parallel     int32
		order        []string
		deleteSource bool
		dryRun       bool
		healthWait   uint32
	)
	cmd := &cobra.Command{
		Use:   "migrate-volumes <stack>",
		Short: "Migrate every VM's disks in a stack to different storage pools",
		Long: `Migrate the volumes of every VM in a stack to a different storage pool.

By default all disks move to the pool given by --to. Use --map to override
per VM or per disk (most-specific wins):

    lv stack migrate-volumes postgres --to fast \
        --map pg-1/data=archive --map pg-2=warm

Running VMs migrate online (libvirt blockdev-mirror, no downtime); stopped VMs
use an offline copy. The rollout is rolling — one VM at a time by default
(--parallel widens it) — so a stateful cluster keeps serving. File-based pools
only (local, dir, nfs, btrfs). Use --dry-run to preview the resolved plan.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			placements, err := parseVolumePlacements(maps)
			if err != nil {
				return err
			}
			if to == "" && len(placements) == 0 {
				return fmt.Errorf("provide --to <pool> and/or one or more --map rules")
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.MigrateStackVolumes(ctx, &pb.MigrateStackVolumesRequest{
					StackName:         args[0],
					DefaultPool:       to,
					Placements:        placements,
					DeleteSource:      deleteSource,
					Parallel:          parallel,
					Order:             order,
					DryRun:            dryRun,
					HealthWaitSeconds: healthWait,
				})
				if err != nil {
					return err
				}
				for {
					prog, err := stream.Recv()
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					printStackVolumeProgress(prog)
					if prog.Stage == pb.StackVolumeProgress_COMPLETE {
						return nil
					}
				}
			})
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "Default target pool for all disks not matched by --map")
	cmd.Flags().StringArrayVar(&maps, "map", nil,
		"Per-VM or per-disk override: vm=pool or vm/disk=pool (repeatable)")
	cmd.Flags().Int32Var(&parallel, "parallel", 1, "How many VMs to migrate at once (1 = rolling)")
	cmd.Flags().StringSliceVar(&order, "order", nil, "Explicit VM order, e.g. replica-1,replica-2,primary")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false, "Delete each source disk after its cutover")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Resolve and preflight the plan without moving data")
	cmd.Flags().Uint32Var(&healthWait, "health-wait", 0, "Seconds to wait for a VM to be healthy between steps (0 = default)")
	return cmd
}

// parseVolumePlacements turns --map values ("vm=pool" or "vm/disk=pool")
// into VolumePlacement messages.
func parseVolumePlacements(maps []string) ([]*pb.VolumePlacement, error) {
	var out []*pb.VolumePlacement
	for _, m := range maps {
		key, pool, ok := strings.Cut(m, "=")
		if !ok || key == "" || pool == "" {
			return nil, fmt.Errorf("invalid --map %q: expected vm=pool or vm/disk=pool", m)
		}
		vm, disk, hasDisk := strings.Cut(key, "/")
		if vm == "" || (hasDisk && disk == "") {
			return nil, fmt.Errorf("invalid --map %q: empty vm or disk", m)
		}
		out = append(out, &pb.VolumePlacement{
			VmName:     vm,
			DiskName:   disk, // "" when no "/disk" → applies to all of the VM's disks
			TargetPool: pool,
		})
	}
	return out, nil
}

func printStackVolumeProgress(p *pb.StackVolumeProgress) {
	switch p.Stage {
	case pb.StackVolumeProgress_PLANNING:
		if p.VmName != "" {
			fmt.Printf("  plan   %s/%s — %s\n", p.VmName, p.DiskName, p.Status)
		} else {
			fmt.Printf("  %s\n", p.Status)
		}
	case pb.StackVolumeProgress_PER_DISK:
		fmt.Printf("  move   %s/%s [%s] %5.1f%% — %s\n", p.VmName, p.DiskName, p.Phase, p.CopyPct, p.Status)
	case pb.StackVolumeProgress_HEALTH_GATE:
		fmt.Printf("  health %s — %s\n", p.VmName, p.Status)
	case pb.StackVolumeProgress_VM_DONE:
		fmt.Printf("  ✓ %s (%d/%d VMs)\n", p.VmName, p.VmsDone, p.VmsTotal)
	case pb.StackVolumeProgress_SKIPPED:
		fmt.Printf("  skip   %s/%s — %s\n", p.VmName, p.DiskName, p.Status)
	case pb.StackVolumeProgress_ERROR:
		fmt.Printf("  ✗ %s/%s — %s\n", p.VmName, p.DiskName, p.Error)
	case pb.StackVolumeProgress_COMPLETE:
		fmt.Printf("Done: %s\n", p.Status)
	}
}
