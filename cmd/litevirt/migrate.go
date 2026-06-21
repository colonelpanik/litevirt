package main

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newMigrateCmd() *cobra.Command {
	var (
		cold        bool
		withStorage bool
	)

	cmd := &cobra.Command{
		Use:   "migrate <vm> <target-host>",
		Short: "Live-migrate a VM to another host",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]
			targetHost := args[1]

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				strategy := pb.MigrateStrategy_MIGRATE_LIVE
				if cold {
					strategy = pb.MigrateStrategy_MIGRATE_COLD
				}

				stream, err := c.MigrateVM(ctx, &pb.MigrateVMRequest{
					VmName:      vmName,
					TargetHost:  targetHost,
					Strategy:    strategy,
					WithStorage: withStorage,
				})
				if err != nil {
					return err
				}

				for {
					prog, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						return err
					}
					fmt.Printf("  %-14s  %.0f%%\n", phaseLabel(prog.Phase), prog.MemoryPct)
					if prog.Phase == pb.MigratePhase_MIGRATE_DONE {
						break
					}
					if prog.Phase == pb.MigratePhase_MIGRATE_FAILED {
						return fmt.Errorf("migration failed")
					}
				}

				fmt.Printf("VM %q migrated to %s\n", vmName, targetHost)
				return nil
			})
		},
	}

	cmd.Flags().BoolVar(&cold, "cold", false, "Cold migration (VM must be stopped)")
	cmd.Flags().BoolVar(&withStorage, "with-storage", false, "Copy storage to target host during migration")
	return cmd
}

func phaseLabel(p pb.MigratePhase) string {
	switch p {
	case pb.MigratePhase_MIGRATE_VALIDATING:
		return "validating"
	case pb.MigratePhase_MIGRATE_PREPARING:
		return "preparing"
	case pb.MigratePhase_MIGRATE_COPYING:
		return "copying"
	case pb.MigratePhase_MIGRATE_CONVERGING:
		return "converging"
	case pb.MigratePhase_MIGRATE_CUTOVER:
		return "cutover"
	case pb.MigratePhase_MIGRATE_COMPLETING:
		return "completing"
	case pb.MigratePhase_MIGRATE_DONE:
		return "done"
	case pb.MigratePhase_MIGRATE_FAILED:
		return "FAILED"
	default:
		return "unknown"
	}
}
