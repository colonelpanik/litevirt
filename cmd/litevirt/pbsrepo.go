package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/litevirt/litevirt/internal/pbsstore"
)

// newBackupRepoCmd groups commands that operate on a local backup
// repository directly. Repo operations are host-local (or NFS-mounted)
// — they don't need to round-trip the daemon, which keeps GC and
// verify cheap to run from a backup host without litevirtd installed.
func newBackupRepoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repo",
		Short: "Manage litevirt backup repositories (PBS-equivalent dedup chunk store)",
	}
	cmd.AddCommand(
		newBackupRepoInitCmd(),
		newBackupRepoListCmd(),
		newBackupRepoVerifyCmd(),
		newBackupRepoGCCmd(),
		newBackupRepoPruneCmd(),
		newBackupRepoSyncCmd(),
	)
	return cmd
}

func newBackupRepoInitCmd() *cobra.Command {
	var encrypted bool
	var keyPath string
	cmd := &cobra.Command{
		Use:   "init <path>",
		Short: "Create a new backup repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if encrypted {
				r, err := pbsstore.InitEncrypted(args[0], pbsstore.EncryptionModeAESGCM)
				if err != nil {
					return err
				}
				if keyPath == "" {
					return errors.New("--encrypted requires --key-file (32 random bytes)")
				}
				key, err := readHexKey(keyPath)
				if err != nil {
					return err
				}
				if err := r.SetKey(key); err != nil {
					return err
				}
				fmt.Printf("Encrypted repository initialised at %s\n", r.Root())
				fmt.Println("Keep the key file safe — without it, no chunk can be decrypted.")
				return nil
			}
			r, err := pbsstore.Init(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Repository initialised at %s\n", r.Root())
			return nil
		},
	}
	cmd.Flags().BoolVar(&encrypted, "encrypted", false, "Mark the repo as AES-256-GCM encrypted")
	cmd.Flags().StringVar(&keyPath, "key-file", "", "Path to a hex-encoded 32-byte key (only with --encrypted)")
	return cmd
}

func newBackupRepoListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls <path>",
		Short: "List snapshots in a backup repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := pbsstore.Open(args[0])
			if err != nil {
				return err
			}
			mans, err := r.ListManifests()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TIMESTAMP\tVM\tDISK\tSIZE\tCHUNKS\tBASED ON")
			for _, m := range mans {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n",
					m.Timestamp, m.VMName, m.DiskName, m.TotalSize, len(m.Chunks), m.BasedOn)
			}
			return w.Flush()
		},
	}
}

func newBackupRepoVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <path>",
		Short: "Recompute every referenced chunk's hash and report mismatches",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := pbsstore.Open(args[0])
			if err != nil {
				return err
			}
			stats, err := pbsstore.Verify(cmd.Context(), r)
			if err != nil {
				return err
			}
			fmt.Printf("Checked %d chunks\n", stats.ChunksChecked)
			if len(stats.Mismatches) > 0 {
				fmt.Printf("Mismatched: %d\n", len(stats.Mismatches))
				for _, id := range stats.Mismatches {
					fmt.Printf("  %s\n", id)
				}
			}
			if len(stats.Missing) > 0 {
				fmt.Printf("Missing:    %d\n", len(stats.Missing))
				for _, id := range stats.Missing {
					fmt.Printf("  %s\n", id)
				}
			}
			if len(stats.Mismatches)+len(stats.Missing) == 0 {
				fmt.Println("OK")
			}
			return nil
		},
	}
}

func newBackupRepoGCCmd() *cobra.Command {
	grace := pbsstore.DefaultChunkGracePeriod
	cmd := &cobra.Command{
		Use:   "gc <path>",
		Short: "Sweep chunks no manifest references",
		Long: "Sweep chunks no manifest references.\n\n" +
			"Unreferenced chunks younger than --grace are retained: a backup in " +
			"flight writes its chunks before its manifest, so a shorter window " +
			"risks deleting a concurrent push's data. Only lower --grace when no " +
			"push can be running against this repository.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := pbsstore.Open(args[0])
			if err != nil {
				return err
			}
			stats, err := pbsstore.GCWithOptions(cmd.Context(), r, pbsstore.GCOptions{ChunkGracePeriod: grace})
			if err != nil {
				return err
			}
			fmt.Printf("Manifests scanned: %d\n", stats.ManifestsScanned)
			fmt.Printf("Live chunks:       %d\n", stats.ChunksReferenced)
			fmt.Printf("Deleted chunks:    %d\n", stats.ChunksDeleted)
			fmt.Printf("Retained (young):  %d\n", stats.ChunksSkippedYoung)
			fmt.Printf("Bytes reclaimed:   %d\n", stats.BytesReclaimed)
			return nil
		},
	}
	cmd.Flags().DurationVar(&grace, "grace", grace,
		"retain unreferenced chunks younger than this (guards against a concurrent push)")
	return cmd
}

func newBackupRepoPruneCmd() *cobra.Command {
	var keepLast, keepDaily, keepWeekly, keepMonthly, keepYearly int
	var apply bool
	cmd := &cobra.Command{
		Use:   "prune <path>",
		Short: "Apply retention policy and drop expired manifests",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := pbsstore.Open(args[0])
			if err != nil {
				return err
			}
			plan, err := pbsstore.PlanPrune(r, pbsstore.RetentionPolicy{
				KeepLast: keepLast, KeepDaily: keepDaily, KeepWeekly: keepWeekly,
				KeepMonthly: keepMonthly, KeepYearly: keepYearly,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Keep:   %d snapshots\n", len(plan.Keep))
			fmt.Printf("Delete: %d snapshots\n", len(plan.Delete))
			for _, m := range plan.Delete {
				fmt.Printf("  - %s %s/%s\n", m.Timestamp, m.VMName, m.DiskName)
			}
			if !apply {
				fmt.Println("\nDry run — re-run with --apply to delete.")
				return nil
			}
			if err := pbsstore.ApplyPrune(r, plan); err != nil {
				return err
			}
			fmt.Println("Pruned. Run `lv backup repo gc` to reclaim chunk space.")
			return nil
		},
	}
	cmd.Flags().IntVar(&keepLast, "keep-last", 0, "Keep the N most recent snapshots regardless of bucket")
	cmd.Flags().IntVar(&keepDaily, "keep-daily", 0, "Keep one snapshot per day for N days")
	cmd.Flags().IntVar(&keepWeekly, "keep-weekly", 0, "Keep one snapshot per ISO week for N weeks")
	cmd.Flags().IntVar(&keepMonthly, "keep-monthly", 0, "Keep one snapshot per month for N months")
	cmd.Flags().IntVar(&keepYearly, "keep-yearly", 0, "Keep one snapshot per year for N years")
	cmd.Flags().BoolVar(&apply, "apply", false, "Actually delete (default: dry-run)")
	return cmd
}

func newBackupRepoSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync <src> <dst>",
		Short: "Copy missing snapshots from src to dst (off-site DR)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := pbsstore.Open(args[0])
			if err != nil {
				return fmt.Errorf("open src: %w", err)
			}
			dst, err := pbsstore.Open(args[1])
			if err != nil {
				return fmt.Errorf("open dst: %w", err)
			}
			stats, err := pbsstore.SyncRepo(cmd.Context(), src, dst)
			if err != nil {
				return err
			}
			fmt.Printf("Manifests copied: %d\n", stats.ManifestsCopied)
			fmt.Printf("Chunks copied:    %d (%d skipped)\n", stats.ChunksCopied, stats.ChunksSkipped)
			fmt.Printf("Bytes copied:     %d\n", stats.BytesCopied)
			return nil
		},
	}
}

// readHexKey reads a hex-encoded 32-byte key from a file, trimming
// whitespace. The file must be 0600.
func readHexKey(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("key file %s must not be group/other-readable", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Trim trailing newlines / whitespace.
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r' || data[len(data)-1] == ' ' || data[len(data)-1] == '\t') {
		data = data[:len(data)-1]
	}
	key, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decode key (expected 64-char hex): %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key length = %d bytes, want 32", len(key))
	}
	return key, nil
}

// keep filepath imported even when no helper consumes it (anchors
// future restore-from-repo tooling).
var _ = filepath.Join
var _ context.Context = nil
