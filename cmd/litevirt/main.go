package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	// Handle --version before cobra so the output format is stable and
	// independent of the command tree. `lv host upgrade` execs `<binary>
	// --version` and parses the `version=` token to decide which hosts are
	// outdated, so this line is load-bearing — keep the `version=` token.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-version":
			fmt.Printf("litevirt version=%s commit=%s\n", version, commit)
			return
		}
	}
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// newRootCmd builds the fully-wired `litevirt` root command — both the CLI
// subcommands and `daemon` (the server). main() and the test harness use it so
// tests exercise the exact command set that ships.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "litevirt",
		Short:         "litevirt — lightweight KVM/QEMU orchestrator",
		Long:          "Manage KVM/QEMU virtual machines across bare-metal hosts. Run the server with `litevirt daemon`.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newHostCmd(),
		newNetworkCmd(),
		newComposeCmd(),
		newLBCmd(),
		newRunCmd(),
		newLsCmd(),
		newInspectCmd(),
		newStartCmd(),
		newStopCmd(),
		newRestartCmd(),
		newRmCmd(),
		newCloneCmd(),
		newTemplateCmd(),
		newConsoleCmd(),
		newVNCCmd(),
		newSpiceCmd(),
		newExecCmd(),
		newSSHCmd(),
		newAnsibleInventoryCmd(),
		newMigrateCmd(),
		newMoveVolumeCmd(),
		newReplicateVolumeCmd(),
		newReplicationCmd(),
		newStackCmd(),
		newImageCmd(),
		newImportCmd(),
		newBackupCmd(),
		newCTCmd(),
		newSGCmd(),
		newFirewallCmd(),
		newSnapshotCmd(),
		newSetMemoryCmd(),
		newMappingCmd(),
		newNotifyCmd(),
		newRegistryCmd(),
		newACMECmd(),
		newVMConfigCmd(),
		newLogsCmd(),
		newRebuildCmd(),
		newCutoverCmd(),
		newUserCmd(),
		newLoginCmd(),
		newLogoutCmd(),
		newWhoamiCmd(),
		newSessionCmd(),
		newTwoFactorCmd(),
		newStatusCmd(),
		newTopCmd(),
		newEventsCmd(),
		newUICmd(),
		newAttachDiskCmd(),
		newDetachDiskCmd(),
		newAttachNicCmd(),
		newDetachNicCmd(),
		newAttachPciCmd(),
		newDetachPciCmd(),
		newResizeDiskCmd(),
		newUninstallCmd(),
		newClusterCmd(),
		newRebalanceCmd(),
		newRegionCmd(),
		newProjectCmd(),
		newPoolCmd(),
		newRoleCmd(),
		newUpdateCmd(),
		newAuditCmd(),
		newStatsCmd(),
		newHealthCmd(),
		newDoctorCmd(),
		newMCPCmd(),
		newVersionCmd(),
		newDaemonCmd(),
		newSchemaMigrateCmd(),
		newGitopsCmd(),
	)

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("litevirt %s (%s)\n", version, commit)
		},
	}
}
