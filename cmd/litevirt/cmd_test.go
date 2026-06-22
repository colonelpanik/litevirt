package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// buildRootCmd mirrors main() registration so tests can inspect the command tree.
func buildRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "lv",
		Short: "litevirt — lightweight KVM/QEMU orchestrator",
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
		newConsoleCmd(),
		newVNCCmd(),
		newExecCmd(),
		newSSHCmd(),
		newAnsibleInventoryCmd(),
		newMigrateCmd(),
		newImageCmd(),
		newBackupCmd(),
		newSnapshotCmd(),
		newVMConfigCmd(),
		newLogsCmd(),
		newRebuildCmd(),
		newCutoverCmd(),
		newUserCmd(),
		newLoginCmd(),
		newLogoutCmd(),
		newWhoamiCmd(),
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
		newUpdateCmd(),
		newAuditCmd(),
		newStatsCmd(),
		newHealthCmd(),
		newVersionCmd(),
	)
	return root
}

func findSubcommand(parent *cobra.Command, name string) *cobra.Command {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Root command registration
// ---------------------------------------------------------------------------

func TestRootCommandHasSubcommands(t *testing.T) {
	root := buildRootCmd()

	required := []string{
		"host", "network", "compose", "lb",
		"run", "ls", "inspect", "start", "stop", "restart", "rm",
		"console", "vnc", "exec", "ssh",
		"ansible-inventory", "migrate",
		"image", "backup", "snapshot",
		"config", "logs", "rebuild", "cutover",
		"user", "login", "logout", "whoami",
		"status", "top", "events", "ui",
		"attach-disk", "detach-disk", "attach-nic", "detach-nic",
		"attach-pci", "detach-pci", "resize-disk",
		"uninstall", "cluster",
		"update", "audit", "stats", "health", "version",
	}
	for _, name := range required {
		if findSubcommand(root, name) == nil {
			t.Errorf("root command missing subcommand %q", name)
		}
	}
}

func TestRootCommandCount(t *testing.T) {
	root := buildRootCmd()
	// Ensure we haven't accidentally lost commands. Update if new ones are added.
	got := len(root.Commands())
	if got < 40 {
		t.Errorf("root has %d subcommands, expected at least 40", got)
	}
}

// ---------------------------------------------------------------------------
// Host subcommands
// ---------------------------------------------------------------------------

func TestHostHasSubcommands(t *testing.T) {
	root := buildRootCmd()
	hostCmd := findSubcommand(root, "host")
	if hostCmd == nil {
		t.Fatal("host subcommand not found on root")
	}

	required := []string{
		"init", "add", "ls", "inspect", "drain", "undrain", "rm",
		"label", "fence", "config", "rescan", "devices", "upgrade", "stats",
	}
	for _, name := range required {
		if findSubcommand(hostCmd, name) == nil {
			t.Errorf("host command missing subcommand %q", name)
		}
	}
}

func TestHostLabelHasSubcommands(t *testing.T) {
	hostCmd := newHostCmd()
	labelCmd := findSubcommand(hostCmd, "label")
	if labelCmd == nil {
		t.Fatal("host label subcommand not found")
	}
	for _, name := range []string{"set", "rm", "ls"} {
		if findSubcommand(labelCmd, name) == nil {
			t.Errorf("host label missing subcommand %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Compose subcommands
// ---------------------------------------------------------------------------

func TestComposeHasSubcommands(t *testing.T) {
	root := buildRootCmd()
	composeCmd := findSubcommand(root, "compose")
	if composeCmd == nil {
		t.Fatal("compose subcommand not found on root")
	}
	for _, name := range []string{"up", "down", "ps", "diff", "ls"} {
		if findSubcommand(composeCmd, name) == nil {
			t.Errorf("compose command missing %q subcommand", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Network subcommands
// ---------------------------------------------------------------------------

func TestNetworkHasSubcommands(t *testing.T) {
	cmd := newNetworkCmd()
	for _, name := range []string{"ls", "inspect", "create", "rm"} {
		if findSubcommand(cmd, name) == nil {
			t.Errorf("network missing subcommand %q", name)
		}
	}
}

func TestNetworkLsHasAlias(t *testing.T) {
	cmd := newNetworkCmd()
	ls := findSubcommand(cmd, "ls")
	if ls == nil {
		t.Fatal("network ls not found")
	}
	found := false
	for _, a := range ls.Aliases {
		if a == "list" {
			found = true
		}
	}
	if !found {
		t.Error("network ls missing 'list' alias")
	}
}

func TestNetworkRmHasAlias(t *testing.T) {
	cmd := newNetworkCmd()
	rm := findSubcommand(cmd, "rm")
	if rm == nil {
		t.Fatal("network rm not found")
	}
	found := false
	for _, a := range rm.Aliases {
		if a == "delete" {
			found = true
		}
	}
	if !found {
		t.Error("network rm missing 'delete' alias")
	}
}

// ---------------------------------------------------------------------------
// Image subcommands
// ---------------------------------------------------------------------------

func TestImageHasSubcommands(t *testing.T) {
	cmd := newImageCmd()
	for _, name := range []string{"pull", "ls", "import", "rm", "push", "build"} {
		if findSubcommand(cmd, name) == nil {
			t.Errorf("image missing subcommand %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// LB subcommands
// ---------------------------------------------------------------------------

func TestLBHasSubcommands(t *testing.T) {
	cmd := newLBCmd()
	for _, name := range []string{"ls", "inspect", "create", "delete", "update", "stats", "drain", "disable", "enable"} {
		if findSubcommand(cmd, name) == nil {
			t.Errorf("lb missing subcommand %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// User subcommands
// ---------------------------------------------------------------------------

func TestUserHasSubcommands(t *testing.T) {
	cmd := newUserCmd()
	for _, name := range []string{"create", "ls", "delete", "token-create", "token-revoke", "reset-admin"} {
		if findSubcommand(cmd, name) == nil {
			t.Errorf("user missing subcommand %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Backup subcommands
// ---------------------------------------------------------------------------

func TestBackupHasSubcommands(t *testing.T) {
	cmd := newBackupCmd()
	for _, name := range []string{"create", "restore"} {
		if findSubcommand(cmd, name) == nil {
			t.Errorf("backup missing subcommand %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Snapshot subcommands
// ---------------------------------------------------------------------------

func TestSnapshotHasSubcommands(t *testing.T) {
	cmd := newSnapshotCmd()
	for _, name := range []string{"create", "ls", "restore", "rm"} {
		if findSubcommand(cmd, name) == nil {
			t.Errorf("snapshot missing subcommand %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Cluster subcommands
// ---------------------------------------------------------------------------

func TestClusterHasSubcommands(t *testing.T) {
	cmd := newClusterCmd()
	for _, name := range []string{"digest", "sync"} {
		if findSubcommand(cmd, name) == nil {
			t.Errorf("cluster missing subcommand %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Argument validation tests
// ---------------------------------------------------------------------------

func TestExactArgs1Commands(t *testing.T) {
	// Commands that require exactly 1 argument.
	cmds := map[string]*cobra.Command{
		"inspect":     newInspectCmd(),
		"start":       newStartCmd(),
		"stop":        newStopCmd(),
		"restart":     newRestartCmd(),
		"rm":          newRmCmd(),
		"console":     newConsoleCmd(),
		"vnc":         newVNCCmd(),
		"stats":       newStatsCmd(),
		"update":      newUpdateCmd(),
		"rebuild":     newRebuildCmd(),
		"cutover":     newCutoverCmd(),
		"config":      newVMConfigCmd(),
		"logs":        newLogsCmd(),
		"uninstall":   newUninstallCmd(),
		"resize-disk": newResizeDiskCmd(),
		"attach-pci":  newAttachPciCmd(),
	}

	for name, cmd := range cmds {
		t.Run(name+"_zero_args", func(t *testing.T) {
			if cmd.Args == nil {
				t.Fatalf("%s: Args is nil", name)
			}
			if err := cmd.Args(cmd, nil); err == nil {
				t.Errorf("%s: expected error with zero args", name)
			}
		})
		t.Run(name+"_one_arg", func(t *testing.T) {
			if err := cmd.Args(cmd, []string{"arg1"}); err != nil {
				t.Errorf("%s: unexpected error with one arg: %v", name, err)
			}
		})
		t.Run(name+"_two_args", func(t *testing.T) {
			if err := cmd.Args(cmd, []string{"arg1", "arg2"}); err == nil {
				t.Errorf("%s: expected error with two args", name)
			}
		})
	}
}

func TestExactArgs2Commands(t *testing.T) {
	// Commands that require exactly 2 arguments.
	cmds := map[string]*cobra.Command{
		"exec":             newExecCmd(), // MinimumNArgs(2), not ExactArgs(2)
		"migrate":          newMigrateCmd(),
		"attach-disk":      newAttachDiskCmd(),
		"detach-disk":      newDetachDiskCmd(),
		"attach-nic":       newAttachNicCmd(),
		"detach-nic":       newDetachNicCmd(),
		"detach-pci":       newDetachPciCmd(),
		"snapshot-create":  newSnapshotCreateCmd(),
		"snapshot-restore": newSnapshotRestoreCmd(),
		"snapshot-rm":      newSnapshotRmCmd(),
	}

	for name, cmd := range cmds {
		t.Run(name+"_zero_args", func(t *testing.T) {
			if cmd.Args == nil {
				t.Fatalf("%s: Args is nil", name)
			}
			if err := cmd.Args(cmd, nil); err == nil {
				t.Errorf("%s: expected error with zero args", name)
			}
		})
		t.Run(name+"_one_arg", func(t *testing.T) {
			if err := cmd.Args(cmd, []string{"arg1"}); err == nil {
				t.Errorf("%s: expected error with one arg", name)
			}
		})
		t.Run(name+"_two_args", func(t *testing.T) {
			if err := cmd.Args(cmd, []string{"arg1", "arg2"}); err != nil {
				t.Errorf("%s: unexpected error with two args: %v", name, err)
			}
		})
	}
}

func TestMinimumNArgs2Commands(t *testing.T) {
	// host label set and host label rm require MinimumNArgs(2).
	cmds := map[string]*cobra.Command{
		"host-label-set": newHostLabelSetCmd(),
		"host-label-rm":  newHostLabelRmCmd(),
	}
	for name, cmd := range cmds {
		t.Run(name+"_zero_args", func(t *testing.T) {
			if err := cmd.Args(cmd, nil); err == nil {
				t.Errorf("%s: expected error with zero args", name)
			}
		})
		t.Run(name+"_one_arg", func(t *testing.T) {
			if err := cmd.Args(cmd, []string{"host"}); err == nil {
				t.Errorf("%s: expected error with one arg", name)
			}
		})
		t.Run(name+"_two_args", func(t *testing.T) {
			if err := cmd.Args(cmd, []string{"host", "key=val"}); err != nil {
				t.Errorf("%s: unexpected error with two args: %v", name, err)
			}
		})
		t.Run(name+"_three_args", func(t *testing.T) {
			if err := cmd.Args(cmd, []string{"host", "a=1", "b=2"}); err != nil {
				t.Errorf("%s: unexpected error with three args: %v", name, err)
			}
		})
	}
}

func TestMinimumNArgs1Commands(t *testing.T) {
	// ssh requires MinimumNArgs(1)
	cmd := newSSHCmd()
	if cmd.Args == nil {
		t.Fatal("ssh Args is nil")
	}
	if err := cmd.Args(cmd, nil); err == nil {
		t.Error("ssh: expected error with zero args")
	}
	if err := cmd.Args(cmd, []string{"vm1"}); err != nil {
		t.Errorf("ssh: unexpected error with one arg: %v", err)
	}
	if err := cmd.Args(cmd, []string{"vm1", "ls", "-la"}); err != nil {
		t.Errorf("ssh: unexpected error with three args: %v", err)
	}
}

func TestMaximumNArgs1Commands(t *testing.T) {
	cmds := map[string]*cobra.Command{
		"host-init":   newHostInitCmd(),
		"host-rescan": newHostRescanCmd(),
	}
	for name, cmd := range cmds {
		t.Run(name+"_zero_args", func(t *testing.T) {
			if err := cmd.Args(cmd, nil); err != nil {
				t.Errorf("%s: unexpected error with zero args: %v", name, err)
			}
		})
		t.Run(name+"_one_arg", func(t *testing.T) {
			if err := cmd.Args(cmd, []string{"arg1"}); err != nil {
				t.Errorf("%s: unexpected error with one arg: %v", name, err)
			}
		})
		t.Run(name+"_two_args", func(t *testing.T) {
			if err := cmd.Args(cmd, []string{"arg1", "arg2"}); err == nil {
				t.Errorf("%s: expected error with two args", name)
			}
		})
	}
}

func TestNoArgsCommands(t *testing.T) {
	// Commands with no Args validator should accept any number of args
	// (they use RunE but don't set Args).
	cmds := map[string]*cobra.Command{
		"health":  newHealthCmd(),
		"status":  newStatusCmd(),
		"login":   newLoginCmd(),
		"logout":  newLogoutCmd(),
		"whoami":  newWhoamiCmd(),
		"version": newVersionCmd(),
	}
	for name, cmd := range cmds {
		t.Run(name, func(t *testing.T) {
			if cmd.Args != nil {
				// If Args is set, verify it accepts zero args.
				if err := cmd.Args(cmd, nil); err != nil {
					t.Errorf("%s: unexpected error with zero args: %v", name, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Flag registration tests
// ---------------------------------------------------------------------------

func TestHostInitFlags(t *testing.T) {
	cmd := newHostInitCmd()
	checkFlags(t, cmd, map[string]string{
		"name":  "",
		"local": "false",
	})
}

func TestHostAddFlags(t *testing.T) {
	cmd := newHostAddCmd()
	if cmd.Flags().Lookup("name") == nil {
		t.Error("host add missing --name flag")
	}
}

func TestHostDrainFlags(t *testing.T) {
	cmd := newHostDrainCmd()
	checkFlags(t, cmd, map[string]string{
		"parallel": "2",
	})
}

func TestHostRmFlags(t *testing.T) {
	cmd := newHostRmCmd()
	checkFlags(t, cmd, map[string]string{
		"force": "false",
	})
}

func TestHostFenceFlags(t *testing.T) {
	cmd := newHostFenceCmd()
	checkFlags(t, cmd, map[string]string{
		"confirmed": "false",
	})
}

func TestHostConfigFlags(t *testing.T) {
	cmd := newHostConfigCmd()
	checkFlags(t, cmd, map[string]string{
		"fence-strategy": "",
		"ipmi-address":   "",
		"ipmi-user":      "",
		"ipmi-pass":      "",
		"watchdog-dev":   "",
	})
}

func TestHostDevicesFlags(t *testing.T) {
	cmd := newHostDevicesCmd()
	checkFlags(t, cmd, map[string]string{
		"type": "",
	})
}

func TestHostUpgradeFlags(t *testing.T) {
	cmd := newHostUpgradeCmd()
	checkFlags(t, cmd, map[string]string{
		"binary": "/usr/local/bin/litevirt",
		"yes":    "false",
	})
	// Check shorthand for --yes
	f := cmd.Flags().Lookup("yes")
	if f.Shorthand != "y" {
		t.Errorf("--yes shorthand = %q, want %q", f.Shorthand, "y")
	}
}

func TestRunFlags(t *testing.T) {
	cmd := newRunCmd()
	checkFlags(t, cmd, map[string]string{
		"name":   "",
		"cpu":    "2",
		"memory": "4096",
		"image":  "",
		"disk":   "20G",
		"host":   "",
	})
}

func TestLsFlags(t *testing.T) {
	cmd := newLsCmd()
	checkFlags(t, cmd, map[string]string{
		"stack": "",
		"host":  "",
	})
}

func TestStopFlags(t *testing.T) {
	cmd := newStopCmd()
	checkFlags(t, cmd, map[string]string{
		"force": "false",
	})
}

func TestRmFlags(t *testing.T) {
	cmd := newRmCmd()
	checkFlags(t, cmd, map[string]string{
		"keep-disks": "false",
	})
}

func TestUpdateFlags(t *testing.T) {
	cmd := newUpdateCmd()
	checkFlags(t, cmd, map[string]string{
		"cpu":                  "0",
		"memory":               "0",
		"disable-vnc":          "false",
		"restart":              "",
		"restart-max-attempts": "0",
		"restart-delay":        "",
		"restart-window":       "",
		"onboot":               "false",
		"startup-order":        "0",
		"start-delay":          "0",
		"stop-delay":           "0",
		"machine":              "",
		"firmware":             "",
		"guest-agent":          "false",
		"min-mem":              "0",
		"max-mem":              "0",
	})
}

// `lv update <vm>` with no field flags must error before contacting the daemon.
func TestUpdate_NoFlagsErrors(t *testing.T) {
	cmd := newUpdateCmd()
	cmd.SetArgs([]string{"some-vm"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error when no field flags are specified")
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Errorf("error = %q, want it to mention specifying at least one field", err.Error())
	}
}

func TestMigrateFlags(t *testing.T) {
	cmd := newMigrateCmd()
	checkFlags(t, cmd, map[string]string{
		"cold": "false",
	})
}

func TestAuditFlags(t *testing.T) {
	// `lv audit` is now a parent command; the --limit flag moved
	// to the `ls` subcommand alongside `verify` and `export`.
	cmd := newAuditCmd()
	lsCmd, _, err := cmd.Find([]string{"ls"})
	if err != nil || lsCmd == nil {
		t.Fatalf("audit ls subcommand missing: %v", err)
	}
	checkFlags(t, lsCmd, map[string]string{
		"limit": "50",
	})
}

func TestComposeUpFlags(t *testing.T) {
	cmd := newUpCmd()
	checkFlags(t, cmd, map[string]string{
		"file": "litevirt-compose.yaml",
		"yes":  "false",
	})
	f := cmd.Flags().Lookup("file")
	if f.Shorthand != "f" {
		t.Errorf("--file shorthand = %q, want %q", f.Shorthand, "f")
	}
	y := cmd.Flags().Lookup("yes")
	if y.Shorthand != "y" {
		t.Errorf("--yes shorthand = %q, want %q", y.Shorthand, "y")
	}
}

func TestComposeDownFlags(t *testing.T) {
	cmd := newDownCmd()
	checkFlags(t, cmd, map[string]string{
		"file": "litevirt-compose.yaml",
		"name": "",
		"yes":  "false",
	})
}

func TestComposePsFlags(t *testing.T) {
	cmd := newPsCmd()
	checkFlags(t, cmd, map[string]string{
		"file": "litevirt-compose.yaml",
	})
}

func TestComposeDiffFlags(t *testing.T) {
	cmd := newDiffCmd()
	checkFlags(t, cmd, map[string]string{
		"file": "litevirt-compose.yaml",
	})
}

func TestImagePullFlags(t *testing.T) {
	cmd := newImagePullCmd()
	checkFlags(t, cmd, map[string]string{
		"name":     "",
		"format":   "qcow2",
		"checksum": "",
	})
}

func TestImageImportFlags(t *testing.T) {
	cmd := newImageImportCmd()
	checkFlags(t, cmd, map[string]string{
		"name":     "",
		"format":   "qcow2",
		"checksum": "",
	})
}

func TestImagePushFlags(t *testing.T) {
	cmd := newImagePushCmd()
	if cmd.Flags().Lookup("to") == nil {
		t.Error("image push missing --to flag")
	}
}

func TestImageBuildFlags(t *testing.T) {
	cmd := newImageBuildCmd()
	if cmd.Flags().Lookup("name") == nil {
		t.Error("image build missing --name flag")
	}
}

func TestNetworkCreateFlags(t *testing.T) {
	cmd := newNetworkCreateCmd()
	checkFlags(t, cmd, map[string]string{
		"type":        "bridge",
		"interface":   "",
		"vlan":        "0",
		"vni":         "0",
		"underlay":    "",
		"subnet":      "",
		"dhcp":        "false",
		"pf":          "",
		"spoof-check": "false",
	})
}

func TestNetworkRmFlags(t *testing.T) {
	cmd := newNetworkRmCmd()
	checkFlags(t, cmd, map[string]string{
		"force": "false",
	})
}

func TestAttachDiskFlags(t *testing.T) {
	cmd := newAttachDiskCmd()
	checkFlags(t, cmd, map[string]string{
		"size": "20G",
		"bus":  "virtio",
	})
}

func TestAttachNicFlags(t *testing.T) {
	cmd := newAttachNicCmd()
	checkFlags(t, cmd, map[string]string{
		"model": "virtio",
		"mac":   "",
	})
}

func TestAttachPciFlags(t *testing.T) {
	cmd := newAttachPciCmd()
	checkFlags(t, cmd, map[string]string{
		"type":   "gpu",
		"vendor": "",
		"count":  "1",
		"sriov":  "false",
	})
}

func TestResizeDiskFlags(t *testing.T) {
	cmd := newResizeDiskCmd()
	checkFlags(t, cmd, map[string]string{
		"disk": "root",
		"size": "",
	})
}

func TestUninstallFlags(t *testing.T) {
	cmd := newUninstallCmd()
	checkFlags(t, cmd, map[string]string{
		"confirmed": "false",
		"keep-data": "false",
	})
}

func TestSSHFlags(t *testing.T) {
	cmd := newSSHCmd()
	checkFlags(t, cmd, map[string]string{
		"user":     "",
		"port":     "0",
		"identity": "",
	})
	// Check shorthands
	for flag, short := range map[string]string{"user": "u", "port": "p", "identity": "i"} {
		f := cmd.Flags().Lookup(flag)
		if f == nil {
			t.Errorf("ssh missing flag --%s", flag)
			continue
		}
		if f.Shorthand != short {
			t.Errorf("--%s shorthand = %q, want %q", flag, f.Shorthand, short)
		}
	}
}

func TestLogsFlags(t *testing.T) {
	cmd := newLogsCmd()
	checkFlags(t, cmd, map[string]string{
		"follow": "false",
		"lines":  "50",
	})
	f := cmd.Flags().Lookup("follow")
	if f.Shorthand != "f" {
		t.Errorf("--follow shorthand = %q, want %q", f.Shorthand, "f")
	}
	n := cmd.Flags().Lookup("lines")
	if n.Shorthand != "n" {
		t.Errorf("--lines shorthand = %q, want %q", n.Shorthand, "n")
	}
}

func TestEventsFlags(t *testing.T) {
	cmd := newEventsCmd()
	if cmd.Flags().Lookup("type") == nil {
		t.Error("events missing --type flag")
	}
}

func TestTopFlags(t *testing.T) {
	cmd := newTopCmd()
	checkFlags(t, cmd, map[string]string{
		"interval": "3s",
	})
}

func TestUIFlags(t *testing.T) {
	cmd := newUICmd()
	checkFlags(t, cmd, map[string]string{
		"open": "false",
	})
}

func TestVMConfigFlags(t *testing.T) {
	cmd := newVMConfigCmd()
	checkFlags(t, cmd, map[string]string{
		"ip":      "",
		"network": "production",
		"boot":    "",
	})
}

func TestBackupCreateFlags(t *testing.T) {
	cmd := newBackupCreateCmd()
	checkFlags(t, cmd, map[string]string{
		"out": "",
	})
	f := cmd.Flags().Lookup("out")
	if f.Shorthand != "o" {
		t.Errorf("--out shorthand = %q, want %q", f.Shorthand, "o")
	}
}

func TestBackupRestoreFlags(t *testing.T) {
	cmd := newBackupRestoreCmd()
	checkFlags(t, cmd, map[string]string{
		"name":    "",
		"cpu":     "2",
		"memory":  "4096",
		"network": "",
	})
}

func TestUserCreateFlags(t *testing.T) {
	cmd := newUserCreateCmd()
	checkFlags(t, cmd, map[string]string{
		"role": "viewer",
	})
}

func TestTokenCreateFlags(t *testing.T) {
	cmd := newTokenCreateCmd()
	checkFlags(t, cmd, map[string]string{
		"expires": "",
	})
}

func TestAnsibleInventoryFlags(t *testing.T) {
	cmd := newAnsibleInventoryCmd()
	checkFlags(t, cmd, map[string]string{
		"list": "false",
		"host": "",
	})
}

func TestLBCreateFlags(t *testing.T) {
	cmd := newLBCreateCmd()
	for _, name := range []string{"vip", "algorithm", "port", "host", "backend", "vm-backend"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("lb create missing --%s flag", name)
		}
	}
	f := cmd.Flags().Lookup("algorithm")
	if f.DefValue != "roundrobin" {
		t.Errorf("--algorithm default = %q, want %q", f.DefValue, "roundrobin")
	}
}

func TestLBUpdateFlags(t *testing.T) {
	cmd := newLBUpdateCmd()
	for _, name := range []string{"algorithm", "vip", "add-backend", "remove-backend", "add-vm-backend", "remove-vm-backend", "port", "host"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("lb update missing --%s flag", name)
		}
	}
}

func TestLBDrainFlags(t *testing.T) {
	cmd := newLBDrainCmd()
	if cmd.Flags().Lookup("backend") == nil {
		t.Error("lb drain missing --backend flag")
	}
}

func TestLBDisableFlags(t *testing.T) {
	cmd := newLBDisableCmd()
	if cmd.Flags().Lookup("backend") == nil {
		t.Error("lb disable missing --backend flag")
	}
}

func TestLBEnableFlags(t *testing.T) {
	cmd := newLBEnableCmd()
	if cmd.Flags().Lookup("backend") == nil {
		t.Error("lb enable missing --backend flag")
	}
}

// ---------------------------------------------------------------------------
// Use string tests — verify exact Use patterns
// ---------------------------------------------------------------------------

func TestCommandUseStrings(t *testing.T) {
	cases := map[string]struct {
		cmd  *cobra.Command
		want string
	}{
		"host":              {newHostCmd(), "host"},
		"network":           {newNetworkCmd(), "network"},
		"compose":           {newComposeCmd(), "compose"},
		"lb":                {newLBCmd(), "lb"},
		"run":               {newRunCmd(), "run"},
		"ls":                {newLsCmd(), "ls"},
		"inspect":           {newInspectCmd(), "inspect <vm>"},
		"start":             {newStartCmd(), "start <vm>"},
		"stop":              {newStopCmd(), "stop <vm>"},
		"restart":           {newRestartCmd(), "restart <vm>"},
		"rm":                {newRmCmd(), "rm <vm>"},
		"console":           {newConsoleCmd(), "console <vm>"},
		"vnc":               {newVNCCmd(), "vnc <vm>"},
		"exec":              {newExecCmd(), "exec <vm> <command> [args...]"},
		"ssh":               {newSSHCmd(), "ssh <vm-name> [-- command...]"},
		"migrate":           {newMigrateCmd(), "migrate <vm> <target-host>"},
		"stats":             {newStatsCmd(), "stats <vm>"},
		"update":            {newUpdateCmd(), "update <vm>"},
		"rebuild":           {newRebuildCmd(), "rebuild <vm>"},
		"cutover":           {newCutoverCmd(), "cutover <vm>"},
		"config":            {newVMConfigCmd(), "config <vm>"},
		"logs":              {newLogsCmd(), "logs <vm>"},
		"audit":             {newAuditCmd(), "audit"},
		"health":            {newHealthCmd(), "health"},
		"status":            {newStatusCmd(), "status"},
		"top":               {newTopCmd(), "top"},
		"events":            {newEventsCmd(), "events [vm]"},
		"ui":                {newUICmd(), "ui"},
		"login":             {newLoginCmd(), "login"},
		"logout":            {newLogoutCmd(), "logout"},
		"whoami":            {newWhoamiCmd(), "whoami"},
		"uninstall":         {newUninstallCmd(), "uninstall <hostname>"},
		"attach-disk":       {newAttachDiskCmd(), "attach-disk <vm> <disk-name>"},
		"detach-disk":       {newDetachDiskCmd(), "detach-disk <vm> <disk-name>"},
		"attach-nic":        {newAttachNicCmd(), "attach-nic <vm> <network>"},
		"detach-nic":        {newDetachNicCmd(), "detach-nic <vm> <mac>"},
		"attach-pci":        {newAttachPciCmd(), "attach-pci <vm>"},
		"detach-pci":        {newDetachPciCmd(), "detach-pci <vm> <pci-address>"},
		"ansible-inventory": {newAnsibleInventoryCmd(), "ansible-inventory"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.cmd.Use != tc.want {
				t.Errorf("Use = %q, want %q", tc.cmd.Use, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Short description non-empty
// ---------------------------------------------------------------------------

func TestAllSubcommandsHaveShortDescription(t *testing.T) {
	root := buildRootCmd()
	for _, cmd := range root.Commands() {
		if cmd.Short == "" {
			t.Errorf("command %q has empty Short description", cmd.Name())
		}
		for _, sub := range cmd.Commands() {
			if sub.Short == "" {
				t.Errorf("command %q > %q has empty Short description", cmd.Name(), sub.Name())
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Pure utility function tests
// ---------------------------------------------------------------------------

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1023, "1023 B"},
		{1 << 20, "1.0 MiB"},
		{5 * (1 << 20), "5.0 MiB"},
		{512 * (1 << 20), "512.0 MiB"},
		{1 << 30, "1.0 GiB"},
		{3 * (1 << 30), "3.0 GiB"},
		{(1 << 30) + (1 << 29), "1.5 GiB"},
		{2*(1<<30) + 7*(1<<30)/10, "2.7 GiB"},
	}
	for _, tc := range cases {
		got := formatBytes(tc.input)
		if got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSafePct(t *testing.T) {
	cases := []struct {
		used, total int64
		want        float64
	}{
		{0, 0, 0},
		{0, 100, 0},
		{50, 100, 50},
		{100, 100, 100},
		{1, 3, 100.0 / 3.0},
	}
	for _, tc := range cases {
		got := safePct(tc.used, tc.total)
		diff := got - tc.want
		if diff < 0 {
			diff = -diff
		}
		if diff > 0.01 {
			t.Errorf("safePct(%d, %d) = %f, want %f", tc.used, tc.total, got, tc.want)
		}
	}
}

func TestSplitKeyValue(t *testing.T) {
	cases := []struct {
		input string
		key   string
		val   string
		isNil bool
	}{
		{"key=value", "key", "value", false},
		{"a=", "a", "", false},
		{"foo=bar=baz", "foo", "bar=baz", false},
		{"noequals", "", "", true},
		{"=startsWithEqual", "", "startsWithEqual", false},
	}
	for _, tc := range cases {
		got := splitKeyValue(tc.input)
		if tc.isNil {
			if got != nil {
				t.Errorf("splitKeyValue(%q) = %v, want nil", tc.input, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("splitKeyValue(%q) = nil, want [%q, %q]", tc.input, tc.key, tc.val)
			continue
		}
		if got[0] != tc.key || got[1] != tc.val {
			t.Errorf("splitKeyValue(%q) = [%q, %q], want [%q, %q]", tc.input, got[0], got[1], tc.key, tc.val)
		}
	}
}

func TestResourceBar(t *testing.T) {
	cases := []struct {
		used, total, width int
		want               string
	}{
		{0, 0, 10, "░░░░░░░░░░"},
		{0, 100, 10, "░░░░░░░░░░"},
		{50, 100, 10, "█████░░░░░"},
		{100, 100, 10, "██████████"},
		{200, 100, 10, "██████████"}, // over 100% capped
		{1, 4, 8, "██░░░░░░"},
	}
	for _, tc := range cases {
		got := resourceBar(tc.used, tc.total, tc.width)
		if got != tc.want {
			t.Errorf("resourceBar(%d, %d, %d) = %q, want %q", tc.used, tc.total, tc.width, got, tc.want)
		}
	}
}

func TestContainsStr(t *testing.T) {
	if containsStr(nil, "x") {
		t.Error("containsStr(nil, x) should be false")
	}
	if containsStr([]string{"a", "b"}, "c") {
		t.Error("containsStr([a,b], c) should be false")
	}
	if !containsStr([]string{"a", "b"}, "b") {
		t.Error("containsStr([a,b], b) should be true")
	}
}

func TestParsePort(t *testing.T) {
	cases := []struct {
		input   string
		listen  int32
		target  int32
		proto   string
		wantErr bool
	}{
		{"80:8080", 80, 8080, "tcp", false},
		{"443:8443/tcp", 443, 8443, "tcp", false},
		{"53:53/udp", 53, 53, "udp", false},
		{"invalid", 0, 0, "", true},
		{"abc:def", 0, 0, "", true},
		{"80:abc", 0, 0, "", true},
	}
	for _, tc := range cases {
		p, err := parsePort(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parsePort(%q): expected error", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePort(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if p.Listen != tc.listen || p.Target != tc.target || p.Protocol != tc.proto {
			t.Errorf("parsePort(%q) = {%d, %d, %q}, want {%d, %d, %q}",
				tc.input, p.Listen, p.Target, p.Protocol,
				tc.listen, tc.target, tc.proto)
		}
	}
}

func TestParseBackend(t *testing.T) {
	cases := []struct {
		input   string
		name    string
		addr    string
		wantErr bool
	}{
		{"web=10.0.0.1:80", "web", "10.0.0.1:80", false},
		{"api=10.0.0.2:8080", "api", "10.0.0.2:8080", false},
		{"noequals", "", "", true},
	}
	for _, tc := range cases {
		b, err := parseBackend(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseBackend(%q): expected error", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseBackend(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if b.Name != tc.name || b.Address != tc.addr {
			t.Errorf("parseBackend(%q) = {%q, %q}, want {%q, %q}",
				tc.input, b.Name, b.Address, tc.name, tc.addr)
		}
	}
}

func TestFirstIP(t *testing.T) {
	if got := firstIP(&pb.VM{}); got != "" {
		t.Errorf("firstIP(no interfaces) = %q, want empty", got)
	}
	if got := firstIP(&pb.VM{Interfaces: []*pb.VMInterface{{Ip: ""}}}); got != "" {
		t.Errorf("firstIP(empty IP) = %q, want empty", got)
	}
	if got := firstIP(&pb.VM{Interfaces: []*pb.VMInterface{{Ip: "10.0.0.1"}}}); got != "10.0.0.1" {
		t.Errorf("firstIP = %q, want %q", got, "10.0.0.1")
	}
	// Multiple interfaces, first with IP wins.
	vm := &pb.VM{Interfaces: []*pb.VMInterface{
		{Ip: ""},
		{Ip: "10.0.0.2"},
		{Ip: "10.0.0.3"},
	}}
	if got := firstIP(vm); got != "10.0.0.2" {
		t.Errorf("firstIP(multi) = %q, want %q", got, "10.0.0.2")
	}
}

func TestHostStateShort(t *testing.T) {
	cases := []struct {
		state pb.HostState
		want  string
	}{
		{pb.HostState_HOST_ACTIVE, "active"},
		{pb.HostState_HOST_DRAINING, "drain"},
		{pb.HostState_HOST_MAINTENANCE, "maint"},
		{pb.HostState_HOST_SUSPECT, "susp"},
		{pb.HostState_HOST_OFFLINE, "OFFLN"},
		{pb.HostState(999), "?"},
	}
	for _, tc := range cases {
		got := hostStateShort(tc.state)
		if got != tc.want {
			t.Errorf("hostStateShort(%v) = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestPhaseLabel(t *testing.T) {
	cases := []struct {
		phase pb.MigratePhase
		want  string
	}{
		{pb.MigratePhase_MIGRATE_VALIDATING, "validating"},
		{pb.MigratePhase_MIGRATE_PREPARING, "preparing"},
		{pb.MigratePhase_MIGRATE_COPYING, "copying"},
		{pb.MigratePhase_MIGRATE_CONVERGING, "converging"},
		{pb.MigratePhase_MIGRATE_CUTOVER, "cutover"},
		{pb.MigratePhase_MIGRATE_COMPLETING, "completing"},
		{pb.MigratePhase_MIGRATE_DONE, "done"},
		{pb.MigratePhase_MIGRATE_FAILED, "FAILED"},
		{pb.MigratePhase(999), "unknown"},
	}
	for _, tc := range cases {
		got := phaseLabel(tc.phase)
		if got != tc.want {
			t.Errorf("phaseLabel(%v) = %q, want %q", tc.phase, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Version command output
// ---------------------------------------------------------------------------

func TestVersionCommandRuns(t *testing.T) {
	cmd := newVersionCmd()
	if cmd.Run == nil {
		t.Error("version command Run is nil")
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// checkFlags verifies that all expected flags exist with expected default values.
func checkFlags(t *testing.T, cmd *cobra.Command, expected map[string]string) {
	t.Helper()
	for name, defVal := range expected {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("missing flag --%s", name)
			continue
		}
		if f.DefValue != defVal {
			t.Errorf("--%s default = %q, want %q", name, f.DefValue, defVal)
		}
	}
}
