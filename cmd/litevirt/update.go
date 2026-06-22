package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newUpdateCmd() *cobra.Command {
	var (
		cpu        int32
		memory     int32
		cpuMode    string
		disableVNC bool
		// live metadata (applied while running, no restart)
		restart      string
		restartMax   int32
		restartDelay string
		restartWin   string
		onboot       bool
		startupOrder int32
		startDelay   int32
		stopDelay    int32
		// redefine-class (require the VM stopped)
		machine    string
		firmware   string
		guestAgent bool
		minMem     int32
		maxMem     int32
	)
	cmd := &cobra.Command{
		Use:   "update <vm>",
		Short: "Reconfigure a VM (restart policy, autostart, resources, ...)",
		Long: `Reconfigure an existing VM.

Restart policy, autostart (onboot) and startup ordering apply LIVE — the VM does
not need to be stopped. CPU, memory, CPU mode, VNC, machine type, firmware,
guest-agent and the balloon min/max bounds change the domain definition, so the
VM must be stopped for those.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			any := false
			for _, n := range []string{"cpu", "memory", "cpu-mode", "disable-vnc",
				"restart", "restart-max-attempts", "restart-delay", "restart-window",
				"onboot", "startup-order", "start-delay", "stop-delay",
				"machine", "firmware", "guest-agent", "min-mem", "max-mem"} {
				if f.Changed(n) {
					any = true
					break
				}
			}
			if !any {
				return fmt.Errorf("specify at least one field to change (see --help)")
			}

			req := &pb.UpdateVMRequest{Name: args[0]}
			// Redefine-class: 0/"" already means "unchanged" server-side.
			if f.Changed("cpu") {
				req.Cpu = cpu
			}
			if f.Changed("memory") {
				req.MemoryMib = memory
			}
			if f.Changed("cpu-mode") {
				req.CpuMode = cpuMode
			}
			req.DisableVnc = disableVNC
			if f.Changed("machine") {
				req.Machine = machine
			}
			if f.Changed("firmware") {
				req.Firmware = firmware
			}
			if f.Changed("guest-agent") {
				req.GuestAgent = &guestAgent
			}
			if f.Changed("min-mem") {
				req.MinMemoryMib = &minMem
			}
			if f.Changed("max-mem") {
				req.MaxMemoryMib = &maxMem
			}
			// Live metadata: only send what changed (presence-detected).
			if f.Changed("restart") || f.Changed("restart-max-attempts") ||
				f.Changed("restart-delay") || f.Changed("restart-window") {
				// condition "none"/"" clears the policy server-side.
				req.Restart = &pb.RestartPolicy{
					Condition:   restart,
					MaxAttempts: restartMax,
					Delay:       restartDelay,
					Window:      restartWin,
				}
			}
			if f.Changed("onboot") {
				req.Onboot = &onboot
			}
			if f.Changed("startup-order") {
				req.StartupOrder = &startupOrder
			}
			if f.Changed("start-delay") {
				req.StartDelaySec = &startDelay
			}
			if f.Changed("stop-delay") {
				req.StopDelaySec = &stopDelay
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.UpdateVM(ctx, req)
				if err != nil {
					return fmt.Errorf("update VM: %w", err)
				}
				fmt.Printf("VM %s updated (cpu: %d, memory: %d MiB, state: %s)\n",
					vm.Name, vm.CpuActual, vm.MemActualMib, vm.State)
				return nil
			})
		},
	}
	cmd.Flags().Int32Var(&cpu, "cpu", 0, "Number of vCPUs (VM must be stopped)")
	cmd.Flags().Int32Var(&memory, "memory", 0, "Memory in MiB (VM must be stopped)")
	cmd.Flags().StringVar(&cpuMode, "cpu-mode", "", "CPU mode: host-passthrough|host-model|custom (VM must be stopped)")
	cmd.Flags().BoolVar(&disableVNC, "disable-vnc", false, "Disable VNC access (VM must be stopped)")
	cmd.Flags().StringVar(&restart, "restart", "", "Auto-restart policy: none|on-failure|always (live; none clears it)")
	cmd.Flags().Int32Var(&restartMax, "restart-max-attempts", 0, "Max restart attempts within the window (0 = unlimited)")
	cmd.Flags().StringVar(&restartDelay, "restart-delay", "", "Delay between restart attempts (e.g. 5s)")
	cmd.Flags().StringVar(&restartWin, "restart-window", "", "Attempt-count window (e.g. 1h)")
	cmd.Flags().BoolVar(&onboot, "onboot", false, "Start this VM automatically when its host boots (live)")
	cmd.Flags().Int32Var(&startupOrder, "startup-order", 0, "Autostart order, lower starts first (live)")
	cmd.Flags().Int32Var(&startDelay, "start-delay", 0, "Seconds to wait after starting before the next VM (live)")
	cmd.Flags().Int32Var(&stopDelay, "stop-delay", 0, "Seconds to wait after stopping during ordered shutdown (live)")
	cmd.Flags().StringVar(&machine, "machine", "", "Machine type, e.g. q35 (VM must be stopped)")
	cmd.Flags().StringVar(&firmware, "firmware", "", "Firmware: uefi|bios (VM must be stopped)")
	cmd.Flags().BoolVar(&guestAgent, "guest-agent", false, "Enable the QEMU guest agent (VM must be stopped)")
	cmd.Flags().Int32Var(&minMem, "min-mem", 0, "Minimum balloon memory in MiB (VM must be stopped)")
	cmd.Flags().Int32Var(&maxMem, "max-mem", 0, "Maximum balloon memory in MiB (VM must be stopped)")
	return cmd
}
