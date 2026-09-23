package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// legacyCPUVM is one VM whose stored spec names no CPU mode.
type legacyCPUVM struct {
	Name string
	Host string
}

// legacyCPUModeVMs selects VMs whose PERSISTED spec carries an empty cpu_mode.
// Those render with NO <cpu> element, so QEMU gives the guest its x86_64
// default — qemu64, which has no sse4.1/sse4.2, no xsave, and therefore no AVX
// or AVX2 — regardless of what the host CPU can do.
//
// A VM with no spec at all is skipped: there is nothing to report and nothing
// an operator could act on.
//
// Pure so the selection is testable without a cluster.
func legacyCPUModeVMs(vms []*pb.VM) []legacyCPUVM {
	var out []legacyCPUVM
	for _, vm := range vms {
		if vm.GetSpec() == nil {
			continue
		}
		if vm.GetSpec().GetCpuMode() != "" {
			continue
		}
		out = append(out, legacyCPUVM{Name: vm.GetName(), Host: vm.GetHostName()})
	}
	return out
}

// newDoctorCPUModeCmd reports VMs still on QEMU's default CPU model.
func newDoctorCPUModeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cpu-mode",
		Short: "Report VMs whose stored spec names no CPU mode (QEMU's qemu64 — no AVX)",
		Long: `List VMs whose PERSISTED spec has an empty cpu_mode.

Such a VM is defined with no <cpu> element, so libvirt passes no -cpu to QEMU and
the guest runs on QEMU's x86_64 default: qemu64. That model reports no sse4.1, no
sse4.2 and no xsave, so it has neither AVX nor AVX2 — on a host that has all of
them. Guest software that assumes a modern baseline will not start, and the fault
looks like a broken binary rather than a hypervisor setting.

New VMs default to ` + lv.DefaultCPUMode + `. VMs listed here were created before that
default existed; their stored spec is honored verbatim so an upgrade never moves a
running guest's CPU underneath it.

Read-only. To move one forward, with the VM STOPPED:

    lv update <vm> --cpu-mode ` + lv.DefaultCPUMode + `

That changes the CPU the guest sees, so it needs a full stop/start (not a reboot),
and it narrows live migration to hosts with an equal-or-richer CPU.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListVMs(ctx, &pb.ListVMsRequest{})
				if err != nil {
					return fmt.Errorf("list VMs: %w", err)
				}
				legacy := legacyCPUModeVMs(resp.GetVms())
				if len(legacy) == 0 {
					fmt.Println("all VMs name a CPU mode")
					return nil
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "VM\tHOST\tCPU MODE")
				for _, l := range legacy {
					fmt.Fprintf(w, "%s\t%s\t%s\n", l.Name, l.Host, "(empty → qemu64)")
				}
				w.Flush()
				fmt.Printf("\n%d VM(s) run on QEMU's default CPU model, which has no AVX or AVX2\n", len(legacy))
				fmt.Printf("however capable the host is. Fix one with: lv update <vm> --cpu-mode %s (stopped).\n", lv.DefaultCPUMode)
				return nil
			})
		},
	}
}
