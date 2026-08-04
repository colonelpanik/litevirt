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

// unpinnedMachine is one VM whose persisted spec still carries an unversioned
// machine alias.
type unpinnedMachine struct {
	Name    string
	Host    string
	Machine string
}

// unpinnedMachineVMs selects VMs whose PERSISTED spec carries an unversioned
// machine alias ("q35", "pc-q35", "") rather than a concrete versioned type.
// A VM with no spec at all is skipped: there is nothing to pin, and nothing an
// operator could act on.
//
// Pure so the selection is testable without a cluster.
func unpinnedMachineVMs(vms []*pb.VM) []unpinnedMachine {
	var out []unpinnedMachine
	for _, vm := range vms {
		if vm.GetSpec() == nil {
			continue
		}
		m := vm.GetSpec().GetMachine()
		if lv.IsPinnedMachineType(m) {
			continue
		}
		out = append(out, unpinnedMachine{Name: vm.GetName(), Host: vm.GetHostName(), Machine: m})
	}
	return out
}

// newDoctorMachineTypesCmd reports VMs persisted with an unversioned machine
// alias — a latent guest-ABI hazard, since libvirt resolves an alias per host
// qemu version and a migration or failover onto a different qemu can shift the
// guest's ABI underneath it.
func newDoctorMachineTypesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "machine-types",
		Short: "Report VMs whose stored spec has an unversioned machine type",
		Long: `List VMs whose PERSISTED spec carries a machine alias ("q35", "pc-q35", or
empty) instead of a concrete versioned type ("pc-q35-9.0").

An alias is resolved by libvirt per host qemu version, so a VM carrying one can
have its guest ABI shift underneath it on a migration or failover to a host with
a different qemu. Create and redefine pin the concrete type at define time, and
the reconciler backfills VMs as it sweeps them — so a VM listed here was
produced by another path (clone/import/restore/promote) and has not yet been
swept on its current host.

Read-only. To pin one now: start the VM (the reconciler pins on its next sweep),
or run 'lv update <vm> --machine <concrete-type>' while it is stopped.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListVMs(ctx, &pb.ListVMsRequest{})
				if err != nil {
					return fmt.Errorf("list VMs: %w", err)
				}
				unpinned := unpinnedMachineVMs(resp.GetVms())
				if len(unpinned) == 0 {
					fmt.Println("all VMs carry a concrete versioned machine type")
					return nil
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "VM\tHOST\tMACHINE")
				for _, u := range unpinned {
					shown := u.Machine
					if shown == "" {
						shown = "(empty)"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\n", u.Name, u.Host, shown)
				}
				w.Flush()
				fmt.Printf("\n%d VM(s) carry an unversioned machine alias; their guest ABI can shift on a\n", len(unpinned))
				fmt.Println("migration or failover to a host with a different qemu version.")
				return nil
			})
		},
	}
}
