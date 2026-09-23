package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// uuidlessVM is one VM whose persisted spec carries no domain uuid.
type uuidlessVM struct {
	Name string
	Host string
}

// uuidlessVMs selects VMs whose PERSISTED spec carries no uuid. Templates are
// excluded: a template is a disk image, never a domain, so it has no uuid to
// record and the mirror ignores it anyway. A VM with no spec at all is skipped —
// there is nothing to fill in and nothing an operator could act on.
//
// IT DEPENDS ON ListVMs PROJECTING `uuid`, and on that projection setting Spec
// whenever a stored spec exists. Both halves are load-bearing and neither is
// visible here: while the projection carried labels alone, a nil Spec meant
// "unlabelled" rather than "spec-less" and every scalar read off it came back
// empty, so this report was exactly inverted — unlabelled legacy VMs skipped,
// labelled healthy ones named. See TestListVMsProjectsTheUUID, which pins the
// data source through the real RPC; the selection test below cannot, because a
// hand-built pb.VMSpec asserts against a value the RPC never produces.
//
// Pure so the selection is testable without a cluster.
func uuidlessVMs(vms []*pb.VM) []uuidlessVM {
	var out []uuidlessVM
	for _, vm := range vms {
		if vm.GetSpec() == nil || vm.GetIsTemplate() {
			continue
		}
		if vm.GetSpec().GetUuid() != "" {
			continue
		}
		out = append(out, uuidlessVM{Name: vm.GetName(), Host: vm.GetHostName()})
	}
	return out
}

// newDoctorVMUUIDsCmd reports VMs persisted without a domain uuid.
func newDoctorVMUUIDsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "vm-uuids",
		Short: "Report VMs whose stored spec has no domain uuid",
		Long: `List VMs whose PERSISTED spec carries no uuid.

The uuid is what makes an identity incarnation-unique, so a VM without one
cannot be named in NetBox at all. The inventory mirror skips it AND counts it as
an unreadable record — and an unreadable record is indistinguishable from a
destroyed VM, so the mirror withholds EVERY delete while one exists. A single
VM listed here therefore stops the whole mirror converging.

libvirt minted a uuid for the domain regardless, so the reconciler adopts it
from the persistent domain XML as it sweeps each VM on its owning host. A VM
listed here has not been swept yet, or its host is not running.

Read-only. To fill one in now: make sure its host is up — the reconciler records
the uuid on its next sweep, whether the VM is running or stopped.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListVMs(ctx, &pb.ListVMsRequest{})
				if err != nil {
					return fmt.Errorf("list VMs: %w", err)
				}
				missing := uuidlessVMs(resp.GetVms())
				if len(missing) == 0 {
					fmt.Println("all VMs carry a domain uuid")
					return nil
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "VM\tHOST")
				for _, u := range missing {
					fmt.Fprintf(w, "%s\t%s\n", u.Name, u.Host)
				}
				w.Flush()
				fmt.Printf("\n%d VM(s) carry no domain uuid; they cannot be mirrored into NetBox,\n", len(missing))
				fmt.Println("and while any of them exists the inventory mirror withholds every delete.")
				return nil
			})
		},
	}
}
