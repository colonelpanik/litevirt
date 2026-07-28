package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newHardwareLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hardware-ls <vm>",
		Short: "List a VM's hardware devices (disks, NICs, PCI)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListVMHardware(ctx, &pb.ListVMHardwareRequest{VmName: args[0]})
				if err != nil {
					return fmt.Errorf("list hardware: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "KIND\tID\tDETAIL\tSTATE\n")
				for _, dev := range resp.GetDevices() {
					switch {
					case dev.GetDisk() != nil:
						d := dev.GetDisk()
						fmt.Fprintf(w, "disk\t%s\ttarget=%s bus=%s size=%s type=%s\t%s\n",
							d.GetDeviceId(), d.GetTarget(), d.GetBus(), formatBytes(d.GetSizeBytes()), d.GetStorageType(), d.GetState())
					case dev.GetNic() != nil:
						n := dev.GetNic()
						fmt.Fprintf(w, "nic\t%s\tnetwork=%s model=%s\t%s\n",
							n.GetMac(), n.GetNetwork(), n.GetModel(), n.GetState())
					case dev.GetPci() != nil:
						p := dev.GetPci()
						addrs := ""
						for i, mem := range p.GetMembers() {
							if i > 0 {
								addrs += ","
							}
							addrs += mem.GetResolvedAddress()
						}
						// A reserved device has no realized members yet; show its
						// desired (claimed) address so the row isn't blank. The STATE
						// column ("reserved" vs "attached") distinguishes the two.
						if addrs == "" {
							addrs = p.GetDesired().GetAddress()
						}
						fmt.Fprintf(w, "pci\t%s\tselector=%s addr=%s\t%s\n",
							p.GetDeviceId(), p.GetSelectorKind(), addrs, p.GetState())
					}
				}
				if err := w.Flush(); err != nil {
					return err
				}

				fmt.Printf("\nhardware adoption: %s\n", resp.GetHardwareAdoptionState())
				if resp.GetHardwareAdoptionState() == "blocked" && resp.GetHardwareAdoptionError() != "" {
					fmt.Printf("  reason: %s\n", resp.GetHardwareAdoptionError())
				}
				return nil
			})
		},
	}
	return cmd
}
