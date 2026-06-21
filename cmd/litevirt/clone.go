package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newCloneCmd() *cobra.Command {
	var (
		mode     string
		project  string
		ip       string
		start    bool
		snapshot string
	)
	cmd := &cobra.Command{
		Use:   "clone <source> <new-name>",
		Short: "Clone a template or stopped VM into a new VM",
		Long: `Clone a template (or a stopped VM) into a new VM.

The clone gets a fresh identity — new MAC addresses and a regenerated cloud-init
instance-id/hostname, so it boots clean (new SSH host keys, new machine-id).

Mode (default: storage-aware auto):
  auto    linked when the source's disks are on shared storage (instant,
          space-efficient); full when on local storage (independent, avoids
          pinning the clone to the source's host)
  linked  qcow2 overlay backed by the source's disk — instant, thin
  full    independent copy (qcow2 convert) — no dependency on the source

Examples:
  lv clone ubuntu-template web-01
  lv clone ubuntu-template web-02 --mode full --start
  lv clone db-template db-staging --ip 10.0.0.50`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.CloneVM(ctx, &pb.CloneVMRequest{
					Source:   args[0],
					Target:   args[1],
					Mode:     mode,
					Project:  project,
					Ip:       ip,
					Start:    start,
					Snapshot: snapshot,
				})
				if err != nil {
					return fmt.Errorf("clone VM: %w", err)
				}
				fmt.Printf("Cloned %s → %s (state: %s)\n", args[0], vm.Name, vm.State)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&mode, "mode", "", "Clone mode: auto (default) | linked | full")
	cmd.Flags().StringVar(&project, "project", "", "Tenancy project for the clone (default: source's)")
	cmd.Flags().StringVar(&ip, "ip", "", "Static IP for the clone's first NIC (default: DHCP)")
	cmd.Flags().BoolVar(&start, "start", false, "Start the clone after creation")
	cmd.Flags().StringVar(&snapshot, "snapshot", "", "Clone from this snapshot of the source")
	return cmd
}

func newTemplateCmd() *cobra.Command {
	var revert bool
	cmd := &cobra.Command{
		Use:   "template <vm>",
		Short: "Convert a stopped VM into a clone template (or --revert back to a VM)",
		Long: `Convert a stopped VM into a template: a VM that can no longer start and
whose disks become immutable clone sources. Use --revert to turn a template
back into a normal, startable VM (refused while linked clones still depend on
it).

Examples:
  lv template ubuntu-base            # ubuntu-base becomes a template
  lv template ubuntu-base --revert   # back to a normal VM`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.ConvertToTemplate(ctx, &pb.ConvertToTemplateRequest{Name: args[0], Revert: revert})
				if err != nil {
					return fmt.Errorf("convert template: %w", err)
				}
				if revert {
					fmt.Printf("%s reverted to a normal VM\n", vm.Name)
				} else {
					fmt.Printf("%s is now a template (clone it with: lv clone %s <new-name>)\n", vm.Name, vm.Name)
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&revert, "revert", false, "Turn a template back into a normal VM")
	return cmd
}
