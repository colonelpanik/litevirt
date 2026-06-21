package main

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newSpiceCmd prints SPICE connection info for a running VM.
//
// litevirt does not bundle a browser-based SPICE client (yet). Operators
// connect with `remote-viewer`, `virt-manager`, or any SPICE client.
//
// Default: print connection details. With --launch, attempt to spawn
// `remote-viewer` if it's installed.
func newSpiceCmd() *cobra.Command {
	var launch bool
	cmd := &cobra.Command{
		Use:   "spice <vm>",
		Short: "Print SPICE connection info for a running VM",
		Long: `Returns the SPICE host and port for a running VM that has SPICE
graphics enabled. Connect with:

    remote-viewer "spice://<host>:<port>"

VMs gain SPICE by setting graphics.spice: true in compose.

Note: SPICE traffic is NOT proxied through the litevirt daemon today; the
client must be able to reach the host directly. Use SSH tunneling if your
host's SPICE port isn't externally reachable:

    lv host ssh <host> -- -L 5901:127.0.0.1:<port>
    remote-viewer spice://127.0.0.1:5901
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(context.Background(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetSpiceInfo(ctx,
					&pb.GetSpiceInfoRequest{VmName: args[0]})
				if err != nil {
					return fmt.Errorf("spice info: %w", err)
				}
				fmt.Printf("VM:   %s\n", args[0])
				fmt.Printf("Host: %s\n", resp.Host)
				fmt.Printf("Port: %d\n", resp.Port)
				fmt.Printf("URI:  %s\n", resp.Uri)
				if launch {
					if path, err := exec.LookPath("remote-viewer"); err == nil {
						fmt.Printf("\nLaunching %s %s\n", path, resp.Uri)
						return exec.Command(path, resp.Uri).Start()
					}
					return fmt.Errorf("remote-viewer not found in PATH; install virt-viewer or omit --launch")
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&launch, "launch", false, "Spawn remote-viewer (requires virt-viewer package)")
	return cmd
}
