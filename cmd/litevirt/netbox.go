package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newNetboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "netbox",
		Short: "Manage the NetBox external IPAM integration",
	}
	cmd.AddCommand(
		newNetboxRekeyCmd(),
	)
	return cmd
}

func newNetboxRekeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rekey <network>",
		Short: "Rewrite a bound network's NetBox identities after a cluster CA replacement",
		Long: `Rewrite the identities litevirt owns in a network's NetBox prefix.

Every NetBox object litevirt creates is stamped with a fingerprint derived from
the cluster CA certificate, which is what keeps two clusters sharing one NetBox
from reclaiming each other's addresses. Replacing the CA changes that
fingerprint, so the binding suspends and new allocations refuse until the
existing objects are re-stamped. Running VMs are unaffected throughout.

The command is safe to re-run: objects already rewritten are skipped, and the
binding resumes only once every one of them has been rewritten.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.RekeyBinding(ctx, &pb.RekeyBindingRequest{Network: args[0]}); err != nil {
					return fmt.Errorf("rekey %s: %w", args[0], err)
				}
				fmt.Printf("Re-keyed NetBox identities for network %q; the binding is live again.\n", args[0])
				return nil
			})
		},
	}
}
