package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newNetboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "netbox",
		Short: "Manage the NetBox external IPAM integration",
	}
	cmd.AddCommand(
		newNetboxRekeyCmd(),
		newNetboxResumeCmd(),
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
					// The server's message is the whole diagnosis: a re-key can
					// rewrite every identity and still leave the binding
					// suspended for a reason only the operator can repair.
					return fmt.Errorf("rekey %s: %s", args[0], status.Convert(err).Message())
				}
				// Printed ONLY on success. The RPC also returns after rewriting
				// every identity and leaving the binding suspended, and claiming
				// "live again" there would send an operator away from a network
				// that still refuses every create.
				fmt.Printf("Re-keyed NetBox identities for network %q; the binding is live again.\n", args[0])
				return nil
			})
		},
	}
}

func newNetboxResumeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "resume <network>",
		Short: "Lift a NetBox binding's suspension once the drift is repaired",
		Long: `Resume a suspended NetBox binding.

A binding suspends when its prefix stops satisfying what the bind validated: it
was re-CIDRed, moved to the global table, or its VRF stopped enforcing
uniqueness. New allocations refuse while it is suspended; running VMs are
untouched. Repair the prefix in NetBox, then run this.

The suspension is lifted only when every bind-time check passes again, so a
binding whose drift is still present is refused with the reason.

Resume does NOT accept a changed CIDR. Re-CIDRing a bound prefix is unsupported:
revert the CIDR in NetBox, or delete and recreate the network to bind against
the new range. A suspension caused by a cluster CA replacement needs the
identity rewrite instead -- run ` + "`lv netbox rekey`" + `.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.ResumeBinding(ctx, &pb.ResumeBindingRequest{Network: args[0]}); err != nil {
					return fmt.Errorf("resume %s: %s", args[0], status.Convert(err).Message())
				}
				fmt.Printf("NetBox binding for network %q is live.\n", args[0])
				return nil
			})
		},
	}
}
