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
		Use:   "rekey [network]",
		Short: "Re-stamp NetBox identities after the cluster fingerprint moved",
		Long: `Rewrite the identities litevirt owns in NetBox.

Every NetBox object litevirt creates is stamped with a fingerprint derived from
the cluster CA certificate recorded in the replicated 'cluster' row, which is
what keeps two clusters sharing one NetBox from reclaiming each other's objects.
That fingerprint is minted ONCE, from whichever node first found the row
missing, and it never tracks 'ca.crt' again -- so replacing the CA on disk does
not move it, does not suspend anything, and needs no re-key.

This command is for a fingerprint that has genuinely moved: the value a binding
recorded no longer equals the cluster's current one, which today means the
'cluster' row itself was rewritten out of band -- an operator edit, or a restore
carrying another installation's CA. Bindings then suspend, new allocations
refuse and the inventory mirror stops recognising what it wrote, until the
existing objects are re-stamped. Running VMs are unaffected throughout.

With a NETWORK, it re-stamps that network's addresses, the mirrored VM and
interface objects, and litevirt's local identity index -- in that order -- and
then resumes the binding.

With NO network, it re-stamps the mirrored inventory and the local index only,
cluster-wide. That is the form for a cluster that uses NetBox purely for
inventory and has no bound network for the other form to name. It resumes
nothing, so a cluster with bound networks still runs the per-network form for
each of them afterwards.

The command is safe to re-run: objects already rewritten are skipped, and a
binding resumes only once every one of them has been rewritten.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			network := ""
			if len(args) == 1 {
				network = args[0]
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.RekeyBinding(ctx, &pb.RekeyBindingRequest{Network: network}); err != nil {
					// The server's message is the whole diagnosis: a re-key can
					// rewrite every identity and still leave the binding
					// suspended for a reason only the operator can repair, and
					// the cluster-scoped form can refuse for want of anything
					// recording the old fingerprint.
					if network == "" {
						return fmt.Errorf("rekey: %s", status.Convert(err).Message())
					}
					return fmt.Errorf("rekey %s: %s", network, status.Convert(err).Message())
				}
				if network == "" {
					// No binding, so nothing to call live. Saying otherwise
					// would imply a suspension had been lifted that this form
					// never touches.
					fmt.Println("Re-keyed the NetBox inventory identities litevirt owns.")
					return nil
				}
				// Printed ONLY on success. The RPC also returns after rewriting
				// every identity and leaving the binding suspended, and claiming
				// "live again" there would send an operator away from a network
				// that still refuses every create.
				fmt.Printf("Re-keyed NetBox identities for network %q; the binding is live again.\n", network)
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

A binding suspends for one of three kinds of reason:

  * DRIFT -- the prefix stopped satisfying what the bind validated: it was
    re-CIDRed, moved to the global table, or its VRF stopped enforcing
    uniqueness. Repair the prefix in NetBox, then run this.
  * AN UNFINISHED ADOPTION -- the bind found addresses this network's guests
    already hold and could not record all of them in NetBox (NetBox became
    unreachable, or one address is held by something else). This command
    FINISHES that adoption: it claims the remaining addresses and only then
    lifts the suspension.
  * AN UNCORROBORATED INVENTORY -- the binding was made on a node that could not
    establish what its guests hold. That one lifts itself on the next NetBox
    maintenance pass; running this finishes it immediately instead.

New allocations refuse while a binding is suspended; running VMs are untouched.

The suspension is lifted only when every bind-time check passes again AND every
owed address is adopted, so a binding whose drift is still present, or whose
adoption still cannot complete, is refused with the reason.

Resume does NOT accept a changed CIDR. Re-CIDRing a bound prefix is unsupported:
revert the CIDR in NetBox, or delete and recreate the network to bind against
the new range. A suspension caused by a moved cluster fingerprint needs the
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
