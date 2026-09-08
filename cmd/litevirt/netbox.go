package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

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
		newNetboxRetireHostCmd(),
		newNetboxWithdrawRetirementCmd(),
		newNetboxRetirementsCmd(),
	)
	return cmd
}

func newNetboxRetireHostCmd() *cobra.Command {
	var (
		knew       []string
		knewNobody bool
		inventory  string
		yes        bool
	)
	cmd := &cobra.Command{
		Use:   "retire-host <host>",
		Short: "Attest that a host is permanently lost so NetBox proofs can proceed without it",
		Long: `Record that a host is PERMANENTLY GONE and retire the premises it can no
longer answer for.

WHAT THIS IS FOR. Reclamation and binding both rest on a whole-cluster proof,
and every participant has to answer. A host that cannot answer leaves the proof
open, so after a permanent loss -- a destroyed machine, a disk that will not come
back -- reclamation and new bindings stay suspended indefinitely. This is the
supported way out.

READ THIS BEFORE USING IT. Everything else these proofs rely on is checked by
machine: each host is asked about its own membership, its own database rows, its
own running domains. THIS COMMAND IS DIFFERENT. It substitutes YOUR judgement
for evidence litevirt cannot obtain, and litevirt CANNOT CHECK WHAT YOU ASSERT.
The record is attributed to you, written to the audit log and replicated, and
none of that makes it correct -- an audit entry says who claimed something, not
whether it was true. If what you attest here is wrong, the consequence is the
one the whole design exists to avoid: an address handed to a new guest while a
running one still holds it.

TWO SEPARATE PREMISES, and neither implies the other:

  * WHAT THE HOST KNEW (--knew / --knew-nobody). Retires the obligation to ask
    THAT host which hosts it knew of. It does NOT retire the hosts it could have
    told you about: the names you pass stay INPUTS to discovery and are queried
    by name, so a lost host that was the only one aware of a third machine still
    causes that machine to be asked. List every host it knew of, generously --
    naming one too many costs a query, naming one too few is how a running
    guest's address gets freed.
  * WHAT BECAME OF ITS RECORDS (--inventory). Retires the obligation to compare
    that host's copy of the address-bearing tables before a binding goes live.
    Needed only for binding and adoption. Use it once you have established what
    happened to any VM, NIC or address records that existed ONLY on the lost
    host -- recovered onto a surviving node, or accounted for some other way.

A THIRD PREMISE IS NOT RETIRABLE HERE. Whether the machine's workloads are
STOPPED is a separate question, and knowing what a host knew says nothing about
it. Reclamation still requires fencing evidence: power the machine off, then run
` + "`lv host fence-confirm <host>`" + `. Until you do, the sweep keeps withholding, and
this command tells you so.

WHAT ENDS A RETIREMENT. Two different things, and the difference matters.

It PAUSES on its own the moment the host is reachable again, or the moment a
different machine is admitted under that name -- the retirement names a specific
incarnation (the certificate serial recorded for that machine), never the
hostname, so a replacement inherits nothing. That is a pause and not a
withdrawal: nothing is written, and the stored grant applies AGAIN if that same
machine goes unreachable once more.

To remove trust in one for good -- because it was a mistake, or the accounting
was wrong -- run ` + "`lv netbox withdraw-retirement`" + `. That is durable and needs no
evidence of its own: withdrawing only ever puts a premise back to being owed.
Run ` + "`lv netbox retirements`" + ` to see what is recorded, what still applies, and
what has been withdrawn.

The command refuses a host that is still responding, and refuses to record
anything until the cluster has finished rolling to a build that understands
these records.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			if len(knew) == 0 && !knewNobody && inventory == "" {
				return fmt.Errorf("nothing to retire: pass --knew (or --knew-nobody) to " +
					"account for what the lost host knew, and/or --inventory to account for " +
					"its unique address records")
			}
			if !yes {
				// The prompt spells out the trade rather than asking for assent
				// to a word like "retire": the whole hazard is that this reads
				// like routine cleanup.
				fmt.Printf("This records YOUR attestation about %s. litevirt cannot verify it.\n", host)
				if len(knew) > 0 {
					fmt.Printf("  it knew of: %s\n", strings.Join(knew, ", "))
				}
				if knewNobody {
					fmt.Println("  it knew of no host this cluster does not already know of")
				}
				if inventory != "" {
					fmt.Printf("  its unique address records: %s\n", inventory)
				}
				fmt.Print("If that is wrong, a running guest's address can be handed out twice. Confirm? [y/N] ")
				var ans string
				fmt.Scanln(&ans)
				if ans != "y" && ans != "Y" {
					fmt.Println("Aborted.")
					return nil
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.RetireLostHost(ctx, &pb.RetireLostHostRequest{
					Host:                host,
					KnewHosts:           knew,
					KnewNobody:          knewNobody,
					InventoryAccounting: inventory,
					Confirmed:           true,
				})
				if err != nil {
					// The server's message is the diagnosis: which premise, which
					// identity, and why it refused.
					return fmt.Errorf("retire-host %s: %s", host, status.Convert(err).Message())
				}
				fmt.Printf("Retired for %s: %s (incarnation %s).\n",
					host, strings.Join(resp.GetPremises(), " and "), resp.GetHostIncarnation())
				if hosts := resp.GetRecoveredHosts(); len(hosts) > 0 {
					fmt.Printf("Still asking, from the manifest: %s\n", strings.Join(hosts, ", "))
				}
				if resp.GetRuntimeEvidenceMissing() {
					// Said on success, because this is the point at which an
					// operator otherwise concludes they are finished.
					fmt.Printf("Reclamation still withholds: nothing yet attests that %s is "+
						"powered off. Power it off, then run `lv host fence-confirm %s`.\n",
						host, host)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringSliceVar(&knew, "knew", nil,
		"Hosts the lost host knew of; they remain inputs to discovery and are still queried")
	cmd.Flags().BoolVar(&knewNobody, "knew-nobody", false,
		"Attest that it knew of no host this cluster does not already know of")
	cmd.Flags().StringVar(&inventory, "inventory", "",
		"What became of address records that existed only on the lost host (retires the inventory premise)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	return cmd
}

func newNetboxWithdrawRetirementCmd() *cobra.Command {
	var (
		incarnation string
		premise     string
		reason      string
	)
	cmd := &cobra.Command{
		Use:   "withdraw-retirement <host>",
		Short: "Remove trust in a recorded permanent-loss attestation",
		Long: `Take back a permanent-loss attestation.

WHAT THIS IS FOR. ` + "`lv netbox retire-host`" + ` substitutes your judgement for
evidence litevirt cannot obtain, and litevirt cannot check what you asserted. If
one turns out to be wrong -- the accounting named the wrong machine, the host was
not permanently lost after all, somebody ran it by mistake -- this is how the
cluster stops relying on it. Without it a mistaken attestation stands
indefinitely.

IT ASKS FOR NOTHING BUT THE TARGET, and that asymmetry is deliberate. Recording
a retirement is guarded: it refuses a host that is still responding, it demands
an accounting, and it re-checks everything immediately before it writes. Removing
one is not guarded at all, because every consequence of a withdrawal is a premise
going back to being OWED -- reclamation and binding withhold rather than proceed.
Making this harder would trade a safe outcome for an unsafe one. So the host does
not have to be dead, unreachable, or currently matching, and it does not even
have to have a host record any more.

A DORMANT GRANT IS A LIVE GRANT, which is why "it already stopped applying" is
not a reason to skip this. A retirement whose host is answering again is merely
PAUSED: nothing was written, and the stored grant applies again the moment that
same machine goes unreachable once more. Withdrawal is the only thing that is
durable.

IT NAMES A MACHINE AND A PREMISE, never just a hostname. --incarnation is
required: a hostname is meant to be reused, so aiming by name would land on
whichever grant that name carries now rather than on the one you meant, leaving
the mistake in place. --premise is required for the same reason the two premises
are separate -- withdrawing what a host KNEW does not withdraw what became of its
RECORDS. Both values are in ` + "`lv netbox retirements`" + `.

WHAT IT DOES NOT DO, and this is the easiest thing to expect wrongly: it does NOT
discard the host identities the attestation named. Those stay inputs to
discovery. Withdrawing permission to trust a source does not establish that the
hosts it named never existed -- and dropping them is how being MORE careful would
end up freeing a live guest's address, because a host nothing records is a host
nothing asks.

It also does not delete the original attestation. Who attested what, when and
why survives untouched, and who withdrew it, when and why is recorded beside it.

RE-ATTESTING AFTER A WITHDRAWAL WORKS. A withdrawal covers the grant versions
recorded when you ran it and nothing attested afterwards, so running
` + "`lv netbox retire-host`" + ` again records a fresh version and supplies the premise
again. That also means a withdrawal that raced somebody else's re-attestation
does not silence it: the listing names the version that is holding the grant up,
and withdrawing again covers it too.

Repeating a withdrawal is safe and reports that nothing new was recorded.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			if incarnation == "" {
				return fmt.Errorf("pass --incarnation: a withdrawal names the exact machine " +
					"(the certificate serial `lv netbox retirements` reports), never the " +
					"hostname, because a hostname is reusable")
			}
			if premise == "" {
				return fmt.Errorf("pass --premise membership or --premise inventory: the two " +
					"are separate grants and withdrawing one does not withdraw the other")
			}
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("pass --reason: the attestation records who asserted what " +
					"and why, and this records who took it back and why")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.WithdrawHostRetirement(ctx, &pb.WithdrawHostRetirementRequest{
					Host:            host,
					HostIncarnation: incarnation,
					Premise:         premise,
					Reason:          reason,
				})
				if err != nil {
					return fmt.Errorf("withdraw-retirement %s: %s",
						host, status.Convert(err).Message())
				}
				if resp.GetNewlyRecorded() == 0 {
					fmt.Printf("Already withdrawn: %s premise for %s (incarnation %s), "+
						"%d grant version(s). Nothing new recorded.\n",
						resp.GetPremise(), host, resp.GetHostIncarnation(),
						len(resp.GetWithdrawnVersions()))
				} else {
					fmt.Printf("Withdrew trust in the %s premise for %s (incarnation %s), "+
						"%d grant version(s).\n",
						resp.GetPremise(), host, resp.GetHostIncarnation(),
						resp.GetNewlyRecorded())
				}
				if !resp.GetGrantWithdrawn() {
					// The concurrent-re-attestation outcome, said plainly. It
					// must never look like the withdrawal was ignored.
					fmt.Printf("The grant is STILL IN FORCE: it rests on grant version(s) "+
						"%s, attested after this withdrawal was aimed. The withdrawal is "+
						"recorded; run this again to cover the newer version too.\n",
						strings.Join(resp.GetUncoveredVersions(), ", "))
					return nil
				}
				fmt.Printf("The %s premise for %s is owed again. This does NOT discard the "+
					"host identities the attestation named -- they remain inputs to "+
					"discovery, so any host it named is still queried.\n",
					resp.GetPremise(), host)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&incarnation, "incarnation", "",
		"The exact incarnation (recorded certificate serial) whose grant is withdrawn; required")
	cmd.Flags().StringVar(&premise, "premise", "",
		"Which premise to withdraw: membership or inventory; required")
	cmd.Flags().StringVar(&reason, "reason", "",
		"Why trust is being removed, recorded beside the original attestation; required")
	return cmd
}

func newNetboxRetirementsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "retirements",
		Short: "List the permanent-loss attestations and whether they still apply",
		Long: `Show every permanent-loss attestation recorded in this cluster.

These are the only premises in the NetBox proofs that no machine verifies, so
reviewing them is the only check there is. Each row names the host, the exact
incarnation it was written against, the premise it retires, who attested it and
when, and the accounting they gave.

A grant stops APPLYING on its own once the host answers again, or once a
different machine is admitted under that name, and this listing says which rows
are no longer honoured and why. That is a PAUSE: the stored grant applies again
if that same machine goes unreachable once more, so a row that does not apply is
not a problem to clean up.

A WITHDRAWN grant is different, and the listing labels it so. Withdrawal is a
recorded decision by a named person and it is durable -- it does not come back
when the host next goes unreachable, and a re-delivered copy of the old grant
cannot resurrect it. The withdrawal appears BESIDE the original attestation
rather than replacing it, so both halves of the decision are readable: who
attested what and why, and who took it back and why. Use
` + "`lv netbox withdraw-retirement`" + ` to record one.

If a withdrawn grant is listed as still APPLYING, a LATER attestation is holding
it up -- somebody re-attested after the withdrawal, and the grant versions that
withdrawal does not reach are named on the row.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListLostHostRetirements(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("retirements: %s", status.Convert(err).Message())
				}
				rows := resp.GetRetirements()
				if len(rows) == 0 {
					fmt.Println("No permanent-loss attestations recorded.")
					return nil
				}
				for _, r := range rows {
					state := "APPLIES"
					if !r.GetApplies() {
						state = "does not apply"
					}
					if r.GetWithdrawn() {
						// Said in the state column, because "withdrawn" is a
						// different fact from "not currently matching" and an
						// operator scanning this list must not have to infer it.
						state += " (WITHDRAWN)"
					}
					fmt.Printf("%s  premise=%s  %s\n", r.GetHostName(), r.GetPremise(), state)
					fmt.Printf("    incarnation %s, attested by %s at %s\n",
						r.GetHostIncarnation(), r.GetAttestedBy(), r.GetAttestedAt())
					for _, a := range r.GetAccounting() {
						fmt.Printf("    accounting: %s\n", a)
					}
					// The withdrawals BESIDE the attestation, never instead of
					// it: both halves of the decision have to be readable.
					for _, w := range r.GetWithdrawals() {
						fmt.Printf("    withdrawn by %s at %s: %s (grant version %s)\n",
							w.GetWithdrawnBy(), w.GetWithdrawnAt(), w.GetReason(),
							w.GetGrantVersion())
					}
					if len(r.GetWithdrawals()) > 0 && len(r.GetUnwithdrawnVersions()) > 0 {
						fmt.Printf("    still resting on grant version(s) no withdrawal "+
							"reaches: %s (a later attestation)\n",
							strings.Join(r.GetUnwithdrawnVersions(), ", "))
					}
					if !r.GetApplies() {
						fmt.Printf("    %s\n", r.GetNotApplyingBecause())
					}
				}
				fmt.Println("\nNothing above was verified by litevirt: each row is an operator's " +
					"assertion substituted for evidence a lost machine could not produce.")
				return nil
			})
		},
	}
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
