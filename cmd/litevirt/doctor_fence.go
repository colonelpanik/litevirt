package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newDoctorFenceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fence",
		Short: "Check whether the shared-storage fence would actually run",
		Long: `Report whether a cross-host transfer of a shared-disk VM would be fenced.

Starting a VM on a second host while the first may still be writing the same
shared disk corrupts it. litevirt guards that with a proof-grade fence — an
IPMI-confirmed power-off or an operator 'lv host fence-confirm' — required
before an ownership transfer of a VM with a disk on shared storage
(nfs/ceph/rbd/iscsi).

That guard has two independent switches, and BOTH must be on:

  shared_storage_fence_v1   latched cluster-wide once every host advertises it
  enforcement.shared_storage_fence   per-host config, default false

A host advertises the token regardless of its own config flag, so the cluster
can show the capability fully latched while individual hosts silently skip the
fence. This command asks every host for its own posture, so that gap is visible.

Exit code: 0 when no shared-disk VM is exposed · 1 when one or more are.

Two things this check cannot establish, reported on every run: each host's own
capability latch is per-node state with no wire representation, and the
shared-disk count comes from the queried node's replicated rows.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				r, err := c.GetFenceReadiness(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("get fence readiness: %w", err)
				}
				printFenceReadiness(r)
				if fenceHazard(r) {
					return silentExitError{code: 1}
				}
				return nil
			})
		},
	}
}

// fenceHazard reports whether anything is actually exposed: shared-disk VMs
// exist AND the fence is not in force everywhere. With no shared-disk VMs the
// switches being off is a posture note, not a hazard — nothing can be corrupted
// by an unfenced transfer of a local-disk VM, whose replica is a different image
// on the target host.
func fenceHazard(r *pb.FenceReadiness) bool {
	return r.GetVmsWithSharedDisk() > 0 && !(r.GetCapabilityLatched() && r.GetEnforcedEverywhere())
}

func printFenceReadiness(r *pb.FenceReadiness) {
	fmt.Printf("shared-disk VMs:            %d\n", r.GetVmsWithSharedDisk())
	fmt.Printf("capability latched:         %v\n", r.GetCapabilityLatched())
	fmt.Printf("enforced on every host:     %v\n", r.GetEnforcedEverywhere())

	if hosts := r.GetHosts(); len(hosts) > 0 {
		fmt.Println("\nhosts:")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  HOST\tPOSTURE\tDETAIL")
		for _, h := range hosts {
			fmt.Fprintf(w, "  %s\t%s\t%s\n", h.GetHost(), hostPostureWord(h), h.GetDetail())
		}
		w.Flush()
	}

	if vms := r.GetSampleVms(); len(vms) > 0 {
		shown := strings.Join(vms, ", ")
		if int32(len(vms)) < r.GetVmsWithSharedDisk() {
			shown += fmt.Sprintf(", … (%d more)", r.GetVmsWithSharedDisk()-int32(len(vms)))
		}
		fmt.Printf("\nVMs on shared storage: %s\n", shown)
	}

	if fenceHazard(r) {
		fmt.Printf("\nWARNING: %d VM(s) have a disk on shared storage and the proof-grade fence\n",
			r.GetVmsWithSharedDisk())
		fmt.Println("is not in force. A failover or auto-promote can start one of them on a second")
		fmt.Println("host while the first may still be writing the same disk, which corrupts it.")
		fmt.Println("\nTo close it:")
		if !r.GetCapabilityLatched() {
			fmt.Println("  - the shared_storage_fence_v1 capability is not latched cluster-wide;")
			fmt.Println("    every host must run a binary that advertises it")
		}
		for _, h := range r.GetHosts() {
			switch {
			case !h.GetReachable():
				fmt.Printf("  - %s did not answer, so its posture is unknown: %s\n", h.GetHost(), h.GetDetail())
			case !h.GetPostureKnown():
				fmt.Printf("  - %s cannot report its posture: %s\n", h.GetHost(), h.GetDetail())
			case !h.GetEnforcing():
				fmt.Printf("  - set enforcement.shared_storage_fence = true on %s and restart it\n", h.GetHost())
			}
		}
	} else if r.GetVmsWithSharedDisk() == 0 {
		fmt.Println("\nno VM known here has a disk on shared storage, so no transfer needs the")
		fmt.Println("proof-grade fence (counted from this node's replicated rows — a VM created")
		fmt.Println("on a peer whose disk rows have not arrived yet is not counted)")
	} else {
		fmt.Println("\nnothing is switched off: every host reports the fence enabled")
	}

	printFenceCaveats(r)
}

// printFenceCaveats says what the report does not establish, on EVERY path.
//
// It used to print only on the clean path, on the reasoning that these are the
// two things that would make a covered result wrong. That had it backwards. The
// caveats are needed at least as much on the hazard path, because that is where
// the host table can read most misleadingly: a fleet can show nine hosts
// `enforcing` above a WARNING, and an operator who fixes the one named host will
// believe they have closed something the latch is still holding open.
func printFenceCaveats(r *pb.FenceReadiness) {
	// The sharpest case, and the reason this moved. `enforcing` in the table is
	// a host's own config flag; the flag does nothing until the capability has
	// latched cluster-wide. With no latch, every "enforcing" row above is a
	// statement of intent and not one of them is fencing anything.
	if !r.GetCapabilityLatched() && anyHostEnforcing(r) {
		fmt.Println("\nnote: the capability is NOT latched, so no host is fencing regardless of the")
		fmt.Println("postures above — `enforcing` there is a host's config flag alone, and the flag")
		fmt.Println("only takes effect once the capability has latched cluster-wide.")
	}

	fmt.Println("\nnot established by this check: each host's OWN capability latch (per-node")
	fmt.Println("state with no wire representation — a host that has not latched takes the")
	fmt.Println("legacy path whatever its flag says), and shared-disk VMs this node has not")
	fmt.Println("yet replicated.")
}

func anyHostEnforcing(r *pb.FenceReadiness) bool {
	for _, h := range r.GetHosts() {
		if h.GetEnforcing() {
			return true
		}
	}
	return false
}

// hostPostureWord renders the three-state posture. "unknown" is deliberately
// distinct from "no": a host that cannot be asked is not a host that answered.
func hostPostureWord(h *pb.FenceHostPosture) string {
	switch {
	case !h.GetReachable():
		return "unknown (unreachable)"
	case !h.GetPostureKnown():
		return "unknown"
	case h.GetEnforcing():
		return "enforcing"
	default:
		return "NOT enforcing"
	}
}
