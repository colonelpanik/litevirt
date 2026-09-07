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

Exit code: 0 when no shared-disk VM is exposed · 1 when one or more are.`,
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

	if !fenceHazard(r) {
		if r.GetVmsWithSharedDisk() == 0 {
			fmt.Println("\nno VM has a disk on shared storage, so no transfer needs the proof-grade fence")
		} else {
			fmt.Println("\nevery shared-disk VM is covered: a cross-host transfer will be fenced")
		}
		return
	}

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
