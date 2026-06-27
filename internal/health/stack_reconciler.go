package health

import (
	"context"
	"log/slog"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/protobuf/types/known/emptypb"
)

const stackReconcileInterval = 30 * time.Second

// StackCleaner is the interface for resource cleanup operations.
// Implemented by grpcapi.Server.
type StackCleaner interface {
	DeleteVM(ctx context.Context, req *pb.DeleteVMRequest) (*emptypb.Empty, error)
	RemoveLBForStack(ctx context.Context, stackName string, vms []corrosion.VMRecord)
	DeprovisionNetworkByName(ctx context.Context, name string) error
	ExternalNetworkNames(ctx context.Context, stackName string) map[string]bool
}

// StackReconciler watches for stacks in "deleting" state and retries
// resource cleanup until all resources are gone, then tombstones the stack.
type StackReconciler struct {
	hostName string
	db       *corrosion.Client
	cleaner  StackCleaner
}

// NewStackReconciler creates a stack reconciler.
func NewStackReconciler(hostName string, db *corrosion.Client) *StackReconciler {
	return &StackReconciler{
		hostName: hostName,
		db:       db,
	}
}

// SetCleaner registers the cleanup implementation (typically grpcapi.Server).
func (r *StackReconciler) SetCleaner(c StackCleaner) {
	r.cleaner = c
}

// Start begins the reconcile loop. Blocks until ctx is cancelled.
func (r *StackReconciler) Start(ctx context.Context) {
	ticker := time.NewTicker(stackReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcile(ctx)
		}
	}
}

func (r *StackReconciler) reconcile(ctx context.Context) {
	if r.cleaner == nil {
		return
	}

	stacks, err := corrosion.ListDeletingStacks(ctx, r.db)
	if err != nil {
		slog.Error("stack-reconciler: list deleting stacks", "error", err)
		return
	}

	for _, stack := range stacks {
		r.reconcileStack(ctx, stack)
	}
}

func (r *StackReconciler) reconcileStack(ctx context.Context, stack corrosion.StackRecord) {
	slog.Info("stack-reconciler: cleaning up stack", "stack", stack.Name)

	// 1. Delete remaining VMs.
	vms, err := corrosion.ListVMs(ctx, r.db, stack.Name, "")
	if err != nil {
		slog.Error("stack-reconciler: list VMs", "stack", stack.Name, "error", err)
		return
	}

	remainingVMs := 0
	for _, vm := range vms {
		if _, err := r.cleaner.DeleteVM(ctx, &pb.DeleteVMRequest{Name: vm.Name}); err != nil {
			slog.Warn("stack-reconciler: delete VM failed, will retry",
				"stack", stack.Name, "vm", vm.Name, "error", err)
			remainingVMs++
		}
	}

	// 2. Ensure LB config is soft-deleted and processes are stopped.
	lbName := stack.Name + "-lb"
	_ = corrosion.SoftDeleteLBConfig(ctx, r.db, lbName)
	r.cleaner.RemoveLBForStack(ctx, stack.Name, vms)

	// 3. Deprovision remaining networks.
	externalNets := r.cleaner.ExternalNetworkNames(ctx, stack.Name)
	nets, _ := corrosion.ListNetworks(ctx, r.db)
	for _, nr := range nets {
		if nr.StackName == stack.Name && !externalNets[nr.Name] {
			if err := r.cleaner.DeprovisionNetworkByName(ctx, nr.Name); err != nil {
				slog.Warn("stack-reconciler: network deprovision failed, will retry",
					"stack", stack.Name, "network", nr.Name, "error", err)
			}
		}
	}

	// 4. If all VMs are gone, tombstone the stack.
	if remainingVMs > 0 {
		slog.Info("stack-reconciler: stack still has resources, will retry",
			"stack", stack.Name, "remaining_vms", remainingVMs)
		return
	}

	// Hard-delete the LB config now that everything is cleaned up.
	_ = corrosion.SoftDeleteLBConfig(ctx, r.db, lbName)
	corrosion.SoftDeleteLBBackends(ctx, r.db, lbName)

	if err := corrosion.DeleteStackRecord(ctx, r.db, stack.Name); err != nil {
		slog.Error("stack-reconciler: tombstone stack failed", "stack", stack.Name, "error", err)
		return
	}

	slog.Info("stack-reconciler: stack fully cleaned up", "stack", stack.Name)
}
