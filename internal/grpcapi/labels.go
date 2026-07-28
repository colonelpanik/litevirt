package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetVMLabels replaces a VM's labels (tags). Labels are metadata stored in the
// spec JSON — not part of the libvirt domain — so this applies to running VMs
// without a redefine. The request is authoritative: an empty map clears tags.
func (s *Server) SetVMLabels(ctx context.Context, req *pb.SetVMLabelsRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.update", "operator"); err != nil {
		s.audit(ctx, "vm.set_labels", req.Name, "permission denied", "denied")
		return nil, err
	}

	// Merge the new labels into the stored spec and persist. Labels live in the
	// replicated cluster state (corrosion), so we write directly — no host forward
	// or libvirt call. MutateDesiredSpec applies the merge to the FRESH spec under
	// the mutation barrier (and touches only spec, not cpu/mem — this is a metadata
	// edit that must not clobber a running VM's live actuals).
	applied, _, err := corrosion.MutateDesiredSpec(ctx, s.db, req.Name, func(old string) (string, error) {
		spec := &pb.VMSpec{}
		if old != "" {
			if err := json.Unmarshal([]byte(old), spec); err != nil {
				return "", fmt.Errorf("parse stored spec: %w", err)
			}
		}
		spec.Labels = req.Labels
		b, err := json.Marshal(spec)
		if err != nil {
			return "", fmt.Errorf("marshal spec: %w", err)
		}
		return string(b), nil
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "persist labels: %v", err)
	}
	if !applied {
		s.audit(ctx, "vm.set_labels", req.Name, "operation in progress", "denied")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot set labels for VM %q: an operation is in progress", req.Name)
	}

	s.audit(ctx, "vm.set_labels", req.Name, "labels="+labelsSummary(req.Labels), "ok")
	return s.vmToProto(ctx, req.Name)
}

// labelsSummary renders a stable "k=v,k2=v2" string for audit logging.
func labelsSummary(labels map[string]string) string {
	if len(labels) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("%s=%s", k, labels[k])
	}
	return out
}
