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
	// replicated cluster state (corrosion), so we write directly — no host
	// forward or libvirt call.
	spec := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			return nil, status.Errorf(codes.Internal, "parse stored spec: %v", err)
		}
	}
	spec.Labels = req.Labels
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal spec: %v", err)
	}
	// Preserve current cpu/mem — this is a metadata-only edit.
	if err := corrosion.UpdateVMSpec(ctx, s.db, req.Name, string(specJSON), vm.CPUActual, vm.MemActual); err != nil {
		return nil, status.Errorf(codes.Internal, "persist labels: %v", err)
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
