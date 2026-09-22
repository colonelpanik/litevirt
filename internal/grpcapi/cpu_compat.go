package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// CheckCPUCompatibility reports whether THIS host can run a guest requiring the
// CPU described by req.CpuXml. Peer-only, read-only, decides nothing: it is the
// destination half of the migration CPU preflight.
func (s *Server) CheckCPUCompatibility(ctx context.Context, req *pb.CheckCPUCompatibilityRequest) (*pb.CheckCPUCompatibilityResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, status.Error(codes.PermissionDenied, "CheckCPUCompatibility is peer-only")
	}
	if req.GetCpuXml() == "" {
		return nil, status.Error(codes.InvalidArgument, "cpu_xml is required")
	}
	verdict, err := s.virt.CompareCPU(req.GetCpuXml())
	if err != nil {
		// Unavailable, not Internal: the caller cannot tell whether this host is
		// compatible, which is a "could not verify" — and the caller is built to
		// proceed on that rather than block a migration on a compare it could not
		// run. Saying Internal would read as a defect on this host.
		return nil, status.Errorf(codes.Unavailable, "compare cpu: %v", err)
	}
	return &pb.CheckCPUCompatibilityResponse{
		Runnable: verdict.Runnable(),
		Verdict:  verdict.String(),
	}, nil
}

// parseSpecCPUMode reads cpu_mode out of a stored spec JSON. An unreadable or
// absent value yields "" — the pre-default shape, which needs no CPU preflight.
func parseSpecCPUMode(specJSON string) string {
	var spec struct {
		CPUMode string `json:"cpu_mode"`
	}
	_ = json.Unmarshal([]byte(specJSON), &spec)
	return spec.CPUMode
}

// effectiveDefaultCPUMode is this node's configured cpu_mode default, falling
// back to the built-in one. Every path that DEFINES a brand-new domain goes
// through here, so none of them can quietly leave a guest on QEMU's qemu64.
func (s *Server) effectiveDefaultCPUMode() string {
	if s.defaultCPUModeCfg != "" {
		return s.defaultCPUModeCfg
	}
	return lv.DefaultCPUMode
}

// mergeCPUModeUpdate folds an update request's cpu_mode/cpu_model onto a stored
// spec's pair and returns the result, or an error if the operator asked for
// something libvirt would reject.
//
// The only subtlety is moving OFF custom: a host-* mode carries no model, so the
// stored one is dropped. Keeping it would fail validation on
// `--cpu-mode host-model` alone — an edit with an obvious intent — and force the
// operator to discover they must also clear a field the new mode does not use.
func mergeCPUModeUpdate(specMode, specModel, reqMode, reqModel string) (mode, model string, err error) {
	mode, model = specMode, specModel
	if reqMode != "" {
		mode = reqMode
		if reqMode != lv.CPUModeCustom {
			model = ""
		}
	}
	if reqModel != "" {
		model = reqModel
	}
	if err := lv.ValidateCPUMode(mode, model); err != nil {
		return "", "", err
	}
	return mode, model, nil
}

// cpuRequirementForMigration derives the CPU requirement a migration of vm must
// satisfy on its destination, reading the SOURCE's live domain XML.
//
// It returns ok=false whenever there is nothing meaningful to check, which is
// the common case and deliberately cheap:
//   - a VM with no <cpu> element at all (an empty cpu_mode — QEMU's qemu64),
//     which is identical on every host and so always compatible;
//   - a custom mode pinned to a named model, likewise identical everywhere.
//
// For host-model, libvirt has already expanded the live XML to a concrete model
// plus feature list, so the requirement is exact. For host-passthrough the live
// XML names no model, so the requirement is the SOURCE HOST's own CPU — which
// is precisely what such a guest is running on.
func (s *Server) cpuRequirementForMigration(vm *corrosion.VMRecord) (cpuXML string, ok bool) {
	mode := parseSpecCPUMode(vm.Spec)
	if !lv.CPUModeExposesHostFeatures(mode) {
		return "", false
	}
	if xmlDesc, err := s.virt.DumpXML(vm.Name); err == nil {
		if req, found := lv.DomainCPURequirement(xmlDesc); found {
			return req, true
		}
	}
	// host-passthrough (or a live XML we could not read): the guest requires this
	// host's CPU.
	if mode == lv.CPUModeHostPassthrough {
		if hostCPU, err := s.virt.HostCPUXML(); err == nil && hostCPU != "" {
			return hostCPU, true
		}
	}
	return "", false
}

// preflightTargetCPU refuses a migration whose destination cannot run the
// guest's CPU, BEFORE any target-side provisioning.
//
// Fail-open by design, and the failure modes matter more than the happy path:
//
//   - an older peer does not implement the RPC (codes.Unimplemented), so during a
//     rolling upgrade the check must be a no-op rather than the reason migration
//     stops working;
//   - a peer that cannot run the compare answers Unavailable, which is "could not
//     verify", not "incompatible".
//
// Only an explicit, positive "this host cannot run that guest" refuses. That is
// the one answer libvirt would otherwise deliver mid-copy, after the target has
// been provisioned and the guest's memory is already moving.
func (s *Server) preflightTargetCPU(ctx context.Context, vm *corrosion.VMRecord, targetHost string) error {
	cpuXML, ok := s.cpuRequirementForMigration(vm)
	if !ok {
		return nil
	}
	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		// Reaching the target is checked for real by the phases that follow; a
		// preflight must not invent its own unreachability failure here.
		return nil
	}
	defer conn.Close()

	resp, err := client.CheckCPUCompatibility(ctx, &pb.CheckCPUCompatibilityRequest{CpuXml: cpuXML})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			slog.Info("skipping migration CPU preflight: target does not implement it",
				"vm", vm.Name, "target", targetHost)
			return nil
		}
		slog.Warn("migration CPU preflight could not verify the target",
			"vm", vm.Name, "target", targetHost, "err", err)
		return nil
	}
	if resp.GetRunnable() {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"target host %q cannot run VM %q: its CPU does not provide what the guest is running on "+
			"(cpu_mode=%s, verdict=%s). Migrate to a host with an equal-or-newer CPU, or stop the VM "+
			"and `lv update %s --cpu-mode custom --cpu-model <baseline>` to pin a model both hosts support.",
		targetHost, vm.Name, parseSpecCPUMode(vm.Spec), resp.GetVerdict(), vm.Name)
}
