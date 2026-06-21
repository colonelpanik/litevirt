// Package tenancy is the business-logic façade over the
// projects + project_quotas Corrosion tables. The raw SQL lives in
// internal/corrosion/projects.go (alongside every other replicated
// table); this package wraps those primitives with the admission
// semantics and quota arithmetic the rest of the codebase consumes.
//
// Separation of concerns:
//
//   - internal/corrosion/projects.go     — table shape, CRUD, raw SQL.
//   - internal/tenancy/ (this package)   — admission decisions, project
//     path arithmetic, transitions emitted to internal/billing.
//   - internal/grpcapi/projects.go       — the gRPC handlers call into
//     this package rather than going to corrosion directly so the
//     billing/admission policy stays in one place.
package tenancy

import (
	"context"
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/billing"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Default is the implicit project every VM lands in if nothing else
// is specified. Re-exported from corrosion so callers don't have to
// reach into the data-layer constants.
const Default = corrosion.DefaultProject

// QuotaRequest is the shape passed into Admit when the gRPC handler
// is deciding whether to accept a CreateVM. Fields mirror the quota
// dimensions from
type QuotaRequest struct {
	VCPU      int
	MemMiB    int
	DiskGiB   int
	NIC       int
	PublicIPs int
	BackupGiB int
}

// Engine bundles the per-cluster admission + billing state. Built by
// the daemon at startup and passed into grpcapi.Server via setter
// (callers that don't construct one get the default behaviour:
// unbounded admission, no billing events emitted).
type Engine struct {
	db      *corrosion.Client
	emitter billing.Emitter
}

// NewEngine constructs an Engine. emitter may be nil — billing events
// will be silently dropped (useful when an operator hasn't configured
// a webhook destination).
func NewEngine(db *corrosion.Client, emitter billing.Emitter) *Engine {
	if emitter == nil {
		emitter = billing.NopEmitter{}
	}
	return &Engine{db: db, emitter: emitter}
}

// NormalizeProject collapses empty strings to the default project so
// the rest of the handler chain doesn't carry blank labels.
func NormalizeProject(name string) string {
	if name == "" {
		return Default
	}
	return name
}

// Admit gates a CreateVM-style request against the project's quota.
// Returns nil when the request fits; otherwise a descriptive error
// the caller maps to ResourceExhausted. The default project skips
// the quota lookup entirely — it's intentionally unbounded.
//
// Admit is the single place where every quota dimension is checked.
// New dimensions (e.g. GPU-count, vGPU-slice) should land here, not
// in the gRPC handler.
func (e *Engine) Admit(ctx context.Context, project string, req QuotaRequest) error {
	project = NormalizeProject(project)
	if project != Default {
		// Validate the project exists. Pre-check here lets the gRPC
		// handler emit codes.NotFound vs codes.ResourceExhausted
		// cleanly.
		p, err := corrosion.GetProject(ctx, e.db, project)
		if err != nil {
			return fmt.Errorf("get project: %w", err)
		}
		if p == nil {
			return fmt.Errorf("project %q not found", project)
		}
	}

	q, err := corrosion.GetProjectQuota(ctx, e.db, project)
	if err != nil {
		return fmt.Errorf("get quota: %w", err)
	}
	if q == nil {
		return nil
	}

	u, err := corrosion.SumProjectUsage(ctx, e.db, project)
	if err != nil {
		return fmt.Errorf("get usage: %w", err)
	}

	var violations []string
	chk := func(name string, used, add, limit int) {
		if limit > 0 && used+add > limit {
			violations = append(violations,
				fmt.Sprintf("%s (used %d + new %d > limit %d)", name, used, add, limit))
		}
	}
	chk("vcpu", u.VCPUUsed, req.VCPU, q.VCPULimit)
	chk("mem_mib", u.MemMiBUsed, req.MemMiB, q.MemMiBLimit)
	chk("disk_gib", u.DiskGiBUsed, req.DiskGiB, q.DiskGiBLimit)
	chk("nic", u.NICUsed, req.NIC, q.NICLimit)
	// public_ips and backup_gib now both have live usage counters
	// (non-private interface addresses; the vm_backups size index), so they
	// gate on used+new like the other dimensions.
	chk("public_ips", u.PublicIPsUsed, req.PublicIPs, q.PublicIPLimit)
	chk("backup_gib", u.BackupGiBUsed, req.BackupGiB, q.BackupGiBLimit)

	if len(violations) > 0 {
		return fmt.Errorf("project %q quota exceeded: %s",
			project, strings.Join(violations, "; "))
	}
	return nil
}

// EmitVMCreated reports a "vm.create" metered event for billing.
// Called by the gRPC handler after a successful CreateVM. Errors
// from the emitter are logged by the emitter implementation; this
// call never returns one.
func (e *Engine) EmitVMCreated(ctx context.Context, project, vmName string, req QuotaRequest) {
	e.emitter.Emit(ctx, billing.Event{
		Kind: "vm.create", Project: NormalizeProject(project), Subject: vmName,
		VCPU: req.VCPU, MemMiB: req.MemMiB, DiskGiB: req.DiskGiB,
	})
}

// EmitVMDeleted reports a "vm.delete" event. Useful for closing out
// metered counters (vm.minute, disk.gb-hour) on the billing side.
func (e *Engine) EmitVMDeleted(ctx context.Context, project, vmName string) {
	e.emitter.Emit(ctx, billing.Event{
		Kind: "vm.delete", Project: NormalizeProject(project), Subject: vmName,
	})
}
