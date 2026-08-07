package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Effective host capacity — what the host is ACTUALLY carrying, not what the
// database believes it allocated. Computed over the UNION of database and
// runtime workloads, so a rogue runtime the database does not know about still
// consumes headroom in every placement decision:
//
//   - a workload present on BOTH sides charges the GREATER configured
//     allocation (a runtime grown past its DB spec is really using the grown
//     size; a DB spec bigger than the runtime is still the promise placement
//     must honor);
//   - a DB-only RUNNING workload keeps its DB charge (the runtime probe may
//     have raced a start);
//   - a runtime-only workload ADDS its runtime allocation on top;
//   - an UNCAPPED runtime-only container, or any probe failure, makes the
//     observation INCOMPLETE — its consumption cannot be attributed, and
//     placement must treat the host as unknown, never as headroom.
//
// Only the observed host samples itself (host_name is the row's ownership),
// from its own runtime inventory — replicated telemetry is never the input.

// SampleHostCapacity computes and publishes this host's effective capacity
// observation. Called by the daemon's capacity sampler loop.
func (s *Server) SampleHostCapacity(ctx context.Context) error {
	inv := s.collectRuntimeInventory(ctx)
	vms, err := corrosion.ListVMs(ctx, s.db, "", s.hostName)
	if err != nil {
		return fmt.Errorf("list VMs: %w", err)
	}
	cts, err := corrosion.ListContainers(ctx, s.db, s.hostName)
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	obs := computeCapacityObservation(s.hostName, inv, vms, cts)
	return corrosion.UpsertHostCapacityObservation(ctx, s.db, obs)
}

// RunCapacitySampler publishes this host's observation on a fixed interval.
func (s *Server) RunCapacitySampler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	sample := func() {
		if err := s.SampleHostCapacity(ctx); err != nil {
			slog.Warn("capacity sampler", "error", err)
		}
	}
	sample()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sample()
		}
	}
}

// computeCapacityObservation is the pure union computation (see the file doc).
func computeCapacityObservation(
	host string,
	inv runtimeInventory,
	vms []corrosion.VMRecord,
	cts []corrosion.ContainerRecord,
) corrosion.HostCapacityObservation {
	obs := corrosion.HostCapacityObservation{
		HostName:  host,
		Complete:  inv.Complete,
		SampledAt: inv.SampledAt,
	}
	var details []string
	if !inv.Complete {
		details = append(details, "runtime inventory incomplete: "+strings.Join(inv.Errors, "; "))
	}

	// The database's charge: running VMs at their recorded actuals, running
	// containers at their declared limits — the same accounting the placement
	// snapshot uses.
	type dbEntry struct{ cpu, mem int }
	dbSide := map[finding]dbEntry{}
	for _, vm := range vms {
		if vm.State == "running" {
			dbSide[finding{kind: corrosion.WorkloadVM, target: vm.Name}] = dbEntry{cpu: vm.CPUActual, mem: vm.MemActual}
		}
	}
	for _, ct := range cts {
		if ct.State == "running" {
			dbSide[finding{kind: corrosion.WorkloadContainer, target: ct.Name}] = dbEntry{cpu: ct.CPULimit, mem: ct.MemMiB}
		}
	}
	for _, e := range dbSide {
		obs.DBCPU += e.cpu
		obs.DBMemMiB += e.mem
	}

	// Union: start from the DB charge, then walk the runtime side.
	obs.EffectiveCPU, obs.EffectiveMemMiB = obs.DBCPU, obs.DBMemMiB
	for _, w := range inv.Workloads {
		if w.State != health.RuntimeRunning {
			continue
		}
		if w.ProbeError != "" {
			obs.Complete = false
			details = append(details, fmt.Sprintf("%s %s: %s", w.Kind, w.Name, w.ProbeError))
		}
		key := finding{kind: w.Kind, target: w.Name}
		if db, matched := dbSide[key]; matched {
			// Matching workload: charge the greater allocation per dimension.
			if w.CPU > db.cpu {
				obs.EffectiveCPU += w.CPU - db.cpu
				details = append(details, fmt.Sprintf("%s %s runs at %d vCPU, DB says %d", w.Kind, w.Name, w.CPU, db.cpu))
			}
			if w.MemoryMiB > db.mem {
				obs.EffectiveMemMiB += w.MemoryMiB - db.mem
				details = append(details, fmt.Sprintf("%s %s runs at %d MiB, DB says %d", w.Kind, w.Name, w.MemoryMiB, db.mem))
			}
			continue
		}
		// Runtime-only: the database does not know this workload exists.
		if w.Uncapped {
			// Unbounded consumption that cannot be attributed: the whole
			// observation is unknowable, not merely bigger.
			obs.Complete = false
			details = append(details, fmt.Sprintf("uncapped runtime-only container %q", w.Name))
			continue
		}
		obs.EffectiveCPU += w.CPU
		obs.EffectiveMemMiB += w.MemoryMiB
		details = append(details, fmt.Sprintf("runtime-only %s %q (+%d vCPU/+%d MiB)", w.Kind, w.Name, w.CPU, w.MemoryMiB))
	}
	obs.ExtraCPU = obs.EffectiveCPU - obs.DBCPU
	obs.ExtraMemMiB = obs.EffectiveMemMiB - obs.DBMemMiB

	sort.Strings(details)
	obs.Detail = strings.Join(details, "; ")
	return obs
}
