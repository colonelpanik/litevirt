package compose

import (
	"fmt"
	"maps"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Action is the coarsest action a set of desired-vs-stored changes requires,
// ordered so a larger value dominates a smaller one (Recreate > Restart > Live >
// NoChange). It answers "how must this update be applied?", not "what changed" —
// the retained deltas in a ChangePlan carry the detail.
type Action int

const (
	ActionNoChange Action = iota
	// ActionLive: every change can be applied to a running VM in place — a live
	// resource resize (cpu grow within the hotplug ceiling / balloon within band)
	// and/or a live-metadata spec patch. No stop, no recreate.
	ActionLive
	// ActionRestart: at least one change bakes into the domain XML (or has no
	// live-apply RPC) and needs a stop→redefine→start. NEVER deletes the VM.
	ActionRestart
	// ActionRecreate: at least one change alters VM identity (image / boot media /
	// disk or network topology / cloud-init) — the only safe apply is delete+create,
	// which destroys disks. Reachable only under an explicit recreate-class strategy.
	ActionRecreate
)

func (a Action) String() string {
	switch a {
	case ActionNoChange:
		return "no-change"
	case ActionLive:
		return "live"
	case ActionRestart:
		return "restart"
	case ActionRecreate:
		return "recreate"
	default:
		return "unknown"
	}
}

// Delta is one changed field with its human-readable old→new values, retained
// even when the plan's Max() downgrades to a coarser action (so a non-in-place
// executor still has the full picture).
type Delta struct {
	Field string
	Old   string
	New   string
}

// StoredDisk is a neutral projection of a persisted disk's topology (identity +
// bus + storage backend), built by the planner so the classifier never imports a
// corrosion/DB type. Size lives outside topology — a grow is the disk-resize
// path's job, not a recreate.
type StoredDisk struct {
	Name    string
	Bus     string
	Storage string
}

// StoredDisksFromSpec projects a VMSpec's disks into the neutral StoredDisk form.
// The planner uses it to build the stored-disk projection from the persisted spec.
func StoredDisksFromSpec(spec *pb.VMSpec) []StoredDisk {
	if spec == nil {
		return nil
	}
	out := make([]StoredDisk, 0, len(spec.Disks))
	for _, d := range spec.Disks {
		if d == nil {
			continue
		}
		out = append(out, StoredDisk{Name: d.Name, Bus: d.Bus, Storage: d.Storage})
	}
	return out
}

// ChangePlan is the classified diff between a desired and a stored VM spec. Every
// changed field lands in exactly one bucket AND is retained (nothing is dropped
// once a coarser action wins), so callers can both decide how to apply the update
// (Max) and report precisely what changed.
type ChangePlan struct {
	// ResourceChanges are live-eligible cpu/memory resizes (Max=Live unless a
	// coarser bucket is also populated).
	ResourceChanges []Delta
	// MetadataChanges are live-eligible spec patches (restart policy, onboot,
	// ordering, labels, placement, migrate) — persisted, no runtime action.
	MetadataChanges []Delta
	// RestartReasons are changes that need a stop→redefine→start.
	RestartReasons []string
	// RecreateReasons are changes that alter VM identity (delete+create only).
	RecreateReasons []string
	// Delegated records changes owned by another path (load-balancer, backup,
	// rolling-update strategy) — recorded, not silently ignored, and never a VM
	// lifecycle action here.
	Delegated []string
}

// Max returns the coarsest action the plan requires (Recreate > Restart > Live >
// NoChange). Delegated-only and empty plans are NoChange — the VM itself needs no
// lifecycle action.
func (p ChangePlan) Max() Action {
	switch {
	case len(p.RecreateReasons) > 0:
		return ActionRecreate
	case len(p.RestartReasons) > 0:
		return ActionRestart
	case len(p.ResourceChanges) > 0 || len(p.MetadataChanges) > 0:
		return ActionLive
	default:
		return ActionNoChange
	}
}

// Classify diffs a desired spec against the stored spec (+ its disk-topology
// projection) and returns the classified ChangePlan. It is a pure function over
// neutral types (gen-package protos + StoredDisk) so it lives in compose without
// importing corrosion, and the planner — which owns the cluster-state snapshot —
// calls it after building the projection.
//
// Inherit-on-unset: an UNSET desired scalar/pointer/slice (zero string, zero int,
// nil message, empty slice) means "compose did not specify it" and is treated as NO
// change — matching compose's documented merge semantics ("child wins if non-zero;
// zero-value inherits"). This is essential because the STORED spec carries create-time
// defaults + server-assigned values (machine, firmware, resolved placement, uuid…)
// that the compose-built desired spec leaves unset; a naive equality would spuriously
// flag every such field as a change and wrongly block an in-place update. A nil stored
// spec is treated as empty.
func Classify(desired, stored *pb.VMSpec, storedDisks []StoredDisk) ChangePlan {
	var p ChangePlan
	if desired == nil {
		return p
	}
	if stored == nil {
		stored = &pb.VMSpec{}
	}

	// --- Live resources: cpu (unset desired inherits) ---
	if desired.Cpu != 0 && desired.Cpu != stored.Cpu {
		delta := Delta{Field: "cpu", Old: fmt.Sprintf("%d", stored.Cpu), New: fmt.Sprintf("%d", desired.Cpu)}
		switch {
		case desired.Cpu < stored.Cpu:
			p.RestartReasons = append(p.RestartReasons,
				fmt.Sprintf("cpu shrink %d→%d needs a restart", stored.Cpu, desired.Cpu))
		case stored.MaxCpu > 0 && desired.Cpu <= stored.MaxCpu:
			p.ResourceChanges = append(p.ResourceChanges, delta) // live grow within hotplug ceiling
		default:
			p.RestartReasons = append(p.RestartReasons,
				fmt.Sprintf("cpu grow %d→%d exceeds the hotplug ceiling (max_cpu=%d) — needs a restart", stored.Cpu, desired.Cpu, stored.MaxCpu))
		}
	}

	// --- Live resources: memory balloon within the domain's band (unset inherits) ---
	if desired.MemoryMib != 0 && desired.MemoryMib != stored.MemoryMib {
		floor := stored.MinMemoryMib
		ceiling := stored.MaxMemoryMib
		if ceiling == 0 {
			ceiling = stored.MemoryMib // no headroom declared: can balloon down but not up
		}
		if desired.MemoryMib >= floor && desired.MemoryMib <= ceiling {
			p.ResourceChanges = append(p.ResourceChanges, Delta{
				Field: "memory", Old: fmt.Sprintf("%d", stored.MemoryMib), New: fmt.Sprintf("%d", desired.MemoryMib)})
		} else {
			p.RestartReasons = append(p.RestartReasons,
				fmt.Sprintf("memory %d→%dMiB is outside the balloon band [%d,%d] — needs a restart", stored.MemoryMib, desired.MemoryMib, floor, ceiling))
		}
	}

	// --- Restart-class: redefine-only fields (no live-apply RPC); unset desired inherits ---
	restartIf := func(cond bool, reason string) {
		if cond {
			p.RestartReasons = append(p.RestartReasons, reason)
		}
	}
	restartIf(desired.MaxCpu != 0 && desired.MaxCpu != stored.MaxCpu, fmt.Sprintf("max_cpu %d→%d needs a redefine", stored.MaxCpu, desired.MaxCpu))
	restartIf(desired.MinMemoryMib != 0 && desired.MinMemoryMib != stored.MinMemoryMib, "min-memory change needs a redefine")
	restartIf(desired.MaxMemoryMib != 0 && desired.MaxMemoryMib != stored.MaxMemoryMib, "max-memory change needs a redefine")
	restartIf(desired.CpuMode != "" && desired.CpuMode != stored.CpuMode, "cpu-mode change needs a redefine")
	restartIf(desired.Machine != "" && desired.Machine != stored.Machine, "machine-type change needs a redefine")
	restartIf(desired.Firmware != "" && desired.Firmware != stored.Firmware, "firmware change needs a redefine")
	// Bools carry no "unset" sentinel; BuildVMSpec applies the same defaults the create
	// path stores (e.g. guest-agent via EffectiveGuestAgent), so an equality compare is
	// safe and won't false-positive on a server default.
	restartIf(desired.GuestAgent != stored.GuestAgent, "guest-agent toggle needs a redefine")
	restartIf(desired.DisableVnc != stored.DisableVnc || desired.EnableSpice != stored.EnableSpice, "graphics change needs a redefine")
	restartIf(desired.SecureBoot != stored.SecureBoot, "secure-boot change needs a redefine")
	restartIf(desired.Tpm != stored.Tpm, "tpm change needs a redefine")
	restartIf(desired.StopTimeoutSec != 0 && desired.StopTimeoutSec != stored.StopTimeoutSec, "stop-grace-period change needs a redefine")
	restartIf(desired.Resources != nil && !proto.Equal(desired.Resources, stored.Resources), "resource-tuning change needs a redefine")
	restartIf(desired.Healthcheck != nil && !proto.Equal(desired.Healthcheck, stored.Healthcheck), "health-check change needs a redefine")
	restartIf(desired.Hooks != nil && !proto.Equal(desired.Hooks, stored.Hooks), "lifecycle-hooks change needs a redefine")
	restartIf(len(desired.Devices) > 0 && !devicesEqual(desired.Devices, stored.Devices), "passthrough-device change needs a redefine")

	// --- Recreate-class: identity fields (delete+create only); unset desired inherits ---
	recreateIf := func(cond bool, reason string) {
		if cond {
			p.RecreateReasons = append(p.RecreateReasons, reason)
		}
	}
	recreateIf(desired.Image != "" && desired.Image != stored.Image, fmt.Sprintf("image %q→%q recreates", stored.Image, desired.Image))
	recreateIf(desired.Iso != "" && desired.Iso != stored.Iso, "boot-media (iso) change recreates")
	if dd := StoredDisksFromSpec(desired); len(dd) > 0 {
		recreateIf(!disksTopologyEqual(dd, storedDisks), "disk-topology change recreates")
	}
	recreateIf(len(desired.Network) > 0 && !networkTopologyEqual(desired.Network, stored.Network), "network-topology change recreates")
	recreateIf(desired.CloudInit != nil && !proto.Equal(desired.CloudInit, stored.CloudInit), "cloud-init change recreates")

	// --- Live metadata: spec-persisted, no runtime action; unset desired inherits ---
	metaIf := func(cond bool, field, old, new string) {
		if cond {
			p.MetadataChanges = append(p.MetadataChanges, Delta{Field: field, Old: old, New: new})
		}
	}
	metaIf(desired.Restart != nil && !proto.Equal(desired.Restart, stored.Restart), "restart", stored.Restart.GetCondition(), desired.Restart.GetCondition())
	metaIf(desired.Onboot != stored.Onboot, "onboot", fmt.Sprintf("%v", stored.Onboot), fmt.Sprintf("%v", desired.Onboot))
	metaIf(desired.StartupOrder != stored.StartupOrder, "startup_order", fmt.Sprintf("%d", stored.StartupOrder), fmt.Sprintf("%d", desired.StartupOrder))
	metaIf(desired.StartDelaySec != stored.StartDelaySec, "start_delay", fmt.Sprintf("%d", stored.StartDelaySec), fmt.Sprintf("%d", desired.StartDelaySec))
	metaIf(desired.StopDelaySec != stored.StopDelaySec, "stop_delay", fmt.Sprintf("%d", stored.StopDelaySec), fmt.Sprintf("%d", desired.StopDelaySec))
	metaIf(len(desired.Labels) > 0 && !maps.Equal(desired.Labels, stored.Labels), "labels", "", "")
	metaIf(desired.Placement != nil && !proto.Equal(desired.Placement, stored.Placement), "placement", "", "")
	metaIf(desired.Migrate != nil && !proto.Equal(desired.Migrate, stored.Migrate), "migrate", "", "")

	// --- Delegated: owned by another path, recorded not ignored ---
	if desired.Loadbalancer != nil && !proto.Equal(desired.Loadbalancer, stored.Loadbalancer) {
		p.Delegated = append(p.Delegated, "load-balancer")
	}
	if desired.Update != nil && !proto.Equal(desired.Update, stored.Update) {
		p.Delegated = append(p.Delegated, "update-strategy")
	}

	return p
}

// devicesEqual compares two device lists by content (order-sensitive — a reorder
// is a topology change to libvirt).
func devicesEqual(a, b []*pb.DeviceSpec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !proto.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// disksTopologyEqual compares disk topology (identity + bus + storage), ignoring
// size (a grow is the resize path's job, not a recreate).
func disksTopologyEqual(a, b []StoredDisk) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// networkTopologyEqual compares NIC topology by the stable, non-server-resolved
// fields (network name + model), ignoring server-assigned MAC/IP so a live
// address assignment never reads as a topology change.
func networkTopologyEqual(a, b []*pb.NetworkAttachment) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].GetName() != b[i].GetName() || a[i].GetModel() != b[i].GetModel() {
			return false
		}
	}
	return true
}
