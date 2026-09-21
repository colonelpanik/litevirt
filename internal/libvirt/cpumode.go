package libvirt

import "fmt"

// CPU mode constants. These are the libvirt `<cpu mode=...>` values litevirt
// renders; anything else is refused at validation so an operator never learns
// about a typo from a raw libvirt define error.
const (
	// CPUModeHostPassthrough exposes the host CPU verbatim. Fastest, and the
	// only mode that carries nested-virt (vmx/svm) and every last feature flag
	// into the guest — but it pins live migration to effectively identical
	// hardware, because the guest sees a CPU libvirt cannot reproduce elsewhere.
	CPUModeHostPassthrough = "host-passthrough"

	// CPUModeHostModel resolves, at domain start, to the closest named model the
	// host supports plus its extra feature flags. The guest gets the host's
	// modern ISA (SSE4.2 / AVX / AVX2 / AVX-512 as the host has them) while
	// staying migratable to any host with an equal-or-richer CPU; libvirt
	// refuses a poorer destination with a clear error instead of running a
	// guest on a CPU that has lost instructions underneath it.
	CPUModeHostModel = "host-model"

	// CPUModeCustom pins a named QEMU CPU model explicitly. Requires a model
	// name (see ValidateCPUMode) — it is the mode to use for a deliberately
	// uniform baseline across a heterogeneous fleet.
	CPUModeCustom = "custom"
)

// DefaultCPUMode is what a VM created without an explicit choice gets.
//
// It is host-model rather than the historical empty string. Empty means "emit
// no <cpu> element", which makes libvirt pass no -cpu to QEMU, which lands the
// guest on QEMU's x86_64 default of `qemu64`: a model with no sse4.1, no
// sse4.2, no xsave, and therefore no AVX and no AVX2, on hosts that have all of
// them. Modern guest software increasingly assumes that baseline — anything
// Bun-compiled requires AVX2 outright — so the old default produced VMs that
// could not run it, with a fault that looks like a broken binary rather than a
// hypervisor setting.
//
// host-model and not host-passthrough because litevirt live-migrates, fails
// over and rebalances: host-model keeps the guest ISA close to the host while
// leaving migration to an equal-or-richer host intact.
//
// This default is applied at CREATE time, into the stored spec — never in the
// renderer. A VM already persisted with an empty cpu_mode keeps rendering
// exactly as it did, so a rolling upgrade cannot change a running guest's CPU
// underneath it (and cannot break its in-flight migratability). Use
// `lv update <vm> --cpu-mode host-model` on a stopped VM to move an existing
// one forward, and `lv doctor cpu-mode` to find them.
const DefaultCPUMode = CPUModeHostModel

// ValidateCPUMode checks a (mode, model) pair before it reaches a stored spec.
//
// The empty mode stays legal: it is what every VM created before this default
// existed carries, and rejecting it would make those specs un-updatable.
//
// custom REQUIRES a model. `<cpu mode='custom'/>` with no <model> child is
// invalid to libvirt, so without this check the pair fails at define time with
// an opaque libvirt error — which is what `--cpu-mode custom` did.
func ValidateCPUMode(mode, model string) error {
	switch mode {
	case "":
		if model != "" {
			return fmt.Errorf("cpu model %q needs --cpu-mode custom", model)
		}
		return nil
	case CPUModeHostPassthrough, CPUModeHostModel:
		if model != "" {
			return fmt.Errorf("cpu model %q is only valid with --cpu-mode custom, not %s", model, mode)
		}
		return nil
	case CPUModeCustom:
		if model == "" {
			return fmt.Errorf("--cpu-mode custom needs a model (--cpu-model, e.g. x86-64-v3); " +
				"libvirt rejects a custom CPU with no model")
		}
		return nil
	default:
		return fmt.Errorf("invalid cpu mode %q: want %s, %s or %s",
			mode, CPUModeHostPassthrough, CPUModeHostModel, CPUModeCustom)
	}
}

// CPUModeExposesHostFeatures reports whether mode derives the guest CPU from
// the host's, and so can differ between two hosts in one cluster. Only those
// modes need a destination CPU-compatibility preflight before a migration; an
// empty mode (qemu64) and a pinned custom model are identical everywhere, so
// checking them would be pure cost.
func CPUModeExposesHostFeatures(mode string) bool {
	return mode == CPUModeHostPassthrough || mode == CPUModeHostModel
}
