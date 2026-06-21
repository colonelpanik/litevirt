package compose

// Named-mode aliases for placement.mode. See
//
// `mode` is a syntactic shortcut: at parse time we expand it into Policy +
// Rebalance fields. If those fields are *also* set explicitly on the same
// PlacementDef, the explicit values win — the alias just provides defaults
// for whatever is unset.
var namedModes = map[string]struct {
	Policy    string
	Rebalance RebalanceDef
}{
	"performance": {
		Policy: "balance",
		Rebalance: RebalanceDef{
			Mode:      "dry-run",
			Threshold: 15,
			Cooldown:  "5m",
		},
	},
	"savings": {
		Policy: "bin-pack",
		Rebalance: RebalanceDef{
			Mode:      "auto",
			Threshold: 25,
			Cooldown:  "10m",
			Budget: &RebalanceBudget{
				MaxConcurrent: 4,
				MaxPerHour:    20,
				Window:        "off-hours",
			},
		},
	},
	"ha-critical": {
		Policy: "spread-strict",
		Rebalance: RebalanceDef{
			Mode:      "on-demand",
			Threshold: 10,
			Cooldown:  "30m",
		},
	},
	"spot-cheap": {
		Policy: "cost-aware",
		Rebalance: RebalanceDef{
			Mode:      "auto",
			Threshold: 20,
			Cooldown:  "15m",
			Budget: &RebalanceBudget{
				MaxConcurrent: 2,
				MaxPerHour:    10,
			},
		},
	},
}

// IsNamedMode reports whether s is a recognized named-mode alias.
func IsNamedMode(s string) bool {
	_, ok := namedModes[s]
	return ok
}

// ExpandPlacementMode applies the named-mode alias defaults to p in-place.
// Explicit Policy / Rebalance fields are preserved; alias fills only the
// unset spots.
//
// Called once per VM after compose parsing, before the spec lands on the
// gRPC wire. Idempotent — calling twice with the same mode is a no-op.
func ExpandPlacementMode(p *PlacementDef) {
	if p == nil || p.Mode == "" {
		return
	}
	alias, ok := namedModes[p.Mode]
	if !ok {
		return // unknown mode — left for validator to flag
	}
	if p.Policy == "" {
		p.Policy = alias.Policy
	}
	if p.Rebalance == nil {
		p.Rebalance = &RebalanceDef{}
	}
	if p.Rebalance.Mode == "" {
		p.Rebalance.Mode = alias.Rebalance.Mode
	}
	if p.Rebalance.Threshold == 0 {
		p.Rebalance.Threshold = alias.Rebalance.Threshold
	}
	if p.Rebalance.Cooldown == "" {
		p.Rebalance.Cooldown = alias.Rebalance.Cooldown
	}
	if p.Rebalance.Budget == nil && alias.Rebalance.Budget != nil {
		b := *alias.Rebalance.Budget
		p.Rebalance.Budget = &b
	}
}

// ValidatePlacement returns user-facing warnings for misconfigured combos.
// Errors (returned via the second slice) abort admission; warnings are
// surfaced via gRPC response metadata so the operator sees them but the
// deploy proceeds.
//
// See — bin-pack + auto rebalance is the canonical "warn at
// admission" example.
func ValidatePlacement(p *PlacementDef) (warnings, errors []string) {
	if p == nil {
		return nil, nil
	}
	policy := p.Policy
	mode := ""
	if p.Rebalance != nil {
		mode = p.Rebalance.Mode
	}
	switch policy {
	case "", "balance", "bin-pack", "spread-strict", "cost-aware":
		// ok
	default:
		errors = append(errors, "placement.policy must be one of: balance, bin-pack, spread-strict, cost-aware")
	}
	switch mode {
	case "", "off", "dry-run", "on-demand", "auto":
		// ok
	default:
		errors = append(errors, "placement.rebalance.mode must be one of: off, dry-run, on-demand, auto")
	}
	if policy == "bin-pack" && mode == "auto" {
		warnings = append(warnings,
			"placement.policy=bin-pack with rebalance.mode=auto: rebalancer will continually contradict bin-pack consolidation. Consider mode=off or policy=balance.")
	}
	if p.Mode != "" && !IsNamedMode(p.Mode) {
		errors = append(errors,
			"placement.mode "+p.Mode+" is not a known named mode (try: performance, savings, ha-critical, spot-cheap)")
	}
	return warnings, errors
}

// ResolveClusterPlacementDefault returns the cluster-wide placement default
// applied to any VM that doesn't have its own PlacementDef. This is read
// from the daemon config; here we just provide the constant default so
// scope-chain resolution can have a fallback.
//
// Per: balance + dry-run is the recommended cluster default.
func ResolveClusterPlacementDefault() *PlacementDef {
	return &PlacementDef{
		Policy: "balance",
		Rebalance: &RebalanceDef{
			Mode:      "dry-run",
			Threshold: 15,
			Cooldown:  "5m",
		},
	}
}

// MergePlacement merges a child PlacementDef on top of a parent (parent
// providing defaults; child overriding). Used to walk the scope chain
// cluster → project → stack → VM.
//
// Mode aliases are first expanded into Policy + Rebalance fields on each
// side; then child's set fields override parent's.
//
// Hard fields (Host, AntiAffinity, Affinity, Require, NoMigrate, MaxPerNode):
// child completely replaces parent if set; otherwise inherits.
func MergePlacement(parent, child *PlacementDef) *PlacementDef {
	if parent == nil && child == nil {
		return nil
	}
	// Expand each side independently so the alias contributes alongside
	// (not under) any explicit fields the child happens to set.
	pCopy := copyPlacement(parent)
	cCopy := copyPlacement(child)
	ExpandPlacementMode(pCopy)
	ExpandPlacementMode(cCopy)

	if pCopy == nil {
		return cCopy
	}
	if cCopy == nil {
		return pCopy
	}

	out := *pCopy

	// Hard scalar fields.
	if cCopy.Host != "" {
		out.Host = cCopy.Host
	}
	if len(cCopy.AntiAffinity) > 0 {
		out.AntiAffinity = cCopy.AntiAffinity
	}
	if len(cCopy.Affinity) > 0 {
		out.Affinity = cCopy.Affinity
	}
	if len(cCopy.Require) > 0 {
		out.Require = cCopy.Require
	}
	if len(cCopy.Prefer) > 0 {
		out.Prefer = cCopy.Prefer
	}
	if cCopy.MaxPerNode > 0 {
		out.MaxPerNode = cCopy.MaxPerNode
	}
	if cCopy.NoMigrate {
		out.NoMigrate = true
	}
	if cCopy.Spread {
		out.Spread = true
	}

	// Policy: child's explicit (or alias-derived) value wins.
	if cCopy.Policy != "" {
		out.Policy = cCopy.Policy
	}

	// Rebalance: per-field override.
	if cCopy.Rebalance != nil {
		if out.Rebalance == nil {
			out.Rebalance = &RebalanceDef{}
		}
		if cCopy.Rebalance.Mode != "" {
			out.Rebalance.Mode = cCopy.Rebalance.Mode
		}
		if cCopy.Rebalance.Threshold > 0 {
			out.Rebalance.Threshold = cCopy.Rebalance.Threshold
		}
		if cCopy.Rebalance.Cooldown != "" {
			out.Rebalance.Cooldown = cCopy.Rebalance.Cooldown
		}
		if cCopy.Rebalance.Budget != nil {
			b := *cCopy.Rebalance.Budget
			out.Rebalance.Budget = &b
		}
	}

	// Once merged, Mode field's job is done — clear it so downstream
	// consumers don't try to re-expand it.
	out.Mode = ""

	return &out
}

func copyPlacement(p *PlacementDef) *PlacementDef {
	if p == nil {
		return nil
	}
	out := *p
	if p.Rebalance != nil {
		r := *p.Rebalance
		if p.Rebalance.Budget != nil {
			b := *p.Rebalance.Budget
			r.Budget = &b
		}
		out.Rebalance = &r
	}
	if p.Require != nil {
		out.Require = make(map[string]string, len(p.Require))
		for k, v := range p.Require {
			out.Require[k] = v
		}
	}
	if p.Prefer != nil {
		out.Prefer = make(map[string]string, len(p.Prefer))
		for k, v := range p.Prefer {
			out.Prefer[k] = v
		}
	}
	if p.AntiAffinity != nil {
		out.AntiAffinity = append([]string(nil), p.AntiAffinity...)
	}
	if p.Affinity != nil {
		out.Affinity = append([]string(nil), p.Affinity...)
	}
	return &out
}
