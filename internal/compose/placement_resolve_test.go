package compose

import "testing"

func TestExpandPlacementMode_Performance(t *testing.T) {
	p := &PlacementDef{Mode: "performance"}
	ExpandPlacementMode(p)
	if p.Policy != "balance" {
		t.Errorf("performance.Policy = %q, want balance", p.Policy)
	}
	if p.Rebalance == nil || p.Rebalance.Mode != "dry-run" {
		t.Errorf("performance.Rebalance.Mode = %+v, want dry-run", p.Rebalance)
	}
}

func TestExpandPlacementMode_Savings(t *testing.T) {
	p := &PlacementDef{Mode: "savings"}
	ExpandPlacementMode(p)
	if p.Policy != "bin-pack" {
		t.Errorf("savings.Policy = %q, want bin-pack", p.Policy)
	}
	if p.Rebalance.Mode != "auto" {
		t.Errorf("savings.Rebalance.Mode = %q, want auto", p.Rebalance.Mode)
	}
	if p.Rebalance.Budget == nil || p.Rebalance.Budget.Window != "off-hours" {
		t.Errorf("savings.Rebalance.Budget = %+v, want window=off-hours", p.Rebalance.Budget)
	}
}

func TestExpandPlacementMode_ExplicitWins(t *testing.T) {
	p := &PlacementDef{
		Mode:   "savings",
		Policy: "balance", // explicit overrides savings's bin-pack
	}
	ExpandPlacementMode(p)
	if p.Policy != "balance" {
		t.Errorf("explicit Policy lost to alias: got %q, want balance", p.Policy)
	}
}

func TestValidatePlacement_BinPackAutoWarns(t *testing.T) {
	p := &PlacementDef{
		Policy:    "bin-pack",
		Rebalance: &RebalanceDef{Mode: "auto"},
	}
	warns, errs := ValidatePlacement(p)
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(warns) == 0 {
		t.Error("expected warning for bin-pack + auto rebalance")
	}
}

func TestValidatePlacement_UnknownPolicy(t *testing.T) {
	p := &PlacementDef{Policy: "magic"}
	_, errs := ValidatePlacement(p)
	if len(errs) == 0 {
		t.Error("expected error for unknown policy")
	}
}

func TestValidatePlacement_UnknownMode(t *testing.T) {
	p := &PlacementDef{Mode: "fastest"}
	_, errs := ValidatePlacement(p)
	if len(errs) == 0 {
		t.Error("expected error for unknown mode")
	}
}

func TestMergePlacement_ChildOverridesParent(t *testing.T) {
	parent := &PlacementDef{
		Policy: "balance",
		Rebalance: &RebalanceDef{
			Mode:      "dry-run",
			Threshold: 15,
		},
	}
	child := &PlacementDef{
		Rebalance: &RebalanceDef{Mode: "auto"},
	}
	merged := MergePlacement(parent, child)
	if merged.Policy != "balance" {
		t.Errorf("inherited Policy = %q, want balance", merged.Policy)
	}
	if merged.Rebalance.Mode != "auto" {
		t.Errorf("Rebalance.Mode = %q, want auto", merged.Rebalance.Mode)
	}
	if merged.Rebalance.Threshold != 15 {
		t.Errorf("inherited Threshold lost: %d", merged.Rebalance.Threshold)
	}
}

func TestMergePlacement_ChainResolves(t *testing.T) {
	cluster := ResolveClusterPlacementDefault()
	stack := &PlacementDef{
		Mode: "ha-critical", // spread-strict + on-demand
	}
	vm := &PlacementDef{
		AntiAffinity: []string{"web-1"},
	}
	step1 := MergePlacement(cluster, stack)
	final := MergePlacement(step1, vm)
	if final.Policy != "spread-strict" {
		t.Errorf("final.Policy = %q, want spread-strict", final.Policy)
	}
	if final.Rebalance.Mode != "on-demand" {
		t.Errorf("final.Rebalance.Mode = %q, want on-demand", final.Rebalance.Mode)
	}
	if len(final.AntiAffinity) != 1 || final.AntiAffinity[0] != "web-1" {
		t.Errorf("final.AntiAffinity = %v, want [web-1]", final.AntiAffinity)
	}
}

func TestClusterDefault_IsBalanceDryRun(t *testing.T) {
	d := ResolveClusterPlacementDefault()
	if d.Policy != "balance" {
		t.Errorf("cluster default Policy = %q, want balance", d.Policy)
	}
	if d.Rebalance == nil || d.Rebalance.Mode != "dry-run" {
		t.Errorf("cluster default Rebalance = %+v, want dry-run", d.Rebalance)
	}
}
