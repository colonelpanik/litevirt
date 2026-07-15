package compose

import (
	"reflect"
	"testing"
)

// vmFieldClass classifies EVERY compose VMDef field as either something a change to
// triggers a stack update ("diffed…") or something the planner deliberately ignores
// ("ignored…", with a reason). The exhaustiveness guard below fails when a new field
// is added without classifying it — so a field that should drive an update can't be
// silently dropped from the diff (the bug that let server-resolved fields or new
// resource knobs go unnoticed).
var vmFieldClass = map[string]string{
	"Extends":         "ignored: service inheritance, resolved before planning",
	"Kind":            "diffed: a runtime change forces recreate",
	"Image":           "diffed: image change recreates",
	"ISO":             "diffed: boot media change recreates",
	"Firmware":        "diffed: firmware change recreates",
	"Machine":         "diffed: machine type change recreates",
	"CPU":             "diffed: cpu change (live-grow or restart)",
	"MaxCPU":          "diffed: vCPU hotplug ceiling change (redefine)",
	"CPUMode":         "diffed: cpu mode change (redefine)",
	"Memory":          "diffed: memory change (live balloon or restart)",
	"MinMemory":       "diffed: balloon floor change (redefine)",
	"MaxMemory":       "diffed: balloon ceiling change (redefine)",
	"Onboot":          "diffed: live metadata update",
	"StartupOrder":    "diffed: live metadata update",
	"StartDelay":      "diffed: live metadata update",
	"StopDelay":       "diffed: live metadata update",
	"Replicas":        "ignored: expands to N instances before planning, not a per-VM field",
	"GuestAgent":      "diffed: guest-agent toggle (redefine)",
	"Graphics":        "diffed: graphics change (redefine)",
	"Disks":           "diffed: disk topology change recreates",
	"Network":         "ignored: server-resolved (MACs/IPs) — a NIC change is handled via attach/detach, not a VM diff",
	"CloudInit":       "diffed: cloud-init hash change",
	"Placement":       "ignored: server-resolved host, not a VM identity field",
	"Migrate":         "ignored: migration policy, not a VM spec field",
	"Update":          "ignored: rolling-update strategy, not a VM spec field",
	"LoadBalancer":    "ignored: stack-level LB config, not a VM spec field",
	"HealthCheck":     "diffed: health-check change",
	"Hooks":           "diffed: lifecycle hooks change",
	"StopGracePeriod": "diffed: live metadata update",
	"Restart":         "diffed: live metadata update",
	"Devices":         "diffed: passthrough device change",
	"Resources":       "diffed: resource tuning change (redefine)",
	"DependsOn":       "ignored: ordering only, not a VM spec field",
	"Labels":          "diffed: label change (live)",
	"IPHint":          "ignored: server-resolved IP assignment hint",
	"Backup":          "ignored: backup schedule, not a VM spec field",
}

// TestVMDefFieldsAllClassified fails if a VMDef field isn't classified — forcing new
// compose fields to declare whether they drive a stack update.
func TestVMDefFieldsAllClassified(t *testing.T) {
	rt := reflect.TypeOf(VMDef{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if _, ok := vmFieldClass[name]; !ok {
			t.Errorf("VMDef field %q is unclassified — add it to vmFieldClass as \"diffed…\" or \"ignored: <reason>\"", name)
		}
	}
	// Guard the guard: no stale entries for removed fields.
	for name := range vmFieldClass {
		if _, ok := rt.FieldByName(name); !ok {
			t.Errorf("vmFieldClass lists %q but VMDef has no such field; remove the stale entry", name)
		}
	}
}
