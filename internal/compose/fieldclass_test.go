package compose

import (
	"reflect"
	"strings"
	"testing"
)

// vmFieldClass maps EVERY compose VMDef field to the ChangePlan bucket a change to
// it lands in (see classify.go). The exhaustiveness guard below fails when a new
// field is added without classifying it — so a field that should drive an update
// can't be silently dropped from the diff. Each value is "<category>: <reason>";
// the category must be one of the known buckets.
//
// Categories:
//
//	live-resource — cpu/memory, applied live (or downgraded to restart when out of band)
//	live-metadata — spec-persisted, applied without a restart
//	restart       — bakes into domain XML / no live-apply RPC: stop→redefine→start
//	recreate      — alters VM identity: delete+create only
//	delegated     — owned by another path (LB/backup/rolling strategy), not a VM lifecycle action
//	ignored       — genuinely not workload state (with a reason)
var vmFieldClass = map[string]string{
	"Extends":         "ignored: service inheritance, resolved before planning",
	"Kind":            "recreate: a runtime change forces delete+create",
	"Image":           "recreate: image change alters VM identity",
	"ISO":             "recreate: boot-media change alters VM identity",
	"Firmware":        "restart: firmware bakes into domain XML",
	"Machine":         "restart: machine type bakes into domain XML",
	"CPU":             "live-resource: grow within the hotplug ceiling live; shrink/beyond-ceiling restarts",
	"MaxCPU":          "restart: vCPU hotplug ceiling is a redefine",
	"CPUMode":         "restart: cpu mode is a redefine",
	"Memory":          "live-resource: balloon within band live; out-of-band restarts",
	"MinMemory":       "restart: balloon floor is a redefine",
	"MaxMemory":       "restart: balloon ceiling is a redefine",
	"Onboot":          "live-metadata: reconciler reads it fresh",
	"StartupOrder":    "live-metadata: reconciler reads it fresh",
	"StartDelay":      "live-metadata: reconciler reads it fresh",
	"StopDelay":       "live-metadata: reconciler reads it fresh",
	"Replicas":        "ignored: expands to N instances before planning, not a per-VM field",
	"GuestAgent":      "restart: guest-agent channel is a redefine",
	"Graphics":        "restart: graphics devices are a redefine",
	"Disks":           "recreate: disk topology alters VM identity",
	"Network":         "recreate: NIC topology alters VM identity",
	"CloudInit":       "recreate: cloud-init seed alters VM identity",
	"Placement":       "live-metadata: persisted in the spec, no runtime action",
	"Migrate":         "live-metadata: persisted in the spec, no runtime action",
	"Update":          "delegated: rolling-update strategy consumed by the rolling engine",
	"LoadBalancer":    "delegated: stack-level LB action",
	"HealthCheck":     "restart: no live-apply RPC — honest RestartRequired",
	"Hooks":           "restart: no live-apply RPC — honest RestartRequired",
	"StopGracePeriod": "restart: no live-apply RPC — honest RestartRequired",
	"Restart":         "live-metadata: reconciler reads the restart policy fresh",
	"Devices":         "restart: passthrough devices are a redefine",
	"Resources":       "restart: resource tuning is a redefine",
	"DependsOn":       "ignored: ordering only, not a VM spec field",
	"Labels":          "live-metadata: applied live via SetVMLabels",
	"IPHint":          "ignored: server-resolved IP assignment hint",
	"Backup":          "delegated: backup schedule reconciled by the scheduler",
}

var knownFieldCategories = map[string]bool{
	"live-resource": true,
	"live-metadata": true,
	"restart":       true,
	"recreate":      true,
	"delegated":     true,
	"ignored":       true,
}

// TestVMDefFieldsAllClassified fails if a VMDef field isn't classified — forcing new
// compose fields to declare which ChangePlan bucket they drive.
func TestVMDefFieldsAllClassified(t *testing.T) {
	rt := reflect.TypeOf(VMDef{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		class, ok := vmFieldClass[name]
		if !ok {
			t.Errorf("VMDef field %q is unclassified — add it to vmFieldClass with a category from %v", name, keysOf(knownFieldCategories))
			continue
		}
		cat := class
		if idx := strings.IndexByte(class, ':'); idx >= 0 {
			cat = class[:idx]
		}
		if !knownFieldCategories[cat] {
			t.Errorf("VMDef field %q has unknown category %q; use one of %v", name, cat, keysOf(knownFieldCategories))
		}
	}
	// Guard the guard: no stale entries for removed fields.
	for name := range vmFieldClass {
		if _, ok := rt.FieldByName(name); !ok {
			t.Errorf("vmFieldClass lists %q but VMDef has no such field; remove the stale entry", name)
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
