package libvirt

import (
	"strings"
	"testing"
)

func TestValidateCPUMode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		model   string
		wantErr bool
	}{
		{name: "empty is legal (pre-default specs)", mode: "", model: ""},
		{name: "host-model", mode: CPUModeHostModel, model: ""},
		{name: "host-passthrough", mode: CPUModeHostPassthrough, model: ""},
		{name: "custom with model", mode: CPUModeCustom, model: "x86-64-v3"},

		{name: "custom without model", mode: CPUModeCustom, model: "", wantErr: true},
		{name: "model without custom", mode: CPUModeHostModel, model: "x86-64-v3", wantErr: true},
		{name: "model with no mode", mode: "", model: "x86-64-v3", wantErr: true},
		{name: "unknown mode", mode: "host-passthru", model: "", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCPUMode(tc.mode, tc.model)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateCPUMode(%q, %q) = nil, want an error", tc.mode, tc.model)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateCPUMode(%q, %q) = %v, want nil", tc.mode, tc.model, err)
			}
		})
	}
}

// The default must be a mode that actually exposes the host's feature set. The
// whole point of having one is that a VM created without a choice does not land
// on QEMU's qemu64, which carries no AVX.
func TestDefaultCPUModeExposesHostFeatures(t *testing.T) {
	if DefaultCPUMode == "" {
		t.Fatal("DefaultCPUMode is empty: a new VM would render with no <cpu> element and run on qemu64")
	}
	if !CPUModeExposesHostFeatures(DefaultCPUMode) {
		t.Fatalf("DefaultCPUMode = %q, which does not derive the guest CPU from the host", DefaultCPUMode)
	}
	if err := ValidateCPUMode(DefaultCPUMode, ""); err != nil {
		t.Fatalf("DefaultCPUMode %q does not validate on its own: %v", DefaultCPUMode, err)
	}
}

func TestCPUModeExposesHostFeatures(t *testing.T) {
	for mode, want := range map[string]bool{
		CPUModeHostModel:       true,
		CPUModeHostPassthrough: true,
		CPUModeCustom:          false,
		"":                     false,
	} {
		if got := CPUModeExposesHostFeatures(mode); got != want {
			t.Errorf("CPUModeExposesHostFeatures(%q) = %v, want %v", mode, got, want)
		}
	}
}

// A custom mode must render a <model> child. Without one libvirt rejects the
// domain, which is what `--cpu-mode custom` used to produce.
func TestGenerateDomainXMLCustomCPUCarriesModel(t *testing.T) {
	xmlDesc, err := GenerateDomainXML(VMConfig{
		Name:      "vm-custom",
		CPU:       2,
		MemoryMiB: 2048,
		CPUMode:   CPUModeCustom,
		CPUModel:  "x86-64-v3",
	})
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if !strings.Contains(xmlDesc, `<cpu mode="custom" match="exact">`) {
		t.Errorf("custom cpu element missing or unmatched in:\n%s", xmlDesc)
	}
	if !strings.Contains(xmlDesc, `<model fallback="allow">x86-64-v3</model>`) {
		t.Errorf("custom cpu carries no <model> child in:\n%s", xmlDesc)
	}
}

// host-model and host-passthrough render as a bare mode with no <model>.
func TestGenerateDomainXMLHostCPUModes(t *testing.T) {
	for _, mode := range []string{CPUModeHostModel, CPUModeHostPassthrough} {
		t.Run(mode, func(t *testing.T) {
			xmlDesc, err := GenerateDomainXML(VMConfig{
				Name: "vm-" + mode, CPU: 2, MemoryMiB: 2048, CPUMode: mode,
			})
			if err != nil {
				t.Fatalf("GenerateDomainXML: %v", err)
			}
			if !strings.Contains(xmlDesc, `<cpu mode="`+mode+`">`) {
				t.Errorf("want a bare <cpu mode=%q> element, got:\n%s", mode, xmlDesc)
			}
			if strings.Contains(xmlDesc, "<model") {
				t.Errorf("%s must not render a <model> child:\n%s", mode, xmlDesc)
			}
		})
	}
}

// An empty mode still renders NO <cpu> element. This is the compatibility half
// of the fix: a VM persisted before the default existed must keep the domain XML
// it has always had, so a rolling upgrade cannot change a running guest's CPU.
func TestGenerateDomainXMLEmptyCPUModeEmitsNoCPUElement(t *testing.T) {
	xmlDesc, err := GenerateDomainXML(VMConfig{Name: "vm-legacy", CPU: 2, MemoryMiB: 2048})
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if strings.Contains(xmlDesc, "<cpu") {
		t.Errorf("empty CPUMode rendered a <cpu> element:\n%s", xmlDesc)
	}
}
