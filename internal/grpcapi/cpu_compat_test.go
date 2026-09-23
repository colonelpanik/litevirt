package grpcapi

import (
	"testing"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

func TestMergeCPUModeUpdate(t *testing.T) {
	for _, tc := range []struct {
		name                string
		specMode, specModel string
		reqMode, reqModel   string
		wantMode, wantModel string
		wantErr             bool
	}{
		{
			name:     "no change leaves the stored pair alone",
			specMode: lv.CPUModeHostModel, reqMode: "",
			wantMode: lv.CPUModeHostModel,
		},
		{
			name:     "a legacy empty spec stays empty when untouched",
			specMode: "", reqMode: "",
			wantMode: "",
		},
		{
			name:     "moving a legacy VM forward",
			specMode: "", reqMode: lv.CPUModeHostModel,
			wantMode: lv.CPUModeHostModel,
		},
		{
			name:     "switching off custom drops the stale model",
			specMode: lv.CPUModeCustom, specModel: "x86-64-v2",
			reqMode:  lv.CPUModeHostModel,
			wantMode: lv.CPUModeHostModel, wantModel: "",
		},
		{
			name:     "switching to custom and naming a model in one call",
			specMode: lv.CPUModeHostModel,
			reqMode:  lv.CPUModeCustom, reqModel: "x86-64-v3",
			wantMode: lv.CPUModeCustom, wantModel: "x86-64-v3",
		},
		{
			name:     "changing only the model of an already-custom VM",
			specMode: lv.CPUModeCustom, specModel: "x86-64-v2",
			reqModel: "x86-64-v3",
			wantMode: lv.CPUModeCustom, wantModel: "x86-64-v3",
		},
		{
			name:     "switching to custom with no model anywhere is refused",
			specMode: lv.CPUModeHostModel,
			reqMode:  lv.CPUModeCustom,
			wantErr:  true,
		},
		{
			name:     "naming a model on a host-derived mode is refused",
			specMode: lv.CPUModeHostModel,
			reqModel: "x86-64-v3",
			wantErr:  true,
		},
		{
			name:     "an unknown mode is refused",
			specMode: lv.CPUModeHostModel,
			reqMode:  "host-passthru",
			wantErr:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode, model, err := mergeCPUModeUpdate(tc.specMode, tc.specModel, tc.reqMode, tc.reqModel)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("mergeCPUModeUpdate = (%q, %q, nil), want an error", mode, model)
				}
				return
			}
			if err != nil {
				t.Fatalf("mergeCPUModeUpdate: %v", err)
			}
			if mode != tc.wantMode || model != tc.wantModel {
				t.Fatalf("mergeCPUModeUpdate = (%q, %q), want (%q, %q)", mode, model, tc.wantMode, tc.wantModel)
			}
		})
	}
}

func TestParseSpecCPUMode(t *testing.T) {
	// The stored spec is encoding/json over the generated VMSpec, so the key is
	// the snake_case protobuf name. A wrong key here would silently disable the
	// migration CPU preflight for every VM.
	if got := parseSpecCPUMode(`{"name":"vm1","cpu_mode":"host-model"}`); got != lv.CPUModeHostModel {
		t.Errorf("parseSpecCPUMode = %q, want %q", got, lv.CPUModeHostModel)
	}
	if got := parseSpecCPUMode(`{"name":"vm1"}`); got != "" {
		t.Errorf("parseSpecCPUMode of a spec with no cpu_mode = %q, want empty", got)
	}
	if got := parseSpecCPUMode("not json"); got != "" {
		t.Errorf("parseSpecCPUMode of garbage = %q, want empty", got)
	}
}
