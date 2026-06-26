package failover

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestVMUsesFirmwareState(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want bool
	}{
		{"plain", `{"name":"a"}`, false},
		{"tpm", `{"name":"a","tpm":true}`, true},
		{"secureboot", `{"name":"a","secure_boot":true}`, true},
		{"both", `{"name":"a","secure_boot":true,"tpm":true}`, true},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := vmUsesFirmwareState(corrosion.VMRecord{Spec: tc.spec}); got != tc.want {
				t.Errorf("vmUsesFirmwareState(%q) = %v, want %v", tc.spec, got, tc.want)
			}
		})
	}
}
