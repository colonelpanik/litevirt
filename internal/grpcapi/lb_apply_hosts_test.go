package grpcapi

import (
	"reflect"
	"testing"
)

// TestLBApplyHosts is the regression for updating a standalone explicit LB created
// with no hosts: CreateLoadBalancer persists hosts=[] but runs locally, so on
// update an empty stored list must normalize to [self] — otherwise the local apply
// loop is skipped and neither HAProxy/keepalived reload nor the LB firewall-intent
// refresh (VIP/ports/SNAT) happens for that shape.
func TestLBApplyHosts(t *testing.T) {
	const self = "host-a"
	cases := []struct {
		name  string
		hosts string
		want  []string
	}{
		{"empty array → self", "[]", []string{self}},
		{"empty string → self", "", []string{self}},
		{"null → self", "null", []string{self}},
		{"malformed → self", "{not json", []string{self}},
		{"single explicit host", `["host-b"]`, []string{"host-b"}},
		{"multi explicit hosts", `["host-b","host-c"]`, []string{"host-b", "host-c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lbApplyHosts(tc.hosts, self); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("lbApplyHosts(%q) = %v, want %v", tc.hosts, got, tc.want)
			}
		})
	}
}
