package cephdeploy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestSpec_Validate covers the operator-facing input-checks.
func TestSpec_Validate(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec CephSpec
		want string // substring of expected error; "" = expect nil
	}{
		{"empty", CephSpec{}, "MonIP required"},
		{"bad ip", CephSpec{MonIP: "not-an-ip"}, "invalid MonIP"},
		{"bad cidr", CephSpec{MonIP: "10.0.0.5", Network: "10.0.0.0"}, "must be CIDR"},
		{"happy", CephSpec{MonIP: "10.0.0.5", Network: "10.0.0.0/24"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Validate()
			if tc.want == "" {
				if err != nil {
					t.Errorf("expected nil, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestParseFSID handles the operator-visible cephadm output snippet.
func TestParseFSID(t *testing.T) {
	out := `INFO:cephadm:Starting bootstrap
INFO:cephadm:Cluster fsid: 7e1c5e2a-aaaa-bbbb-cccc-dddddddddddd
INFO:cephadm:Verifying podman
`
	if got := parseFSID(out); got != "7e1c5e2a-aaaa-bbbb-cccc-dddddddddddd" {
		t.Errorf("parseFSID = %q", got)
	}
	// Missing line → empty string, not error.
	if got := parseFSID("nothing here"); got != "" {
		t.Errorf("parseFSID(missing) = %q, want \"\"", got)
	}
}

// TestCephHealth_DetailString collapses health.checks into a one-line
// summary the UI can show on the dashboard.
func TestCephHealth_DetailString(t *testing.T) {
	raw := `{
		"status": "HEALTH_WARN",
		"checks": {
			"OSD_DOWN": {
				"severity": "HEALTH_WARN",
				"summary": {"message": "1 osds down"}
			}
		}
	}`
	var h cephHealth
	if err := json.Unmarshal([]byte(raw), &h); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := h.detailString()
	if !strings.Contains(got, "OSD_DOWN") || !strings.Contains(got, "1 osds down") {
		t.Errorf("detail = %q, want OSD_DOWN summary", got)
	}
}

// TestCephHealth_DetailString_NoChecks falls back to the bare status.
func TestCephHealth_DetailString_NoChecks(t *testing.T) {
	h := cephHealth{Status: "HEALTH_OK"}
	if got := h.detailString(); got != "HEALTH_OK" {
		t.Errorf("detail with no checks = %q, want HEALTH_OK", got)
	}
}

// TestStatusJSON_Decode parses a real-shape `ceph -s --format json`
// blob and confirms every Status field lands populated.
func TestStatusJSON_Decode(t *testing.T) {
	raw := `{
		"fsid": "abc",
		"health": {"status": "HEALTH_OK", "checks": {}},
		"monmap": {"num_mons": 3},
		"osdmap": {"num_osds": 6, "num_up_osds": 6, "num_in_osds": 6},
		"pgmap":  {"num_pgs": 128, "bytes_avail": 9000, "bytes_used": 1000}
	}`
	var s cephStatusJSON
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.FSID != "abc" || s.Health.Status != "HEALTH_OK" {
		t.Errorf("top-level fields off: %+v", s)
	}
	if s.MonMap.NumMons != 3 || s.OSDMap.NumOSDs != 6 || s.PGMap.NumPGs != 128 {
		t.Errorf("nested fields off: %+v", s)
	}
}

// TestRunner_BinDefaultsAndOverride covers the small CephadmRunner shim.
func TestRunner_BinDefaultsAndOverride(t *testing.T) {
	r := &CephadmRunner{}
	if r.bin() != "cephadm" {
		t.Errorf("default bin = %q", r.bin())
	}
	r.Bin = "/opt/ceph/bin/cephadm"
	if r.bin() != "/opt/ceph/bin/cephadm" {
		t.Errorf("override = %q", r.bin())
	}
}

// staticRunner is a Runner double for tests in other packages
// (currently just a sanity check that the interface is satisfied).
type staticRunner struct{}

func (staticRunner) Bootstrap(context.Context, CephSpec) (string, error) { return "fsid", nil }
func (staticRunner) AddMon(context.Context, string) error                { return nil }
func (staticRunner) AddMgr(context.Context, string) error                { return nil }
func (staticRunner) AddOSD(context.Context, string, string) error        { return nil }
func (staticRunner) Status(context.Context) (Status, error)              { return Status{Health: "HEALTH_OK"}, nil }
func (staticRunner) OSDTree(context.Context) (OSDTree, error)            { return OSDTree{}, nil }

func TestRunnerInterface_Satisfied(t *testing.T) {
	var _ Runner = staticRunner{}
	var _ Runner = &CephadmRunner{}
}
