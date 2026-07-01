package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestVMDTOOmitsRawSpec(t *testing.T) {
	vm := &pb.VM{
		Name:     "vm1",
		HostName: "host1",
		Spec: &pb.VMSpec{
			Name:    "secret-spec-name",
			Project: "project-a",
		},
	}
	b, err := json.Marshal(vmDTO(vm))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "secret-spec-name") || strings.Contains(s, "spec") || strings.Contains(s, "cloud") {
		t.Fatalf("safe VM DTO leaked raw spec fields: %s", s)
	}
	if !strings.Contains(s, "project-a") {
		t.Fatalf("safe VM DTO dropped project: %s", s)
	}
}

func TestAuditDTOOmitsIdentityTargetAndDetail(t *testing.T) {
	entries := mapAudit([]*pb.AuditEntry{{
		Timestamp: "2026-07-01T00:00:00Z",
		Username:  "operator@example",
		Action:    "vm.start",
		Target:    "/projects/private/vms/vm1",
		Detail:    "private payload",
		Result:    "ok",
	}})
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, forbidden := range []string{"operator@example", "/projects/private", "private payload"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("safe audit DTO leaked %q in %s", forbidden, s)
		}
	}
}

func TestMapErrorRetryableCodes(t *testing.T) {
	for _, tc := range []struct {
		code      codes.Code
		retryable bool
	}{
		{codes.Unavailable, true},
		{codes.DeadlineExceeded, true},
		{codes.Unauthenticated, false},
		{codes.PermissionDenied, false},
		{codes.InvalidArgument, false},
	} {
		got := mapError(status.Error(tc.code, "boom"))
		if got.Code != tc.code.String() {
			t.Fatalf("code = %q, want %q", got.Code, tc.code.String())
		}
		if got.Retryable != tc.retryable {
			t.Fatalf("%s retryable = %v, want %v", tc.code, got.Retryable, tc.retryable)
		}
		if got.Hint == "" {
			t.Fatalf("%s missing hint", tc.code)
		}
	}
}

func TestValidateArgsRejectsMissingUnknownAndWrongTypes(t *testing.T) {
	schema := objectSchema(map[string]any{
		"name":    stringSchema("name"),
		"confirm": booleanSchema("confirm"),
		"limit":   integerSchema("limit"),
	}, "name", "confirm")
	for _, args := range []map[string]any{
		{"name": "vm1"},
		{"name": "vm1", "confirm": true, "extra": "no"},
		{"name": "vm1", "confirm": "true"},
		{"name": "vm1", "confirm": true, "limit": 1.5},
		{"name": "vm1", "confirm": true, "limit": -1.0},
	} {
		if err := validateArgs(args, schema); err == nil {
			t.Fatalf("validateArgs(%v) succeeded, want error", args)
		}
	}
	if err := validateArgs(map[string]any{"name": "vm1", "confirm": true, "limit": float64(10)}, schema); err != nil {
		t.Fatalf("validateArgs valid input: %v", err)
	}
}
