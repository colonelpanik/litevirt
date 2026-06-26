package grpcapi

import (
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// TestManifestProjectExtraction verifies the project is read from the manifest's
// embedded spec (the backup's authoritative project), and "" for a legacy
// manifest with no spec.
func TestManifestProjectExtraction(t *testing.T) {
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "vm", Project: "acme"})
	if got := manifestVMProject(&pbsstore.Manifest{VMSpecJSON: string(specJSON)}); got != "acme" {
		t.Errorf("manifestVMProject = %q, want acme", got)
	}
	if got := manifestVMProject(&pbsstore.Manifest{}); got != "" {
		t.Errorf("manifestVMProject(legacy) = %q, want empty", got)
	}
	ctJSON, _ := json.Marshal(containerBackupSpec{Name: "ct", Project: "acme"})
	if got := manifestContainerProject(&pbsstore.Manifest{ContainerSpecJSON: string(ctJSON)}); got != "acme" {
		t.Errorf("manifestContainerProject = %q, want acme", got)
	}
}

// TestRestoreAuthDecision verifies the manifest project wins, a name-reuse
// mismatch with a live row requires admin (denied for a non-admin), and an
// undeterminable project requires admin.
func TestRestoreAuthDecision(t *testing.T) {
	s := testServer(t)
	op := userCtx("op", "operator")
	adm := adminCtx()

	// Manifest project present, no live row → use it (operator allowed to proceed
	// to the per-path check, i.e. no admin gate here).
	if proj, err := s.restoreAuthDecision(op, "acme", "", false); err != nil || proj != "acme" {
		t.Errorf("manifest-only = %q,%v want acme,nil", proj, err)
	}
	// Manifest project matches live row → use it, no admin gate.
	if proj, err := s.restoreAuthDecision(op, "acme", "acme", true); err != nil || proj != "acme" {
		t.Errorf("matching = %q,%v want acme,nil", proj, err)
	}
	// Manifest project differs from a live row (name reuse) → admin required.
	if _, err := s.restoreAuthDecision(op, "acme", "other", true); err == nil {
		t.Error("mismatch as operator should be denied (admin required)")
	}
	if proj, err := s.restoreAuthDecision(adm, "acme", "other", true); err != nil || proj != "acme" {
		t.Errorf("mismatch as admin = %q,%v want acme,nil", proj, err)
	}
	// Legacy manifest (no project) with a live row → fall back to the row.
	if proj, err := s.restoreAuthDecision(op, "", "team-x", true); err != nil || proj != "team-x" {
		t.Errorf("legacy+row = %q,%v want team-x,nil", proj, err)
	}
	// No project anywhere → admin required.
	if _, err := s.restoreAuthDecision(op, "", "", false); err == nil {
		t.Error("undeterminable project as operator should be denied")
	}
}
