package grpcapi

import (
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// TestDeriveVMProject_FromManifestWhenRowGone verifies a restore for a VM whose
// row is gone derives the project from the manifest's embedded spec — NOT a
// default fallback — so authorization can't be made against the wrong project.
func TestDeriveVMProject_FromManifestWhenRowGone(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "gone", Project: "acme"})
	if got, ok := s.deriveVMProject(ctx, "gone", &pbsstore.Manifest{VMSpecJSON: string(specJSON)}); !ok || got != "acme" {
		t.Fatalf("deriveVMProject = %q,%v want acme,true", got, ok)
	}
	// No row and no embedded project → undeterminable (the handler then requires admin).
	if _, ok := s.deriveVMProject(ctx, "gone", &pbsstore.Manifest{}); ok {
		t.Error("deriveVMProject should be false with no row + no spec project")
	}
}

func TestDeriveContainerProject_FromManifestWhenRowGone(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	specJSON, _ := json.Marshal(containerBackupSpec{Name: "gone", Project: "acme"})
	if got, ok := s.deriveContainerProject(ctx, "gone", &pbsstore.Manifest{ContainerSpecJSON: string(specJSON)}); !ok || got != "acme" {
		t.Fatalf("deriveContainerProject = %q,%v want acme,true", got, ok)
	}
	if _, ok := s.deriveContainerProject(ctx, "gone", &pbsstore.Manifest{}); ok {
		t.Error("deriveContainerProject should be false with no row + no spec project")
	}
}
