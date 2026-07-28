package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestScheduleRBACTarget_PoolProjectScoped: pool-scoped schedules must authorize against the
// project-scoped pool path (matching pool CRUD/content), and FAIL CLOSED to an unmatched
// sentinel when the owning project can't be uniquely resolved — never a guessed path a grant
// could match.
func TestScheduleRBACTarget_PoolProjectScoped(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	seed := func(host, name, project string) {
		if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
			HostName: host, Name: name, Project: project, Driver: "dir",
		}); err != nil {
			t.Fatalf("UpsertStoragePool(%s/%s): %v", host, name, err)
		}
	}

	// A project-owned pool → project-scoped path.
	seed("h1", "hot", "tenant-a")
	if got, want := s.scheduleRBACTarget(ctx, "pool", "", "hot", ""), poolRBACPathFor("tenant-a", "hot"); got != want {
		t.Fatalf("project pool: got %q, want %q", got, want)
	}

	// A found GLOBAL pool (Project "") legitimately maps to the global pool path.
	seed("h1", "shared", "")
	if got, want := s.scheduleRBACTarget(ctx, "pool", "", "shared", ""), poolRBACPathFor("", "shared"); got != want {
		t.Fatalf("global pool: got %q, want %q", got, want)
	}

	// Same pool name across multiple hosts, SAME project → still resolves uniquely.
	seed("h2", "hot", "tenant-a")
	if got, want := s.scheduleRBACTarget(ctx, "pool", "", "hot", ""), poolRBACPathFor("tenant-a", "hot"); got != want {
		t.Fatalf("multi-host same-project pool: got %q, want %q", got, want)
	}

	// Unknown pool → unmatched sentinel, NOT the empty-project global path.
	if got := s.scheduleRBACTarget(ctx, "pool", "", "ghost", ""); !strings.Contains(got, "\x00") || got == poolRBACPathFor("", "ghost") {
		t.Fatalf("unknown pool must be an unmatched sentinel, got %q", got)
	}

	// Name collision: same name, DIFFERENT projects → fail closed to a sentinel.
	seed("h1", "dup", "tenant-a")
	seed("h2", "dup", "tenant-b")
	if got := s.scheduleRBACTarget(ctx, "pool", "", "dup", ""); !strings.Contains(got, "\x00") {
		t.Fatalf("cross-project name collision must be an unmatched sentinel, got %q", got)
	}
}
