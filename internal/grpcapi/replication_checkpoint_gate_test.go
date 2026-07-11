package grpcapi

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestAdvanceReplicationCheckpoint_CommitFailurePreservesParent reproduces the P1
// replication-chain bug: the pre-fix advance deletes the parent checkpoint bitmap
// BEFORE the new anchor is durably recorded, and swallows the anchor-write error.
// A failed anchor write then leaves the DB pointing at a deleted bitmap, the new
// checkpoint leaked, and no error surfaced — the incremental chain silently
// degrades to full copies.
//
// A BEFORE UPDATE/INSERT trigger on replication_checkpoints forces the anchor
// write to fail. Correct behavior: the parent is NOT deleted, the new anchor is
// not (falsely) committed, and errCheckpointCommit is returned so the caller can
// preserve the retryable parent. This fails against the pre-fix ordering.
func TestAdvanceReplicationCheckpoint_CommitFailurePreservesParent(t *testing.T) {
	s := testServer(t)
	fake := &fakeBackupSource{}
	s.SetBackupSource(fake)
	ctx := context.Background()

	const (
		vm       = "repl-vm"
		repo     = "repo-a"
		parentCP = "cp-parent"
		newCP    = "cp-new"
	)
	// Seed the existing parent anchor, then make any further write to the table fail.
	if err := corrosion.SetReplicationCheckpoint(ctx, s.db, vm, repo, parentCP); err != nil {
		t.Fatalf("seed parent checkpoint: %v", err)
	}
	for _, trg := range []string{
		`CREATE TRIGGER inject_upd BEFORE UPDATE ON replication_checkpoints BEGIN SELECT RAISE(ABORT, 'inject'); END;`,
		`CREATE TRIGGER inject_ins BEFORE INSERT ON replication_checkpoints BEGIN SELECT RAISE(ABORT, 'inject'); END;`,
	} {
		if err := s.db.Execute(ctx, trg); err != nil {
			t.Fatalf("create trigger: %v", err)
		}
	}

	err := s.advanceReplicationCheckpoint(ctx, vm, repo, parentCP, newCP)

	if err == nil {
		t.Error("advanceReplicationCheckpoint returned nil; want an error when the anchor write fails")
	} else if !errors.Is(err, errCheckpointCommit) {
		t.Errorf("error %v is not errCheckpointCommit; RunReplication would wrongly reset the chain", err)
	}
	if fake.deletedCheckpoint(parentCP) {
		t.Error("parent checkpoint was deleted even though the new anchor was not recorded (chain broken)")
	}
}

// TestAdvanceReplicationCheckpoint_SuccessRecordsThenDropsParent proves the happy
// path: the new anchor is recorded first, then the parent bitmap is dropped.
func TestAdvanceReplicationCheckpoint_SuccessRecordsThenDropsParent(t *testing.T) {
	s := testServer(t)
	fake := &fakeBackupSource{}
	s.SetBackupSource(fake)
	ctx := context.Background()

	const (
		vm       = "repl-vm"
		repo     = "repo-a"
		parentCP = "cp-parent"
		newCP    = "cp-new"
	)
	if err := corrosion.SetReplicationCheckpoint(ctx, s.db, vm, repo, parentCP); err != nil {
		t.Fatalf("seed parent checkpoint: %v", err)
	}

	if err := s.advanceReplicationCheckpoint(ctx, vm, repo, parentCP, newCP); err != nil {
		t.Fatalf("advanceReplicationCheckpoint: %v", err)
	}

	got, err := corrosion.GetReplicationCheckpoint(ctx, s.db, vm, repo)
	if err != nil {
		t.Fatalf("get checkpoint: %v", err)
	}
	if got != newCP {
		t.Errorf("anchor = %q, want the new checkpoint %q", got, newCP)
	}
	if !fake.deletedCheckpoint(parentCP) {
		t.Error("parent checkpoint should have been dropped after the anchor was recorded")
	}
}
