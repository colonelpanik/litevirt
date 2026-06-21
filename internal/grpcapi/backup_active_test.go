package grpcapi

import "testing"

// TestBackupInProgress covers the in-memory active-backup tracking the
// reconciler consults to tell a live backup apart from a stuck "backing-up"
// state row.
func TestBackupInProgress(t *testing.T) {
	s := &Server{}
	if s.BackupInProgress("vm1") {
		t.Fatal("expected false before any backup")
	}
	s.markBackupActive("vm1")
	if !s.BackupInProgress("vm1") {
		t.Fatal("expected true while backup active")
	}
	if s.BackupInProgress("vm2") {
		t.Fatal("unrelated VM must not report active")
	}
	s.clearBackupActive("vm1")
	if s.BackupInProgress("vm1") {
		t.Fatal("expected false after clear")
	}
}
