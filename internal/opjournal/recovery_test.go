package opjournal

import (
	"testing"
)

func TestDecideRecovery(t *testing.T) {
	e := Entry{OperationID: "op1", OwnerEpoch: 3}
	cases := []struct {
		name              string
		opExists          bool
		currentOwnerEpoch int64
		opTerminal        bool
		want              RecoveryAction
	}{
		{"live, same epoch, non-terminal → resume", true, 3, false, RecoveryResume},
		{"live, same epoch, terminal → cleanup", true, 3, true, RecoveryCleanup},
		{"operation GC'd → supersede", false, 3, false, RecoverySupersede},
		{"ownership taken over (newer epoch) → supersede", true, 4, false, RecoverySupersede},
		{"ownership taken over even if terminal → supersede", true, 5, true, RecoverySupersede},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideRecovery(e, tc.opExists, tc.currentOwnerEpoch, tc.opTerminal); got != tc.want {
				t.Fatalf("DecideRecovery = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPlanRecovery(t *testing.T) {
	j, _ := Open(t.TempDir())
	// live/non-terminal (resume), terminal (cleanup), taken-over (supersede).
	for _, e := range []Entry{
		{OperationID: "resume-op", OwnerEpoch: 1, ResourceID: "vm1"},
		{OperationID: "done-op", OwnerEpoch: 1, ResourceID: "vm2"},
		{OperationID: "stolen-op", OwnerEpoch: 1, ResourceID: "vm3"},
	} {
		if err := j.Write(e); err != nil {
			t.Fatalf("Write %s: %v", e.OperationID, err)
		}
	}
	lookup := func(id string) (bool, int64, bool, error) {
		switch id {
		case "resume-op":
			return true, 1, false, nil // live, same epoch, non-terminal
		case "done-op":
			return true, 1, true, nil // live, same epoch, terminal
		case "stolen-op":
			return true, 2, false, nil // epoch advanced → taken over
		}
		return false, 0, false, nil
	}
	plan, corrupt, err := j.PlanRecovery(lookup)
	if err != nil || len(corrupt) != 0 || len(plan) != 3 {
		t.Fatalf("PlanRecovery: plan=%d corrupt=%d err=%v", len(plan), len(corrupt), err)
	}
	got := map[string]RecoveryAction{}
	for _, p := range plan {
		got[p.Entry.OperationID] = p.Action
	}
	if got["resume-op"] != RecoveryResume || got["done-op"] != RecoveryCleanup || got["stolen-op"] != RecoverySupersede {
		t.Fatalf("unexpected plan: %v", got)
	}
}
