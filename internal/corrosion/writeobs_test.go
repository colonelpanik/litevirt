package corrosion

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// TestClassifyWriteErr_RoutineOutcomesAreNotStoreFaults.
//
// Everything that was not ErrNoRowsAffected fell into db_error, so the two
// outcomes a healthy fleet produces routinely — an ownership move mid-publish
// and a cancelled shutdown — were charted as store faults on
// litevirt_state_write_failures_total. Eleven routed call sites classify through
// here, so the distinction has to live here rather than at each of them.
func TestClassifyWriteErr_RoutineOutcomesAreNotStoreFaults(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		want      string
		isRoutine bool
	}{
		{"nil", nil, "", false},
		{"no rows", fmt.Errorf("update: %w", ErrNoRowsAffected), WriteClassNoRows, false},
		{"ownership moved", fmt.Errorf("refusing: %w", ErrOwnershipMoved), WriteClassOwnershipMoved, true},
		{"cancelled", fmt.Errorf("lookup: %w", context.Canceled), WriteClassCancelled, true},
		{"deadline", fmt.Errorf("lookup: %w", context.DeadlineExceeded), WriteClassCancelled, true},
		{"store fault", errors.New("database is locked"), WriteClassDBError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyWriteErr(tc.err); got != tc.want {
				t.Errorf("ClassifyWriteErr = %q, want %q", got, tc.want)
			}
			if got := Routine(tc.err); got != tc.isRoutine {
				t.Errorf("Routine = %v, want %v", got, tc.isRoutine)
			}
		})
	}
}
