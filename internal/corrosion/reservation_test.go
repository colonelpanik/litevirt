package corrosion

import (
	"context"
	"fmt"
	"math"
	"strings"
	"testing"
)

func mustOp(t *testing.T, db *Client, id, kind, resJSON string, terminal bool) {
	t.Helper()
	ctx := context.Background()
	if err := InsertOperation(ctx, db, OperationRecord{
		ID: id, Method: "m", ResourceKind: "vm", ResourceID: id,
		OperationKind: kind, RequestHash: "h", ReservationJSON: resJSON,
	}); err != nil {
		t.Fatalf("InsertOperation: %v", err)
	}
	if err := AppendOperationStep(ctx, db, OperationStepRecord{OperationID: id, StepName: OpStepPlanned}); err != nil {
		t.Fatalf("append planned: %v", err)
	}
	if terminal {
		if err := AppendOperationStep(ctx, db, OperationStepRecord{OperationID: id, StepName: OpStepCompleted}); err != nil {
			t.Fatalf("append completed: %v", err)
		}
	}
}

// TestHostFreeCapacity: free = total - running actuals - nonterminal reservations;
// a TERMINAL operation's reservation is not counted.
func TestHostFreeCapacity(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := InsertHost(ctx, db, HostRecord{Name: "h1", CPUTotal: 32, MemTotal: 65536, State: "HOST_ACTIVE"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	// A running VM consumes committed capacity.
	if err := InsertVM(ctx, db, VMRecord{Name: "vm1", HostName: "h1", State: "running", Spec: "{}", CPUActual: 4, MemActual: 8192}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// A nonterminal op reserves a grow delta on h1.
	rv := ReservationVector{TargetHost: "h1", TargetCPU: 8, TargetMemMiB: 16384}
	enc, _ := rv.Encode()
	mustOp(t, db, "grow-op", string(OpResourceUpdateRunning), enc, false)
	// A TERMINAL op's reservation must NOT count.
	rvDone := ReservationVector{TargetHost: "h1", TargetCPU: 100, TargetMemMiB: 100000}
	encDone, _ := rvDone.Encode()
	mustOp(t, db, "done-op", string(OpResourceUpdateRunning), encDone, true)

	// Neutral policy (ratio 1, no reserve, no per-VM overhead) isolates the
	// subtraction this test is about from capacity POLICY, which has its own
	// tests. Under it the arithmetic is the original raw one.
	neutral := CapacityPolicy{CPUOvercommit: 1, MemOvercommit: 1, VMMemOverheadMiB: 0}
	freeCPU, freeMem, ok, err := HostFreeCapacityWithPolicy(ctx, db, "h1", neutral)
	if err != nil || !ok {
		t.Fatalf("HostFreeCapacity: ok=%v err=%v", ok, err)
	}
	// 32 - 4 (running) - 8 (reserved) = 20 ; 65536 - 8192 - 16384 = 40960
	if freeCPU != 20 {
		t.Errorf("freeCPU = %d, want 20", freeCPU)
	}
	if freeMem != 40960 {
		t.Errorf("freeMem = %d, want 40960", freeMem)
	}

	// And with the DEFAULT policy the same host reports MORE cpu (4x ratio, less
	// 1 reserved) and LESS memory (5% reserve + one VM's qemu overhead) — proving
	// the policy is actually applied rather than silently ignored.
	defCPU, defMem, ok, err := HostFreeCapacity(ctx, db, "h1")
	if err != nil || !ok {
		t.Fatalf("HostFreeCapacity (default policy): ok=%v err=%v", ok, err)
	}
	if defCPU <= freeCPU {
		t.Errorf("default-policy freeCPU = %d, want more than the neutral %d (4x overcommit)", defCPU, freeCPU)
	}
	if defMem >= freeMem {
		t.Errorf("default-policy freeMem = %d, want less than the neutral %d (host reserve + qemu overhead)", defMem, freeMem)
	}
}

func TestProjectReserved_OnlyNonterminal(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	rv := ReservationVector{Project: "acme", ProjectCPU: 6, ProjectMemMiB: 12288}
	enc, _ := rv.Encode()
	mustOp(t, db, "p-live", string(OpResourceUpdateRunning), enc, false)
	rvDone := ReservationVector{Project: "acme", ProjectCPU: 99, ProjectMemMiB: 99}
	encDone, _ := rvDone.Encode()
	mustOp(t, db, "p-done", string(OpResourceUpdateRunning), encDone, true)

	cpu, mem, err := ProjectReserved(ctx, db, "acme")
	if err != nil {
		t.Fatalf("ProjectReserved: %v", err)
	}
	if cpu != 6 || mem != 12288 {
		t.Errorf("project reserved = (%d,%d), want (6,12288)", cpu, mem)
	}
}

func TestReservationValidateRejectsNegativeAndIncoherentVectors(t *testing.T) {
	tests := []struct {
		name string
		rv   ReservationVector
	}{
		{name: "negative project cpu", rv: ReservationVector{Project: "p1", ProjectCPU: -1}},
		{name: "negative project memory", rv: ReservationVector{Project: "p1", ProjectMemMiB: -1}},
		{name: "negative target cpu", rv: ReservationVector{TargetHost: "h1", TargetCPU: -1}},
		{name: "negative target memory", rv: ReservationVector{TargetHost: "h1", TargetMemMiB: -1}},
		{name: "target cpu without host", rv: ReservationVector{TargetCPU: 1}},
		{name: "target memory without host", rv: ReservationVector{TargetMemMiB: 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.rv.Validate(); err == nil {
				t.Fatalf("Validate(%+v) succeeded, want error", tc.rv)
			}
			if encoded, err := tc.rv.Encode(); err == nil {
				t.Fatalf("Encode(%+v) = %q, want error", tc.rv, encoded)
			}
		})
	}
}

func TestReservationValidateMaximumBoundaryAndLegacyVectors(t *testing.T) {
	tests := []struct {
		name string
		rv   ReservationVector
	}{
		{name: "zero"},
		{name: "maximum", rv: ReservationVector{
			Project: "p1", ProjectCPU: math.MaxInt, ProjectMemMiB: math.MaxInt,
			TargetHost: "h1", TargetCPU: math.MaxInt, TargetMemMiB: math.MaxInt,
		}},
		{name: "legacy target only", rv: ReservationVector{TargetHost: "h1", TargetCPU: 1}},
		{name: "legacy default project", rv: ReservationVector{ProjectCPU: 1, ProjectMemMiB: 2}},
		{name: "legacy source host", rv: ReservationVector{SourceHost: "h0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.rv.Validate(); err != nil {
				t.Fatalf("Validate(%+v): %v", tc.rv, err)
			}
			encoded, err := tc.rv.Encode()
			if err != nil {
				t.Fatalf("Encode(%+v): %v", tc.rv, err)
			}
			decoded, err := DecodeReservation(encoded)
			if err != nil {
				t.Fatalf("DecodeReservation(%q): %v", encoded, err)
			}
			if decoded != tc.rv {
				t.Fatalf("round trip = %+v, want %+v", decoded, tc.rv)
			}
		})
	}
}

func TestDecodeReservationRejectsInvalidCurrentVectors(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "negative", raw: `{"target_host":"h1","target_cpu":-1}`},
		{name: "missing host", raw: `{"target_mem_mib":1}`},
		{name: "integer overflow", raw: fmt.Sprintf(`{"target_host":"h1","target_cpu":%d0}`, math.MaxInt)},
		{name: "malformed", raw: `{"target_host":`},
		{name: "null", raw: `null`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if rv, err := DecodeReservation(tc.raw); err == nil {
				t.Fatalf("DecodeReservation(%q) = %+v, want error", tc.raw, rv)
			}
		})
	}
}

func TestReservationAggregationRejectsInvalidAndOverflowingCurrentTotals(t *testing.T) {
	tests := []struct {
		name       string
		first      string
		second     string
		reserved   func(context.Context, *Client) (int, int, error)
		wantErrSub string
	}{
		{
			name:       "negative host vector",
			first:      `{"target_host":"h1","target_cpu":-1}`,
			reserved:   func(ctx context.Context, c *Client) (int, int, error) { return HostReserved(ctx, c, "h1") },
			wantErrSub: "negative",
		},
		{
			name:       "malformed host vector",
			first:      `{"target_host":`,
			reserved:   func(ctx context.Context, c *Client) (int, int, error) { return HostReserved(ctx, c, "h1") },
			wantErrSub: "unexpected",
		},
		{
			name:       "host cpu overflow",
			first:      fmt.Sprintf(`{"target_host":"h1","target_cpu":%d}`, math.MaxInt),
			second:     `{"target_host":"h1","target_cpu":1}`,
			reserved:   func(ctx context.Context, c *Client) (int, int, error) { return HostReserved(ctx, c, "h1") },
			wantErrSub: "overflow",
		},
		{
			name:       "host memory overflow",
			first:      fmt.Sprintf(`{"target_host":"h1","target_mem_mib":%d}`, math.MaxInt),
			second:     `{"target_host":"h1","target_mem_mib":1}`,
			reserved:   func(ctx context.Context, c *Client) (int, int, error) { return HostReserved(ctx, c, "h1") },
			wantErrSub: "overflow",
		},
		{
			name:       "project cpu overflow",
			first:      fmt.Sprintf(`{"project":"p1","project_cpu":%d}`, math.MaxInt),
			second:     `{"project":"p1","project_cpu":1}`,
			reserved:   func(ctx context.Context, c *Client) (int, int, error) { return ProjectReserved(ctx, c, "p1") },
			wantErrSub: "overflow",
		},
		{
			name:       "project memory overflow",
			first:      fmt.Sprintf(`{"project":"p1","project_mem_mib":%d}`, math.MaxInt),
			second:     `{"project":"p1","project_mem_mib":1}`,
			reserved:   func(ctx context.Context, c *Client) (int, int, error) { return ProjectReserved(ctx, c, "p1") },
			wantErrSub: "overflow",
		},
		{
			name:       "malformed project vector",
			first:      `{"project":`,
			reserved:   func(ctx context.Context, c *Client) (int, int, error) { return ProjectReserved(ctx, c, "p1") },
			wantErrSub: "unexpected",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			mustOp(t, c, "op-1", string(OpResourceUpdateRunning), tc.first, false)
			if tc.second != "" {
				mustOp(t, c, "op-2", string(OpResourceUpdateRunning), tc.second, false)
			}
			first, second, err := tc.reserved(context.Background(), c)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("reserved = (%d,%d), err=%v, want %q error", first, second, err, tc.wantErrSub)
			}
			if first != 0 || second != 0 {
				t.Fatalf("error result = (%d,%d), want fail-closed zero totals", first, second)
			}
		})
	}
}

func TestReservationAggregationRejectsCurrentProjectMismatch(t *testing.T) {
	for _, tc := range []struct {
		name          string
		vectorProject string
		projectCPU    int
		reserved      func(context.Context, *Client) (int, int, error)
	}{
		{
			name:          "host different project",
			vectorProject: "other",
			projectCPU:    1,
			reserved:      func(ctx context.Context, c *Client) (int, int, error) { return HostReserved(ctx, c, "h1") },
		},
		{
			name:          "project different project",
			vectorProject: "other",
			projectCPU:    1,
			reserved:      func(ctx context.Context, c *Client) (int, int, error) { return ProjectReserved(ctx, c, "p1") },
		},
		{
			name:     "host missing project",
			reserved: func(ctx context.Context, c *Client) (int, int, error) { return HostReserved(ctx, c, "h1") },
		},
		{
			name:     "project missing project",
			reserved: func(ctx context.Context, c *Client) (int, int, error) { return ProjectReserved(ctx, c, "p1") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := newTestDB(t)
			if applied, err := ClaimInitialProjectAuthority(ctx, c, "p1", "authority-1"); err != nil || !applied {
				t.Fatalf("claim authority: applied=%v err=%v", applied, err)
			}
			raw, err := (ReservationVector{
				Project: tc.vectorProject, ProjectCPU: tc.projectCPU, TargetHost: "h1", TargetCPU: 1,
			}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := InsertOperation(ctx, c, OperationRecord{
				ID: "op-project-mismatch", Method: "ResizeVM", Project: "p1",
				ResourceKind: "vm", ResourceID: "vm1",
				OperationKind: string(OpResourceUpdateRunning), RequestHash: "hash",
				ReservationJSON: raw,
			}); err != nil {
				t.Fatal(err)
			}
			if err := AppendOperationStep(ctx, c, OperationStepRecord{
				OperationID: "op-project-mismatch", StepName: OpStepPlanned,
			}); err != nil {
				t.Fatal(err)
			}
			facts, err := reservationStepFacts(&ReservationFacts{
				Project: "p1", AuthorityEpoch: 1, AuthorityHost: "authority-1",
			}, "p1")
			if err != nil {
				t.Fatal(err)
			}
			if err := AppendOperationStep(ctx, c, OperationStepRecord{
				OperationID: "op-project-mismatch", StepName: OpStepReserved, Facts: facts,
			}); err != nil {
				t.Fatal(err)
			}
			first, second, err := tc.reserved(ctx, c)
			if err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("reserved = (%d,%d), err=%v, want project mismatch", first, second, err)
			}
			if first != 0 || second != 0 {
				t.Fatalf("error result = (%d,%d), want fail-closed zero totals", first, second)
			}
		})
	}
}

func TestHostFreeCapacityMaximumReservationCannotUnderflow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := InsertHost(ctx, c, HostRecord{
		Name: "h1", CPUTotal: 1, MemTotal: 1, State: "HOST_ACTIVE",
	}); err != nil {
		t.Fatal(err)
	}
	if err := InsertVM(ctx, c, VMRecord{
		Name: "vm1", HostName: "h1", State: "running", Spec: "{}",
		CPUActual: 3, MemActual: 3,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := (ReservationVector{
		TargetHost: "h1", TargetCPU: math.MaxInt, TargetMemMiB: math.MaxInt,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	mustOp(t, c, "op-max", string(OpResourceUpdateRunning), raw, false)

	neutral := CapacityPolicy{CPUOvercommit: 1, MemOvercommit: 1}
	cpu, mem, ok, err := HostFreeCapacityWithPolicy(ctx, c, "h1", neutral)
	if err != nil || !ok {
		t.Fatalf("HostFreeCapacityWithPolicy: ok=%v err=%v", ok, err)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("free capacity = (%d,%d), want fail-closed (0,0)", cpu, mem)
	}
}

func TestBeginVMOperationRejectsInvalidReservation(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := InsertVM(ctx, c, VMRecord{
		Name: "vm1", HostName: "h1", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	op := OperationRecord{
		ID: "op-invalid-reservation", Method: "ResizeVM", ResourceKind: "vm",
		ResourceID: "vm1", OperationKind: string(OpResourceUpdateRunning),
		RequestHash: "hash", ReservationJSON: `{"target_host":"h1","target_cpu":-1}`,
	}
	applied, err := c.BeginVMOperation(ctx, op, `{"cpu":2}`, 0, 0)
	if err == nil || applied {
		t.Fatalf("BeginVMOperation: applied=%v err=%v, want validation error", applied, err)
	}
	if got, err := GetOperation(ctx, c, op.ID); err != nil || got != nil {
		t.Fatalf("invalid operation persisted: op=%+v err=%v", got, err)
	}
}
