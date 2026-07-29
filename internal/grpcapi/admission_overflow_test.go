package grpcapi

import (
	"context"
	"math"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCheckProjectQuotaMaximumReservationCannotOverflow(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: "p1", VCPULimit: 100, MemMiBLimit: 100,
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := (corrosion.ReservationVector{
		Project: "p1", ProjectCPU: math.MaxInt, ProjectMemMiB: math.MaxInt,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertOperation(ctx, s.db, corrosion.OperationRecord{
		ID: "op-max-reservation", Method: "ResizeVM", Project: "p1",
		ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "hash",
		ReservationJSON: raw,
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
		OperationID: "op-max-reservation", StepName: corrosion.OpStepPlanned,
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.checkProjectQuota(ctx, "p1", 1, 1); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("checkProjectQuota error = %v, want ResourceExhausted", err)
	}
}
