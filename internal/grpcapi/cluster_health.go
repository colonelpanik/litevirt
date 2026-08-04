package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GetClusterHealth is THE health read. It aggregates the durable condition
// set, evaluator coverage, the observer→target connectivity mesh, and per-host
// capacity assessments into one response with one overall state — the single
// surface the CLI, REST, MCP, UI, and dashboard all consume. There is no
// per-signal health RPC and no operator force-clear: the rows say what the
// evaluators proved, and only the evaluators change them.
func (s *Server) GetClusterHealth(ctx context.Context, req *pb.GetClusterHealthRequest) (*pb.ClusterHealth, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}

	conditions, err := corrosion.ListHealthConditions(ctx, s.db, req.GetIncludeResolved())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list health conditions: %v", err)
	}
	evaluators, err := corrosion.ListHealthEvaluatorStatus(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list evaluator status: %v", err)
	}
	capacity, err := corrosion.ListHostCapacityObservations(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list capacity observations: %v", err)
	}
	edges, err := s.db.Query(ctx,
		`SELECT observer, target, status, consecutive_failures, last_seen
		 FROM host_health WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query connectivity: %v", err)
	}

	resp := &pb.ClusterHealth{
		Overall:     overallHealth(conditions, evaluators, capacity),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, h := range conditions {
		resp.Conditions = append(resp.Conditions, &pb.HealthCondition{
			Evaluator: h.Evaluator, Code: h.Code,
			SubjectKind: h.SubjectKind, SubjectId: h.SubjectID,
			Lifecycle: h.Lifecycle, Severity: h.Severity,
			Hosts: h.Hosts, Evidence: h.Evidence,
			ObserveCount: int32(h.ObserveCount), CleanCount: int32(h.CleanCount),
			FirstSeen: h.FirstSeen, LastSeen: h.LastSeen,
			ConfirmedAt: h.ConfirmedAt, ResolvedAt: h.ResolvedAt,
			Reporter: h.Reporter,
		})
	}
	for _, e := range evaluators {
		resp.Evaluators = append(resp.Evaluators, &pb.HealthEvaluatorStatus{
			Evaluator: e.Evaluator, LastScan: e.LastScan,
			Coverage: e.Coverage, Reporter: e.Reporter, Detail: e.Detail,
		})
	}
	for _, r := range edges {
		resp.Connectivity = append(resp.Connectivity, &pb.ConnectivityEdge{
			Observer: r.String("observer"), Target: r.String("target"),
			Status:              r.String("status"),
			ConsecutiveFailures: int32(r.Int("consecutive_failures")),
			LastSeen:            r.String("last_seen"),
		})
	}
	for _, c := range capacity {
		resp.Capacity = append(resp.Capacity, &pb.HostCapacityAssessment{
			HostName: c.HostName,
			DbCpu:    int32(c.DBCPU), DbMemMib: int32(c.DBMemMiB),
			ExtraCpu: int32(c.ExtraCPU), ExtraMemMib: int32(c.ExtraMemMiB),
			EffectiveCpu: int32(c.EffectiveCPU), EffectiveMemMib: int32(c.EffectiveMemMiB),
			Complete: c.Complete, Detail: c.Detail, SampledAt: c.SampledAt,
		})
	}
	return resp, nil
}

// Overall cluster-health states.
const (
	HealthHealthy  = "HEALTHY"
	HealthDegraded = "DEGRADED"
	HealthCritical = "CRITICAL"
	HealthUnknown  = "UNKNOWN"
)

// overallHealth rolls the pieces into one state:
//
//	CRITICAL — any ACTIVE critical condition (an observed one included: the
//	           operator should be looking before the confirm lands);
//	DEGRADED — active warning conditions, an evaluator without complete
//	           coverage, or an incomplete capacity observation;
//	UNKNOWN  — no evaluator has ever completed a scan (nothing is watching,
//	           which is not the same as nothing being wrong);
//	HEALTHY  — none of the above.
func overallHealth(conditions []corrosion.HealthCondition, evaluators []corrosion.HealthEvaluatorStatus, capacity []corrosion.HostCapacityObservation) string {
	if len(evaluators) == 0 {
		return HealthUnknown
	}
	degraded := false
	for _, h := range conditions {
		if h.Lifecycle == corrosion.ConditionResolved {
			continue
		}
		if h.Severity == corrosion.SeverityCritical {
			return HealthCritical
		}
		degraded = true
	}
	for _, e := range evaluators {
		if e.Coverage != corrosion.CoverageComplete {
			degraded = true
		}
	}
	for _, c := range capacity {
		if !c.Complete {
			degraded = true
		}
	}
	if degraded {
		return HealthDegraded
	}
	return HealthHealthy
}
