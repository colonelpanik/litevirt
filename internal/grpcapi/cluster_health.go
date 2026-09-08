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
		Overall:     overallHealth(conditions, evaluators, capacity, time.Now().UTC()),
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

// evaluatorScanTTL is how old an evaluator's last scan may be before its
// evaluation is STALE. The detector runs every 60s and its leader lease fails
// over within ~2 intervals, so five intervals of silence is a wedged or
// fleet-wide-stopped detector, not scheduling jitter. The evaluator status row
// is LWW state with no expiry — without this bound, the last row ever written
// keeps saying coverage=complete forever and a stopped detector leaves the
// cluster green-and-blind indefinitely. (Compare localInventoryTTL: the OTHER
// input admission trusts is already freshness-bounded; this closes the same
// hole for the roll-up.)
const evaluatorScanTTL = 5 * time.Minute

// overallHealth rolls the pieces into one state:
//
//	CRITICAL — any ACTIVE critical condition (an observed one included: the
//	           operator should be looking before the confirm lands);
//	DEGRADED — active warning conditions, an evaluator without complete
//	           coverage, a STALE evaluator (last scan past evaluatorScanTTL),
//	           or an incomplete capacity observation;
//	UNKNOWN  — no evaluator has ever completed a scan, or every evaluator's
//	           last scan is stale (nothing is watching NOW, which is not the
//	           same as nothing being wrong);
//	HEALTHY  — none of the above.
//
// Deliberately, staleness does NOT gate admission. The ownership admission
// gate acts on durable condition rows plus a freshly-probed LOCAL inventory,
// both of which stay sound when the detector stops — what is lost is the
// discovery of NEW cross-host conditions, which this roll-up now surfaces
// instead of hiding. Coupling every admission to a single detector's liveness
// would make that detector a cluster-wide availability SPOF, which is a worse
// trade than a loudly-degraded health state; an operator who wants a hard stop
// on a blind cluster has the DEGRADED/UNKNOWN exit codes to wire it from.
func overallHealth(conditions []corrosion.HealthCondition, evaluators []corrosion.HealthEvaluatorStatus, capacity []corrosion.HostCapacityObservation, now time.Time) string {
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
	allStale := true
	for _, e := range evaluators {
		stale := true
		if at, err := time.Parse(time.RFC3339, e.LastScan); err == nil && now.Sub(at) <= evaluatorScanTTL {
			stale = false
			allStale = false
		}
		if stale || e.Coverage != corrosion.CoverageComplete {
			degraded = true
		}
	}
	if allStale {
		return HealthUnknown
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
