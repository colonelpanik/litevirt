package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Durable cluster-health storage (v50).
//
// These are STORAGE primitives: full-row writes and typed reads. The lifecycle
// POLICY — what counts as an observation, when a condition confirms, who may
// resolve it and under what coverage — lives in the health evaluator, which is
// the only writer. Keeping policy out of the storage layer means the rules are
// in one place and the rows can never encode a transition the evaluator did not
// decide.
//
// Merge is default LWW. Condition rows are keyed per evaluator and written by
// one evaluator instance at a time (the detector lease holder), so last-writer-
// wins converges every replica to the newest scan; capacity rows are written
// only by the host they describe (host_name is the ownership, the same rule
// host_networks uses).

// Condition lifecycle states.
const (
	ConditionObserved  = "observed"
	ConditionConfirmed = "confirmed"
	ConditionResolved  = "resolved"
)

// Condition severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Evaluator coverage states. Absence of a condition is only meaningful under
// CoverageComplete: a partial or unreachable scan cannot prove anything is gone.
const (
	CoverageComplete    = "complete"
	CoveragePartial     = "partial"
	CoverageUnreachable = "unreachable"
	CoverageUnsupported = "unsupported"
)

// HealthCondition is one detected condition's current state. Identity is
// (evaluator, code, subject_kind, subject_id); everything else is the latest
// scan's view of it.
type HealthCondition struct {
	Evaluator   string
	Code        string
	SubjectKind string // vm | container | vip | host | cluster
	SubjectID   string

	Lifecycle string // ConditionObserved | ConditionConfirmed | ConditionResolved
	Severity  string // SeverityInfo | SeverityWarning | SeverityCritical
	Hosts     []string
	Evidence  string // canonical structured evidence (JSON)

	ObserveCount int // consecutive positive scans
	CleanCount   int // consecutive complete clean scans

	FirstSeen   string // RFC3339
	LastSeen    string
	ConfirmedAt string // "" until confirmed
	ResolvedAt  string // "" until resolved
	Reporter    string // host that wrote the latest transition
}

// UpsertHealthCondition writes a condition's full current state. The caller (the
// evaluator) has already decided the lifecycle transition; this persists it.
func UpsertHealthCondition(ctx context.Context, c *Client, h HealthCondition) error {
	if h.Evaluator == "" || h.Code == "" || h.SubjectKind == "" {
		return fmt.Errorf("corrosion: health condition requires evaluator, code and subject_kind (got %q/%q/%q)",
			h.Evaluator, h.Code, h.SubjectKind)
	}
	hosts := ""
	if len(h.Hosts) > 0 {
		b, err := json.Marshal(h.Hosts)
		if err != nil {
			return err
		}
		hosts = string(b)
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO health_conditions (evaluator, code, subject_kind, subject_id,
		   lifecycle, severity, hosts, evidence, observe_count, clean_count,
		   first_seen, last_seen, confirmed_at, resolved_at, reporter,
		   created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(evaluator, code, subject_kind, subject_id) DO UPDATE SET
		   lifecycle = excluded.lifecycle,
		   severity = excluded.severity,
		   hosts = excluded.hosts,
		   evidence = excluded.evidence,
		   observe_count = excluded.observe_count,
		   clean_count = excluded.clean_count,
		   first_seen = excluded.first_seen,
		   last_seen = excluded.last_seen,
		   confirmed_at = excluded.confirmed_at,
		   resolved_at = excluded.resolved_at,
		   reporter = excluded.reporter,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		h.Evaluator, h.Code, h.SubjectKind, h.SubjectID,
		h.Lifecycle, h.Severity, hosts, h.Evidence, h.ObserveCount, h.CleanCount,
		h.FirstSeen, h.LastSeen, nullIfEmpty(h.ConfirmedAt), nullIfEmpty(h.ResolvedAt), h.Reporter,
		nowRFC3339Nano(), now)
}

// GetHealthCondition reads one condition by identity; ok=false when absent.
func GetHealthCondition(ctx context.Context, c *Client, evaluator, code, subjectKind, subjectID string) (HealthCondition, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT evaluator, code, subject_kind, subject_id, lifecycle, severity, hosts,
		        evidence, observe_count, clean_count, first_seen, last_seen,
		        confirmed_at, resolved_at, reporter
		 FROM health_conditions
		 WHERE evaluator = ? AND code = ? AND subject_kind = ? AND subject_id = ?
		   AND deleted_at IS NULL`,
		evaluator, code, subjectKind, subjectID)
	if err != nil || len(rows) == 0 {
		return HealthCondition{}, false, err
	}
	return scanHealthCondition(rows[0]), true, nil
}

// ListHealthConditions returns every live condition. includeResolved=false
// filters to observed+confirmed — the "active conditions" every consumer
// (GetClusterHealth, admission) reads.
func ListHealthConditions(ctx context.Context, c *Client, includeResolved bool) ([]HealthCondition, error) {
	q := `SELECT evaluator, code, subject_kind, subject_id, lifecycle, severity, hosts,
	             evidence, observe_count, clean_count, first_seen, last_seen,
	             confirmed_at, resolved_at, reporter
	      FROM health_conditions WHERE deleted_at IS NULL`
	if !includeResolved {
		q += ` AND lifecycle != 'resolved'`
	}
	q += ` ORDER BY evaluator, code, subject_kind, subject_id`
	rows, err := c.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]HealthCondition, 0, len(rows))
	for _, r := range rows {
		out = append(out, scanHealthCondition(r))
	}
	return out, nil
}

func scanHealthCondition(r Row) HealthCondition {
	h := HealthCondition{
		Evaluator:    r.String("evaluator"),
		Code:         r.String("code"),
		SubjectKind:  r.String("subject_kind"),
		SubjectID:    r.String("subject_id"),
		Lifecycle:    r.String("lifecycle"),
		Severity:     r.String("severity"),
		Evidence:     r.String("evidence"),
		ObserveCount: r.Int("observe_count"),
		CleanCount:   r.Int("clean_count"),
		FirstSeen:    r.String("first_seen"),
		LastSeen:     r.String("last_seen"),
		ConfirmedAt:  r.String("confirmed_at"),
		ResolvedAt:   r.String("resolved_at"),
		Reporter:     r.String("reporter"),
	}
	if hosts := r.String("hosts"); hosts != "" {
		_ = json.Unmarshal([]byte(hosts), &h.Hosts)
	}
	return h
}

// ResolvedConditionRetention is how long a RESOLVED condition stays readable
// before GC tombstones it. Long enough that an operator investigating "what
// happened last week" still finds the record; bounded so the table cannot grow
// without limit.
const ResolvedConditionRetention = 30 * 24 * time.Hour

// TombstoneResolvedHealthConditions soft-deletes conditions resolved more than
// ResolvedConditionRetention ago, returning how many it removed. Convergence-
// safe the same way every retention delete here is: it tombstones (deleted_at)
// rather than hard-deleting, so replicas that have not yet seen the resolution
// converge to the tombstone instead of resurrecting the row.
func TombstoneResolvedHealthConditions(ctx context.Context, c *Client, now time.Time) (int, error) {
	cutoff := now.Add(-ResolvedConditionRetention).UTC().Format(time.RFC3339)
	n, err := c.ExecuteRows(ctx,
		`UPDATE health_conditions SET deleted_at = ?, updated_at = ?
		 WHERE lifecycle = 'resolved' AND deleted_at IS NULL
		   AND resolved_at IS NOT NULL AND resolved_at < ?`,
		nowRFC3339(), c.NowTS(), cutoff)
	return int(n), err
}

// HealthEvaluatorStatus is one evaluator's latest scan: when, with what
// coverage, run by whom.
type HealthEvaluatorStatus struct {
	Evaluator string
	LastScan  string // RFC3339
	Coverage  string // CoverageComplete | CoveragePartial | CoverageUnreachable | CoverageUnsupported
	Reporter  string
	Detail    string
}

// UpsertHealthEvaluatorStatus records an evaluator's completed scan.
func UpsertHealthEvaluatorStatus(ctx context.Context, c *Client, st HealthEvaluatorStatus) error {
	if st.Evaluator == "" {
		return fmt.Errorf("corrosion: evaluator status requires an evaluator name")
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO health_evaluator_status (evaluator, last_scan, coverage, reporter, detail,
		   created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(evaluator) DO UPDATE SET
		   last_scan = excluded.last_scan,
		   coverage = excluded.coverage,
		   reporter = excluded.reporter,
		   detail = excluded.detail,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		st.Evaluator, st.LastScan, st.Coverage, st.Reporter, st.Detail,
		nowRFC3339Nano(), now)
}

// ListHealthEvaluatorStatus returns every evaluator's latest scan record.
func ListHealthEvaluatorStatus(ctx context.Context, c *Client) ([]HealthEvaluatorStatus, error) {
	rows, err := c.Query(ctx,
		`SELECT evaluator, last_scan, coverage, reporter, detail
		 FROM health_evaluator_status WHERE deleted_at IS NULL ORDER BY evaluator`)
	if err != nil {
		return nil, err
	}
	out := make([]HealthEvaluatorStatus, 0, len(rows))
	for _, r := range rows {
		out = append(out, HealthEvaluatorStatus{
			Evaluator: r.String("evaluator"),
			LastScan:  r.String("last_scan"),
			Coverage:  r.String("coverage"),
			Reporter:  r.String("reporter"),
			Detail:    r.String("detail"),
		})
	}
	return out, nil
}

// HostCapacityObservation is one host's runtime-inventory capacity sample: what
// the database has allocated there, what runtime-only workloads add on top, and
// the effective union. Complete=false marks a sample that could not account for
// everything — placement must treat that as "unknown", never as headroom.
type HostCapacityObservation struct {
	HostName        string
	DBCPU           int
	DBMemMiB        int
	ExtraCPU        int
	ExtraMemMiB     int
	EffectiveCPU    int
	EffectiveMemMiB int
	Complete        bool
	Detail          string
	SampledAt       string // RFC3339 of the local inventory scan
}

// UpsertHostCapacityObservation writes a host's latest sample. Only the
// observed host itself calls this — host_name is the ownership.
func UpsertHostCapacityObservation(ctx context.Context, c *Client, o HostCapacityObservation) error {
	if o.HostName == "" {
		return fmt.Errorf("corrosion: capacity observation requires a host name")
	}
	complete := 0
	if o.Complete {
		complete = 1
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO host_capacity_observations (host_name, db_cpu, db_mem_mib,
		   extra_cpu, extra_mem_mib, effective_cpu, effective_mem_mib, complete,
		   detail, sampled_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(host_name) DO UPDATE SET
		   db_cpu = excluded.db_cpu,
		   db_mem_mib = excluded.db_mem_mib,
		   extra_cpu = excluded.extra_cpu,
		   extra_mem_mib = excluded.extra_mem_mib,
		   effective_cpu = excluded.effective_cpu,
		   effective_mem_mib = excluded.effective_mem_mib,
		   complete = excluded.complete,
		   detail = excluded.detail,
		   sampled_at = excluded.sampled_at,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		o.HostName, o.DBCPU, o.DBMemMiB, o.ExtraCPU, o.ExtraMemMiB,
		o.EffectiveCPU, o.EffectiveMemMiB, complete, o.Detail, o.SampledAt,
		nowRFC3339Nano(), now)
}

// GetHostCapacityObservation reads one host's sample; ok=false when the host
// has never reported.
func GetHostCapacityObservation(ctx context.Context, c *Client, host string) (HostCapacityObservation, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, db_cpu, db_mem_mib, extra_cpu, extra_mem_mib,
		        effective_cpu, effective_mem_mib, complete, detail, sampled_at
		 FROM host_capacity_observations WHERE host_name = ? AND deleted_at IS NULL`, host)
	if err != nil || len(rows) == 0 {
		return HostCapacityObservation{}, false, err
	}
	return scanCapacityObservation(rows[0]), true, nil
}

// ListHostCapacityObservations returns every host's latest sample.
func ListHostCapacityObservations(ctx context.Context, c *Client) ([]HostCapacityObservation, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, db_cpu, db_mem_mib, extra_cpu, extra_mem_mib,
		        effective_cpu, effective_mem_mib, complete, detail, sampled_at
		 FROM host_capacity_observations WHERE deleted_at IS NULL ORDER BY host_name`)
	if err != nil {
		return nil, err
	}
	out := make([]HostCapacityObservation, 0, len(rows))
	for _, r := range rows {
		out = append(out, scanCapacityObservation(r))
	}
	return out, nil
}

func scanCapacityObservation(r Row) HostCapacityObservation {
	return HostCapacityObservation{
		HostName:        r.String("host_name"),
		DBCPU:           r.Int("db_cpu"),
		DBMemMiB:        r.Int("db_mem_mib"),
		ExtraCPU:        r.Int("extra_cpu"),
		ExtraMemMiB:     r.Int("extra_mem_mib"),
		EffectiveCPU:    r.Int("effective_cpu"),
		EffectiveMemMiB: r.Int("effective_mem_mib"),
		Complete:        r.Int("complete") != 0,
		Detail:          r.String("detail"),
		SampledAt:       r.String("sampled_at"),
	}
}

// WorkloadHasActiveOwnershipCondition reports whether an ACTIVE (observed or
// confirmed) ownership-class condition names this workload. Automated recovery
// consults it before restoring anything: recovery may restore an
// already-database-accounted workload, but it must never act on a workload
// whose ownership is in dispute — restarting one side of a dual-run is exactly
// how a transient condition becomes a corrupted disk.
func WorkloadHasActiveOwnershipCondition(ctx context.Context, c *Client, subjectKind, name string) (bool, string, error) {
	rows, err := c.Query(ctx,
		`SELECT code FROM health_conditions
		 WHERE subject_kind = ? AND subject_id = ? AND lifecycle != 'resolved'
		   AND deleted_at IS NULL
		   AND code IN ('vm_dual_run', 'ct_dual_run', 'runtime_owner_mismatch', 'owner_epoch_mismatch')
		 LIMIT 1`, subjectKind, name)
	if err != nil {
		return false, "", err
	}
	if len(rows) == 0 {
		return false, "", nil
	}
	return true, rows[0].String("code"), nil
}
