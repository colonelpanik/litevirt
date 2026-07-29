package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Audit chain observability.
//
// Lazily registered like the signal counter, because the audit chain is touched
// from contexts that exist before (and independently of) the metrics server.

var (
	auditOnce      sync.Once
	auditVerified  *prometheus.GaugeVec
	auditFindings  *prometheus.GaugeVec
	auditHeadTotal prometheus.Counter
)

func auditInit() {
	auditOnce.Do(func() {
		auditVerified = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_audit_chain_last_verified_ok",
			Help: "1 if the last audit chain verification found no evidence of tampering, 0 otherwise. " +
				"Unsigned rows do not count as tampering — they predate enforcement.",
		}, []string{"host"})
		auditFindings = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_audit_chain_findings",
			Help: "Count of audit chain findings from the last verification, by kind " +
				"(broken_hash, bad_signature, unknown_key, seq_gap, laundered, truncated, " +
				"retired_key, head_mismatch, unsigned, unsigned_after_signed).",
		}, []string{"kind"})
		auditHeadTotal = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "litevirt_audit_chain_heads_published_total",
			Help: "Signed audit chain heads published by this host. A head is the only thing " +
				"that can detect a truncated chain tail, so a stalled counter means that " +
				"detection has quietly stopped.",
		})
		prometheus.DefaultRegisterer.MustRegister(auditVerified, auditFindings, auditHeadTotal)
	})
}

// AuditChainVerified records the outcome of a chain verification.
//
// The findings are reported per kind rather than as one boolean because the
// responses differ: a bad signature means someone edited a row without the
// host's key, a truncation means rows are simply gone, and a pile of unsigned
// rows means enforcement was turned on recently — which is not an incident.
func AuditChainVerified(host string, ok bool, findings map[string]int) {
	auditInit()
	v := 0.0
	if ok {
		v = 1
	}
	auditVerified.WithLabelValues(host).Set(v)
	for kind, n := range findings {
		auditFindings.WithLabelValues(kind).Set(float64(n))
	}
}

// AuditChainHeadPublished counts one signed head reaching the log.
func AuditChainHeadPublished() {
	auditInit()
	auditHeadTotal.Inc()
}
