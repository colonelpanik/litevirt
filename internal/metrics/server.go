package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// Server serves Prometheus metrics on an HTTP endpoint.
type Server struct {
	port     int
	bindAddr string // host part of the listen address; "" = all interfaces
	db       *corrosion.Client
	virt     *libvirt.Client
	hostName string
	httpSrv  *http.Server
}

// NewServer creates a metrics server. bindAddr is the interface to listen on
// (e.g. "127.0.0.1" to restrict /metrics to loopback); an empty string keeps
// the historical behaviour of binding all interfaces.
func NewServer(port int, bindAddr string, db *corrosion.Client, virt *libvirt.Client, hostName string) *Server {
	return &Server{
		port:     port,
		bindAddr: bindAddr,
		db:       db,
		virt:     virt,
		hostName: hostName,
	}
}

// Start begins serving metrics. Blocks.
func (s *Server) Start() {
	collector := newCollector(s.db, s.virt, s.hostName)
	prometheus.MustRegister(collector)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/api/v1/status", s.handleStatus)

	s.httpSrv = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.bindAddr, s.port),
		Handler: mux,
	}

	slog.Info("metrics server starting", "addr", s.httpSrv.Addr, "bind", s.bindAddr)
	if err := s.httpSrv.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("metrics server error", "error", err)
	}
}

// Stop gracefully shuts down the metrics server.
func (s *Server) Stop(ctx context.Context) {
	if s.httpSrv != nil {
		s.httpSrv.Shutdown(ctx)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// ═══════════ Prometheus Collector ═══════════

type collector struct {
	db       *corrosion.Client
	virt     *libvirt.Client
	hostName string

	hostVMCount    *prometheus.Desc
	hostCPUTotal   *prometheus.Desc
	hostMemTotal   *prometheus.Desc
	vmState        *prometheus.Desc
	vmCPU          *prometheus.Desc
	vmMemory       *prometheus.Desc
	vmDiskRead     *prometheus.Desc
	vmDiskWrite    *prometheus.Desc
	vmDiskReadOps  *prometheus.Desc
	vmDiskWriteOps *prometheus.Desc
	vmNetRx        *prometheus.Desc
	vmNetTx        *prometheus.Desc
	peerHealthy    *prometheus.Desc
	daemonUptime   *prometheus.Desc
	daemonOpenFDs  *prometheus.Desc // #48: FD leak detection
	clockSkew      *prometheus.Desc // #41: clock skew between hosts
	snapshotDepth  *prometheus.Desc // #45: snapshot chain depth

	// cluster-correctness metrics.
	leaderHolder       *prometheus.Desc // who holds the failover lease
	fenceFailures      *prometheus.Desc // count of fencing_log rows with non-success result
	hlcRejected        *prometheus.Desc // remote HLC timestamps rejected for skew
	mutationLogSize    *prometheus.Desc // mutation_log row count (replication backlog)
	replicationMinSeq  *prometheus.Desc // MIN(last_seq) across replication_watermarks
	replicationPending *prometheus.Desc // entries ahead of the slowest LIVE peer

	// placement / rebalancer metrics.
	placementDecisions *prometheus.Desc // counter labeled by policy + result
	hostPressure       *prometheus.Desc // post-snapshot pressure per host × dimension
	rebalanceProposals *prometheus.Desc // pending proposals labeled by policy
	rebalanceApplied   *prometheus.Desc // applied/approved/rejected proposals
}

func newCollector(db *corrosion.Client, virt *libvirt.Client, hostName string) *collector {
	return &collector{
		db:       db,
		virt:     virt,
		hostName: hostName,
		hostVMCount: prometheus.NewDesc(
			"litevirt_host_vm_count", "Number of VMs on this host",
			nil, prometheus.Labels{"host": hostName},
		),
		hostCPUTotal: prometheus.NewDesc(
			"litevirt_host_cpu_total", "Total CPU cores",
			nil, prometheus.Labels{"host": hostName},
		),
		hostMemTotal: prometheus.NewDesc(
			"litevirt_host_memory_total_mib", "Total memory in MiB",
			nil, prometheus.Labels{"host": hostName},
		),
		vmState: prometheus.NewDesc(
			"litevirt_vm_state", "VM state (1=running, 0=other)",
			[]string{"vm", "state"}, nil,
		),
		vmCPU: prometheus.NewDesc(
			"litevirt_vm_cpu_count", "VM vCPU count",
			[]string{"vm"}, nil,
		),
		vmMemory: prometheus.NewDesc(
			"litevirt_vm_memory_mib", "VM memory in MiB",
			[]string{"vm"}, nil,
		),
		// Per-VM I/O counters sourced from libvirt.GetAllDomainStats.
		// libvirt resets these to zero on guest reboot, so prometheus
		// will see a counter reset there — handle in PromQL via
		// rate()'s built-in reset detection.
		vmDiskRead: prometheus.NewDesc(
			"litevirt_vm_disk_read_bytes_total",
			"Cumulative bytes read across all of a VM's disks since the domain started",
			[]string{"vm"}, prometheus.Labels{"host": hostName},
		),
		vmDiskWrite: prometheus.NewDesc(
			"litevirt_vm_disk_write_bytes_total",
			"Cumulative bytes written across all of a VM's disks since the domain started",
			[]string{"vm"}, prometheus.Labels{"host": hostName},
		),
		vmDiskReadOps: prometheus.NewDesc(
			"litevirt_vm_disk_read_ops_total",
			"Cumulative read operations across all of a VM's disks since the domain started",
			[]string{"vm"}, prometheus.Labels{"host": hostName},
		),
		vmDiskWriteOps: prometheus.NewDesc(
			"litevirt_vm_disk_write_ops_total",
			"Cumulative write operations across all of a VM's disks since the domain started",
			[]string{"vm"}, prometheus.Labels{"host": hostName},
		),
		vmNetRx: prometheus.NewDesc(
			"litevirt_vm_net_rx_bytes_total",
			"Cumulative bytes received across all of a VM's NICs since the domain started",
			[]string{"vm"}, prometheus.Labels{"host": hostName},
		),
		vmNetTx: prometheus.NewDesc(
			"litevirt_vm_net_tx_bytes_total",
			"Cumulative bytes transmitted across all of a VM's NICs since the domain started",
			[]string{"vm"}, prometheus.Labels{"host": hostName},
		),
		peerHealthy: prometheus.NewDesc(
			"litevirt_peer_healthy", "Whether a peer host is healthy (1=yes, 0=no)",
			[]string{"target"}, nil,
		),
		daemonUptime: prometheus.NewDesc(
			"litevirt_daemon_uptime_seconds", "Daemon uptime",
			nil, prometheus.Labels{"host": hostName},
		),
		daemonOpenFDs: prometheus.NewDesc(
			"litevirt_daemon_open_fds", "Number of open file descriptors in the litevirtd process",
			nil, prometheus.Labels{"host": hostName},
		),
		clockSkew: prometheus.NewDesc(
			"litevirt_cluster_clock_skew_seconds", "Observed clock skew between this host and a peer",
			[]string{"target"}, nil,
		),
		snapshotDepth: prometheus.NewDesc(
			"litevirt_vm_snapshot_chain_depth", "Snapshot chain depth per VM",
			[]string{"vm"}, nil,
		),
		leaderHolder: prometheus.NewDesc(
			"litevirt_failover_leader",
			"1 if this host currently holds the failover-leader lease",
			nil, prometheus.Labels{"host": hostName},
		),
		fenceFailures: prometheus.NewDesc(
			"litevirt_fence_failures_total",
			"Cumulative count of fencing_log rows with result != 'fenced' or 'manual-confirmed'",
			nil, prometheus.Labels{"host": hostName},
		),
		hlcRejected: prometheus.NewDesc(
			"litevirt_hlc_rejected_total",
			"Cumulative count of remote HLC timestamps rejected for exceeding MaxSkewMS",
			nil, prometheus.Labels{"host": hostName},
		),
		mutationLogSize: prometheus.NewDesc(
			"litevirt_mutation_log_rows",
			"Current row count in the mutation_log table (replication backlog)",
			nil, prometheus.Labels{"host": hostName},
		),
		replicationMinSeq: prometheus.NewDesc(
			"litevirt_replication_min_watermark_seq",
			"MIN(last_seq) across replication_watermarks; gates mutation_log compaction",
			nil, prometheus.Labels{"host": hostName},
		),
		replicationPending: prometheus.NewDesc(
			"litevirt_replication_pending_entries",
			"mutation_log entries written but not yet acked by the slowest LIVE peer (MAX(seq) - MIN(live last_seq)); 0 when there are no live peers",
			nil, prometheus.Labels{"host": hostName},
		),
		placementDecisions: prometheus.NewDesc(
			"litevirt_placement_decisions_total",
			"Cumulative placement decisions emitted by the engine",
			[]string{"policy", "result"}, nil,
		),
		hostPressure: prometheus.NewDesc(
			"litevirt_host_pressure",
			"Per-host current resource pressure (used + 0)/capacity per dimension. 0 = idle, 1 = full.",
			[]string{"host", "dim"}, nil,
		),
		rebalanceProposals: prometheus.NewDesc(
			"litevirt_rebalance_proposals_pending",
			"Number of rebalance proposals currently pending by policy",
			[]string{"policy"}, nil,
		),
		rebalanceApplied: prometheus.NewDesc(
			"litevirt_rebalance_proposals_total",
			"Cumulative rebalance proposals by terminal status",
			[]string{"status"}, nil,
		),
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.hostVMCount
	ch <- c.hostCPUTotal
	ch <- c.hostMemTotal
	ch <- c.vmState
	ch <- c.vmCPU
	ch <- c.vmMemory
	ch <- c.vmDiskRead
	ch <- c.vmDiskWrite
	ch <- c.vmDiskReadOps
	ch <- c.vmDiskWriteOps
	ch <- c.vmNetRx
	ch <- c.vmNetTx
	ch <- c.peerHealthy
	ch <- c.daemonOpenFDs
	ch <- c.clockSkew
	ch <- c.snapshotDepth
	ch <- c.leaderHolder
	ch <- c.fenceFailures
	ch <- c.hlcRejected
	ch <- c.mutationLogSize
	ch <- c.replicationMinSeq
	ch <- c.replicationPending
	ch <- c.placementDecisions
	ch <- c.hostPressure
	ch <- c.rebalanceProposals
	ch <- c.rebalanceApplied
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()

	// Host-level metrics
	host, err := corrosion.GetHost(ctx, c.db, c.hostName)
	if err == nil && host != nil {
		ch <- prometheus.MustNewConstMetric(c.hostCPUTotal, prometheus.GaugeValue, float64(host.CPUTotal))
		ch <- prometheus.MustNewConstMetric(c.hostMemTotal, prometheus.GaugeValue, float64(host.MemTotal))
	}

	// VM metrics
	vms, err := corrosion.ListVMs(ctx, c.db, "", c.hostName)
	if err == nil {
		ch <- prometheus.MustNewConstMetric(c.hostVMCount, prometheus.GaugeValue, float64(len(vms)))
		for _, vm := range vms {
			running := 0.0
			if vm.State == "running" {
				running = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.vmState, prometheus.GaugeValue, running, vm.Name, vm.State)
			ch <- prometheus.MustNewConstMetric(c.vmCPU, prometheus.GaugeValue, float64(vm.CPUActual), vm.Name)
			ch <- prometheus.MustNewConstMetric(c.vmMemory, prometheus.GaugeValue, float64(vm.MemActual), vm.Name)
		}
	}

	// Per-VM disk + network counters sourced from libvirt. We iterate
	// running domains via GetAllDomainStats — libvirt's bulk-stats API
	// is one round trip regardless of VM count, so the cost stays
	// constant as the host fills up.
	if c.virt != nil {
		stats, err := c.virt.GetAllDomainStats()
		if err == nil {
			for _, ds := range stats {
				ch <- prometheus.MustNewConstMetric(c.vmDiskRead, prometheus.CounterValue, float64(ds.DiskRdBytes), ds.Name)
				ch <- prometheus.MustNewConstMetric(c.vmDiskWrite, prometheus.CounterValue, float64(ds.DiskWrBytes), ds.Name)
				ch <- prometheus.MustNewConstMetric(c.vmDiskReadOps, prometheus.CounterValue, float64(ds.DiskRdReqs), ds.Name)
				ch <- prometheus.MustNewConstMetric(c.vmDiskWriteOps, prometheus.CounterValue, float64(ds.DiskWrReqs), ds.Name)
				ch <- prometheus.MustNewConstMetric(c.vmNetRx, prometheus.CounterValue, float64(ds.NetRxBytes), ds.Name)
				ch <- prometheus.MustNewConstMetric(c.vmNetTx, prometheus.CounterValue, float64(ds.NetTxBytes), ds.Name)
			}
		}
	}

	// Peer health
	rows, err := c.db.Query(ctx,
		`SELECT target, status FROM host_health WHERE observer = ?`, c.hostName)
	if err == nil {
		for _, r := range rows {
			val := 0.0
			if r.String("status") == "healthy" {
				val = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.peerHealthy, prometheus.GaugeValue, val, r.String("target"))
		}
	}

	// Open file descriptors (#48): read /proc/self/fd to detect FD leaks.
	if fds, err := os.ReadDir(filepath.Join("/proc", "self", "fd")); err == nil {
		ch <- prometheus.MustNewConstMetric(c.daemonOpenFDs, prometheus.GaugeValue, float64(len(fds)))
	}

	// Clock skew (#41): report skew from clock_skew table. Only FRESH rows —
	// a peer whose skew was fixed (or that was removed) stops being rewritten,
	// so a stale row would otherwise report phantom skew forever. updated_at is
	// RFC3339, so the cutoff is too (strftime with the T/Z literals).
	skewRows, err := c.db.Query(ctx,
		`SELECT target, CAST(skew_seconds AS INTEGER) as skew_int FROM clock_skew
		 WHERE observer = ? AND updated_at > strftime('%Y-%m-%dT%H:%M:%SZ','now','-10 minutes')`, c.hostName)
	if err == nil {
		for _, r := range skewRows {
			ch <- prometheus.MustNewConstMetric(c.clockSkew, prometheus.GaugeValue,
				float64(r.Int("skew_int")), r.String("target"))
		}
	}

	// Snapshot chain depth (#45): report per-VM snapshot count.
	snapRows, err := c.db.Query(ctx,
		`SELECT vm_name, COUNT(*) as depth FROM snapshots
		 WHERE deleted_at IS NULL GROUP BY vm_name`)
	if err == nil {
		for _, r := range snapRows {
			ch <- prometheus.MustNewConstMetric(c.snapshotDepth, prometheus.GaugeValue,
				float64(r.Int("depth")), r.String("vm_name"))
		}
	}

	// Failover-leader lease holder. expires_at is RFC3339, so compare against an
	// RFC3339 cutoff, not datetime('now') (whose space text mis-sorts a same-day
	// lease and would always report it valid).
	leaderVal := 0.0
	if leaderRows, lerr := c.db.Query(ctx,
		`SELECT holder FROM leader_election
		 WHERE key = 'failover' AND expires_at >= ?`,
		time.Now().UTC().Format(time.RFC3339)); lerr == nil {
		if len(leaderRows) > 0 && leaderRows[0].String("holder") == c.hostName {
			leaderVal = 1.0
		}
	}
	ch <- prometheus.MustNewConstMetric(c.leaderHolder, prometheus.GaugeValue, leaderVal)

	// Cumulative fence failures.
	if rows, ferr := c.db.Query(ctx,
		`SELECT COUNT(*) AS cnt FROM fencing_log
		 WHERE result NOT IN ('fenced', 'manual-confirmed')`); ferr == nil && len(rows) > 0 {
		ch <- prometheus.MustNewConstMetric(c.fenceFailures,
			prometheus.CounterValue, float64(rows[0].Int("cnt")))
	}

	// HLC rejected timestamps. Surfaced via Clock.Rejected().
	if c.db != nil {
		if hlc := c.db.Clock(); hlc != nil {
			ch <- prometheus.MustNewConstMetric(c.hlcRejected,
				prometheus.CounterValue, float64(hlc.Rejected()))
		}
	}

	// Mutation log size.
	if rows, merr := c.db.Query(ctx,
		`SELECT COUNT(*) AS cnt FROM mutation_log`); merr == nil && len(rows) > 0 {
		ch <- prometheus.MustNewConstMetric(c.mutationLogSize,
			prometheus.GaugeValue, float64(rows[0].Int("cnt")))
	}

	// Replication watermark floor. Lowest peer seq pins compaction.
	if rows, rerr := c.db.Query(ctx,
		`SELECT COALESCE(MIN(last_seq), 0) AS m FROM replication_watermarks`); rerr == nil && len(rows) > 0 {
		ch <- prometheus.MustNewConstMetric(c.replicationMinSeq,
			prometheus.GaugeValue, float64(rows[0].Int("m")))
	}

	// Replication backlog ahead of the slowest LIVE peer: entries written but
	// not yet acked by the peer that's furthest behind. Complements
	// mutation_log_rows (total, incl. already-replicated-but-unpruned) and
	// replication_min_watermark_seq. Reported as 0 when there are no live peers
	// so a single node (or a fully-partitioned one) doesn't report its whole
	// log as "pending". The live cutoff matches the replicator's prune logic.
	liveCutoff := time.Now().Add(-corrosion.LiveWatermarkWindow).UTC().Format(time.RFC3339)
	pending := 0.0
	if wm, werr := c.db.Query(ctx,
		`SELECT COUNT(*) AS live, COALESCE(MIN(last_seq), 0) AS minseq
		 FROM replication_watermarks WHERE updated_at > ?`, liveCutoff); werr == nil && len(wm) > 0 {
		if wm[0].Int("live") > 0 {
			if mx, merr := c.db.Query(ctx,
				`SELECT COALESCE(MAX(seq), 0) AS m FROM mutation_log`); merr == nil && len(mx) > 0 {
				if lag := mx[0].Int("m") - wm[0].Int("minseq"); lag > 0 {
					pending = float64(lag)
				}
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(c.replicationPending, prometheus.GaugeValue, pending)

	// Per-host CPU + RAM pressure. Cheap: uses the same data the
	// host_vm_count above is derived from.
	hostList, _ := corrosion.ListHosts(ctx, c.db)
	for _, h := range hostList {
		if h.IsWitness() {
			continue
		}
		// Read current usage by summing running VMs.
		usedCPU, usedMem := 0, 0
		if hostVMs, err := corrosion.ListVMs(ctx, c.db, "", h.Name); err == nil {
			for _, vm := range hostVMs {
				if vm.State == "running" || vm.State == "creating" || vm.State == "starting" {
					usedCPU += vm.CPUActual
					usedMem += vm.MemActual
				}
			}
		}
		if h.CPUTotal > 0 {
			ch <- prometheus.MustNewConstMetric(c.hostPressure,
				prometheus.GaugeValue, float64(usedCPU)/float64(h.CPUTotal), h.Name, "cpu")
		}
		if h.MemTotal > 0 {
			ch <- prometheus.MustNewConstMetric(c.hostPressure,
				prometheus.GaugeValue, float64(usedMem)/float64(h.MemTotal), h.Name, "ram")
		}
	}

	// Rebalance proposals: pending count grouped by policy.
	if pendingRows, perr := c.db.Query(ctx,
		`SELECT policy, COUNT(*) AS cnt FROM rebalance_proposals
		 WHERE status = 'pending' GROUP BY policy`); perr == nil {
		for _, r := range pendingRows {
			ch <- prometheus.MustNewConstMetric(c.rebalanceProposals,
				prometheus.GaugeValue, float64(r.Int("cnt")), r.String("policy"))
		}
	}
	// Cumulative count by terminal status.
	if statusRows, perr := c.db.Query(ctx,
		`SELECT status, COUNT(*) AS cnt FROM rebalance_proposals
		 WHERE status IN ('applied','approved','rejected','expired') GROUP BY status`); perr == nil {
		for _, r := range statusRows {
			ch <- prometheus.MustNewConstMetric(c.rebalanceApplied,
				prometheus.CounterValue, float64(r.Int("cnt")), r.String("status"))
		}
	}
}
