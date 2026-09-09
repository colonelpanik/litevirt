package metrics

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/lxc"
)

// containerStatter reads a container's live cgroup usage (host-local, no RPC).
// nil → container usage metrics are skipped. *lxc.LxcRunner satisfies it.
type containerStatter interface {
	Stats(ctx context.Context, name string) (lxc.ContainerStats, error)
}

// Server serves Prometheus metrics on an HTTP endpoint.
type Server struct {
	port     int
	bindAddr string // host part of the listen address; "" = all interfaces
	db       *corrosion.Client
	virt     *libvirt.Client
	ctStat   containerStatter
	hostName string
	// mu guards httpSrv and stopped. Start assigns httpSrv from whatever
	// goroutine the daemon launches it on (`go d.metrics.Start()`), and Stop
	// runs on the shutdown path — so the two race, and an unsynchronised Stop
	// could read nil during startup, skip the shutdown, and leave the endpoint
	// serving after shutdown was requested.
	mu      sync.Mutex
	httpSrv *http.Server
	stopped bool
	// reg is where the collector registers. nil means
	// prometheus.DefaultRegisterer, which is what the daemon uses.
	// Injectable ONLY so a test can drive the real Start more than once in a
	// process: MustRegister panics on a duplicate, and Stop shuts the HTTP
	// server down without unregistering, so `go test -count=2` would panic on
	// the second run. promhttp still serves the default registry, so an
	// injected one isolates registration, not the served output.
	reg prometheus.Registerer
	// log is the logger the exposure warning goes to. nil means slog.Default().
	// Injectable ONLY so a test can read what was logged without calling
	// slog.SetDefault, which cannot be restored: SetDefault also rewires the
	// std log package, and the restore path skips that when the previous
	// handler is the default one — so a save/restore pair permanently routes
	// std-log writes into the test's dead buffer for the rest of the binary.
	log *slog.Logger
}

// registerer is the injected registry or the process default. Never nil.
func (s *Server) registerer() prometheus.Registerer {
	if s.reg != nil {
		return s.reg
	}
	return prometheus.DefaultRegisterer
}

// logger is the injected logger or the process default. Never nil.
func (s *Server) logger() *slog.Logger {
	if s.log != nil {
		return s.log
	}
	return slog.Default()
}

// Addr is the address the metrics listener binds, composed the one way. The
// daemon's startup banner reads it from here rather than reassembling it, which
// is how the banner came to claim 0.0.0.0 for a loopback-bound endpoint.
func (s *Server) Addr() string {
	return net.JoinHostPort(normalizeBind(s.bindAddr), strconv.Itoa(s.port))
}

// NewServer creates a metrics server. bindAddr is the interface to listen on
// (e.g. "127.0.0.1" to restrict /metrics to loopback); an empty string keeps
// the historical behaviour of binding all interfaces. ctStat may be nil
// (container cgroup-usage metrics are then skipped).
func NewServer(port int, bindAddr string, db *corrosion.Client, virt *libvirt.Client, ctStat containerStatter, hostName string) *Server {
	return &Server{
		port:     port,
		bindAddr: bindAddr,
		db:       db,
		virt:     virt,
		ctStat:   ctStat,
		hostName: hostName,
	}
}

// Start begins serving metrics. Blocks.
func (s *Server) Start() {
	collector := newCollector(s.db, s.virt, s.ctStat, s.hostName)
	s.registerer().MustRegister(collector)
	registerTelemetryMetrics()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/api/v1/status", s.handleStatus)

	srv := &http.Server{
		// Addr(), not Sprintf("%s:%d"): an IPv6 literal needs brackets and must
		// not get them twice. See normalizeBind.
		Addr:    s.Addr(),
		Handler: mux,
	}

	s.mu.Lock()
	if s.stopped {
		// Stop already ran, so serving now would outlive the shutdown that
		// asked for it. Nothing has listened yet, so there is nothing to close.
		s.mu.Unlock()
		return
	}
	s.httpSrv = srv
	s.mu.Unlock()

	s.logger().Info("metrics server starting", "addr", srv.Addr, "bind", s.bindAddr)
	warnIfMetricsWorldReadable(s.logger(), s.bindAddr, s.port)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		s.logger().Error("metrics server error", "error", err)
	}
}

// metricsExposure is how far a metrics_bind value reaches.
type metricsExposure int

const (
	// metricsBindRestricted is loopback, an RFC1918 private address, a CGNAT
	// address (a tailnet), or link-local. Reachable by something, but by a
	// bounded something the operator chose.
	metricsBindRestricted metricsExposure = iota
	// metricsBindWildcard is every interface — the DEFAULT, and the case an
	// operator most likely did not choose.
	metricsBindWildcard
	// metricsBindPublic is a globally routable address. Almost never deliberate
	// for an endpoint with no authentication.
	metricsBindPublic
)

// cgnatV4 is 100.64.0.0/10, RFC 6598 shared address space. netip has no
// predicate for it and classifies it exactly like 8.8.8.8 — not private, global
// unicast — but it is where tailnet addresses live, so binding there is a
// deliberately restricted choice and must not be warned about.
var cgnatV4 = netip.MustParsePrefix("100.64.0.0/10")

// normalizeBind strips the brackets an operator may write around an IPv6
// literal, so ONE spelling reaches both the listener and the classifier.
//
// This also fixes a bind that could not work: the address was composed with
// Sprintf("%s:%d"), so metrics_bind "::" produced ":::7444" — "too many colons"
// — and ListenAndServe failed, silently leaving the node with no metrics
// endpoint at all, because Start only logs that error. "[::]" worked. Both
// spellings now normalise to the same host and are joined with
// net.JoinHostPort, which re-adds the brackets exactly once.
func normalizeBind(bindAddr string) string {
	return strings.Trim(bindAddr, "[]")
}

// classifyMetricsBind decides how far this bind reaches.
//
// A hostname is reported RESTRICTED rather than resolved. Resolution at startup
// can block, can disagree with what the listener later does, and a hostname
// pointing at a wildcard is rare — while a false warning is one an operator
// cannot silence, which is how a startup warning becomes one everybody skips.
// The doc comment on the warning says plainly that silence is not a safety
// claim, and configuration.md repeats it.
func classifyMetricsBind(bindAddr string) metricsExposure {
	host := normalizeBind(bindAddr)
	if host == "" {
		return metricsBindWildcard
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return metricsBindRestricted // a hostname — not classified, see above
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified():
		return metricsBindWildcard
	case addr.IsLoopback(), addr.IsPrivate(), addr.IsLinkLocalUnicast(), cgnatV4.Contains(addr):
		return metricsBindRestricted
	default:
		return metricsBindPublic
	}
}

// warnIfMetricsWorldReadable says once, at startup, when this endpoint is
// reachable from off-box with no credential.
//
// It is easy to read `metrics_bind: ""` as a listener detail. It is not: the
// endpoint has no TLS and no authentication of any kind, and it serves the
// cluster's inventory — every VM name, every container name, this host's name,
// their CPU/memory/disk allocations — alongside `litevirt_enforcement_*`, which
// states which security kill-switches are off on this node. Anyone who can
// reach the port gets all of it. That is a reasonable default for a metrics
// endpoint on a trusted management network and a poor one anywhere else, and
// nothing in the daemon distinguishes the two.
//
// SILENCE IS NOT A SAFETY CLAIM. It means the bind is not a wildcard and not
// obviously public — a private, CGNAT or link-local address, or a hostname this
// deliberately does not resolve. Whether the networks that can reach it are
// trusted is not something the daemon can know.
//
// The default is deliberately NOT changed to loopback here. A silent flip would
// break every deployment scraping from a remote Prometheus, and it would break
// it invisibly — the endpoint would simply stop answering. This repo's
// convention for a behaviour change is a flag whose default keeps the existing
// behaviour, so the flag stays and the exposure is stated instead.
func warnIfMetricsWorldReadable(log *slog.Logger, bindAddr string, port int) {
	const what = "it serves VM and container names, host inventory and resource allocations, " +
		"and litevirt_enforcement_* (which security kill-switches are off on this node)"
	switch classifyMetricsBind(bindAddr) {
	case metricsBindWildcard:
		log.Warn("metrics endpoint is bound to EVERY interface with NO authentication or TLS: "+
			what+". Set metrics_bind to 127.0.0.1, or to a management-network address, unless "+
			"every network that can reach this port is trusted",
			"port", port, "metrics_bind", bindAddr)
	case metricsBindPublic:
		log.Warn("metrics endpoint is bound to a PUBLIC address with NO authentication or TLS: "+
			what+". Anyone who can route to this address can read it — set metrics_bind to "+
			"127.0.0.1 or a management-network address",
			"port", port, "metrics_bind", bindAddr)
	}
}

// Stop gracefully shuts down the metrics server.
//
// Safe before Start has assigned the listener: it records the intent, so a Start
// that has not begun serving yet returns instead of coming up after shutdown.
func (s *Server) Stop(ctx context.Context) {
	s.mu.Lock()
	s.stopped = true
	srv := s.httpSrv
	s.mu.Unlock()
	if srv != nil {
		srv.Shutdown(ctx)
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
	ctStat   containerStatter
	hostName string

	hostVMCount    *prometheus.Desc
	hostCPUTotal   *prometheus.Desc
	hostMemTotal   *prometheus.Desc
	vmState        *prometheus.Desc
	vmCPU          *prometheus.Desc
	vmMemory       *prometheus.Desc
	hostCtCount    *prometheus.Desc
	ctState        *prometheus.Desc
	ctCPULimit     *prometheus.Desc
	ctMemLimit     *prometheus.Desc
	ctCPUSeconds   *prometheus.Desc // live cgroup CPU usage (A3b)
	ctMemBytes     *prometheus.Desc // live cgroup memory usage (A3b)
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
	leaseTerm          *prometheus.Desc // highest lease incarnation per lease key
	fenceFailures      *prometheus.Desc // count of fencing_log rows with non-success result
	hlcRejected        *prometheus.Desc // remote HLC timestamps rejected for skew
	mutationLogSize    *prometheus.Desc // mutation_log row count (replication backlog)
	replicationMinSeq  *prometheus.Desc // MIN(last_seq) across replication_watermarks
	replicationPending *prometheus.Desc // entries ahead of the slowest LIVE peer
	replicationPeerLag *prometheus.Desc // per-peer backlog: MAX(seq) - peer last_seq

	// NetBox IPAM gauges. Both are CURRENT state, which the NetBox counters
	// cannot express: a counter of suspensions keeps rising after an operator
	// has repaired one, and queued mirror work is a depth, not a total.
	netboxSyncQueueDepth    *prometheus.Desc // pending netbox_sync_queue items
	netboxBindingsSuspended *prometheus.Desc // bindings refusing new allocations right now

	// placement / rebalancer metrics.
	placementDecisions *prometheus.Desc // counter labeled by policy + result
	hostPressure       *prometheus.Desc // post-snapshot pressure per host × dimension
	rebalanceProposals *prometheus.Desc // pending proposals labeled by policy
	rebalanceApplied   *prometheus.Desc // applied/approved/rejected proposals
}

func newCollector(db *corrosion.Client, virt *libvirt.Client, ctStat containerStatter, hostName string) *collector {
	return &collector{
		db:       db,
		virt:     virt,
		ctStat:   ctStat,
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
		hostCtCount: prometheus.NewDesc(
			"litevirt_host_container_count", "Number of containers on this host",
			nil, nil,
		),
		ctState: prometheus.NewDesc(
			"litevirt_container_state", "Container state (1=running, 0=other)",
			[]string{"container", "state"}, nil,
		),
		ctCPULimit: prometheus.NewDesc(
			"litevirt_container_cpu_limit", "Container CPU-shares limit (0=unlimited)",
			[]string{"container"}, nil,
		),
		ctMemLimit: prometheus.NewDesc(
			"litevirt_container_memory_limit_mib", "Container memory limit in MiB (0=unlimited)",
			[]string{"container"}, nil,
		),
		ctCPUSeconds: prometheus.NewDesc(
			"litevirt_container_cpu_seconds_total", "Cumulative container CPU time in seconds (cgroup-v2 cpu.stat)",
			[]string{"container"}, nil,
		),
		ctMemBytes: prometheus.NewDesc(
			"litevirt_container_memory_bytes", "Current container memory usage in bytes (cgroup-v2 memory.current)",
			[]string{"container"}, nil,
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
		leaseTerm: prometheus.NewDesc(
			"litevirt_leader_lease_term",
			"Highest recorded lease incarnation (fencing term) per leader-lease key. "+
				"Each new term is one acquisition, so the RATE is leadership churn — alert on "+
				"it climbing faster than the expected failover rate. Whether a term is "+
				"ENFORCED depends on enforcement.lease_term plus the lease_term_v1 latch; "+
				"this gauge is the audit record either way.",
			[]string{"key"}, prometheus.Labels{"host": hostName},
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
		replicationPeerLag: prometheus.NewDesc(
			"litevirt_replication_peer_pending_entries",
			"Per-peer replication backlog: local mutation_log tail (MAX(seq)) minus the peer's acknowledged last_seq. One series per live peer; a single climbing series identifies the lagging peer",
			[]string{"peer"}, prometheus.Labels{"host": hostName},
		),
		netboxSyncQueueDepth: prometheus.NewDesc(
			"litevirt_netbox_sync_queue_depth",
			"Pending items in netbox_sync_queue (the inventory mirror's work queue). A depth that never returns to 0 means the mirror is not draining",
			nil, prometheus.Labels{"host": hostName},
		),
		netboxBindingsSuspended: prometheus.NewDesc(
			"litevirt_netbox_bindings_suspended",
			"NetBox prefix bindings currently suspended by revalidation drift. Each one refuses every new allocation on its network until an operator runs `lv netbox resume` or `lv netbox rekey`",
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
			"Rebalance proposals by status (applied/failed/rejected/expired terminal; approved/applying in-flight)",
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
	ch <- c.hostCtCount
	ch <- c.ctState
	ch <- c.ctCPULimit
	ch <- c.ctMemLimit
	ch <- c.ctCPUSeconds
	ch <- c.ctMemBytes
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
	ch <- c.leaseTerm
	ch <- c.fenceFailures
	ch <- c.hlcRejected
	ch <- c.mutationLogSize
	ch <- c.replicationMinSeq
	ch <- c.replicationPending
	ch <- c.replicationPeerLag
	ch <- c.netboxSyncQueueDepth
	ch <- c.netboxBindingsSuspended
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

	// Container metrics. State + declared limits from the containers table;
	// actual cgroup cpu/mem usage (A3b) comes from the host-local runtime when
	// one is wired (ctStat), best-effort — a container with no readable cgroup
	// (stopped, or a cgroup-v1 host → ErrStatsUnavailable) is silently skipped.
	if cts, err := corrosion.ListContainers(ctx, c.db, c.hostName); err == nil {
		ch <- prometheus.MustNewConstMetric(c.hostCtCount, prometheus.GaugeValue, float64(len(cts)))
		for _, ct := range cts {
			running := 0.0
			if ct.State == "running" {
				running = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.ctState, prometheus.GaugeValue, running, ct.Name, ct.State)
			ch <- prometheus.MustNewConstMetric(c.ctCPULimit, prometheus.GaugeValue, float64(ct.CPULimit), ct.Name)
			ch <- prometheus.MustNewConstMetric(c.ctMemLimit, prometheus.GaugeValue, float64(ct.MemMiB), ct.Name)
			if c.ctStat != nil && ct.State == "running" {
				if st, serr := c.ctStat.Stats(ctx, ct.Name); serr == nil {
					ch <- prometheus.MustNewConstMetric(c.ctCPUSeconds, prometheus.CounterValue, float64(st.CPUUsageUsec)/1e6, ct.Name)
					ch <- prometheus.MustNewConstMetric(c.ctMemBytes, prometheus.GaugeValue, float64(st.MemBytes), ct.Name)
				}
			}
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

	// Leader-lease terms, one series per key. This is the signal
	// docs/operating-model.md tells operators to alert on: the docs named term
	// growth before any metric exposed it, leaving raw SQL as the only access
	// path. The key label is bounded by the rows that exist, and only three keys
	// are ever written (failover, the rebalancer's, dual_run_detector).
	if termRows, terr := c.db.Query(ctx,
		`SELECT key, MAX(term) AS term FROM leader_lease_terms
		 WHERE deleted_at IS NULL GROUP BY key`); terr == nil {
		for _, r := range termRows {
			ch <- prometheus.MustNewConstMetric(c.leaseTerm, prometheus.GaugeValue,
				float64(r.Int64("term")), r.String("key"))
		}
	}

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

	// Replication watermark floor over LIVE peers. Replication is PUSH over the
	// relay topology, so this node holds a permanently-stale watermark for any
	// peer it does not itself serve — and an unfiltered MIN reported the
	// slowest-EVER-seen peer instead of the current compaction floor, pinning
	// the gauge far below reality. The prune has always filtered to live
	// watermarks (pruneMutationLog); this now matches it, using the same cutoff
	// the pending_entries query below computes.
	liveCutoff := time.Now().Add(-corrosion.LiveWatermarkWindow).UTC().Format(time.RFC3339)
	if rows, rerr := c.db.Query(ctx,
		`SELECT COALESCE(MIN(last_seq), 0) AS m FROM replication_watermarks WHERE updated_at > ?`,
		liveCutoff); rerr == nil && len(rows) > 0 {
		ch <- prometheus.MustNewConstMetric(c.replicationMinSeq,
			prometheus.GaugeValue, float64(rows[0].Int("m")))
	}

	// Replication backlog ahead of the slowest LIVE peer: entries written but
	// not yet acked by the peer that's furthest behind. Complements
	// mutation_log_rows (total, incl. already-replicated-but-unpruned) and
	// replication_min_watermark_seq. Reported as 0 when there are no live peers
	// so a single node (or a fully-partitioned one) doesn't report its whole
	// log as "pending". The live cutoff matches the replicator's prune logic.
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

	// Per-peer replication backlog: how far each LIVE peer is behind the local
	// mutation_log tail. Restricted to watermarks updated within
	// LiveWatermarkWindow so a departed peer doesn't leave a stuck series
	// behind forever; the lag is clamped at 0 (a peer can momentarily report a
	// watermark past our local MAX after applying our own filtered entries).
	maxSeq := 0
	if mx, merr := c.db.Query(ctx, `SELECT COALESCE(MAX(seq),0) AS m FROM mutation_log`); merr == nil && len(mx) > 0 {
		maxSeq = mx[0].Int("m")
	}
	peerCutoff := time.Now().Add(-corrosion.LiveWatermarkWindow).UTC().Format(time.RFC3339)
	if pr, perr := c.db.Query(ctx,
		`SELECT peer_name, last_seq FROM replication_watermarks WHERE updated_at > ?`, peerCutoff); perr == nil {
		for _, row := range pr {
			lag := maxSeq - row.Int("last_seq")
			if lag < 0 {
				lag = 0
			}
			ch <- prometheus.MustNewConstMetric(c.replicationPeerLag,
				prometheus.GaugeValue, float64(lag), row.String("peer_name"))
		}
	}

	// NetBox IPAM current state. Both tables are small (one row per bound
	// prefix; one per queued mirror item), so these are two counting reads.
	if qr, qerr := c.db.Query(ctx,
		`SELECT COUNT(*) AS cnt FROM netbox_sync_queue WHERE deleted_at IS NULL`); qerr == nil && len(qr) > 0 {
		ch <- prometheus.MustNewConstMetric(c.netboxSyncQueueDepth,
			prometheus.GaugeValue, float64(qr[0].Int("cnt")))
	}
	if br, berr := c.db.Query(ctx,
		`SELECT COUNT(*) AS cnt FROM netbox_bindings WHERE suspended = 1 AND deleted_at IS NULL`); berr == nil && len(br) > 0 {
		ch <- prometheus.MustNewConstMetric(c.netboxBindingsSuspended,
			prometheus.GaugeValue, float64(br[0].Int("cnt")))
	}

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
		// Fold running containers into host pressure (declared limits — a
		// cgroup-actual reading is the A3b follow-up; an unlimited container
		// contributes 0 to that dimension).
		if hostCts, err := corrosion.ListContainers(ctx, c.db, h.Name); err == nil {
			for _, ct := range hostCts {
				if ct.State == "running" {
					usedCPU += ct.CPULimit
					usedMem += ct.MemMiB
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
	// Count by status — terminal (applied/rejected/expired/failed) plus the
	// transient in-flight states the executor uses (approved/applying).
	if statusRows, perr := c.db.Query(ctx,
		`SELECT status, COUNT(*) AS cnt FROM rebalance_proposals
		 WHERE status IN ('applied','approved','applying','rejected','expired','failed') GROUP BY status`); perr == nil {
		for _, r := range statusRows {
			ch <- prometheus.MustNewConstMetric(c.rebalanceApplied,
				prometheus.CounterValue, float64(r.Int("cnt")), r.String("status"))
		}
	}
}
