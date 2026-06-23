package lb

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Manager creates and manages HAProxy + keepalived instances as direct processes.
type Manager struct {
	configDir string // base dir for generated configs
	runDir    string // PID files
}

// applyLocks serializes Apply/Remove per LB name. NewManager() is constructed
// fresh per call (so a per-instance lock would serialize nothing), and peers run
// Apply via forwardLBApply, so the lock must be process-global here in the lb
// package — the one place every apply/teardown on a host funnels through.
// Holding it across exec is intended: it collapses the deploy/migration apply
// storm and stops an apply from racing a teardown (the orphan-spawning race).
var (
	applyLocksMu sync.Mutex
	applyLocks   = map[string]*sync.Mutex{}
)

// lbLock returns the per-LB mutex for name, creating it on first use.
func lbLock(name string) *sync.Mutex {
	applyLocksMu.Lock()
	defer applyLocksMu.Unlock()
	m := applyLocks[name]
	if m == nil {
		m = &sync.Mutex{}
		applyLocks[name] = m
	}
	return m
}

// NewManager returns a Manager.
func NewManager() *Manager {
	return &Manager{
		configDir: "/etc/litevirt/lb",
		runDir:    "/run/litevirt/lb",
	}
}

// Apply writes HAProxy + keepalived configs and starts/reloads processes.
// It is idempotent: calling Apply twice with the same config is safe.
func (m *Manager) Apply(ctx context.Context, cfg Config) error {
	lk := lbLock(cfg.Name)
	lk.Lock()
	defer lk.Unlock()

	if err := os.MkdirAll(m.configDir, 0750); err != nil {
		return fmt.Errorf("create lb config dir: %w", err)
	}
	if err := os.MkdirAll(m.runDir, 0755); err != nil {
		return fmt.Errorf("create lb run dir: %w", err)
	}

	// Write haproxy config. Detect change BEFORE writing so we only reload the
	// running process when the rendered config actually differs (a burst of
	// identical re-applies during deploy/migration must not churn — that churn
	// is what spawned reload-race orphan processes).
	haproxyCfg, err := RenderHAProxy(cfg)
	if err != nil {
		return err
	}
	haproxyPath := filepath.Join(m.configDir, cfg.Name+"-haproxy.cfg")
	haproxyChanged := configChanged(haproxyPath, haproxyCfg)
	if err := os.WriteFile(haproxyPath, []byte(haproxyCfg), 0640); err != nil {
		return fmt.Errorf("write haproxy config: %w", err)
	}

	// Write keepalived config (same change-detection).
	keepalivedCfg, err := RenderKeepalived(cfg)
	if err != nil {
		return err
	}
	keepalivedPath := filepath.Join(m.configDir, cfg.Name+"-keepalived.conf")
	keepalivedChanged := configChanged(keepalivedPath, keepalivedCfg)
	if err := os.WriteFile(keepalivedPath, []byte(keepalivedCfg), 0640); err != nil {
		return fmt.Errorf("write keepalived config: %w", err)
	}

	// Write combined PEM files for TLS-terminated ports.
	for _, p := range cfg.Ports {
		if p.TLS == nil {
			continue
		}
		cert, err := os.ReadFile(p.TLS.Cert)
		if err != nil {
			return fmt.Errorf("read TLS cert %s: %w", p.TLS.Cert, err)
		}
		key, err := os.ReadFile(p.TLS.Key)
		if err != nil {
			return fmt.Errorf("read TLS key %s: %w", p.TLS.Key, err)
		}
		pemPath := filepath.Join(m.configDir, fmt.Sprintf("%s-%d.pem", cfg.Name, p.Listen))
		combined := append(cert, key...)
		if err := os.WriteFile(pemPath, combined, 0600); err != nil {
			return fmt.Errorf("write TLS PEM %s: %w", pemPath, err)
		}
	}

	// Write conntrackd + notify script if SNAT is enabled.
	if cfg.SNATEnabled {
		conntrackdCfg, err := RenderConntrackd(cfg)
		if err != nil {
			slog.Warn("conntrackd config render failed (SNAT failover may not work)", "lb", cfg.Name, "error", err)
		} else {
			ctPath := filepath.Join(m.configDir, cfg.Name+"-conntrackd.conf")
			if err := os.WriteFile(ctPath, []byte(conntrackdCfg), 0640); err != nil {
				slog.Warn("write conntrackd config failed", "error", err)
			}
		}

		notifyScript, err := RenderNotifyScript(cfg)
		if err != nil {
			slog.Warn("notify script render failed", "lb", cfg.Name, "error", err)
		} else {
			notifyPath := filepath.Join(m.configDir, cfg.Name+"-notify.sh")
			if err := os.WriteFile(notifyPath, []byte(notifyScript), 0750); err != nil {
				slog.Warn("write notify script failed", "error", err)
			}
		}
	}

	// Ensure ip_nonlocal_bind is enabled so HAProxy can bind to the VIP
	// even when it's not yet assigned (e.g. on BACKUP nodes).
	exec.CommandContext(ctx, "sysctl", "-w", "net.ipv4.ip_nonlocal_bind=1").Run() //nolint:errcheck

	// Validate haproxy config.
	if out, err := exec.CommandContext(ctx, "haproxy", "-c", "-f", haproxyPath).CombinedOutput(); err != nil {
		return fmt.Errorf("haproxy config validation failed: %w\n%s", err, out)
	}

	// Start conntrackd before keepalived if SNAT is enabled.
	if cfg.SNATEnabled {
		ctPath := filepath.Join(m.configDir, cfg.Name+"-conntrackd.conf")
		ctPid := filepath.Join(m.runDir, cfg.Name+"-conntrackd.pid")
		if err := m.startConntrackd(ctx, ctPath, ctPid); err != nil {
			slog.Warn("conntrackd start failed (SNAT failover may not work)", "lb", cfg.Name, "error", err)
		}
	}

	// Start keepalived first to assign the VIP, then start HAProxy which binds to
	// it. Even if HAProxy fails (e.g. port conflict), keepalived runs so the VIP
	// can fail back to a working host. Restart keepalived only when its config
	// changed OR it isn't running — never skip a dead keepalived (that's exactly
	// the unassigned-VIP case). (Trade-off: a healthy LB with unchanged config
	// won't pick up a future keepalivedArgs code change until its config changes
	// or the process restarts; ReconcileLBs is the catch-up.)
	keepalivedPid := filepath.Join(m.runDir, cfg.Name+"-keepalived.pid")
	if keepalivedChanged || !pidAlive(keepalivedPid) {
		if err := m.startOrReloadKeepalived(keepalivedPath, keepalivedPid); err != nil {
			slog.Error("keepalived start failed — VIP NOT assigned, LB unreachable", "lb", cfg.Name, "error", err)
		}
	}

	// Start or reload haproxy only when its config changed or it isn't running.
	haproxyPid := filepath.Join(m.runDir, cfg.Name+"-haproxy.pid")
	if haproxyChanged || !pidAlive(haproxyPid) {
		if err := m.startOrReloadHAProxy(haproxyPath, haproxyPid); err != nil {
			return fmt.Errorf("haproxy start/reload: %w", err)
		}
	}

	slog.Info("LB applied", "name", cfg.Name, "vip", cfg.VIP, "backends", len(cfg.Backends), "snat", cfg.SNATEnabled)
	return nil
}

// configChanged reports whether rendered differs from what's already on disk at
// path (a missing/unreadable file counts as changed).
func configChanged(path, rendered string) bool {
	existing, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	return string(existing) != rendered
}

// pidAlive reports whether the PID recorded in pidFile names a live process.
func pidAlive(pidFile string) bool {
	pid := readPid(pidFile)
	return pid > 0 && processAlive(pid)
}

// cmdlineMatchesBinaryConfig reports whether a /proc cmdline (NUL-separated
// argv) is a `binary` process launched with the given config path as one of its
// arguments. Matching the exact cfgPath field keeps the sweep scoped to one LB.
func cmdlineMatchesBinaryConfig(cmdline, binary, cfgPath string) bool {
	if cfgPath == "" {
		return false
	}
	hasBin, hasCfg := false, false
	for _, f := range strings.Split(cmdline, "\x00") {
		switch {
		case filepath.Base(f) == binary:
			hasBin = true
		case f == cfgPath:
			hasCfg = true
		}
	}
	return hasBin && hasCfg
}

// killProcByConfig SIGTERMs (then SIGKILLs) every `binary` process bound to
// cfgPath. Used at teardown to catch reload/restart siblings the pidfile no
// longer tracks (haproxy `-sf` reloads, racing keepalived restarts). Killing a
// keepalived parent also reaps its vrrp/checkers children. No-op when /proc is
// unavailable.
func killProcByConfig(binary, cfgPath string) {
	matches, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, cf := range matches {
		data, err := os.ReadFile(cf)
		if err != nil {
			continue // process exited between glob and read
		}
		if !cmdlineMatchesBinaryConfig(string(data), binary, cfgPath) {
			continue
		}
		pid, err := strconv.Atoi(filepath.Base(filepath.Dir(cf)))
		if err != nil || pid <= 0 {
			continue
		}
		slog.Info("sweeping stray process", "binary", binary, "pid", pid, "config", cfgPath)
		syscall.Kill(pid, syscall.SIGTERM)
		for i := 0; i < 20 && processAlive(pid); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		if processAlive(pid) {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// Remove stops and removes LB instances for the given name.
func (m *Manager) Remove(ctx context.Context, name string) error {
	// Same key as Apply so teardown can't interleave with an in-flight apply
	// (which would resurrect what we're tearing down / orphan a process).
	lk := lbLock(name)
	lk.Lock()
	defer lk.Unlock()

	keepalivedPid := filepath.Join(m.runDir, name+"-keepalived.pid")
	pidFiles := []string{
		filepath.Join(m.runDir, name+"-haproxy.pid"),
		keepalivedPid,
		filepath.Join(m.runDir, name+"-conntrackd.pid"),
	}
	// keepalived's vrrp/checkers children have their own per-LB pidfiles now.
	pidFiles = append(pidFiles, keepalivedChildPidFiles(keepalivedPid)...)
	for _, pidFile := range pidFiles {
		killByPidFile(pidFile)
	}

	// Sweep any haproxy/keepalived still bound to this LB's config file. Reloads
	// and racing restarts (haproxy `-sf`, repeated applyLBFromSpec) can leave a
	// sibling the pidfile no longer tracks; this catches them so teardown leaves
	// no orphaned process (killing a keepalived parent reaps its children too).
	killProcByConfig("haproxy", filepath.Join(m.configDir, name+"-haproxy.cfg"))
	killProcByConfig("keepalived", filepath.Join(m.configDir, name+"-keepalived.conf"))

	// Remove config files.
	for _, f := range []string{
		filepath.Join(m.configDir, name+"-haproxy.cfg"),
		filepath.Join(m.configDir, name+"-keepalived.conf"),
		filepath.Join(m.configDir, name+"-conntrackd.conf"),
		filepath.Join(m.configDir, name+"-notify.sh"),
	} {
		os.Remove(f)
	}

	slog.Info("LB removed", "name", name)
	return nil
}

// SetBackendEnabled enables or disables a backend in HAProxy via its stats socket.
// It discovers all backend sections from the config file and applies the action
// to the named server in each one.
func (m *Manager) SetBackendEnabled(ctx context.Context, lbName, backendName string, enabled bool) error {
	socketPath := filepath.Join(m.runDir, lbName+"-haproxy.sock")
	action := "enable"
	if !enabled {
		action = "disable"
	}

	// Discover backend section names from the config file.
	backends := m.discoverBackendSections(lbName)
	if len(backends) == 0 {
		// Fallback: try the old naming convention.
		backends = []string{lbName + "-backend"}
	}

	var lastErr error
	for _, be := range backends {
		cmd := fmt.Sprintf("%s server %s/%s\n", action, be, backendName)
		if err := runHAProxyCmd(ctx, socketPath, cmd); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// discoverBackendSections parses the HAProxy config to find backend section names.
func (m *Manager) discoverBackendSections(lbName string) []string {
	cfgPath := filepath.Join(m.configDir, lbName+"-haproxy.cfg")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil
	}
	var backends []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "backend ") {
			backends = append(backends, strings.TrimPrefix(line, "backend "))
		}
	}
	return backends
}

// ── Stats + Drain ────────────────────────────────────────────────────────────

// BackendStats holds parsed HAProxy stats for one backend server.
type BackendStats struct {
	ProxyName     string // pxname
	ServerName    string // svname
	Status        string // UP, DOWN, DRAIN, MAINT
	CurrentSess   int64  // scur
	TotalSess     int64  // stot
	BytesIn       int64  // bin
	BytesOut      int64  // bout
	Rate          int64  // rate
	ErrConn       int64  // econ
	ErrResp       int64  // eresp
	Resp2xx       int64  // hrsp_2xx
	Resp4xx       int64  // hrsp_4xx
	Resp5xx       int64  // hrsp_5xx
	AvgResponseMs int64  // rtime
	AvgQueueMs    int64  // qtime
	Type          int    // 0=frontend, 1=backend, 2=server
}

// Stats holds parsed HAProxy stats for an entire LB.
type Stats struct {
	Name    string
	Entries []BackendStats
}

// GetStats reads HAProxy stats from the socket and returns parsed results.
func (m *Manager) GetStats(ctx context.Context, lbName string) (*Stats, error) {
	if _, err := exec.LookPath("socat"); err != nil {
		return nil, fmt.Errorf("socat not found (install with: apt install socat)")
	}
	socketPath := filepath.Join(m.runDir, lbName+"-haproxy.sock")
	out, err := runHAProxyCmdOutput(ctx, socketPath, "show stat\n")
	if err != nil {
		return nil, fmt.Errorf("haproxy show stat: %w", err)
	}
	entries, err := parseHAProxyCSV(out)
	if err != nil {
		return nil, err
	}
	return &Stats{Name: lbName, Entries: entries}, nil
}

// DrainBackend puts a backend in drain mode (finish existing connections, reject new ones).
func (m *Manager) DrainBackend(ctx context.Context, lbName, backendName string) (int64, error) {
	socketPath := filepath.Join(m.runDir, lbName+"-haproxy.sock")

	backends := m.discoverBackendSections(lbName)
	if len(backends) == 0 {
		backends = []string{lbName + "-backend"}
	}

	for _, be := range backends {
		cmd := fmt.Sprintf("set server %s/%s state drain\n", be, backendName)
		if err := runHAProxyCmd(ctx, socketPath, cmd); err != nil {
			return 0, fmt.Errorf("drain %s/%s: %w", be, backendName, err)
		}
	}

	// Read current connections for this backend.
	stats, err := m.GetStats(ctx, lbName)
	if err != nil {
		return 0, nil // drain succeeded, just can't read connections
	}
	var conns int64
	for _, e := range stats.Entries {
		if e.Type == 2 && e.ServerName == backendName {
			conns += e.CurrentSess
		}
	}
	return conns, nil
}

// parseHAProxyCSV parses HAProxy "show stat" CSV output into BackendStats entries.
func parseHAProxyCSV(output string) ([]BackendStats, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		return nil, nil
	}

	// First line is headers prefixed with "# "
	headerLine := strings.TrimPrefix(lines[0], "# ")
	headers := strings.Split(headerLine, ",")
	colIdx := make(map[string]int, len(headers))
	for i, h := range headers {
		colIdx[strings.TrimSpace(h)] = i
	}

	var entries []BackendStats
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		e := BackendStats{
			ProxyName:     csvField(fields, colIdx, "pxname"),
			ServerName:    csvField(fields, colIdx, "svname"),
			Status:        csvField(fields, colIdx, "status"),
			CurrentSess:   csvFieldInt(fields, colIdx, "scur"),
			TotalSess:     csvFieldInt(fields, colIdx, "stot"),
			BytesIn:       csvFieldInt(fields, colIdx, "bin"),
			BytesOut:      csvFieldInt(fields, colIdx, "bout"),
			Rate:          csvFieldInt(fields, colIdx, "rate"),
			ErrConn:       csvFieldInt(fields, colIdx, "econ"),
			ErrResp:       csvFieldInt(fields, colIdx, "eresp"),
			Resp2xx:       csvFieldInt(fields, colIdx, "hrsp_2xx"),
			Resp4xx:       csvFieldInt(fields, colIdx, "hrsp_4xx"),
			Resp5xx:       csvFieldInt(fields, colIdx, "hrsp_5xx"),
			AvgResponseMs: csvFieldInt(fields, colIdx, "rtime"),
			AvgQueueMs:    csvFieldInt(fields, colIdx, "qtime"),
			Type:          int(csvFieldInt(fields, colIdx, "type")),
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func csvField(fields []string, colIdx map[string]int, name string) string {
	idx, ok := colIdx[name]
	if !ok || idx >= len(fields) {
		return ""
	}
	return fields[idx]
}

func csvFieldInt(fields []string, colIdx map[string]int, name string) int64 {
	s := csvField(fields, colIdx, name)
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

// runHAProxyCmdOutput runs a command on the HAProxy socket and returns the output.
func runHAProxyCmdOutput(ctx context.Context, socketPath, cmd string) (string, error) {
	proc := exec.CommandContext(ctx, "socat", "stdio", "UNIX-CONNECT:"+socketPath)
	conn, err := proc.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("socat stdin: %w", err)
	}
	proc.Stderr = nil
	var stdout strings.Builder
	proc.Stdout = &stdout
	if err := proc.Start(); err != nil {
		return "", fmt.Errorf("socat start: %w", err)
	}
	fmt.Fprint(conn, cmd)
	conn.Close()
	if err := proc.Wait(); err != nil {
		return "", fmt.Errorf("socat wait: %w", err)
	}
	return stdout.String(), nil
}

// startOrReloadHAProxy starts haproxy or gracefully reloads it if already running.
func (m *Manager) startOrReloadHAProxy(cfgPath, pidFile string) error {
	// If already running, do a graceful reload by starting a new process
	// with -sf <old_pid> which tells haproxy to take over the sockets.
	if pid := readPid(pidFile); pid > 0 {
		if processAlive(pid) {
			cmd := exec.Command("haproxy", "-f", cfgPath, "-p", pidFile,
				"-sf", strconv.Itoa(pid))
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("haproxy reload: %w: %s", err, out)
			}
			slog.Info("haproxy reloaded", "config", cfgPath)
			return nil
		}
	}

	// PID file is stale/missing. Check for an orphaned haproxy via pgrep.
	// If found, use graceful takeover (-sf) to inherit the listening socket
	// instead of kill-then-start which races with socket release.
	if orphanPid := m.findOrphanedHAProxy(cfgPath); orphanPid > 0 {
		slog.Warn("found orphaned haproxy, attempting graceful takeover",
			"pid", orphanPid, "config", cfgPath)
		cmd := exec.Command("haproxy", "-f", cfgPath, "-p", pidFile,
			"-sf", strconv.Itoa(orphanPid))
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if out, err := cmd.CombinedOutput(); err == nil {
			slog.Info("haproxy takeover succeeded", "old_pid", orphanPid, "config", cfgPath)
			return nil
		} else {
			slog.Warn("haproxy takeover failed, falling back to kill+start",
				"error", err, "output", string(out))
			m.killOrphanedHAProxy(cfgPath)
		}
	}

	// Start fresh (no existing process).
	cmd := exec.Command("haproxy", "-f", cfgPath, "-p", pidFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("haproxy start: %w: %s", err, out)
	}
	slog.Info("haproxy started", "config", cfgPath)
	return nil
}

// findOrphanedHAProxy returns the PID of an orphaned haproxy using this config, or 0.
func (m *Manager) findOrphanedHAProxy(cfgPath string) int {
	out, err := exec.Command("pgrep", "-f", "haproxy.*"+filepath.Base(cfgPath)).Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err == nil && pid > 0 && processAlive(pid) {
			return pid
		}
	}
	return 0
}

// killOrphanedHAProxy finds and kills any haproxy process using the given config
// file. Used as fallback when graceful takeover fails.
func (m *Manager) killOrphanedHAProxy(cfgPath string) {
	out, err := exec.Command("pgrep", "-f", "haproxy.*"+filepath.Base(cfgPath)).Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || pid <= 0 {
			continue
		}
		slog.Warn("killing orphaned haproxy", "pid", pid, "config", cfgPath)
		syscall.Kill(pid, syscall.SIGTERM)
		for i := 0; i < 30; i++ {
			if !processAlive(pid) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if processAlive(pid) {
			syscall.Kill(pid, syscall.SIGKILL)
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// keepalivedArgs builds the keepalived command line for one LB instance.
//
// Each LB gets its own vrrp (-r) and checkers (-c) child pidfiles, derived from
// the parent pidfile. keepalived's child processes otherwise default to shared
// paths (/var/run/keepalived_vrrp.pid, /var/run/keepalived_checkers.pid), so a
// second stack LB on the same host hits "daemon is already running" and never
// assigns its VIP.
func keepalivedArgs(cfgPath, pidFile string) []string {
	base := strings.TrimSuffix(pidFile, ".pid")
	return []string{
		"-f", cfgPath,
		"-p", pidFile,
		"-r", base + "_vrrp.pid",
		"-c", base + "_checkers.pid",
	}
}

// keepalivedChildPidFiles returns the vrrp + checkers child pidfiles for a
// parent keepalived pidfile (see keepalivedArgs), so teardown can reap them.
func keepalivedChildPidFiles(pidFile string) []string {
	base := strings.TrimSuffix(pidFile, ".pid")
	return []string{base + "_vrrp.pid", base + "_checkers.pid"}
}

// startOrReloadKeepalived starts or restarts keepalived.
func (m *Manager) startOrReloadKeepalived(cfgPath, pidFile string) error {
	// Kill existing and wait for it to fully exit (release PID file lock).
	if pid := readPid(pidFile); pid > 0 && processAlive(pid) {
		syscall.Kill(pid, syscall.SIGTERM)
		// Wait up to 3 seconds for the old process to die.
		for i := 0; i < 30; i++ {
			if !processAlive(pid) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		// Force kill if still alive.
		if processAlive(pid) {
			syscall.Kill(pid, syscall.SIGKILL)
			time.Sleep(100 * time.Millisecond)
		}
	}
	os.Remove(pidFile) //nolint:errcheck

	// Let keepalived daemonize (default behavior). It double-forks internally,
	// writes its own PID file, and the initial process exits. cmd.Run() waits
	// for that initial exit, then the actual daemon is reparented to init.
	cmd := exec.Command("keepalived", keepalivedArgs(cfgPath, pidFile)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keepalived start: %w: %s", err, out)
	}

	// Give it a moment to write the PID file then verify it's running.
	time.Sleep(500 * time.Millisecond)
	pid := readPid(pidFile)
	if pid > 0 && processAlive(pid) {
		slog.Info("keepalived started", "config", cfgPath, "pid", pid)
	} else {
		slog.Error("keepalived did not start — VIP will NOT be assigned", "config", cfgPath, "pid", pid, "output", string(out))
	}
	return nil
}

// KeepalivedRunning reports whether this LB's keepalived process is alive — the
// real signal that its VIP is assigned. HAProxy binds the VIP non-locally even
// when keepalived is down, so "haproxy is up" is NOT evidence the VIP works.
func (m *Manager) KeepalivedRunning(name string) bool {
	return pidAlive(filepath.Join(m.runDir, name+"-keepalived.pid"))
}

// startConntrackd starts conntrackd for SNAT conntrack replication.
func (m *Manager) startConntrackd(ctx context.Context, cfgPath, pidFile string) error {
	// Kill existing if running.
	if pid := readPid(pidFile); pid > 0 && processAlive(pid) {
		syscall.Kill(pid, syscall.SIGTERM)
		for i := 0; i < 20; i++ {
			if !processAlive(pid) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if processAlive(pid) {
			syscall.Kill(pid, syscall.SIGKILL)
			time.Sleep(100 * time.Millisecond)
		}
	}
	os.Remove(pidFile) //nolint:errcheck

	cmd := exec.Command("conntrackd", "-C", cfgPath, "-d")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("conntrackd start: %w: %s", err, out)
	}

	slog.Info("conntrackd started", "config", cfgPath)
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func readPid(pidFile string) int {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func killByPidFile(pidFile string) {
	pid := readPid(pidFile)
	if pid > 0 && processAlive(pid) {
		slog.Info("killing process", "pid", pid, "pidFile", pidFile)
		syscall.Kill(pid, syscall.SIGTERM)
		for i := 0; i < 30; i++ {
			if !processAlive(pid) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if processAlive(pid) {
			slog.Warn("force killing process", "pid", pid, "pidFile", pidFile)
			syscall.Kill(pid, syscall.SIGKILL)
		}
	} else {
		slog.Info("no running process for pidFile", "pidFile", pidFile, "pid", pid)
	}
	os.Remove(pidFile)
}

func runHAProxyCmd(ctx context.Context, socketPath, cmd string) error {
	proc := exec.CommandContext(ctx, "socat", "stdio", "UNIX-CONNECT:"+socketPath)
	conn, err := proc.StdinPipe()
	if err != nil {
		slog.Warn("haproxy runtime cmd skipped (socat unavailable)", "cmd", strings.TrimSpace(cmd))
		return nil
	}
	if err := proc.Start(); err != nil {
		slog.Warn("haproxy runtime cmd skipped", "cmd", strings.TrimSpace(cmd), "error", err)
		return nil
	}
	fmt.Fprint(conn, cmd)
	conn.Close()
	return proc.Wait()
}

// AllocVRID picks a VRID (1–254) based on the LB name. It is deterministic but
// can collide (two names hashing to the same slot fight over the VIP); prefer
// AllocVRIDExcluding when the set of in-use VRIDs is known, or assign
// explicitly in production.
func AllocVRID(name string) int {
	h := 0
	for _, c := range name {
		h = (h*31 + int(c)) % 254
	}
	return h + 1 // 1–254
}

// AllocVRIDExcluding picks a VRID for name that isn't already in `used`. It
// starts at the deterministic hash slot (AllocVRID) and linearly probes
// forward, wrapping over 1..254, returning the first free value — so a name
// that would collide is deterministically bumped to a free slot instead of
// silently sharing a VRID. If all 254 slots are taken it falls back to the
// hash slot (the caller should warn).
func AllocVRIDExcluding(name string, used map[int]bool) int {
	start := AllocVRID(name)
	if !used[start] {
		return start
	}
	for i := 1; i < 254; i++ {
		cand := (start-1+i)%254 + 1
		if !used[cand] {
			return cand
		}
	}
	return start
}

// DetectInterface returns the default network interface name.
func DetectInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "eth0"
	}
	// Output: "default via X.X.X.X dev ethN..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return "eth0"
}

// DetectInterfaceForIP finds the network interface whose subnet contains the
// given IP address. This is used to put the keepalived VIP on the correct
// interface (e.g., the bridge where VMs live). Falls back to DetectInterface().
func DetectInterfaceForIP(targetIP string) string {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return DetectInterface()
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return DetectInterface()
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.Contains(ip) {
				return iface.Name
			}
		}
	}

	return DetectInterface()
}

// VRIDFromString converts a string to a stable VRID (helper for tests).
func VRIDFromString(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return AllocVRID(s)
	}
	if n < 1 || n > 254 {
		return AllocVRID(s)
	}
	return n
}
