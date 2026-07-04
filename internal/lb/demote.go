package lb

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DemoteAll drops EVERY VIP this host is configured to run (Phase 2 isolated-side
// self-demotion), driven by LOCAL RUNTIME state — the rendered keepalived configs on
// THIS host — NOT the (possibly stale / gossip-crossed) DB. For each config it stops
// keepalived (confirming it's gone) and removes the EXACT rendered <ip>/<prefix> dev
// <iface> tuple keepalived was assigning. This is correct in the asymmetric case
// where the DB says this host no longer runs the LB but a local keepalived still
// holds the VIP. Returns held=true if this host has ANY LB configured (so the monitor
// knows there was something to stand down) and the FIRST error — a keepalived that
// can't be confirmed stopped, or a config that can't be parsed, which the caller must
// treat as an unconfirmed demotion (→ self-fence: the VIP may still be assigned).
func (m *Manager) DemoteAll(keepalivedStopTimeout time.Duration) (held bool, err error) {
	confs, _ := filepath.Glob(filepath.Join(m.configDir, "*-keepalived.conf"))
	var firstErr error
	for _, confPath := range confs {
		held = true
		name := strings.TrimSuffix(filepath.Base(confPath), "-keepalived.conf")
		data, rerr := os.ReadFile(confPath)
		if rerr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read keepalived config %s: %w", confPath, rerr)
			}
			continue
		}
		vip, prefix, iface, ok := parseKeepalivedVIP(string(data))
		if !ok {
			// Can't determine what to delete → we can't confirm the VIP is gone.
			if firstErr == nil {
				firstErr = fmt.Errorf("cannot parse VIP tuple from %s (fail closed)", confPath)
			}
			continue
		}
		if derr := m.Demote(Config{Name: name, VIP: vip, VIPPrefix: prefix, Interface: iface}, keepalivedStopTimeout); derr != nil {
			if firstErr == nil {
				firstErr = derr
			}
		}
	}

	// Fail-closed orphan sweep. A keepalived can outlive its rendered config: an
	// incomplete teardown that partially killed the process THEN removed the
	// *-keepalived.conf leaves a running keepalived still holding a VIP that no
	// glob above can see. Config-driven demotion would report held=false and the
	// monitor would never self-fence — the exact "unknown release must fail closed"
	// case. Quorum is lost, so this host must drop EVERY VIP it owns: SIGKILL any
	// LITEVIRT-OWNED keepalived still alive. We can't identify such an orphan's VIP to
	// `ip addr del`, so even a successful kill leaves the address possibly assigned —
	// return an error so the caller self-fences (a reboot is the only way to guarantee
	// the VIP is gone). Scoped to litevirt-owned processes (cmdline references a config
	// under m.configDir, which survives the file's deletion) so an UNRELATED keepalived
	// on the host is never touched — its VIP isn't ours to demote.
	if pids := litevirtKeepalivedPids(m.configDir); len(pids) > 0 {
		held = true
		for _, pid := range pids {
			syscall.Kill(pid, syscall.SIGKILL)
		}
		time.Sleep(200 * time.Millisecond)
		if firstErr == nil {
			if rem := litevirtKeepalivedPids(m.configDir); len(rem) > 0 {
				firstErr = fmt.Errorf("litevirt keepalived still running after demotion (config-less orphan, pids %v) — VIP release unconfirmed", rem)
			} else {
				firstErr = fmt.Errorf("killed a config-less litevirt keepalived orphan — its VIP address cannot be identified/removed, release unconfirmed")
			}
		}
	}
	return held, firstErr
}

// litevirtKeepalived is one running LITEVIRT-OWNED keepalived process and the config
// path its cmdline references (under configDir).
type litevirtKeepalived struct {
	pid    int
	config string
}

// scanLitevirtKeepaliveds scans /proc for running keepalived processes that are
// LITEVIRT-OWNED: a keepalived whose cmdline references a config path under configDir
// (a `<configDir>/*-keepalived.conf`). The path string survives the config FILE's
// deletion (it stays in the process's argv), so this still catches an orphan whose
// rendered config was already removed — while NEVER matching an unrelated system
// keepalived (a different config dir), whose VIP is not ours to reason about. Empty on a
// /proc-less host.
func scanLitevirtKeepaliveds(configDir string) []litevirtKeepalived {
	var out []litevirtKeepalived
	matches, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, cf := range matches {
		data, err := os.ReadFile(cf)
		if err != nil {
			continue // process exited between glob and read
		}
		isKeepalived, cfgPath := false, ""
		for _, f := range strings.Split(string(data), "\x00") {
			if f == "" {
				continue
			}
			if filepath.Base(f) == "keepalived" {
				isKeepalived = true
			}
			if strings.HasPrefix(f, configDir+string(os.PathSeparator)) && strings.HasSuffix(f, "-keepalived.conf") {
				cfgPath = f
			}
		}
		if !isKeepalived || cfgPath == "" {
			continue
		}
		if pid, err := strconv.Atoi(filepath.Base(filepath.Dir(cf))); err == nil && pid > 0 {
			out = append(out, litevirtKeepalived{pid: pid, config: cfgPath})
		}
	}
	return out
}

// litevirtKeepalivedPids returns just the pids from scanLitevirtKeepaliveds.
func litevirtKeepalivedPids(configDir string) []int {
	ks := scanLitevirtKeepaliveds(configDir)
	pids := make([]int, 0, len(ks))
	for _, k := range ks {
		pids = append(pids, k.pid)
	}
	return pids
}

// VIPAssigned reports whether vip is currently assigned on this host's KERNEL — the
// authoritative "is this host answering the VIP" check (not a keepalived pid signal).
// When iface is empty it scans ALL interfaces (the robust default: a caller can't
// reliably guess the holder's interface, and the holder may have moved it). Returns
// (found, err); err on an `ip` failure so the caller FAILS CLOSED — an UNKNOWN state
// must never read as "released" in the majority-reclaim proof.
func (m *Manager) VIPAssigned(vip, iface string) (bool, error) {
	if vip == "" {
		return false, nil
	}
	args := []string{"-o", "addr", "show"}
	if iface != "" {
		args = append(args, "dev", iface)
	}
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("ip addr show: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return addrShowHasVIP(string(out), vip), nil
}

// ClaimsVIP reports whether THIS host could hold OR become master of vip — the by-VIP
// ownership signal Phase 2 needs. It is true if this host renders a keepalived config
// whose virtual_ipaddress includes vip (a VRRP participant: the MASTER holds the address,
// a BACKUP holds none but can take over — a kernel-address check alone would miss the
// backup), or the vip address is assigned on this host's kernel (a stale address left by
// a keepalived that died without a clean release).
//
// It FAILS CLOSED (returns an error) whenever participation can't be determined, so the
// caller never reads an indeterminate state as "not claiming":
//   - a keepalived config that can't be read or parsed (its VIP is unknown → might be vip);
//   - a LITEVIRT-OWNED keepalived PROCESS with no readable config (a config-less orphan:
//     its config was deleted but it still runs and can become master — exactly the case
//     rendersVIP-by-file would miss);
//   - the kernel-address check itself failing.
func (m *Manager) ClaimsVIP(vip string) (bool, error) {
	want := bareIP(vip)

	// 1. Rendered configs. A config we can't read/parse has an unknown VIP → fail closed.
	parsed := map[string]bool{}
	confs, _ := filepath.Glob(filepath.Join(m.configDir, "*-keepalived.conf"))
	for _, cf := range confs {
		data, err := os.ReadFile(cf)
		if err != nil {
			return false, fmt.Errorf("keepalived config %s unreadable — VIP participation indeterminate: %w", filepath.Base(cf), err)
		}
		cvip, _, _, ok := parseKeepalivedVIP(string(data))
		if !ok {
			return false, fmt.Errorf("keepalived config %s unparseable — VIP participation indeterminate", filepath.Base(cf))
		}
		if want != "" && cvip == want {
			return true, nil
		}
		parsed[cf] = true
	}

	// 2. A litevirt-owned keepalived PROCESS whose config file we didn't parse (deleted →
	//    config-less orphan) could render this VIP. We can't rule it out → fail closed.
	for _, k := range scanLitevirtKeepaliveds(m.configDir) {
		if !parsed[k.config] {
			return false, fmt.Errorf("litevirt keepalived pid %d has no readable config (config-less orphan) — VIP participation indeterminate", k.pid)
		}
	}

	// 3. Stale kernel address with no config (fails closed on an `ip` error).
	return m.VIPAssigned(vip, "")
}

// bareIP strips a trailing /prefix, returning just the address.
func bareIP(vip string) string {
	if i := strings.LastIndex(vip, "/"); i > 0 {
		return vip[:i]
	}
	return vip
}

// addrShowHasVIP reports whether `ip -o addr show` output lists vip as an assigned
// address. Both sides are matched as BARE IPs (prefix stripped): callers pass the VIP
// as either a bare IP or a CIDR (lbSpec.Vip is usually "10.0.100.50/24"), and a CIDR
// query must still match the kernel's bare address — else a still-assigned holder
// would read as released.
func addrShowHasVIP(out, vip string) bool {
	vip = bareIP(vip)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if (f == "inet" || f == "inet6") && i+1 < len(fields) {
				addr := fields[i+1]
				if slash := strings.LastIndex(addr, "/"); slash > 0 {
					addr = addr[:slash]
				}
				if addr == vip {
					return true
				}
			}
		}
	}
	return false
}

// parseKeepalivedVIP extracts the exact tuple keepalived is configured to assign from
// a rendered keepalived.conf: the vrrp_instance `interface <iface>` directive and the
// `<ip>/<prefix>` inside its virtual_ipaddress block. ok=false if either is missing.
//
// Single-VIP assumption: this returns the LAST address parsed from the (single)
// virtual_ipaddress block, which is exact only because RenderKeepalived emits exactly
// one address per LB (see the INVARIANT there). If the renderer is ever changed to emit
// multiple VIPs per instance, this must be reworked to return all of them and callers
// (Demote/DemoteAll) must remove every one.
func parseKeepalivedVIP(config string) (vip string, prefix int, iface string, ok bool) {
	sc := bufio.NewScanner(strings.NewReader(config))
	inVIP := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "interface "):
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface "))
		case strings.HasPrefix(line, "virtual_ipaddress"):
			inVIP = true
		case inVIP && strings.HasPrefix(line, "}"):
			inVIP = false
		case inVIP && strings.Contains(line, "/"):
			ipCidr := strings.Fields(line)[0] // "<ip>/<prefix>" (ignore any trailing tokens)
			if slash := strings.LastIndex(ipCidr, "/"); slash > 0 {
				if p, perr := strconv.Atoi(ipCidr[slash+1:]); perr == nil {
					vip, prefix = ipCidr[:slash], p
				}
			}
		}
	}
	return vip, prefix, iface, vip != "" && iface != ""
}

// Demote drops this host's VIP for LB `name` when the host has lost quorum (Phase 2
// minority self-demotion). Order is load-bearing:
//
//  1. stop keepalived and CONFIRM it is gone — a live or stuck keepalived re-adds
//     the VIP the instant we delete it, so removing the address before keepalived is
//     confirmed dead is pointless;
//  2. only THEN remove the VIP address directly (it is otherwise keepalived-managed,
//     with no `ip addr` control path), using the exact <ip>/<prefix> dev <iface>
//     tuple from the stored LB config.
//
// Returns an error if keepalived can't be confirmed stopped within
// keepalivedStopTimeout — the caller MUST then self-fence: the VIP may still be
// assigned and a partitioned host can't tell the majority it failed, so a hung
// keepalived would otherwise overlap with a majority reclaim undetectably.
// "Address already absent" counts as success (we want the VIP GONE).
func (m *Manager) Demote(cfg Config, keepalivedStopTimeout time.Duration) error {
	lk := lbLock(cfg.Name)
	lk.Lock()
	defer lk.Unlock()

	if err := m.stopKeepalivedConfirmed(cfg.Name, keepalivedStopTimeout); err != nil {
		return fmt.Errorf("demote %s: %w", cfg.Name, err)
	}
	if err := removeVIPAddr(cfg.VIP, cfg.VIPPrefix, cfg.Interface); err != nil {
		return fmt.Errorf("demote %s: remove VIP: %w", cfg.Name, err)
	}
	slog.Warn("LB demoted (quorum lost) — keepalived stopped and VIP removed",
		"lb", cfg.Name, "vip", cfg.VIP, "iface", cfg.Interface)
	return nil
}

// stopKeepalivedConfirmed SIGTERMs keepalived for `name` (tracked parent + children,
// and any config-bound sibling the pidfile lost), waits up to `timeout` for a clean
// exit, then SIGKILLs the survivors, and finally VERIFIES none remain. It returns an
// error if any keepalived bound to this LB's config is still alive — the signal to
// self-fence.
func (m *Manager) stopKeepalivedConfirmed(name string, timeout time.Duration) error {
	keepalivedPid := filepath.Join(m.runDir, name+"-keepalived.pid")
	cfgPath := filepath.Join(m.configDir, name+"-keepalived.conf")
	trackedPids := append([]string{keepalivedPid}, keepalivedChildPidFiles(keepalivedPid)...)

	signalAll := func(sig syscall.Signal) {
		for _, pf := range trackedPids {
			if pid := readPid(pf); pid > 0 && processAlive(pid) {
				syscall.Kill(pid, sig)
			}
		}
		for _, pid := range keepalivedPidsForConfig(cfgPath) {
			syscall.Kill(pid, sig)
		}
	}

	stopped := func() bool {
		return !pidAlive(keepalivedPid) && len(keepalivedPidsForConfig(cfgPath)) == 0
	}

	signalAll(syscall.SIGTERM)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if stopped() {
			removeKeepalivedPidFiles(keepalivedPid)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Ceiling exceeded — SIGKILL and re-verify (briefly, to let the kernel reap).
	signalAll(syscall.SIGKILL)
	for i := 0; i < 20; i++ {
		if stopped() {
			removeKeepalivedPidFiles(keepalivedPid)
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("keepalived not confirmed stopped for LB %q within %s (survivors: %v)",
		name, timeout, keepalivedPidsForConfig(cfgPath))
}

// keepalivedPidsForConfig returns every keepalived pid whose cmdline binds cfgPath
// (scanning /proc; mirrors killProcByConfig's matcher). Empty on a /proc-less host.
func keepalivedPidsForConfig(cfgPath string) []int {
	var pids []int
	matches, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, cf := range matches {
		data, err := os.ReadFile(cf)
		if err != nil {
			continue
		}
		if !cmdlineMatchesBinaryConfig(string(data), "keepalived", cfgPath) {
			continue
		}
		if pid, err := strconv.Atoi(filepath.Base(filepath.Dir(cf))); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

func removeKeepalivedPidFiles(keepalivedPid string) {
	os.Remove(keepalivedPid)
	for _, cf := range keepalivedChildPidFiles(keepalivedPid) {
		os.Remove(cf)
	}
}

// removeVIPAddr deletes vip/prefix from iface. Treating "already absent" as success
// is deliberate: the goal is the VIP GONE, and gone-already satisfies it. Works for
// IPv4 and IPv6 (`ip` infers the family). A zero/absent prefix defaults to a host
// route (/32 or /128) so we never issue `<ip>/0`.
// vipDelAddr formats the <ip>/<prefix> argument for `ip addr del`, defaulting a
// zero/absent prefix to a host route (/32 IPv4, /128 IPv6) so we never issue /0.
func vipDelAddr(vip string, prefix int) string {
	if prefix <= 0 {
		if strings.Contains(vip, ":") {
			prefix = 128
		} else {
			prefix = 32
		}
	}
	return fmt.Sprintf("%s/%d", vip, prefix)
}

func removeVIPAddr(vip string, prefix int, iface string) error {
	if vip == "" || iface == "" {
		return nil
	}
	addr := vipDelAddr(vip, prefix)
	out, err := exec.Command("ip", "addr", "del", addr, "dev", iface).CombinedOutput()
	if err == nil {
		return nil
	}
	s := strings.ToLower(string(out))
	// EADDRNOTAVAIL / not-configured / missing device → the address isn't assigned
	// here, which is exactly the state we wanted.
	if strings.Contains(s, "cannot assign requested address") ||
		strings.Contains(s, "does not exist") ||
		strings.Contains(s, "not found") {
		return nil
	}
	return fmt.Errorf("ip addr del %s dev %s: %v: %s", addr, iface, err, strings.TrimSpace(string(out)))
}
