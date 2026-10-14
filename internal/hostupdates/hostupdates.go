// Package hostupdates reports a host's pending OS package updates. It is
// read-only: it asks the package manager what its CACHED indexes say is
// upgradable and installs nothing. litevirt does not orchestrate OS patching;
// this only tells an operator a host is behind, and whether any of what is
// pending is a security update.
//
// Supported managers: apt (Debian, Ubuntu) and dnf/yum (RHEL family). The
// index is refreshed (apt-get update / dnf makecache) only when the operator
// opts in with host_updates.refresh_index, because a refresh is a network
// call and, on apt, takes the package lock.
package hostupdates

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// Host labels the daemon publishes so every node (and `lv host inspect`) can
// read another host's state from the replicated host record. A count, or
// "unknown" when the check itself failed, so a broken check never reads as
// "fully patched".
const (
	LabelPending  = "litevirt.os-updates"
	LabelSecurity = "litevirt.os-security-updates"
)

// Pkg is one upgradable package.
type Pkg struct {
	Name     string
	Version  string
	Security bool
}

// Status is the outcome of one check.
type Status struct {
	// Supported is false when no known package manager is installed (an
	// appliance, a container host image): nothing is reported then.
	Supported bool
	Manager   string // "apt" | "dnf" | "yum"
	Pending   int
	Security  int
	Packages  []Pkg
	// Err is set when the check could not be completed. Pending/Security are
	// then not to be trusted (or are from a cached index when only a refresh
	// failed; see Check).
	Err string
}

// Runner runs a command and returns its stdout.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExitCodeError is a non-zero exit status; dnf check-update uses 100 for
// "updates available".
type ExitCodeError int

func (e ExitCodeError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func exitCode(err error) (int, bool) {
	var ce ExitCodeError
	if errors.As(err, &ce) {
		return int(ce), true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	return 0, false
}

// Options configures Check. The zero value runs the real package managers.
type Options struct {
	Run Runner
	// Have reports whether a binary is installed; nil uses PATH.
	Have func(bin string) bool
	// RefreshIndex refreshes the package index before reading it.
	RefreshIndex bool
}

// ExecRun is the production Runner: LC_ALL=C so the output parses, stdout only.
func ExecRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
			return out, ExitCodeError(ee.ExitCode())
		}
	}
	return out, err
}

func havePath(bin string) bool { _, err := exec.LookPath(bin); return err == nil }

// Check reads the pending updates of this host.
func Check(ctx context.Context, o Options) Status {
	run := o.Run
	if run == nil {
		run = ExecRun
	}
	have := o.Have
	if have == nil {
		have = havePath
	}
	switch {
	case have("apt") && have("apt-get"):
		return checkApt(ctx, run, o.RefreshIndex)
	case have("dnf"):
		return checkDnf(ctx, run, "dnf", o.RefreshIndex)
	case have("yum"):
		return checkDnf(ctx, run, "yum", o.RefreshIndex)
	}
	return Status{}
}

func checkApt(ctx context.Context, run Runner, refresh bool) Status {
	st := Status{Supported: true, Manager: "apt"}
	if refresh {
		if _, err := run(ctx, "apt-get", "update", "-q"); err != nil {
			st.Err = "index refresh failed (reporting the cached index): " + err.Error()
		}
	}
	out, err := run(ctx, "apt", "list", "--upgradable")
	if err != nil {
		st.Err = "apt list --upgradable: " + err.Error()
		st.Pending, st.Security = 0, 0
		return st
	}
	st.Packages = ParseAptUpgradable(string(out))
	for _, p := range st.Packages {
		st.Pending++
		if p.Security {
			st.Security++
		}
	}
	return st
}

// ParseAptUpgradable parses `apt list --upgradable`. A package is a security
// update when any suite it is offered from is a security suite
// ("jammy-security", "bookworm-security", "stable-security").
func ParseAptUpgradable(out string) []Pkg {
	var pkgs []Pkg
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.Contains(line, "[upgradable from") {
			continue // "Listing...", warnings
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name, suites, ok := strings.Cut(f[0], "/")
		if !ok || name == "" {
			continue
		}
		p := Pkg{Name: name, Version: f[1]}
		for _, s := range strings.Split(suites, ",") {
			if strings.Contains(s, "security") {
				p.Security = true
			}
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func checkDnf(ctx context.Context, run Runner, bin string, refresh bool) Status {
	st := Status{Supported: true, Manager: bin}
	if refresh {
		if _, err := run(ctx, bin, "-q", "makecache"); err != nil {
			st.Err = "index refresh failed (reporting the cached index): " + err.Error()
		}
	}
	// --cacheonly: never reach the network on a read-only check.
	out, err := run(ctx, bin, "-q", "--cacheonly", "check-update")
	if err != nil {
		if code, ok := exitCode(err); !ok || code != 100 {
			st.Err = bin + " check-update: " + err.Error()
			return st
		}
	}
	names := ParseDnfCheckUpdate(string(out))
	secOut, serr := run(ctx, bin, "-q", "--cacheonly", "updateinfo", "list", "--security")
	var sec map[string]bool
	secUnknown := false
	if serr == nil {
		var readable bool
		if sec, readable = ParseDnfSecurityChecked(string(secOut)); !readable {
			secUnknown = true // a partial count would read as "only these"
			if st.Err == "" {
				st.Err = "security advisories listed in a form this build cannot read"
			}
		}
	} else if st.Err == "" {
		// Security metadata is optional (yum without the plugin): the total
		// stands, the security count is unknown rather than zero.
		st.Err = "security advisories unavailable: " + serr.Error()
	}
	for _, n := range names {
		st.Packages = append(st.Packages, Pkg{Name: n, Security: sec[n] && !secUnknown})
		st.Pending++
		if sec[n] && !secUnknown {
			st.Security++
		}
	}
	return st
}

// ParseDnfCheckUpdate returns the package names `dnf check-update` lists as
// upgradable. Sections after "Obsoleting Packages" are not upgrades.
func ParseDnfCheckUpdate(out string) []string {
	var names []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Obsoleting") || strings.HasPrefix(line, "Security:") {
			break
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		i := strings.LastIndex(f[0], ".")
		if i <= 0 {
			continue
		}
		n := f[0][:i]
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return names
}

// ParseDnfSecurity returns the set of package names named by
// `dnf updateinfo list --security` (ParseDnfSecurityChecked).
func ParseDnfSecurity(out string) map[string]bool {
	set, _ := ParseDnfSecurityChecked(out)
	return set
}

// ParseDnfSecurityChecked parses `dnf updateinfo list --security` in both
// layouts:
//
//	dnf4: ADVISORY  Severity/Sec.  name-ver-rel.arch
//	dnf5: ADVISORY  security  Severity  name-[epoch:]ver-rel.arch  issued-date issued-time
//
// ok is false when the output lists advisories this parser could not read: the
// security count is then unknown, never zero.
func ParseDnfSecurityChecked(out string) (set map[string]bool, ok bool) {
	set = map[string]bool{}
	unread := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || !advisoryID(f[0]) {
			continue // headers, "Last metadata expiration check", blank lines
		}
		var nevra string
		switch {
		case strings.EqualFold(f[1], "security") && len(f) >= 4: // dnf5
			nevra = f[3]
		case strings.Contains(f[1], "Sec"): // dnf4
			nevra = f[len(f)-1]
		}
		if n := nevraName(nevra); n != "" {
			set[n] = true
			continue
		}
		unread++
	}
	return set, unread == 0
}

// advisoryID reports whether s looks like an advisory id: letters, then a
// '-', then digits (FEDORA-2024-1a2b3c, RHSA-2024:1234, ALSA-2024:0001).
func advisoryID(s string) bool {
	pre, rest, ok := strings.Cut(s, "-")
	if !ok || pre == "" || rest == "" || strings.ToUpper(pre) != pre {
		return false
	}
	return rest[0] >= '0' && rest[0] <= '9'
}

// nevraName strips ".arch", "-release" and "-version" off name-version-release.arch.
func nevraName(nevra string) string {
	if i := strings.LastIndex(nevra, "."); i > 0 {
		nevra = nevra[:i]
	}
	for k := 0; k < 2; k++ {
		i := strings.LastIndex(nevra, "-")
		if i <= 0 {
			return ""
		}
		nevra = nevra[:i]
	}
	return nevra
}

// Labels renders the status as the host labels the daemon publishes. A failed
// check publishes "unknown" for both, never a count.
func (s Status) Labels() map[string]string {
	if s.Err != "" && s.Pending == 0 && len(s.Packages) == 0 {
		return map[string]string{LabelPending: "unknown", LabelSecurity: "unknown"}
	}
	sec := strconv.Itoa(s.Security)
	if s.Err != "" && s.Manager != "apt" && s.Security == 0 {
		sec = "unknown" // advisories unreadable: total stands, security count does not
	}
	return map[string]string{LabelPending: strconv.Itoa(s.Pending), LabelSecurity: sec}
}

// FromLabels reads the counts back off a host record's labels; ok is false
// when the host has not published them or the last check failed.
func FromLabels(labels map[string]string) (pending, security int, ok bool) {
	p, err1 := strconv.Atoi(labels[LabelPending])
	s, err2 := strconv.Atoi(labels[LabelSecurity])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return p, s, true
}

// Names returns the upgradable package names, sorted, security ones first.
func (s Status) Names(limit int) []string {
	var sec, other []string
	for _, p := range s.Packages {
		if p.Security {
			sec = append(sec, p.Name)
		} else {
			other = append(other, p.Name)
		}
	}
	sort.Strings(sec)
	sort.Strings(other)
	all := append(sec, other...)
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all
}
