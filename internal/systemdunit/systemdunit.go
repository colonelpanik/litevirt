// Package systemdunit holds the canonical text of the systemd units litevirt
// installs, so the installer and the upgrade path cannot disagree about them.
//
// They used to be two independent string constants — one in internal/cli's
// embedded setup script, one in internal/grpcapi's upgrade path — with a comment
// asking that they "drift together". They drifted. The installer's copy kept
// StartLimitBurst=3/600s and, worse, a rollback unit with NO sentinel gate, so on
// any node initialized by `lv host init` and never upgraded, three restarts inside
// ten minutes would downgrade a perfectly healthy binary and burn the only .old.
// The upgrade path rewrites the unit, but it only runs during an upgrade, so
// nothing ever repaired a freshly-installed node.
//
// This package is a stdlib-only leaf, like internal/upgrade, so both callers can
// import it without internal/cli gaining an edge to internal/grpcapi.
package systemdunit

// Paths the units are installed to.
const (
	MainPath        = "/etc/systemd/system/litevirt.service"
	RollbackPath    = "/etc/systemd/system/litevirt-rollback.service"
	NeedrestartPath = "/etc/needrestart/conf.d/99-litevirt.conf"
)

// UninstallExitCode is the status the daemon exits with once an uninstall has
// removed the unit files and the binary. RestartPreventExitStatus below pins it,
// because under Restart=always systemd would otherwise restart the unit — which
// by then has no ExecStart left to run.
const UninstallExitCode = 10

// Main is the litevirt daemon unit.
//
// Restart=always, not on-failure. systemd.service(5) counts termination by
// SIGHUP, SIGINT, SIGTERM or SIGPIPE as a CLEAN exit, and on-failure restarts on
// none of them — so a SIGHUP from needrestart or unattended-upgrades left the node
// down indefinitely with the unit reporting Result=success and NRestarts=0
// (kvm001, 2026-07-24, ~3h; libvirtd went down with it and both VMs stopped). The
// daemon also now refuses to die on SIGHUP/SIGPIPE, so this is the second of two
// independent guards, not the only one.
//
// KillMode=process keeps systemd out of the cgroup subtree where a future
// KillMode=control-group accident could reach into QEMU children. Delegate=no is
// deliberate for the same reason.
//
// StartLimitBurst is generous because a burst of EXTERNAL restarts (a package
// manager's needrestart during an apt run) must not trip the start limit — that
// fires OnFailure=litevirt-rollback and would downgrade a healthy binary.
// Genuine upgrade-time crash loops are caught by the sentinel gate in Rollback
// plus the in-process health watchdog.
const Main = `[Unit]
Description=litevirt daemon
After=network-online.target libvirtd.service
Wants=network-online.target
Wants=libvirtd.service
# A burst of external restarts (e.g. a package manager's needrestart during an apt
# run) must NOT trip the start limit — that would fire OnFailure=litevirt-rollback
# and downgrade a HEALTHY binary. Generous window; genuine upgrade-time crash loops
# are caught by the sentinel-gated rollback below + the in-process health watchdog.
StartLimitBurst=10
StartLimitIntervalSec=300
OnFailure=litevirt-rollback.service

[Service]
Type=simple
ExecStart=/usr/local/bin/litevirt daemon
KillMode=process
Delegate=no
# NOT on-failure: systemd treats death by SIGHUP/SIGINT/SIGTERM/SIGPIPE as a clean
# exit and would never restart, leaving the node down (kvm001, 2026-07-24).
Restart=always
RestartSec=5
# Uninstall removes the unit and the binary, then exits with this status. Without
# this, Restart=always would try to restart a unit whose ExecStart is gone.
RestartPreventExitStatus=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

// Rollback is the companion oneshot systemd fires when the main unit enters a
// failed state (StartLimitBurst exceeded — i.e. a new binary panicking on every
// start). It restores .old over the current binary ONLY while an upgrade is
// actually in progress, which the .upgrade-pending sentinel signals.
//
// The sentinel gate is essential and is what the installer's copy was missing.
// Without it ANY failed state — including an external restart storm against a
// perfectly healthy binary — downgrades that binary and can burn the only .old,
// taking the node down (the 2026-07-15 docker004 outage). This mirrors the
// in-process health watchdog, which also acts only while the sentinel is present.
//
// The journal-tagged log lines are intentionally loud: an operator should be able
// to see in `journalctl -u litevirt-rollback` that something rolled back, and
// equally that something deliberately did not.
const Rollback = `[Unit]
Description=litevirt daemon rollback (auto-restore previous binary on a failed upgrade)

[Service]
Type=oneshot
ExecStart=/bin/sh -c '\
  if [ ! -f /usr/local/bin/litevirt.upgrade-pending ]; then \
    logger -t litevirt-rollback "litevirt entered a failed state but no upgrade is in progress (no sentinel) — NOT rolling back the binary; leaving it for systemd/operator"; \
    exit 0; \
  fi; \
  if [ -f /usr/local/bin/litevirt.old ]; then \
    logger -t litevirt-rollback "RESTORING previous litevirt binary after a failed upgrade"; \
    mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt; \
    systemctl reset-failed litevirt.service; \
    systemctl start litevirt.service; \
  else \
    logger -t litevirt-rollback "no .old binary to roll back to; leaving litevirt in failed state"; \
    exit 1; \
  fi'
`

// Needrestart tells needrestart (run by unattended-upgrades after a library
// upgrade) never to auto-restart litevirt. A stateful orchestrator must not be
// bounced mid-operation, and a restart storm can trip the start limit.
const Needrestart = `# Managed by litevirt. Never let needrestart auto-restart the orchestrator daemon on
# a library upgrade — a mid-operation restart is disruptive and a restart storm can
# trip systemd's start limit + the rollback unit.
push @{$nrconf{blacklist_rc}}, qr(^litevirt\.service$);
`
