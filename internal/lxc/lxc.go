// Package lxc is litevirt's LXC + OCI container runtime. It mirrors
// the VM lifecycle surface (Create / Start / Stop / Delete / Console /
// Exec / List) so a single gRPC service plus shared schedulers can
// host both kinds of workload.
//
// We shell out to the system's lxc-* binaries rather than vendor
// go-lxc; this keeps the litevirtd binary CGO-free and matches how
// Proxmox's pve-container is implemented. The binaries are part of
// the host bootstrap (`apt install lxc` or equivalent).
//
// split:
//
//	1.4.A (this file): Runtime interface + production Runner +
//	                   Container struct + create/start/stop/delete.
//	1.4.B: OCI image pull → LXC rootfs (umoci shell-out).
//	1.4.C: Networking — veth attach into existing bridges/VXLANs.
//	1.4.D: Compose workloads schema + CLI + UI + docs.
package lxc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
)

// ErrStatsUnavailable is returned by Stats when live cgroup usage can't be read
// (e.g. a cgroup-v1-only host, or the container has no cgroup yet). Callers (the
// metrics collector) skip the usage sample via errors.Is rather than logging.
var ErrStatsUnavailable = errors.New("container cgroup stats unavailable")

// ErrContainerNotFound is returned (wrapped) by Delete when lxc-destroy reports
// the container does not exist. The fail-closed DeleteContainer handler tests it
// with errors.Is to treat deletion as idempotent (a runtime that's already gone
// is success) — without string-matching command output up in the gRPC layer.
var ErrContainerNotFound = errors.New("container not found")

// ContainerStats is a point-in-time cgroup-v2 usage sample for a container.
type ContainerStats struct {
	CPUUsageUsec uint64 // cumulative CPU time (cpu.stat usage_usec)
	MemBytes     int64  // current memory usage (memory.current)
}

// State is the libvirt-style lifecycle state, mirrored for parity with
// the existing VM domain states so the UI can render both with the
// same components.
type State string

const (
	StateUnknown  State = ""
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateStopping State = "stopping"
	StateError    State = "error"
)

// Container describes one LXC container as known to litevirt.
type Container struct {
	Name      string
	State     State
	RootFS    string            // path to the container's rootfs (file or dir)
	CPULimit  int               // shares; 0 = unlimited
	MemoryMiB int               // hard cap; 0 = unlimited
	Network   []NetworkAttach   // veth attachments, each into an existing bridge
	Labels    map[string]string // free-form metadata used by compose / UI
	Image     string            // origin image name (oci://… or alpine:3.19)
}

// NetworkAttach describes one container NIC.
type NetworkAttach struct {
	Name   string // unique within a container (eth0, eth1, …)
	Bridge string // host bridge to attach to (br0, vxlan-prod, …)
	IP     string // optional static IP; empty = DHCP / RA
	MAC    string // optional fixed MAC; empty = OS-generated
	Veth   string // optional deterministic host-side veth name (lxc.net.N.veth.pair); ≤15 bytes
}

// ExecResult captures the outcome of lxc-attach.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runtime is the shell-out boundary. Production wires LxcRunner; tests
// inject a fake.
type Runtime interface {
	// Create allocates a new container (rootfs + config) but does not
	// start it. The caller is responsible for populating the rootfs;
	// CreateOpts.Template can be "download" to use lxc-templates' own
	// pull mechanism, or a path to an already-extracted rootfs.
	Create(ctx context.Context, opts CreateOpts) (*Container, error)
	// Start brings a stopped container up.
	Start(ctx context.Context, name string) error
	// Stop performs a clean shutdown (SIGTERM with a kill timeout).
	Stop(ctx context.Context, name string, timeoutSec int) error
	// Delete removes a stopped container and its rootfs.
	Delete(ctx context.Context, name string) error
	// Exec runs a command inside a running container.
	Exec(ctx context.Context, name string, argv []string) (ExecResult, error)
	// State queries lxc-info for the current state.
	State(ctx context.Context, name string) (State, error)
	// IP returns the container's primary IPv4 address (lxc-info -iH), or ""
	// if it has none yet. Used to discover a running container's address for
	// load balancer backends.
	IP(ctx context.Context, name string) (string, error)
	// List enumerates every container known to LXC on this host.
	List(ctx context.Context) ([]string, error)
	// Freeze suspends every process in a running container (lxc-freeze) so its
	// rootfs can be read consistently (backup/snapshot quiesce). Pair with
	// Unfreeze; a no-op-ish error on an already-frozen/stopped container is fine.
	Freeze(ctx context.Context, name string) error
	// Unfreeze resumes a frozen container (lxc-unfreeze). Always call it (defer)
	// after Freeze so a failed backup never leaves the container suspended.
	Unfreeze(ctx context.Context, name string) error
	// RootFSPath returns the host filesystem path of the container's root
	// (lxc.rootfs.path), the directory tree backup/snapshot/clone operate on.
	RootFSPath(name string) (string, error)
	// ExportContainer writes a tar stream of the container's on-disk directory
	// (its config + rootfs) to w. Quiesce with Freeze first for a consistent
	// read. The stream is self-contained: ImportContainer rebuilds the container
	// from it alone, even on a different host.
	ExportContainer(ctx context.Context, name string, w io.Writer) error
	// ImportContainer rebuilds a container's on-disk directory from a tar stream
	// produced by ExportContainer, then rewrites the config's rootfs path so it
	// is valid at this host's lxcpath. The container is left stopped.
	ImportContainer(ctx context.Context, name string, r io.Reader) error
	// ContainerExists reports whether the on-disk container dir exists (independent of
	// any DB row) — used by the crash-idempotent restore resume path.
	ContainerExists(name string) (bool, error)
	// RevertContainer replaces an EXISTING container's on-disk dir from a
	// snapshot tar (in-place snapshot revert — clobbers). The container must be
	// stopped first.
	RevertContainer(ctx context.Context, name string, r io.Reader) error
	// CloneContainer makes a full copy of src's on-disk dir as dst and gives it
	// a fresh identity (new hostname/uts.name, regenerated NIC MAC(s), reset
	// machine-id). The src should be stopped/frozen for a consistent copy.
	CloneContainer(ctx context.Context, src, dst string) error
	// Stats returns a live cgroup-v2 usage sample (host-local, no RPC). Returns
	// ErrStatsUnavailable when usage can't be read (cgroup-v1 host, no cgroup yet).
	Stats(ctx context.Context, name string) (ContainerStats, error)
}

// CreateOpts collects parameters for Runtime.Create.
type CreateOpts struct {
	Name string
	// Template selects how the rootfs is populated:
	//   - "download": lxc-create's download template (uses Distro/Release/Arch).
	//   - a rootfs path ("rootfs:<path>", an absolute path, or "./relative"):
	//     an already-extracted rootfs (e.g. from `lv ct pull` / umoci). We
	//     synthesise an LXC config that points at it — lxc-create has no way to
	//     adopt a pre-existing rootfs. A directory holding an OCI/umoci bundle
	//     (a "rootfs/" subdir) is descended into automatically.
	//   - any other bare name (e.g. "busybox"): passed to `lxc-create -t`.
	Template string
	// Distro / Release / Arch are forwarded to the lxc-download template
	// when Template == "download". Ignored otherwise.
	Distro  string
	Release string
	Arch    string
	// CPULimit / MemoryMiB end up as cgroup constraints.
	CPULimit  int
	MemoryMiB int
	// Network is applied as a series of `lxc.net.N.*` config keys.
	Network []NetworkAttach
	// Labels are persisted into a litevirt-specific config block (we
	// own them — LXC ignores).
	Labels map[string]string
}

// Validate checks cross-field invariants before any shell-out.
func (o *CreateOpts) Validate() error {
	if o == nil {
		return errors.New("nil CreateOpts")
	}
	if o.Name == "" {
		return errors.New("container name required")
	}
	if strings.ContainsAny(o.Name, "/ \t\n") {
		return fmt.Errorf("invalid container name %q: must not contain whitespace or '/'", o.Name)
	}
	if o.Template == "" {
		return errors.New("template required (\"download\" or rootfs path)")
	}
	if o.Template == "download" && o.Distro == "" {
		return errors.New("download template requires distro (e.g. alpine, ubuntu)")
	}
	for i, n := range o.Network {
		if n.Bridge == "" {
			return fmt.Errorf("network[%d]: bridge required", i)
		}
	}
	return nil
}

// LxcRunner is the production Runtime backed by lxc-* CLI tools.
type LxcRunner struct {
	// Lxcpath optionally overrides /var/lib/lxc — set per-host so test
	// rigs and fenced containers can coexist.
	Lxcpath string

	// HostName is this daemon's cluster host name, mixed into a clone's
	// deterministic NIC MAC (corrosion.ContainerMAC) so the on-disk config matches
	// the interface row grpcapi records on the SAME host. Empty in bare/test rigs.
	HostName string

	// cgPathMu guards cgPathCache, which memoizes each running container's
	// resolved cgroup-v2 directory so Stats doesn't shell out to lxc-info on
	// every Prometheus scrape (which may run concurrently). Invalidated on a
	// stat failure (container restarted → new cgroup path).
	cgPathMu    sync.Mutex
	cgPathCache map[string]string
}

// NewLxcRunner returns a Runtime configured to talk to /var/lib/lxc.
func NewLxcRunner() *LxcRunner { return &LxcRunner{} }

// withLxcpath prepends -P <path> if a non-default lxcpath is set —
// every lxc-* binary accepts the same flag.
func (r *LxcRunner) withLxcpath(args []string) []string {
	if r.Lxcpath == "" {
		return args
	}
	return append([]string{"-P", r.Lxcpath}, args...)
}

func (r *LxcRunner) run(ctx context.Context, bin string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, r.withLxcpath(args)...)
	stderr := strings.Builder{}
	cmd.Stderr = stringWriter{&stderr}
	out, err := cmd.Output()
	return out, []byte(stderr.String()), err
}

// defaultLxcpath is LXC's standard container store, used when Lxcpath is unset.
const defaultLxcpath = "/var/lib/lxc"

func (r *LxcRunner) lxcpath() string {
	if r.Lxcpath != "" {
		return r.Lxcpath
	}
	return defaultLxcpath
}

// Create implements Runtime.Create. See CreateOpts.Template for the modes.
//
// For a rootfs path we write the container config directly instead of shelling
// out: lxc-create's -t flag expects a template *script*, so handing it a rootfs
// directory just fails ("exit status 1"). This is the path used by `lv ct pull`
// → `lv ct create` for OCI images.
func (r *LxcRunner) Create(ctx context.Context, opts CreateOpts) (*Container, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if opts.Template != "download" {
		rootfs, ok, err := resolveRootfs(opts.Template)
		if err != nil {
			return nil, err
		}
		if ok {
			return r.createFromRootfs(opts, rootfs)
		}
	}
	args := []string{"-n", opts.Name, "-t", opts.Template}
	if opts.Template == "download" {
		args = append(args, "--",
			"-d", opts.Distro,
			"-r", opts.Release,
			"-a", opts.Arch,
		)
	}
	if _, stderr, err := r.run(ctx, "lxc-create", args...); err != nil {
		return nil, cmdErr("lxc-create", opts.Name, stderr, err)
	}
	// lxc-create wrote the base config (with a default NIC from
	// /etc/lxc/default.conf). Re-render the network from opts (so an explicit
	// --network wins) and apply cgroup limits.
	if err := r.finalizeContainerConfig(opts); err != nil {
		return nil, fmt.Errorf("apply container network/resource config for %q: %w", opts.Name, err)
	}
	return &Container{
		Name:      opts.Name,
		State:     StateStopped,
		CPULimit:  opts.CPULimit,
		MemoryMiB: opts.MemoryMiB,
		Network:   opts.Network,
		Labels:    opts.Labels,
		Image:     opts.Distro + ":" + opts.Release,
	}, nil
}

// createFromRootfs materialises a container around an already-extracted rootfs
// by writing <lxcpath>/<name>/config — no lxc-create. The config mirrors what
// the download template produces (common.conf + apparmor + a veth NIC) so the
// container starts identically.
func (r *LxcRunner) createFromRootfs(opts CreateOpts, rootfs string) (*Container, error) {
	containerDir := filepath.Join(r.lxcpath(), opts.Name)
	configPath := filepath.Join(containerDir, "config")
	if _, err := os.Stat(configPath); err == nil {
		return nil, fmt.Errorf("container %q already exists at %s", opts.Name, containerDir)
	}
	if err := os.MkdirAll(containerDir, 0o755); err != nil {
		return nil, fmt.Errorf("create container dir %s: %w", containerDir, err)
	}
	if err := os.WriteFile(configPath, []byte(renderBaseRootfsConfig(opts.Name, rootfs)), 0o644); err != nil {
		return nil, fmt.Errorf("write lxc config %s: %w", configPath, err)
	}
	// Apply network (explicit --network or the lxcbr0 default) and cgroup limits.
	if err := r.finalizeContainerConfig(opts); err != nil {
		return nil, fmt.Errorf("apply container network/resource config for %q: %w", opts.Name, err)
	}
	return &Container{
		Name:      opts.Name,
		State:     StateStopped,
		RootFS:    rootfs,
		CPULimit:  opts.CPULimit,
		MemoryMiB: opts.MemoryMiB,
		Network:   opts.Network,
		Labels:    opts.Labels,
		// Image is left to the gRPC layer, which records the originating OCI
		// reference (req.Image) — Create can't infer it from a rootfs path.
	}, nil
}

// Start runs lxc-start in daemon mode.
func (r *LxcRunner) Start(ctx context.Context, name string) error {
	if _, stderr, err := r.run(ctx, "lxc-start", "-n", name, "-d"); err != nil {
		return cmdErr("lxc-start", name, stderr, err)
	}
	return nil
}

// Stop runs lxc-stop with the supplied SIGTERM-then-SIGKILL timeout.
func (r *LxcRunner) Stop(ctx context.Context, name string, timeoutSec int) error {
	args := []string{"-n", name}
	if timeoutSec > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", timeoutSec))
	}
	if _, stderr, err := r.run(ctx, "lxc-stop", args...); err != nil {
		return cmdErr("lxc-stop", name, stderr, err)
	}
	return nil
}

// Delete runs lxc-destroy with -f, which stops the container first if it's
// running. Without -f, lxc-destroy refuses a running container ("<name> is
// running"), so `lv ct rm` and `compose down` of a running container would fail.
func (r *LxcRunner) Delete(ctx context.Context, name string) error {
	if _, stderr, err := r.run(ctx, "lxc-destroy", "-f", "-n", name); err != nil {
		// Only classify as not-found when the container is ACTUALLY gone on disk
		// (its config is absent). A broad stderr match would mask a real failure —
		// a corrupt config, a busy mount, a permission/read error — that leaves
		// runtime state behind while the gRPC layer tombstones the row and reports
		// success. Verifying the path keeps that across lxc-* versions/wording.
		cfg := filepath.Join(r.lxcpath(), name, "config")
		if _, statErr := os.Stat(cfg); os.IsNotExist(statErr) {
			return fmt.Errorf("%w: lxc-destroy %s: %s", ErrContainerNotFound, name, strings.TrimSpace(string(stderr)))
		}
		return cmdErr("lxc-destroy", name, stderr, err)
	}
	return nil
}

// execPATH is injected into the attach context so a bare command (e.g. "cat")
// resolves: modern lxc-attach starts with a cleared environment, so without
// this PATH only absolute paths would work.
const execPATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Exec runs argv inside the container via lxc-attach.
func (r *LxcRunner) Exec(ctx context.Context, name string, argv []string) (ExecResult, error) {
	args := append([]string{"-n", name, "--set-var", execPATH, "--"}, argv...)
	out, stderr, err := r.run(ctx, "lxc-attach", args...)
	res := ExecResult{Stdout: out, Stderr: stderr}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}

// State queries lxc-info.
func (r *LxcRunner) State(ctx context.Context, name string) (State, error) {
	out, _, err := r.run(ctx, "lxc-info", "-n", name, "-s", "-H")
	if err != nil {
		return StateUnknown, err
	}
	return parseLxcInfoState(string(out)), nil
}

// IP returns the container's primary IPv4 (lxc-info -iH), or "" if it has
// none assigned yet. `-iH` prints one IP per line (IPv4 and IPv6); we pick the
// first IPv4 that isn't loopback so the result is usable as an LB backend.
func (r *LxcRunner) IP(ctx context.Context, name string) (string, error) {
	out, _, err := r.run(ctx, "lxc-info", "-n", name, "-iH")
	if err != nil {
		return "", err
	}
	return parseLxcInfoIP(string(out)), nil
}

// Stats reads a running container's live cgroup-v2 usage. It discovers the
// cgroup directory from the container's init PID (`lxc-info -n <name> -p -H` →
// /proc/<pid>/cgroup), caches it (mutex-guarded; concurrent scrapes), and reads
// cpu.stat + memory.current. Returns ErrStatsUnavailable on a cgroup-v1 host or
// when the container has no readable cgroup (so the collector skips, no spam).
func (r *LxcRunner) Stats(ctx context.Context, name string) (ContainerStats, error) {
	if err := safename.ValidateContainerName(name); err != nil {
		return ContainerStats{}, err
	}

	dir, err := r.cgroupDir(ctx, name)
	if err != nil {
		return ContainerStats{}, err
	}
	cpu, cerr := readCPUUsageUsec(filepath.Join(dir, "cpu.stat"))
	mem, merr := readUint(filepath.Join(dir, "memory.current"))
	if cerr != nil || merr != nil {
		// Require BOTH reads: a partial read would emit a bogus 0 for the missing
		// metric (a fake counter reset / memory drop). A failure usually means the
		// cached path is stale (container restarted → new cgroup) or gone, so drop
		// it; the next scrape re-discovers. Report unavailable for this round.
		r.cgPathMu.Lock()
		delete(r.cgPathCache, name)
		r.cgPathMu.Unlock()
		return ContainerStats{}, ErrStatsUnavailable
	}
	return ContainerStats{CPUUsageUsec: cpu, MemBytes: int64(mem)}, nil
}

// cgroupDir resolves (and memoizes) the container's cgroup-v2 directory under
// /sys/fs/cgroup. Returns ErrStatsUnavailable on a non-v2 layout.
func (r *LxcRunner) cgroupDir(ctx context.Context, name string) (string, error) {
	r.cgPathMu.Lock()
	if r.cgPathCache != nil {
		if dir, ok := r.cgPathCache[name]; ok {
			r.cgPathMu.Unlock()
			return dir, nil
		}
	}
	r.cgPathMu.Unlock()

	out, _, err := r.run(ctx, "lxc-info", "-n", name, "-p", "-H")
	if err != nil {
		return "", ErrStatsUnavailable
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return "", ErrStatsUnavailable // not running / no init PID
	}
	rel, err := cgroupV2RelPath(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	// rel begins with "/"; filepath.Join keeps it inside /sys/fs/cgroup.
	dir := filepath.Join("/sys/fs/cgroup", filepath.Clean("/"+rel))
	r.cgPathMu.Lock()
	if r.cgPathCache == nil {
		r.cgPathCache = map[string]string{}
	}
	r.cgPathCache[name] = dir
	r.cgPathMu.Unlock()
	return dir, nil
}

// cgroupV2RelPath parses /proc/<pid>/cgroup and returns the unified-hierarchy
// (cgroup-v2) path — the line prefixed "0::". Absent → ErrStatsUnavailable
// (cgroup-v1 host; usage lives in per-controller hierarchies we don't read).
func cgroupV2RelPath(procCgroupFile string) (string, error) {
	data, err := os.ReadFile(procCgroupFile)
	if err != nil {
		return "", ErrStatsUnavailable
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			return strings.TrimSpace(rel), nil
		}
	}
	return "", ErrStatsUnavailable
}

// readCPUUsageUsec extracts the `usage_usec` value from a cgroup-v2 cpu.stat file.
func readCPUUsageUsec(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
			return strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
	}
	return 0, fmt.Errorf("usage_usec not found in %s", path)
}

// readUint reads a single-integer cgroup file (e.g. memory.current). A "max"
// sentinel (unlimited) reads as 0.
func readUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

// parseLxcInfoIP returns the first non-loopback IPv4 from lxc-info -iH output.
func parseLxcInfoIP(s string) string {
	for _, line := range strings.Split(s, "\n") {
		ip := net.ParseIP(strings.TrimSpace(line))
		if ip == nil || ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		return ip.String()
	}
	return ""
}

// List enumerates lxc-ls --running --stopped output.
func (r *LxcRunner) List(ctx context.Context) ([]string, error) {
	out, _, err := r.run(ctx, "lxc-ls", "--quiet")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			names = append(names, t)
		}
	}
	return names, nil
}

// Freeze suspends a running container's processes (lxc-freeze).
func (r *LxcRunner) Freeze(ctx context.Context, name string) error {
	if _, stderr, err := r.run(ctx, "lxc-freeze", "-n", name); err != nil {
		return fmt.Errorf("lxc-freeze %s: %w: %s", name, err, stderr)
	}
	return nil
}

// Unfreeze resumes a frozen container (lxc-unfreeze).
func (r *LxcRunner) Unfreeze(ctx context.Context, name string) error {
	if _, stderr, err := r.run(ctx, "lxc-unfreeze", "-n", name); err != nil {
		return fmt.Errorf("lxc-unfreeze %s: %w: %s", name, err, stderr)
	}
	return nil
}

// RootFSPath returns the host path of the container's root from its config's
// lxc.rootfs.path (stripping the "dir:" prefix the download template writes),
// falling back to the standard <lxcpath>/<name>/rootfs layout.
func (r *LxcRunner) RootFSPath(name string) (string, error) {
	cfg := filepath.Join(r.lxcpath(), name, "config")
	data, err := os.ReadFile(cfg)
	if err != nil {
		return "", fmt.Errorf("read container config %s: %w", cfg, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(t, "lxc.rootfs.path"); ok {
			if _, v, found := strings.Cut(rest, "="); found {
				p := strings.TrimPrefix(strings.TrimSpace(v), "dir:")
				if p != "" {
					return p, nil
				}
			}
		}
	}
	return filepath.Join(r.lxcpath(), name, "rootfs"), nil
}

// ExportContainer tars the container's whole on-disk directory (config + rootfs)
// from <lxcpath> to w. Tarring the directory — not just the rootfs — keeps the
// LXC config (network, limits, mounts) in the archive so a restore is faithful
// without a source cluster. Freeze the container first for a consistent read.
func (r *LxcRunner) ExportContainer(ctx context.Context, name string, w io.Writer) error {
	dir := filepath.Join(r.lxcpath(), name)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("container dir %s: %w", dir, err)
	}
	// -C <lxcpath> <name> stores paths relative to the container name, so a
	// restore can extract under a different lxcpath. --numeric-owner keeps uid/gid
	// stable across hosts that may not share /etc/passwd.
	cmd := exec.CommandContext(ctx, "tar", "-C", r.lxcpath(), "--numeric-owner", "-cf", "-", name)
	stderr := strings.Builder{}
	cmd.Stderr = stringWriter{&stderr}
	cmd.Stdout = w
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tar export %s: %w: %s", name, err, stderr.String())
	}
	return nil
}

// ImportContainer extracts a tar stream from ExportContainer into <lxcpath>,
// recreating <lxcpath>/<name>/{config,rootfs}, then rewrites lxc.rootfs.path to
// this host's layout (the archived config may carry the source host's path).
// It refuses to clobber an existing container directory.
func (r *LxcRunner) ImportContainer(ctx context.Context, name string, src io.Reader) error {
	return r.importContainer(ctx, name, src, false)
}

// RevertContainer replaces an EXISTING container's on-disk dir from a snapshot
// tar (produced by ExportContainer): it removes <lxcpath>/<name> and extracts
// the tar in its place, then rewrites lxc.rootfs.path. Unlike ImportContainer it
// clobbers — it's the in-place snapshot-revert path. The container MUST be
// stopped first (the caller stops it); replacing the rootfs of a running
// container is unsafe.
func (r *LxcRunner) RevertContainer(ctx context.Context, name string, src io.Reader) error {
	return r.importContainer(ctx, name, src, true)
}

// ContainerExists reports whether the on-disk container dir <lxcpath>/<name> exists,
// independent of any DB row or valid config — the primitive the restore resume path uses
// to detect an untracked artifact left by a crash between import and row-write. A stat
// error other than "not exist" is returned so the caller fails closed.
func (r *LxcRunner) ContainerExists(name string) (bool, error) {
	if err := safename.ValidateContainerName(name); err != nil {
		return false, err
	}
	_, err := os.Stat(filepath.Join(r.lxcpath(), name))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// importContainer is the shared extract path. replace=false refuses to clobber
// (fresh import/restore); replace=true renames any existing dir aside first and
// restores it on failure (crash-safe snapshot revert — a corrupt snapshot tar
// can never lose the live container).
func (r *LxcRunner) importContainer(ctx context.Context, name string, src io.Reader, replace bool) error {
	// The name becomes <lxcpath>/<name>; validate it before it composes a path.
	if err := safename.ValidateContainerName(name); err != nil {
		return err
	}
	dir := filepath.Join(r.lxcpath(), name)
	var backup string
	if _, err := os.Stat(dir); err == nil {
		if !replace {
			return fmt.Errorf("container dir %s already exists; refusing to overwrite", dir)
		}
		// Move the current dir aside rather than deleting it, so we can roll
		// back if the extract fails.
		backup = dir + ".revert-old"
		_ = os.RemoveAll(backup) // clear any stale backup from a prior crash
		if err := os.Rename(dir, backup); err != nil {
			return fmt.Errorf("set aside existing dir %s for revert: %w", dir, err)
		}
	}
	// rollback restores the set-aside dir on any failure past this point.
	rollback := func(cause error) error {
		_ = os.RemoveAll(dir)
		if backup != "" {
			_ = os.Rename(backup, dir)
		}
		return cause
	}
	if err := os.MkdirAll(r.lxcpath(), 0o755); err != nil {
		return rollback(fmt.Errorf("ensure lxcpath %s: %w", r.lxcpath(), err))
	}
	// Slip-safe extraction: the archive is untrusted backup-repo data, so we
	// contain every member under <lxcpath>, never write through a symlink, and
	// require the single top-level dir to be the container name (a tampered
	// archive can't clobber a sibling container). Replaces a bare `tar -xf`.
	if err := safename.ExtractRootfsTar(src, r.lxcpath(), name); err != nil {
		return rollback(fmt.Errorf("extract container %s: %w", name, err))
	}
	if err := r.rewriteRootFSPath(name); err != nil {
		return rollback(err)
	}
	if backup != "" {
		_ = os.RemoveAll(backup) // success — drop the old copy
	}
	return nil
}

// CloneContainer makes a full copy of src's on-disk dir as dst (`cp -a`), then
// rewrites the clone's config + rootfs for a fresh identity: new lxc.uts.name,
// a regenerated MAC on every NIC, a rootfs.path pointing at the clone, and a
// reset machine-id + hostname inside the rootfs (so the guest first-boots
// clean). The caller should freeze/stop src first for a consistent copy.
// Container clones are always full copies (no qcow2 backing), so there's no
// linked-clone dependency to track.
func (r *LxcRunner) CloneContainer(ctx context.Context, src, dst string) error {
	srcDir := filepath.Join(r.lxcpath(), src)
	dstDir := filepath.Join(r.lxcpath(), dst)
	if _, err := os.Stat(srcDir); err != nil {
		return fmt.Errorf("source container dir %s: %w", srcDir, err)
	}
	if _, err := os.Stat(dstDir); err == nil {
		return fmt.Errorf("container dir %s already exists; refusing to overwrite", dstDir)
	}
	if err := os.MkdirAll(r.lxcpath(), 0o755); err != nil {
		return fmt.Errorf("ensure lxcpath %s: %w", r.lxcpath(), err)
	}
	// `cp -a` preserves perms/owners/symlinks/timestamps — an archive copy.
	cmd := exec.CommandContext(ctx, "cp", "-a", srcDir, dstDir)
	stderr := strings.Builder{}
	cmd.Stderr = stringWriter{&stderr}
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(dstDir)
		return fmt.Errorf("cp -a %s %s: %w: %s", srcDir, dstDir, err, stderr.String())
	}
	if err := r.cloneFreshIdentity(dst); err != nil {
		_ = os.RemoveAll(dstDir)
		return err
	}
	return nil
}

// cloneFreshIdentity rewrites a freshly-copied clone's config (rootfs.path,
// uts.name, regenerated NIC MACs) and resets in-rootfs identity files so the
// clone doesn't collide with its source.
func (r *LxcRunner) cloneFreshIdentity(name string) error {
	cfg := filepath.Join(r.lxcpath(), name, "config")
	data, err := os.ReadFile(cfg)
	if err != nil {
		return fmt.Errorf("read clone config %s: %w", cfg, err)
	}
	rootfsLine := "lxc.rootfs.path = dir:" + filepath.Join(r.lxcpath(), name, "rootfs")
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "lxc.rootfs.path"):
			lines[i] = rootfsLine
		case strings.HasPrefix(t, "lxc.uts.name"):
			lines[i] = "lxc.uts.name = " + name
		case strings.HasPrefix(t, "lxc.net.") && strings.Contains(t, ".hwaddr"):
			// Fresh, DETERMINISTIC MAC keyed on the clone's name+ordinal, so the
			// on-disk config matches the interface row the clone path records.
			if n, ok := lxcNetOrdinal(t); ok {
				lines[i] = fmt.Sprintf("lxc.net.%d.hwaddr = %s", n, corrosion.ContainerMAC(r.HostName, name, n))
			}
		case strings.HasPrefix(t, "lxc.net.") && strings.Contains(t, ".veth.pair"):
			// Re-key the host veth to the clone's deterministic name so it can't
			// collide with the source's veth on the same host (and matches the DB).
			if n, ok := lxcNetOrdinal(t); ok {
				lines[i] = fmt.Sprintf("lxc.net.%d.veth.pair = %s", n, corrosion.ContainerVethName(name, n))
			}
		case strings.HasPrefix(t, "lxc.net.") && strings.Contains(t, ".ipv4.address"):
			// Drop the source's static IP — a clone is a new workload (dynamic IP).
			lines[i] = ""
		}
	}
	if err := os.WriteFile(cfg, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return fmt.Errorf("rewrite clone config %s: %w", cfg, err)
	}
	// Best-effort in-guest identity reset (so systemd regenerates machine-id and
	// the hostname matches the clone). Missing files are fine.
	rootfs := filepath.Join(r.lxcpath(), name, "rootfs")
	_ = os.WriteFile(filepath.Join(rootfs, "etc", "hostname"), []byte(name+"\n"), 0o644)
	for _, mid := range []string{"etc/machine-id", "var/lib/dbus/machine-id"} {
		p := filepath.Join(rootfs, mid)
		if _, err := os.Stat(p); err == nil {
			_ = os.WriteFile(p, nil, 0o644) // truncate → regenerated on first boot
		}
	}
	return nil
}

// randomMAC returns a fresh locally-administered MAC under the QEMU OUI
// (52:54:00) — mirrors libvirt.GenerateMAC without importing that package.
func randomMAC() string {
	buf := make([]byte, 3)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", buf[0], buf[1], buf[2])
}

// lxcNetOrdinal extracts N from a "lxc.net.<N>.<key>" config line.
func lxcNetOrdinal(line string) (int, bool) {
	rest := strings.TrimPrefix(strings.TrimSpace(line), "lxc.net.")
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest[:dot])
	if err != nil {
		return 0, false
	}
	return n, true
}

// rewriteRootFSPath pins the container config's lxc.rootfs.path to this host's
// <lxcpath>/<name>/rootfs after an import, so a container restored under a
// different lxcpath (or from another host) boots against the real rootfs.
func (r *LxcRunner) rewriteRootFSPath(name string) error {
	cfg := filepath.Join(r.lxcpath(), name, "config")
	data, err := os.ReadFile(cfg)
	if err != nil {
		return fmt.Errorf("read imported config %s: %w", cfg, err)
	}
	want := "lxc.rootfs.path = dir:" + filepath.Join(r.lxcpath(), name, "rootfs")
	lines := strings.Split(string(data), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "lxc.rootfs.path") {
			lines[i] = want
			replaced = true
		}
	}
	if !replaced {
		lines = append([]string{want}, lines...)
	}
	if err := os.WriteFile(cfg, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return fmt.Errorf("rewrite imported config %s: %w", cfg, err)
	}
	return nil
}

// parseLxcInfoState normalises lxc-info -s -H output ("RUNNING\n",
// "STOPPED\n", "FROZEN\n") to our State enum.
func parseLxcInfoState(s string) State {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "running":
		return StateRunning
	case "stopped":
		return StateStopped
	case "starting":
		return StateStarting
	case "stopping":
		return StateStopping
	case "frozen":
		// Treat frozen as running for orchestration purposes — there's
		// nothing the scheduler should do differently.
		return StateRunning
	}
	return StateUnknown
}

// cmdErr formats a failed lxc-* invocation, folding in the captured stderr so
// the real cause (e.g. "Couldn't find a matching image") surfaces instead of a
// bare "exit status 1".
func cmdErr(bin, name string, stderr []byte, err error) error {
	if s := strings.TrimSpace(string(stderr)); s != "" {
		return fmt.Errorf("%s %s: %w: %s", bin, name, err, s)
	}
	return fmt.Errorf("%s %s: %w", bin, name, err)
}

// resolveRootfs decides whether template names a pre-extracted rootfs and, if
// so, returns the absolute path to the actual root filesystem. It returns
// ok=false for a bare template name (e.g. "busybox"), which the caller hands to
// lxc-create unchanged. A directory holding an OCI/umoci bundle (a "rootfs/"
// subdir) is descended into.
func resolveRootfs(template string) (path string, ok bool, err error) {
	p := template
	explicit := false
	if strings.HasPrefix(p, "rootfs:") {
		p, explicit = strings.TrimPrefix(p, "rootfs:"), true
	}
	// Only a path-shaped value is a rootfs candidate; a bare name is a
	// template name for lxc-create.
	if !explicit && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "./") && !strings.HasPrefix(p, "../") {
		return "", false, nil
	}
	abs, aerr := filepath.Abs(p)
	if aerr != nil {
		return "", false, fmt.Errorf("resolve rootfs path %q: %w", p, aerr)
	}
	if !isDir(abs) {
		return "", false, fmt.Errorf("rootfs template %q is not an existing directory", template)
	}
	// OCI/umoci bundle: the flattened fs is in rootfs/. Only descend when abs
	// isn't itself a rootfs, so a real rootfs that happens to contain /rootfs
	// is left alone.
	if !looksLikeRootfs(abs) && isDir(filepath.Join(abs, "rootfs")) {
		abs = filepath.Join(abs, "rootfs")
	}
	if !looksLikeRootfs(abs) {
		return "", false, fmt.Errorf("rootfs template %q does not look like a root filesystem (no bin//etc//usr/…)", template)
	}
	return abs, true, nil
}

// renderBaseRootfsConfig builds the non-network/non-cgroup portion of an LXC
// config for a container backed by an existing rootfs, mirroring the structure
// lxc-create's download template emits. The network and resource stanzas are
// layered on afterwards by finalizeContainerConfig (shared with the download
// path) so both creation paths apply --network and --cpu/--memory identically.
func renderBaseRootfsConfig(name, rootfs string) string {
	var b strings.Builder
	b.WriteString("# Managed by litevirt — container created from a pre-extracted rootfs.\n")
	// common.conf carries the baseline mounts/capabilities lxc-create would
	// otherwise include; reference it only if present on this host.
	if fileExists("/usr/share/lxc/config/common.conf") {
		b.WriteString("lxc.include = /usr/share/lxc/config/common.conf\n")
	}
	b.WriteString("lxc.apparmor.profile = generated\n")
	b.WriteString("lxc.apparmor.allow_nesting = 1\n")
	fmt.Fprintf(&b, "lxc.rootfs.path = dir:%s\n", rootfs)
	fmt.Fprintf(&b, "lxc.uts.name = %s\n", name)
	return b.String()
}

// finalizeContainerConfig rewrites <lxcpath>/<name>/config so its network and
// cgroup stanzas reflect CreateOpts, for BOTH the download and rootfs paths.
// It strips any pre-existing `lxc.net.*` lines (the download template injects a
// default lxcbr0 NIC from /etc/lxc/default.conf) and re-renders the network from
// opts.Network — falling back to a single lxcbr0 veth when none is given — then
// appends the cgroup limits from opts.CPULimit/MemoryMiB. This is what wires
// `lv ct create --network` and `--cpu/--memory` through to the live container.
func (r *LxcRunner) finalizeContainerConfig(opts CreateOpts) error {
	path := filepath.Join(r.lxcpath(), opts.Name, "config")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read container config %s: %w", path, err)
	}
	var b strings.Builder
	var rootfs string
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "lxc.net.") {
			continue // drop the existing network stanza; we re-render it below
		}
		if rest, ok := strings.CutPrefix(t, "lxc.rootfs.path"); ok {
			if _, v, found := strings.Cut(rest, "="); found {
				rootfs = strings.TrimPrefix(strings.TrimSpace(v), "dir:")
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	cfg := strings.TrimRight(b.String(), "\n") + "\n"

	netCfg, err := NetworkConfig(opts.Network)
	if err != nil {
		return fmt.Errorf("render network config: %w", err)
	}
	if netCfg == "" {
		netCfg = defaultNetConfig()
	}
	cfg += netCfg
	cfg += ResourceConfig(opts.CPULimit, opts.MemoryMiB)

	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		return err
	}
	// When a static IP is requested, configure the guest's own networking too —
	// otherwise the stock image's boot-time DHCP client flushes the address LXC
	// assigned via lxc.net.*.ipv4.address.
	if rootfs != "" {
		if err := configureGuestStaticIP(rootfs, opts.Network); err != nil {
			return fmt.Errorf("configure guest static networking: %w", err)
		}
	}
	return nil
}

// configureGuestStaticIP writes the guest's /etc/network/interfaces (ifupdown,
// as used by the Alpine/Debian LXC images) when any NIC requests a static IP,
// so the guest brings the interface up static at boot instead of running a DHCP
// client that clobbers the address. No-op when no static IP is requested — the
// image's default (usually DHCP) is left untouched. Guests with no ifupdown
// (e.g. minimal OCI images) ignore the file and simply keep the address LXC
// assigned, which isn't fought by any in-guest DHCP.
func configureGuestStaticIP(rootfs string, nics []NetworkAttach) error {
	anyStatic := false
	for _, n := range nics {
		if n.IP != "" {
			anyStatic = true
		}
	}
	if !anyStatic {
		return nil
	}
	netDir := filepath.Join(rootfs, "etc", "network")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Managed by litevirt — static addressing from `lv ct create --network`.\n")
	b.WriteString("auto lo\niface lo inet loopback\n\n")
	for i, n := range nics {
		name := n.Name
		if name == "" {
			name = fmt.Sprintf("eth%d", i)
		}
		fmt.Fprintf(&b, "auto %s\n", name)
		if n.IP == "" {
			fmt.Fprintf(&b, "iface %s inet dhcp\n\n", name)
			continue
		}
		addr, netmask := splitCIDR(n.IP)
		fmt.Fprintf(&b, "iface %s inet static\n    address %s\n", name, addr)
		if netmask != "" {
			fmt.Fprintf(&b, "    netmask %s\n", netmask)
		}
		b.WriteString("\n")
	}
	return os.WriteFile(filepath.Join(netDir, "interfaces"), []byte(b.String()), 0o644)
}

// splitCIDR turns "10.0.3.5/24" into ("10.0.3.5", "255.255.255.0") for
// busybox/ifupdown, which wants address and netmask separately. A bare IP
// (no prefix) returns an empty netmask.
func splitCIDR(s string) (addr, netmask string) {
	if ip, ipnet, err := net.ParseCIDR(s); err == nil {
		return ip.String(), net.IP(ipnet.Mask).String()
	}
	return s, ""
}

// defaultNetConfig is the fallback NIC (a veth on the host's lxcbr0) used when
// no explicit network is requested — matching what the download template's
// default.conf provides, so a plain container still gets connectivity.
func defaultNetConfig() string {
	return "lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\nlxc.net.0.flags = up\n"
}

func isDir(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }

func fileExists(p string) bool { fi, err := os.Stat(p); return err == nil && !fi.IsDir() }

// looksLikeRootfs reports whether dir resembles a Linux root filesystem, used
// to tell an extracted rootfs from an arbitrary directory and to decide whether
// to descend into a bundle's rootfs/ subdir.
func looksLikeRootfs(dir string) bool {
	for _, d := range []string{"bin", "etc", "usr", "sbin", "lib"} {
		if isDir(filepath.Join(dir, d)) {
			return true
		}
	}
	return false
}

// stringWriter adapts a strings.Builder to io.Writer so cmd.Stderr
// can stream into it directly.
type stringWriter struct{ b *strings.Builder }

func (w stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
