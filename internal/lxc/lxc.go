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
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

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
	// List enumerates every container known to LXC on this host.
	List(ctx context.Context) ([]string, error)
}

// CreateOpts collects parameters for Runtime.Create.
type CreateOpts struct {
	Name string
	// Template is either "download" (use lxc-download), a path to a
	// pre-extracted rootfs, or "rootfs:<path>" to bind-mount an
	// already-prepared directory (used after umoci extraction in 1.4.B).
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

// Create implements Runtime.Create via lxc-create.
func (r *LxcRunner) Create(ctx context.Context, opts CreateOpts) (*Container, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	args := []string{"-n", opts.Name, "-t", opts.Template}
	if opts.Template == "download" {
		args = append(args, "--",
			"-d", opts.Distro,
			"-r", opts.Release,
			"-a", opts.Arch,
		)
	}
	if _, _, err := r.run(ctx, "lxc-create", args...); err != nil {
		return nil, fmt.Errorf("lxc-create %s: %w", opts.Name, err)
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

// Start runs lxc-start in daemon mode.
func (r *LxcRunner) Start(ctx context.Context, name string) error {
	if _, _, err := r.run(ctx, "lxc-start", "-n", name, "-d"); err != nil {
		return fmt.Errorf("lxc-start %s: %w", name, err)
	}
	return nil
}

// Stop runs lxc-stop with the supplied SIGTERM-then-SIGKILL timeout.
func (r *LxcRunner) Stop(ctx context.Context, name string, timeoutSec int) error {
	args := []string{"-n", name}
	if timeoutSec > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", timeoutSec))
	}
	if _, _, err := r.run(ctx, "lxc-stop", args...); err != nil {
		return fmt.Errorf("lxc-stop %s: %w", name, err)
	}
	return nil
}

// Delete runs lxc-destroy. Caller must have stopped the container first.
func (r *LxcRunner) Delete(ctx context.Context, name string) error {
	if _, _, err := r.run(ctx, "lxc-destroy", "-n", name); err != nil {
		return fmt.Errorf("lxc-destroy %s: %w", name, err)
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

// stringWriter adapts a strings.Builder to io.Writer so cmd.Stderr
// can stream into it directly.
type stringWriter struct{ b *strings.Builder }

func (w stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
