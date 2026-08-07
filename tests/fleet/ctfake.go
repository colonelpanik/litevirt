package fleet

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/lxc"
)

// CTFake is an in-process container runtime for the fleet harness — the
// container-side analogue of internal/libvirtfake. It implements
// grpcapi.ContainerRuntime with REAL on-disk state under a per-node root:
// each container is a directory (config + rootfs) that ExportContainer
// streams as a genuine tar and ImportContainer extracts.
//
// The realism matters for the migrate scenarios. A map-only fake would let a
// migration "succeed" while moving nothing; here the source's bytes are
// chunked through pbsstore, streamed to the target over real gRPC, and laid
// back down on the target's disk. A test can read the target's rootfs and
// prove the payload it asserts on actually crossed the wire.
//
// Safe for concurrent use: the gRPC handlers call in from server goroutines
// while the scenario reads counters from the test goroutine.
type CTFake struct {
	mu   sync.Mutex
	root string

	// state tracks the runtime state of each existing container
	// ("running"/"stopped"). Absence means the container does not exist,
	// which is kept in sync with the on-disk dir.
	state map[string]string
	// ips is what IPContainer reports, keyed by name.
	ips map[string]string
	// limits is what ContainerLimits reports, keyed by name — recorded at
	// create from the request's CPU/memory so the runtime-inventory collector
	// sees the same limits the caller configured. Absent = uncapped (0,0).
	limits map[string][2]int

	// Call counters/records. Read them with the accessors, never directly —
	// the handlers write these from other goroutines.
	createCalls []grpcapi.CreateContainerOpts
	startCalls  []string
	stopCalls   []string
	deleteCalls []string
	freezeCalls []string
	unfrzCalls  []string
	exportCalls []string
	importCalls []string

	// Injected failures. Set before driving the RPC under test.
	startErr  error
	exportErr error
	importErr error

	// onExport runs INSIDE ExportContainer, i.e. during a migrate's archive
	// phase — after the source's preflight has passed but before the IPAM
	// handoff and the target's restore. It is the seam for mutating cluster
	// state mid-migrate, which is the only way to reach the target-side
	// failures that a preflight would otherwise have caught first.
	onExport func()
}

// NewCTFake returns a container runtime rooted at dir. The directory is
// created if absent.
func NewCTFake(dir string) *CTFake {
	_ = os.MkdirAll(dir, 0o755)
	return &CTFake{
		root:  dir,
		state: make(map[string]string),
		ips:   make(map[string]string),
	}
}

// dir is the on-disk home of one container: <root>/<name>/.
func (f *CTFake) dir(name string) string { return filepath.Join(f.root, name) }

// ── scenario helpers ────────────────────────────────────────────────────

// Seed materialises a stopped container with a rootfs carrying payload, as if
// it had been created here earlier. Returns the container's dir.
func (f *CTFake) Seed(name, payload string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seedLocked(name, payload)
}

func (f *CTFake) seedLocked(name, payload string) string {
	d := f.dir(name)
	_ = os.MkdirAll(filepath.Join(d, "rootfs"), 0o755)
	_ = os.WriteFile(filepath.Join(d, "config"), []byte("lxc.rootfs.path = "+filepath.Join(d, "rootfs")+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(d, "rootfs", "payload"), []byte(payload), 0o644)
	f.state[name] = "stopped"
	return d
}

// Payload reads back the marker file Seed wrote. Returns "" when the
// container (or its payload) is not present on this node — which is how a
// scenario proves a migration's bytes did, or did not, land here.
func (f *CTFake) Payload(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(f.dir(name), "rootfs", "payload"))
	if err != nil {
		return ""
	}
	return string(b)
}

// Exists reports whether the container's dir is present on this node.
func (f *CTFake) Exists(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.state[name]
	return ok
}

// State returns the fake's view of the container's run state ("" if absent).
func (f *CTFake) State(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state[name]
}

// SetIP makes IPContainer report ip for name.
func (f *CTFake) SetIP(name, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ips[name] = ip
}

// FailStart makes the next StartContainer calls fail with err.
func (f *CTFake) FailStart(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startErr = err
}

// FailExport makes ExportContainer fail with err — the archive-phase failure
// that must roll the source back untouched.
func (f *CTFake) FailExport(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exportErr = err
}

// FailImport makes ImportContainer fail with err — a target-side failure
// BEFORE the target writes its cluster row.
func (f *CTFake) FailImport(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.importErr = err
}

// OnExport registers fn to run inside the next ExportContainer call. See the
// onExport field: this is the mid-migrate window.
func (f *CTFake) OnExport(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onExport = fn
}

// Counter accessors. Each returns a copy taken under the lock.

func (f *CTFake) StartCalls() []string  { return f.snapshot(func() []string { return f.startCalls }) }
func (f *CTFake) StopCalls() []string   { return f.snapshot(func() []string { return f.stopCalls }) }
func (f *CTFake) DeleteCalls() []string { return f.snapshot(func() []string { return f.deleteCalls }) }
func (f *CTFake) FreezeCalls() []string { return f.snapshot(func() []string { return f.freezeCalls }) }
func (f *CTFake) UnfreezeCalls() []string {
	return f.snapshot(func() []string { return f.unfrzCalls })
}
func (f *CTFake) ExportCalls() []string { return f.snapshot(func() []string { return f.exportCalls }) }
func (f *CTFake) ImportCalls() []string { return f.snapshot(func() []string { return f.importCalls }) }

func (f *CTFake) snapshot(get func() []string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	src := get()
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// ── grpcapi.ContainerRuntime ────────────────────────────────────────────

func (f *CTFake) CreateContainer(_ context.Context, opts grpcapi.CreateContainerOpts) (*grpcapi.ContainerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls = append(f.createCalls, opts)
	f.seedLocked(opts.Name, "created-by-"+opts.Name)
	if f.limits == nil {
		f.limits = map[string][2]int{}
	}
	f.limits[opts.Name] = [2]int{opts.CPULimit, opts.MemoryMiB}
	return &grpcapi.ContainerInfo{Name: opts.Name, State: "stopped"}, nil
}

// ContainerLimits reports the limits recorded at create; a container seeded
// outside CreateContainer (a bare Seed) is uncapped, matching a runtime-only
// rogue with no configured limits.
func (f *CTFake) ContainerLimits(_ context.Context, name string) (int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.state[name]; !ok {
		return 0, 0, fmt.Errorf("container %q does not exist", name)
	}
	l := f.limits[name]
	return l[0], l[1], nil
}

func (f *CTFake) StartContainer(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls = append(f.startCalls, name)
	if f.startErr != nil {
		return f.startErr
	}
	if _, ok := f.state[name]; !ok {
		return lxc.ErrContainerNotFound
	}
	f.state[name] = "running"
	return nil
}

func (f *CTFake) StopContainer(_ context.Context, name string, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls = append(f.stopCalls, name)
	if _, ok := f.state[name]; !ok {
		return lxc.ErrContainerNotFound
	}
	f.state[name] = "stopped"
	return nil
}

func (f *CTFake) DeleteContainer(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls = append(f.deleteCalls, name)
	if _, ok := f.state[name]; !ok {
		// Idempotent: the migrate finaliser treats this as success on retry.
		return lxc.ErrContainerNotFound
	}
	delete(f.state, name)
	delete(f.ips, name)
	return os.RemoveAll(f.dir(name))
}

func (f *CTFake) ExecContainer(_ context.Context, name string, argv []string) (grpcapi.ContainerExecResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.state[name]; !ok {
		return grpcapi.ContainerExecResult{}, lxc.ErrContainerNotFound
	}
	return grpcapi.ContainerExecResult{Stdout: []byte(strings.Join(argv, " ")), ExitCode: 0}, nil
}

func (f *CTFake) StateContainer(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.state[name]
	if !ok {
		return "", lxc.ErrContainerNotFound
	}
	return st, nil
}

func (f *CTFake) IPContainer(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ips[name], nil
}

func (f *CTFake) ListContainers(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.state))
	for n := range f.state {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (f *CTFake) ContainerExists(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.state[name]
	return ok, nil
}

func (f *CTFake) FreezeContainer(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.freezeCalls = append(f.freezeCalls, name)
	return nil
}

func (f *CTFake) UnfreezeContainer(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unfrzCalls = append(f.unfrzCalls, name)
	return nil
}

func (f *CTFake) ContainerRootFSPath(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.state[name]; !ok {
		return "", lxc.ErrContainerNotFound
	}
	return filepath.Join(f.dir(name), "rootfs"), nil
}

// ExportContainer writes the container's whole on-disk dir as a real tar
// stream — the same self-contained shape lxc.ExportContainer produces.
func (f *CTFake) ExportContainer(_ context.Context, name string, w io.Writer) error {
	// Record the attempt BEFORE any injected failure: a scenario asserting
	// "the export was reached" needs the call to count even when it fails,
	// otherwise an injected error is indistinguishable from never getting there.
	f.mu.Lock()
	f.exportCalls = append(f.exportCalls, name)
	injected, hook := f.exportErr, f.onExport
	_, ok := f.state[name]
	base := f.dir(name)
	f.mu.Unlock()
	// Run the hook outside the lock so it may call back into this fake.
	if hook != nil {
		hook()
	}
	if injected != nil {
		return injected
	}
	if !ok {
		return lxc.ErrContainerNotFound
	}

	tw := tar.NewWriter(w)
	err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(base, path)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		hdr, herr := tar.FileInfoHeader(info, "")
		if herr != nil {
			return herr
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		src, oerr := os.Open(path)
		if oerr != nil {
			return oerr
		}
		defer src.Close()
		_, cerr := io.Copy(tw, src)
		return cerr
	})
	if err != nil {
		_ = tw.Close()
		return err
	}
	return tw.Close()
}

// ImportContainer rebuilds the container's dir from an ExportContainer tar.
// The container is left stopped, matching the real runtime's contract.
func (f *CTFake) ImportContainer(_ context.Context, name string, r io.Reader) error {
	f.mu.Lock()
	f.importCalls = append(f.importCalls, name) // recorded before the injected failure; see ExportContainer
	if f.importErr != nil {
		err := f.importErr
		f.mu.Unlock()
		return err
	}
	base := f.dir(name)
	f.mu.Unlock()

	if err := extractTar(r, base); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[name] = "stopped"
	return nil
}

// RevertContainer clobbers the container's dir from a snapshot tar.
func (f *CTFake) RevertContainer(ctx context.Context, name string, r io.Reader) error {
	f.mu.Lock()
	base := f.dir(name)
	f.mu.Unlock()
	if err := os.RemoveAll(base); err != nil {
		return err
	}
	return f.ImportContainer(ctx, name, r)
}

func (f *CTFake) CloneContainer(_ context.Context, src, dst string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.state[src]; !ok {
		return lxc.ErrContainerNotFound
	}
	if err := copyTree(f.dir(src), f.dir(dst)); err != nil {
		return err
	}
	f.state[dst] = "stopped"
	return nil
}

func (f *CTFake) PullOCIImage(_ context.Context, _, dest, _, _, _ string) error {
	if dest == "" {
		return fmt.Errorf("ctfake: empty OCI destination")
	}
	return os.MkdirAll(dest, 0o755)
}

// ── tar/dir helpers ─────────────────────────────────────────────────────

func extractTar(r io.Reader, base string) error {
	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// Reject traversal — the real importer is fed bytes from a peer.
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("ctfake: unsafe tar path %q", hdr.Name)
		}
		dst := filepath.Join(base, clean)
		if hdr.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, b, 0o644)
	})
}
