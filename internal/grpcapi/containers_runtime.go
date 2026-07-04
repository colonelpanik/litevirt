package grpcapi

import (
	"context"
	"io"

	"github.com/litevirt/litevirt/internal/lxc"
)

// LXCRuntimeAdapter wraps an internal/lxc.Runtime to satisfy
// grpcapi.ContainerRuntime. Kept here (rather than in internal/lxc)
// so internal/lxc has no dependency on internal/grpcapi.
type LXCRuntimeAdapter struct {
	Inner lxc.Runtime
}

// NewLXCRuntimeAdapter wraps a production LxcRunner.
func NewLXCRuntimeAdapter(inner lxc.Runtime) *LXCRuntimeAdapter {
	return &LXCRuntimeAdapter{Inner: inner}
}

func (a *LXCRuntimeAdapter) CreateContainer(ctx context.Context, opts CreateContainerOpts) (*ContainerInfo, error) {
	nics := make([]lxc.NetworkAttach, 0, len(opts.Networks))
	for _, n := range opts.Networks {
		nics = append(nics, lxc.NetworkAttach{Name: n.Name, Bridge: n.Bridge, IP: n.IP, MAC: n.MAC, Veth: n.Veth})
	}
	c, err := a.Inner.Create(ctx, lxc.CreateOpts{
		Name: opts.Name, Template: opts.Template,
		Distro: opts.Distro, Release: opts.Release, Arch: opts.Arch,
		CPULimit: opts.CPULimit, MemoryMiB: opts.MemoryMiB,
		Network: nics, Labels: opts.Labels,
	})
	if err != nil {
		return nil, err
	}
	return &ContainerInfo{Name: c.Name, State: string(c.State), Image: c.Image}, nil
}

func (a *LXCRuntimeAdapter) StartContainer(ctx context.Context, name string) error {
	return a.Inner.Start(ctx, name)
}

func (a *LXCRuntimeAdapter) StopContainer(ctx context.Context, name string, timeoutSec int) error {
	return a.Inner.Stop(ctx, name, timeoutSec)
}

func (a *LXCRuntimeAdapter) DeleteContainer(ctx context.Context, name string) error {
	return a.Inner.Delete(ctx, name)
}

func (a *LXCRuntimeAdapter) ExecContainer(ctx context.Context, name string, argv []string) (ContainerExecResult, error) {
	r, err := a.Inner.Exec(ctx, name, argv)
	if err != nil {
		return ContainerExecResult{}, err
	}
	return ContainerExecResult{Stdout: r.Stdout, Stderr: r.Stderr, ExitCode: r.ExitCode}, nil
}

func (a *LXCRuntimeAdapter) StateContainer(ctx context.Context, name string) (string, error) {
	st, err := a.Inner.State(ctx, name)
	return string(st), err
}

func (a *LXCRuntimeAdapter) IPContainer(ctx context.Context, name string) (string, error) {
	return a.Inner.IP(ctx, name)
}

func (a *LXCRuntimeAdapter) FreezeContainer(ctx context.Context, name string) error {
	return a.Inner.Freeze(ctx, name)
}

func (a *LXCRuntimeAdapter) UnfreezeContainer(ctx context.Context, name string) error {
	return a.Inner.Unfreeze(ctx, name)
}

func (a *LXCRuntimeAdapter) ContainerRootFSPath(name string) (string, error) {
	return a.Inner.RootFSPath(name)
}

func (a *LXCRuntimeAdapter) ExportContainer(ctx context.Context, name string, w io.Writer) error {
	return a.Inner.ExportContainer(ctx, name, w)
}

func (a *LXCRuntimeAdapter) ImportContainer(ctx context.Context, name string, r io.Reader) error {
	return a.Inner.ImportContainer(ctx, name, r)
}

func (a *LXCRuntimeAdapter) ContainerExists(ctx context.Context, name string) (bool, error) {
	return a.Inner.ContainerExists(name)
}

func (a *LXCRuntimeAdapter) RevertContainer(ctx context.Context, name string, r io.Reader) error {
	return a.Inner.RevertContainer(ctx, name, r)
}

func (a *LXCRuntimeAdapter) CloneContainer(ctx context.Context, src, dst string) error {
	return a.Inner.CloneContainer(ctx, src, dst)
}

func (a *LXCRuntimeAdapter) ListContainers(ctx context.Context) ([]string, error) {
	return a.Inner.List(ctx)
}

func (a *LXCRuntimeAdapter) PullOCIImage(ctx context.Context, image, dest, tag, username, password string) error {
	return lxc.PullOCI(ctx, lxc.PullOCIOptions{
		Image: image, Dest: dest, Tag: tag, Username: username, Password: password,
	})
}
