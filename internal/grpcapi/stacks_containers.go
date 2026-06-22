package grpcapi

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

// buildContainerRequest converts a compose container workload (kind: lxc | oci)
// into a CreateContainerRequest for the planner-resolved host. The deploy path
// calls CreateContainer + StartContainer with the result, so a compose stack can
// mix VMs and containers.
//
// image →:
//   - a rootfs path ("/abs", "./rel", "../rel", "rootfs:<p>"): used verbatim as
//     the Template — a pre-extracted rootfs (e.g. from `lv ct pull`). Works for
//     both lxc and oci workloads.
//   - "distro[:release]" (kind: lxc): the LXC `download` template.
//   - an OCI registry ref (kind: oci, not a path): NOT auto-pulled by compose
//     yet — returns a clear error directing the operator to pre-pull. (follow-up)
//
// Container NICs attach to the resolved scoped-network bridge (resolveBridge,
// the same mapping VMs use). Full network provisioning + IPAM + security-groups
// for container veths is a separate follow-up; a container sharing a stack
// network with a VM finds the bridge already provisioned by the VM path.
func (s *Server) buildContainerRequest(ctx context.Context, instanceName string, d *compose.VMDef, f *compose.File, targetHost string) (*pb.CreateContainerRequest, error) {
	req := &pb.CreateContainerRequest{
		HostName:  targetHost,
		Name:      instanceName,
		Cpu:       int32(d.CPU),
		MemoryMib: int32(d.Memory),
		Labels:    d.Labels,
		Image:     d.Image,
		Arch:      "amd64",
	}

	switch {
	case isRootfsTemplate(d.Image):
		req.Template = d.Image
	case d.Kind == compose.WorkloadKindLXC:
		distro, release, _ := strings.Cut(d.Image, ":")
		if distro == "" {
			return nil, fmt.Errorf("container %q: kind=lxc needs image: \"distro[:release]\" (e.g. \"alpine:3.21\") or a rootfs path", instanceName)
		}
		req.Template, req.Distro, req.Release = "download", distro, release
	default: // kind=oci with a registry ref
		return nil, fmt.Errorf(
			"container %q: compose can't auto-pull OCI image %q yet — pre-pull it (`lv ct pull %s --dest <rootfs-dir>`) and set image: to that rootfs path",
			instanceName, d.Image, d.Image)
	}

	if d.Restart != nil {
		req.Restart = &pb.RestartPolicy{
			Condition:   d.Restart.Condition,
			Delay:       d.Restart.Delay,
			MaxAttempts: int32(d.Restart.MaxAttempts),
			Window:      d.Restart.Window,
		}
	}

	for _, n := range d.Network {
		req.Networks = append(req.Networks, &pb.ContainerNetwork{
			Name:   n.Name,
			Bridge: resolveBridge(ctx, s.db, n.Name),
			Ip:     n.IP,
			Mac:    n.MAC,
		})
	}
	return req, nil
}

// isRootfsTemplate reports whether a compose container `image:` is a rootfs
// path/reference (vs a download distro or an OCI registry ref).
func isRootfsTemplate(image string) bool {
	return strings.HasPrefix(image, "/") || strings.HasPrefix(image, "./") ||
		strings.HasPrefix(image, "../") || strings.HasPrefix(image, "rootfs:")
}
