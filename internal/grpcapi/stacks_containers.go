package grpcapi

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// deleteWorkload removes a planned workload, routing containers to
// DeleteContainer (on their resolved/current host) and VMs to DeleteVM. Used by
// the deploy executor for OpDelete and the delete half of an OpUpdate recreate.
func (s *Server) deleteWorkload(ctx context.Context, a planner.VMAction) error {
	if a.IsContainer {
		_, err := s.DeleteContainer(ctx, &pb.DeleteContainerRequest{HostName: a.TargetHost, Name: a.VMName})
		return err
	}
	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: a.VMName})
	return err
}

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
	// Tag the container with its compose stack (reserved label) so the deploy
	// planner's current-state diff and `compose down` can find it — the
	// containers table has no stack_name column. Compose's value wins over any
	// user-set label of the same key.
	labels := map[string]string{}
	for k, v := range d.Labels {
		labels[k] = v
	}
	labels[corrosion.LabelStack] = f.Name

	req := &pb.CreateContainerRequest{
		HostName:  targetHost,
		Name:      instanceName,
		Cpu:       int32(d.CPU),
		MemoryMib: int32(d.Memory),
		Labels:    labels,
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
		// Resolve against the SCOPED network name. Compose registers each network
		// as "<stack>_<name>", and an isolated network's host bridge is derived
		// from that scoped name (br-iso-<hash>). Resolving the bare name misses
		// the lookup and returns an invalid bridge, so the container's veth can't
		// attach and lxc-start aborts (the VM path scopes it the same way).
		scoped := compose.ScopedNetworkName(f.Name, n.Name)
		ipCIDR, bareIP := n.IP, n.IP
		if n.IP != "" {
			if addr, _, hasPrefix := strings.Cut(n.IP, "/"); hasPrefix {
				bareIP = addr // caller already supplied a CIDR
			} else if def := lookupNetworkDef(ctx, s.db, scoped); def != nil {
				// lxc.net.*.ipv4.address needs addr/prefix; compose NICs carry a
				// bare IP, so borrow the prefix from the network's subnet.
				if _, bits, ok := strings.Cut(def.Subnet, "/"); ok && bits != "" {
					ipCIDR = n.IP + "/" + bits
				}
			}
		}
		req.Networks = append(req.Networks, &pb.ContainerNetwork{
			Name:   n.Name,
			Bridge: resolveBridge(ctx, s.db, scoped),
			Ip:     ipCIDR,
			Mac:    n.MAC,
		})
		// Record the bare address so the container can be discovered as an LB
		// backend cluster-wide (see corrosion.LabelIP). DHCP NICs (no IP) are
		// resolved locally on the LB host at apply time instead.
		if bareIP != "" && labels[corrosion.LabelIP] == "" {
			labels[corrosion.LabelIP] = bareIP
		}
	}
	return req, nil
}

// isRootfsTemplate reports whether a compose container `image:` is a rootfs
// path/reference (vs a download distro or an OCI registry ref).
func isRootfsTemplate(image string) bool {
	return strings.HasPrefix(image, "/") || strings.HasPrefix(image, "./") ||
		strings.HasPrefix(image, "../") || strings.HasPrefix(image, "rootfs:")
}
