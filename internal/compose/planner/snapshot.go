// Package planner resolves a compose file into a fully-planned set of resource
// actions against a point-in-time cluster state snapshot. The planner makes all
// placement, device, network target, and LB decisions up front so that execution
// is deterministic and requires no further queries.
package planner

import (
	"context"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ClusterState is a point-in-time snapshot of the cluster, loaded once before
// planning. The planner works entirely off this snapshot — no Corrosion queries
// during the resolve phase.
type ClusterState struct {
	Hosts      []corrosion.HostRecord
	VMs        []corrosion.VMRecord
	Networks   []corrosion.NetworkRecord
	LBs        []corrosion.LBConfigRecord
	Devices    map[string][]corrosion.PCIDeviceRecord // host → available devices
	ImageHosts map[string][]string                    // imageName → hosts that have it (status=ready)
}

// LoadClusterState queries Corrosion once and builds an immutable snapshot.
func LoadClusterState(ctx context.Context, db *corrosion.Client) (*ClusterState, error) {
	hosts, err := corrosion.ListHosts(ctx, db)
	if err != nil {
		return nil, err
	}

	vms, err := corrosion.ListVMs(ctx, db, "", "")
	if err != nil {
		return nil, err
	}

	networks, err := corrosion.ListNetworks(ctx, db)
	if err != nil {
		return nil, err
	}

	lbs, err := corrosion.ListLBConfigs(ctx, db)
	if err != nil {
		return nil, err
	}

	// Load available PCI devices per host.
	devices := make(map[string][]corrosion.PCIDeviceRecord, len(hosts))
	for _, h := range hosts {
		if h.State != "active" {
			continue
		}
		devs, err := corrosion.GetAvailableDevicesWithTopology(ctx, db, h.Name, "")
		if err != nil {
			continue
		}
		devices[h.Name] = devs
	}

	// Load image availability: which hosts have each image ready.
	images, err := corrosion.ListImages(ctx, db)
	if err != nil {
		return nil, err
	}
	imageHosts := make(map[string][]string, len(images))
	for _, img := range images {
		ihs, err := corrosion.GetImageHosts(ctx, db, img.Name)
		if err != nil {
			continue
		}
		for _, ih := range ihs {
			if ih.Status == "ready" {
				imageHosts[img.Name] = append(imageHosts[img.Name], ih.HostName)
			}
		}
	}

	return &ClusterState{
		Hosts:      hosts,
		VMs:        vms,
		Networks:   networks,
		LBs:        lbs,
		Devices:    devices,
		ImageHosts: imageHosts,
	}, nil
}
