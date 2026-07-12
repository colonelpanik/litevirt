// Package region exposes the federation-as-a-first-class-API surface
// described in A "region" in litevirt is a failure-domain
// label on a host (`hosts.region` column); the cluster is already a
// CRDT mesh that survives WAN latency, so federation is about
// *surfacing* what's there rather than building a new replication
// layer.
//
// The package is deliberately small: it summarises hosts/VMs by region
// and validates cross-region migrations. The actual migration is still
// MigrateVM in internal/grpcapi — region is a routing input, not a
// separate execution path.
package region

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Default is the region every host gets if none is set. Single-region
// clusters never see anything else.
const Default = "default"

// Status is a region's roll-up: the set of hosts in the region, the VM
// counts, and the most recent host heartbeat (proxy for liveness).
type Status struct {
	Name        string
	HostCount   int
	ActiveHosts int
	VMCount     int
	LastUpdated time.Time
}

// List returns every distinct region present in the cluster, sorted
// for deterministic output. A cluster with zero hosts returns a single
// entry for "default" so the UI / CLI always have something to show.
func List(ctx context.Context, db *corrosion.Client) ([]string, error) {
	hosts, err := corrosion.ListHosts(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	seen := map[string]struct{}{}
	for _, h := range hosts {
		seen[h.Region] = struct{}{}
	}
	if len(seen) == 0 {
		seen[Default] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out, nil
}

// StatusAll returns one Status per region. ActiveHosts counts hosts in
// state "active"; VMCount counts non-deleted VMs hosted on any of the
// region's hosts.
func StatusAll(ctx context.Context, db *corrosion.Client) ([]Status, error) {
	hosts, err := corrosion.ListHosts(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	vms, err := corrosion.ListVMs(ctx, db, "", "")
	if err != nil {
		return nil, fmt.Errorf("list vms: %w", err)
	}

	hostRegion := map[string]string{}
	byName := map[string]*Status{}
	ensure := func(region string) *Status {
		if s, ok := byName[region]; ok {
			return s
		}
		s := &Status{Name: region}
		byName[region] = s
		return s
	}
	for _, h := range hosts {
		hostRegion[h.Name] = h.Region
		st := ensure(h.Region)
		st.HostCount++
		if h.State == "active" {
			st.ActiveHosts++
		}
		if t, ok := corrosion.ParseUpdatedAt(h.UpdatedAt); ok && t.After(st.LastUpdated) {
			st.LastUpdated = t
		}
	}
	for _, vm := range vms {
		if region, ok := hostRegion[vm.HostName]; ok {
			ensure(region).VMCount++
		}
	}
	if len(byName) == 0 {
		ensure(Default)
	}

	out := make([]Status, 0, len(byName))
	for _, s := range byName {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ErrSameRegion is returned by ValidateCrossRegion when both source
// and target hosts live in the same region — the operator probably
// meant MigrateVM, not CrossRegionMigrate.
var ErrSameRegion = errors.New("source and target are in the same region; use MigrateVM")

// ValidateCrossRegion checks that the named source/target hosts exist,
// are in different regions, and are both active. Returns the resolved
// regions (src, dst) so the caller can log them.
func ValidateCrossRegion(ctx context.Context, db *corrosion.Client, srcHost, dstHost string) (src, dst string, err error) {
	if srcHost == dstHost {
		return "", "", fmt.Errorf("source and target hosts are identical (%q)", srcHost)
	}
	s, err := corrosion.GetHost(ctx, db, srcHost)
	if err != nil || s == nil {
		return "", "", fmt.Errorf("source host %q not found", srcHost)
	}
	t, err := corrosion.GetHost(ctx, db, dstHost)
	if err != nil || t == nil {
		return "", "", fmt.Errorf("target host %q not found", dstHost)
	}
	if s.State != "active" {
		return "", "", fmt.Errorf("source host %q is %q, must be active", srcHost, s.State)
	}
	if t.State != "active" {
		return "", "", fmt.Errorf("target host %q is %q, must be active", dstHost, t.State)
	}
	if s.Region == t.Region {
		return s.Region, t.Region, fmt.Errorf("%w: both in %q", ErrSameRegion, s.Region)
	}
	return s.Region, t.Region, nil
}
