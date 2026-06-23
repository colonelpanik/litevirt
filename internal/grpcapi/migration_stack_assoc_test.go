package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// When migration provisions a stack network on the target host, the request
// must carry stack_name. Otherwise the target writes the network row with an
// empty stack_name (CRDT then replicates it back, clobbering the original), and
// `compose down` can no longer match the network — orphaning the bridge +
// dnsmasq + row.
func TestRemoteProvisionRequest_PreservesStackName(t *testing.T) {
	nr := &corrosion.NetworkRecord{
		Name:      "lbmix_lbnet",
		StackName: "lbmix",
		Type:      "isolated",
		Config:    `{"subnet":"10.77.0.0/24"}`,
	}
	req := remoteProvisionRequest(nr.Name, nr)

	if req.Name != "lbmix_lbnet" || req.NetType != "isolated" || req.Config != nr.Config {
		t.Fatalf("request mapping wrong: %+v", req)
	}
	if req.StackName != "lbmix" {
		t.Errorf("StackName = %q, want lbmix — a migration to a peer would clobber the network's stack association", req.StackName)
	}
}

// A bridge network with no explicit type still defaults to "bridge" and keeps
// its stack association.
func TestRemoteProvisionRequest_DefaultsTypeKeepsStack(t *testing.T) {
	nr := &corrosion.NetworkRecord{Name: "app_lan", StackName: "app", Type: ""}
	req := remoteProvisionRequest(nr.Name, nr)
	if req.NetType != "bridge" {
		t.Errorf("NetType = %q, want bridge (default)", req.NetType)
	}
	if req.StackName != "app" {
		t.Errorf("StackName = %q, want app", req.StackName)
	}
}
