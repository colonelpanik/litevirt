package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// A VM whose PERSISTED spec carries an unversioned machine alias ("q35", "pc",
// or empty) is a latent guest-ABI hazard: libvirt resolves an alias per host
// qemu version, so a migration or failover onto a host with a different qemu
// can silently shift the guest's ABI underneath it. Create and redefine pin the
// concrete type at define time, and the reconciler backfills VMs it sweeps —
// but a VM produced by a path that does neither, and never swept, keeps the
// alias. This report is how an operator finds those.
func TestUnpinnedMachineVMs(t *testing.T) {
	vms := []*pb.VM{
		{Name: "pinned", HostName: "h1", Spec: &pb.VMSpec{Machine: "pc-q35-9.0"}},
		{Name: "alias-q35", HostName: "h1", Spec: &pb.VMSpec{Machine: "q35"}},
		{Name: "alias-bare-pc-q35", HostName: "h2", Spec: &pb.VMSpec{Machine: "pc-q35"}},
		{Name: "alias-empty", HostName: "h2", Spec: &pb.VMSpec{Machine: ""}},
		{Name: "no-spec", HostName: "h3"},
		{Name: "pinned-i440", HostName: "h3", Spec: &pb.VMSpec{Machine: "pc-i440fx-8.2"}},
	}

	got := unpinnedMachineVMs(vms)

	var names []string
	for _, u := range got {
		names = append(names, u.Name)
	}
	want := []string{"alias-q35", "alias-bare-pc-q35", "alias-empty"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("unpinned = %v, want %v", names, want)
	}
	// A VM with no spec at all is not reportable as "unpinned" — there is
	// nothing to pin and nothing an operator could act on.
	for _, u := range got {
		if u.Name == "no-spec" {
			t.Fatal("a VM with no persisted spec must not be reported")
		}
	}
	// The report carries the host, so an operator knows where to look.
	if got[0].Host != "h1" {
		t.Fatalf("host = %q, want h1", got[0].Host)
	}
}
