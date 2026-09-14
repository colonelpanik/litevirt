package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// A VM whose PERSISTED spec carries no uuid cannot be named in NetBox — the
// identity is uuid-derived — and, worse, the inventory mirror counts it as an
// unreadable record and withholds EVERY delete while one exists. So a single
// VM in this report stops the whole mirror converging, and this is how an
// operator finds them.
//
// SELECTION ONLY. These pb.VM values are hand-built, so this test says nothing
// about whether the RPC actually populates the field it reads — and that gap is
// exactly where the original defect lived: the selector was right while
// ListVMs projected labels alone, so the live report was inverted with this
// test green. TestListVMsProjectsTheUUID is what pins the data source.
func TestUUIDlessVMs(t *testing.T) {
	vms := []*pb.VM{
		{Name: "has-uuid", HostName: "h1", Spec: &pb.VMSpec{Uuid: "5113ced7-9006-4086-b7dd-9d1840181e03"}},
		{Name: "legacy-a", HostName: "h1", Spec: &pb.VMSpec{}},
		{Name: "legacy-b", HostName: "h2", Spec: &pb.VMSpec{Uuid: ""}},
		{Name: "no-spec", HostName: "h3"},
		// A template is a disk image, never a domain: it has no uuid to record
		// and the mirror ignores it, so reporting one would be noise an operator
		// cannot act on.
		{Name: "a-template", HostName: "h3", IsTemplate: true, Spec: &pb.VMSpec{}},
	}

	got := uuidlessVMs(vms)

	var names []string
	for _, u := range got {
		names = append(names, u.Name)
	}
	want := []string{"legacy-a", "legacy-b"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("uuidless = %v, want %v", names, want)
	}
	for _, u := range got {
		if u.Name == "no-spec" {
			t.Error("a VM with no spec at all must not be reported: nothing to fill in")
		}
		if u.Name == "a-template" {
			t.Error("a template has no domain and is never mirrored; reporting it is noise")
		}
	}
}
