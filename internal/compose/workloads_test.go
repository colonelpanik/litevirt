package compose

import (
	"strings"
	"testing"
)

// TestFoldWorkloads_VMKindFoldsIntoVMs verifies a `workloads:` entry
// with explicit `kind: vm` ends up in the canonical VMs map after
// parse, indistinguishable from a `vms:` entry.
func TestFoldWorkloads_VMKindFoldsIntoVMs(t *testing.T) {
	in := `
version: "1"
name: test-stack
images:
  ubuntu: { source: example.com/ubuntu.qcow2 }
networks:
  prod: { driver: bridge, bridge: br0 }
workloads:
  web:
    kind: vm
    image: ubuntu
    cpu: 2
    memory: 1024
    disks:
      root: { size: 10G }
    network:
      - { name: prod }
`
	f, err := ParseBytes([]byte(in))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	v, ok := f.VMs["web"]
	if !ok {
		t.Fatalf("expected `web` to land in f.VMs, got %v", f.VMs)
	}
	if v.Kind != WorkloadKindVM {
		t.Errorf("Kind = %q, want vm", v.Kind)
	}
	if f.Workloads != nil {
		t.Errorf("Workloads should be nil after fold, got %+v", f.Workloads)
	}
}

// TestFoldWorkloads_ImplicitKindDefaultsToVM covers the common case
// where users write `workloads:` with no `kind:` line — that should
// be a plain VM, not an error.
func TestFoldWorkloads_ImplicitKindDefaultsToVM(t *testing.T) {
	in := `
version: "1"
name: test-stack
images:
  ubuntu: { source: example.com/ubuntu.qcow2 }
networks:
  prod: { driver: bridge, bridge: br0 }
workloads:
  vm-no-kind:
    image: ubuntu
    cpu: 1
    memory: 512
    disks: { root: { size: 5G } }
    network: [{ name: prod }]
`
	f, err := ParseBytes([]byte(in))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	v := f.VMs["vm-no-kind"]
	if v.Kind != WorkloadKindVM {
		t.Errorf("Kind = %q, want vm (default)", v.Kind)
	}
}

// TestFoldWorkloads_LXCKindPreserved keeps kind=lxc on the VMDef so
// the deploy dispatcher can branch later.
func TestFoldWorkloads_LXCKindPreserved(t *testing.T) {
	in := `
version: "1"
name: test-stack
images:
  alpine: { source: docker.io/library/alpine:3.19 }
networks:
  prod: { driver: bridge, bridge: br0 }
workloads:
  ct1:
    kind: lxc
    image: alpine
    cpu: 1
    memory: 256
    network: [{ name: prod }]
`
	f, err := ParseBytes([]byte(in))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if f.VMs["ct1"].Kind != WorkloadKindLXC {
		t.Errorf("Kind = %q, want lxc", f.VMs["ct1"].Kind)
	}
}

// TestFoldWorkloads_DuplicateNameRejected — the same name in `vms:`
// and `workloads:` is ambiguous; the parser refuses rather than
// silently overwriting.
func TestFoldWorkloads_DuplicateNameRejected(t *testing.T) {
	in := `
version: "1"
name: test-stack
images:
  ubuntu: { source: example.com/ubuntu.qcow2 }
networks:
  prod: { driver: bridge, bridge: br0 }
vms:
  shared:
    image: ubuntu
    cpu: 1
    memory: 512
    disks: { root: { size: 5G } }
    network: [{ name: prod }]
workloads:
  shared:
    kind: vm
    image: ubuntu
    cpu: 1
    memory: 512
    disks: { root: { size: 5G } }
    network: [{ name: prod }]
`
	_, err := ParseBytes([]byte(in))
	if err == nil || !strings.Contains(err.Error(), "shared") {
		t.Fatalf("expected duplicate-name error mentioning shared, got %v", err)
	}
}

// TestFoldWorkloads_UnknownKindRejected — typo guard.
func TestFoldWorkloads_UnknownKindRejected(t *testing.T) {
	in := `
version: "1"
name: test-stack
images:
  alpine: { source: foo }
networks:
  prod: { driver: bridge, bridge: br0 }
workloads:
  weird:
    kind: kubernetes
    image: alpine
    cpu: 1
    memory: 256
    network: [{ name: prod }]
`
	_, err := ParseBytes([]byte(in))
	if err == nil || !strings.Contains(err.Error(), "kubernetes") {
		t.Fatalf("expected unknown-kind error mentioning the bad value, got %v", err)
	}
}
