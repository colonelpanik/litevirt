package grpcapi

import (
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// vmRBACPath builds the canonical RBAC path for a VM from its record,
// honoring the VM's tenancy project rather than assuming "_default".
// This is the path used for RequirePerm checks on per-VM operations.
func vmRBACPath(vm *corrosion.VMRecord) string {
	return "/projects/" + tenancy.NormalizeProject(vm.Project) + "/vms/" + vm.Name
}

// vmRBACPathFor builds the canonical RBAC path for a VM from an explicit
// project + name. Used at sites (e.g. CreateVM) where no VMRecord exists
// yet because the VM is being created from a spec.
func vmRBACPathFor(project, name string) string {
	return "/projects/" + tenancy.NormalizeProject(project) + "/vms/" + name
}

// ctRBACPathFor builds the canonical RBAC path for a container from an explicit
// project + name — the container analogue of vmRBACPathFor. Used by every
// container RPC so the permission check honors the container's tenancy project
// rather than assuming "_default".
func ctRBACPathFor(project, name string) string {
	return "/projects/" + tenancy.NormalizeProject(project) + "/containers/" + name
}
