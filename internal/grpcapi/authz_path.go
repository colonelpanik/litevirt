package grpcapi

import (
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// projectRBACBase returns the RBAC path root for a (possibly hierarchical)
// project, e.g. "/projects/acme/team". It is the single place RBAC paths are
// built from a project, so callers never hand-concatenate "/projects/"+name
// (which produced double slashes and "acme" vs "/acme" drift).
//
// A malformed project (a '..'/slash-bearing name, e.g. from a polluted or
// peer-replicated row) must NOT silently map onto another tenant's path, so it
// canonicalizes to a sentinel that matches no normal grant — only a cluster-root
// "/" grant (full admin) can then act on it. Project names are validated at
// ingress (CreateVM/CreateProject/container create), so this is defense in depth.
func projectRBACBase(project string) string {
	canon, err := safename.CanonicalProjectName(tenancy.NormalizeProject(project))
	if err != nil {
		return "/projects/\x00invalid"
	}
	return safename.ProjectRBACPath(canon)
}

// safeRBACSegment returns name when it is a valid single path segment, else a
// sentinel that matches no normal grant. RBAC paths append it instead of the
// raw name so a path-like VM/container name (from a request not yet validated,
// or a polluted/replicated row) can't widen or escape the authorization path.
func safeRBACSegment(name string) string {
	if safename.ValidateName(name) != nil {
		return "\x00invalid"
	}
	return name
}

// vmRBACPath builds the canonical RBAC path for a VM from its record,
// honoring the VM's tenancy project rather than assuming "_default".
// This is the path used for RequirePerm checks on per-VM operations.
func vmRBACPath(vm *corrosion.VMRecord) string {
	return projectRBACBase(vm.Project) + "/vms/" + safeRBACSegment(vm.Name)
}

// vmRBACPathFor builds the canonical RBAC path for a VM from an explicit
// project + name. Used at sites (e.g. CreateVM) where no VMRecord exists
// yet because the VM is being created from a spec.
func vmRBACPathFor(project, name string) string {
	return projectRBACBase(project) + "/vms/" + safeRBACSegment(name)
}

// ctRBACPathFor builds the canonical RBAC path for a container from an explicit
// project + name — the container analogue of vmRBACPathFor. Used by every
// container RPC so the permission check honors the container's tenancy project
// rather than assuming "_default".
func ctRBACPathFor(project, name string) string {
	return projectRBACBase(project) + "/containers/" + safeRBACSegment(name)
}

// stackRBACPath builds the RBAC path for a stack under the default project,
// validating the stack-name segment (a path-like name yields a sentinel).
func stackRBACPath(stack string) string {
	return projectRBACBase(tenancy.Default) + "/stacks/" + safeRBACSegment(stack)
}
