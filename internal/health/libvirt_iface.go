package health

import lv "github.com/litevirt/litevirt/internal/libvirt"

// LibvirtBackend is the exact subset of *libvirt.Client that the reconciler
// depends on (see every r.virt.* call in reconciler.go). Extracting it as an
// interface lets the in-process fleet harness drive the reconciler with a
// libvirt fake to assert cluster-wide invariants (e.g. no VM double-start),
// while production passes the real *lv.Client — which satisfies this interface
// unchanged.
//
// Keep this list aligned with the reconciler's usage: adding a r.virt.<method>
// call means adding it here (and to libvirtfake).
type LibvirtBackend interface {
	DomainExists(name string) bool
	DomainState(name string) (string, error)
	DomainStateReason(name string) (lv.DomainStatus, error)
	ListDomains() ([]string, error)
	DefineDomain(xmlConfig string) error
	StartDomain(name string) error
	DestroyDomain(name string) error
	UndefineDomain(name string, removeStorage bool) error
	UndefineDomainPreservingState(name string) error
}
