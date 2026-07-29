package grpcapi

import (
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// hotplugFake exposes the injected libvirt fake for direct scenario setup.
func hotplugFake(t *testing.T, s *Server) *libvirtfake.Fake {
	t.Helper()
	f, ok := s.virt.(*libvirtfake.Fake)
	if !ok {
		t.Fatalf("expected a *libvirtfake.Fake backend, got %T", s.virt)
	}
	return f
}

// The bug these pin: DetachNIC has only a MAC to work from, so it marshals
// `<interface type="bridge">` with an EMPTY `<source>`. libvirt matches an
// interface by MAC BEFORE validating the device element, so that malformed
// source is never examined while the MAC is present — and is reported as
//
//	XML error: Missing required attribute 'bridge' in element 'source'
//
// the moment it is absent, which says nothing about the real problem.
//
// The pre-existing guard is a DATABASE lookup, so it only catches a MAC litevirt
// never recorded. It passes whenever the row exists but the live domain
// disagrees — the post-crash / failed-prior-detach / manual-virsh state — and
// that case is non-convergent: every retry reproduces the same misleading error
// because nothing clears it. Reproduced on a real cluster by removing a NIC with
// virsh behind litevirt's back and then asking litevirt to detach it.

const nicDomainXML = `<domain type='kvm'><devices>
  <interface type='bridge'>
    <mac address='52:54:00:AA:BB:CC'/>
    <source bridge='br0'/>
  </interface>
</devices></domain>`

func TestDetachNICIfPresent_DetachesWhenPresent(t *testing.T) {
	s := hotplugDiskServer(t)
	fake := hotplugFake(t, s)
	fake.SetActiveXML("vm1", nicDomainXML)

	if err := s.detachNICIfPresent("vm1", "52:54:00:aa:bb:cc"); err != nil {
		t.Fatalf("detach of a present NIC: %v", err)
	}
	if got := fake.DetachNICCount(); got != 1 {
		t.Fatalf("DetachNIC called %d times, want 1 — a present NIC must actually be detached", got)
	}
}

func TestDetachNICIfPresent_NoOpWhenAbsent(t *testing.T) {
	s := hotplugDiskServer(t)
	fake := hotplugFake(t, s)
	fake.SetActiveXML("vm1", nicDomainXML)

	// A MAC the live domain does not carry — the DB/live drift case. Reaching
	// libvirt here is what produces the misleading XML error.
	if err := s.detachNICIfPresent("vm1", "52:54:00:de:ad:be"); err != nil {
		t.Fatalf("absent NIC must be a no-op, got %v", err)
	}
	if got := fake.DetachNICCount(); got != 0 {
		t.Fatalf("DetachNIC called %d times for an absent NIC, want 0", got)
	}
}

// TestDetachNICIfPresent_ConvergesOnRetry is the property the no-op buys: an
// operator recovering from drift can retry and make progress, instead of hitting
// the same error forever.
func TestDetachNICIfPresent_ConvergesOnRetry(t *testing.T) {
	s := hotplugDiskServer(t)
	fake := hotplugFake(t, s)
	fake.SetActiveXML("vm1", nicDomainXML)

	const mac = "52:54:00:aa:bb:cc"
	if err := s.detachNICIfPresent("vm1", mac); err != nil {
		t.Fatalf("first detach: %v", err)
	}
	// Second call sees the NIC already gone and must succeed, not error.
	if err := s.detachNICIfPresent("vm1", mac); err != nil {
		t.Fatalf("retry after a completed detach must converge, got %v", err)
	}
	if got := fake.DetachNICCount(); got != 1 {
		t.Fatalf("DetachNIC called %d times across two attempts, want 1", got)
	}
}

// TestDetachNICIfPresent_FailsClosedOnDumpError: membership could not be
// confirmed, so the NIC must NOT be assumed gone — same posture as
// detachHostdevIfPresent.
func TestDetachNICIfPresent_FailsClosedOnDumpError(t *testing.T) {
	s := hotplugDiskServer(t)
	fake := hotplugFake(t, s)
	fake.FailDumpXML = func(string) error { return errors.New("libvirt unreachable") }

	err := s.detachNICIfPresent("vm1", "52:54:00:aa:bb:cc")
	if err == nil {
		t.Fatal("a DumpXML failure must fail closed, not be treated as already-detached")
	}
	if !strings.Contains(err.Error(), "libvirt unreachable") {
		t.Fatalf("got %v, want the underlying read failure surfaced", err)
	}
	if got := fake.DetachNICCount(); got != 0 {
		t.Fatalf("DetachNIC called %d times despite an unconfirmable read, want 0", got)
	}
}
