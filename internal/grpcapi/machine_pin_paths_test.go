package grpcapi

import (
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Every path that DEFINES a domain and then persists its spec must pin the
// concrete machine type the way CreateVM does. libvirt resolves an alias
// ("q35") against the local qemu at define time, so persisting the alias
// instead of the resolved value lets a later migration or failover re-resolve
// it on a host with a different qemu — silently shifting the guest ABI.
//
// pinMachineFromDomain is the shared helper those paths call. This pins its
// contract: it upgrades an alias to the resolved concrete type, leaves an
// already-concrete value alone, and never downgrades to an alias or empty when
// libvirt cannot answer.
func TestPinMachineFromDomain(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	if err := fake.DefineDomain(`<domain type='kvm'><name>resolved</name><os><type machine='pc-q35-9.0'>hvm</type></os></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>still-alias</name><os><type machine='q35'>hvm</type></os></domain>`); err != nil {
		t.Fatal(err)
	}
	s.virt = fake

	// Alias in, concrete out.
	spec := &pb.VMSpec{Name: "resolved", Machine: "q35"}
	s.pinMachineFromDomain(spec)
	if spec.Machine != "pc-q35-9.0" {
		t.Fatalf("machine = %q, want the resolved pc-q35-9.0", spec.Machine)
	}

	// Already concrete: untouched even though THIS host's domain would resolve
	// to a different concrete type. The stored value is the contract the VM was
	// created under; re-pinning it to the local answer is exactly the silent
	// ABI shift this whole mechanism exists to prevent.
	//
	// The domain here must resolve to a DIFFERENT CONCRETE type — pointing it
	// at an alias-only domain made this assertion vacuous (the alias would not
	// have been written either way), which mutation testing caught.
	concrete := &pb.VMSpec{Name: "resolved", Machine: "pc-i440fx-8.2"}
	s.pinMachineFromDomain(concrete)
	if concrete.Machine != "pc-i440fx-8.2" {
		t.Fatalf("a concrete machine type must not be rewritten, got %q", concrete.Machine)
	}

	// libvirt can only offer an alias → leave the spec as it was, never
	// "pin" an alias over another alias and never blank it.
	unresolvable := &pb.VMSpec{Name: "still-alias", Machine: "q35"}
	s.pinMachineFromDomain(unresolvable)
	if unresolvable.Machine != "q35" {
		t.Fatalf("machine = %q, want the original alias left alone", unresolvable.Machine)
	}

	// Domain absent entirely → unchanged, not blanked.
	absent := &pb.VMSpec{Name: "ghost", Machine: "q35"}
	s.pinMachineFromDomain(absent)
	if absent.Machine != "q35" {
		t.Fatalf("machine = %q, want q35 when the domain is absent", absent.Machine)
	}

	// Nil spec must not panic (promote/import call this on best-effort paths).
	s.pinMachineFromDomain(nil)

	// Sanity: the helper's notion of "concrete" is the shared one.
	if !lv.IsPinnedMachineType("pc-q35-9.0") || lv.IsPinnedMachineType("q35") {
		t.Fatal("IsPinnedMachineType contract changed")
	}
}

// The audit that motivated this: only create and the stopped-VM redefine pinned
// at define time, so a VM produced by import/promote persisted whatever alias
// its spec carried and relied on a later reconciler sweep to fix it. This
// asserts the two call sites are actually wired — a helper nothing calls is
// worth nothing.
func TestPersistPathsCallThePinHelper(t *testing.T) {
	for _, src := range []struct{ file, what string }{
		{"vmimport.go", "import"},
		{"promote.go", "promote"},
		{"templates.go", "clone"},
		{"restore_live_autostart.go", "restore"},
	} {
		body, err := readSource(src.file)
		if err != nil {
			t.Fatalf("read %s: %v", src.file, err)
		}
		if !strings.Contains(body, "pinMachineFromDomain") {
			t.Errorf("%s (%s) persists a VM spec but never calls pinMachineFromDomain — "+
				"an alias would be stored and only fixed by a later reconciler sweep",
				src.file, src.what)
		}
	}
}

func readSource(name string) (string, error) {
	b, err := os.ReadFile(name)
	return string(b), err
}
