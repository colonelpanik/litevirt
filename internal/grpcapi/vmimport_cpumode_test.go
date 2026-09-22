package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// An import DEFINES a brand-new domain, and the foreign source carries no
// litevirt cpu_mode. Without a default the imported guest gets no <cpu> element
// at all — QEMU's qemu64, with no SSE4.2/AVX/AVX2 — which is strictly further
// from the hardware the guest was installed on than the host-derived default is.
func TestImportVM_GetsTheCPUModeDefault(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()

	if err := importSmallVM(t, s, "imp-cpu", "", 512, false); err != nil {
		t.Fatalf("ImportVM: %v", err)
	}

	rec, err := corrosion.GetVM(context.Background(), s.db, "imp-cpu")
	if err != nil || rec == nil {
		t.Fatalf("GetVM: rec=%v err=%v", rec, err)
	}
	var spec pb.VMSpec
	if uerr := json.Unmarshal([]byte(rec.Spec), &spec); uerr != nil {
		t.Fatalf("unmarshal imported spec: %v", uerr)
	}
	if spec.GetCpuMode() != lv.DefaultCPUMode {
		t.Fatalf("imported cpu_mode = %q, want %q", spec.GetCpuMode(), lv.DefaultCPUMode)
	}

	// The DOMAIN must carry it too: a spec claiming host-model over a domain with
	// no <cpu> element is a lie the guest never benefits from.
	domXML, err := s.virt.DumpXML("imp-cpu")
	if err != nil {
		t.Fatalf("DumpXML: %v", err)
	}
	if !strings.Contains(domXML, `mode="`+lv.DefaultCPUMode+`"`) {
		t.Errorf("imported domain XML carries no %s cpu element:\n%s", lv.DefaultCPUMode, domXML)
	}
}

// The node's configured default applies to imports too.
func TestImportVM_HonorsConfiguredDefaultCPUMode(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	s.SetDefaultCPUMode(lv.CPUModeHostPassthrough)

	if err := importSmallVM(t, s, "imp-cfg", "", 512, false); err != nil {
		t.Fatalf("ImportVM: %v", err)
	}
	domXML, err := s.virt.DumpXML("imp-cfg")
	if err != nil {
		t.Fatalf("DumpXML: %v", err)
	}
	if !strings.Contains(domXML, `mode="`+lv.CPUModeHostPassthrough+`"`) {
		t.Errorf("imported domain XML does not carry the configured mode:\n%s", domXML)
	}
}
