package grpcapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// seedCloneSource stages a stopped template VM with one real qcow2 disk and the
// given cpu_mode/cpu_model in its stored spec.
func seedCloneSource(t *testing.T, s *Server, name, cpuMode, cpuModel string) {
	t.Helper()
	ctx := adminCtx()
	srcDisk := s.images.DiskPath(name, "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 64*1024*1024, nil); err != nil {
		t.Fatalf("create source qcow2: %v", err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: name, Cpu: 2, MemoryMib: 2048, CpuMode: cpuMode, CpuModel: cpuModel,
	})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: name, HostName: "test-host", State: "stopped", IsTemplate: true, Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: "test-host", Path: srcDisk, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

func clonedSpec(t *testing.T, s *Server, name string) *pb.VMSpec {
	t.Helper()
	rec, err := corrosion.GetVM(adminCtx(), s.db, name)
	if err != nil || rec == nil {
		t.Fatalf("GetVM %s: rec=%v err=%v", name, rec, err)
	}
	var spec pb.VMSpec
	if uerr := json.Unmarshal([]byte(rec.Spec), &spec); uerr != nil {
		t.Fatalf("unmarshal cloned spec: %v", uerr)
	}
	return &spec
}

// A clone of a pre-default template must not inherit the qemu64 hazard. This
// mirrors the machine-type pin the clone path already does for the same reason:
// a brand-new domain should not start life carrying its source's latent problem.
func TestCloneVM_LegacySourceGetsTheCPUModeDefault(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	seedCloneSource(t, s, "tpl-legacy", "", "")

	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl-legacy", Target: "clone1", Mode: "full"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	if got := clonedSpec(t, s, "clone1").GetCpuMode(); got != lv.DefaultCPUMode {
		t.Fatalf("clone cpu_mode = %q, want %q", got, lv.DefaultCPUMode)
	}
	// And the DOMAIN must actually carry it — a spec that says host-model over a
	// domain with no <cpu> element would be a lie the guest never sees.
	domXML, err := s.virt.DumpXML("clone1")
	if err != nil {
		t.Fatalf("DumpXML: %v", err)
	}
	if !strings.Contains(domXML, `mode="`+lv.DefaultCPUMode+`"`) {
		t.Errorf("clone domain XML carries no %s cpu element:\n%s", lv.DefaultCPUMode, domXML)
	}
}

// A source that DOES name a mode is reproduced exactly — a clone is still a
// copy, and the default only fills a hole.
func TestCloneVM_ExplicitSourceCPUModeIsReproduced(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	seedCloneSource(t, s, "tpl-custom", lv.CPUModeCustom, "x86-64-v3")

	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl-custom", Target: "clone2", Mode: "full"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	spec := clonedSpec(t, s, "clone2")
	if spec.GetCpuMode() != lv.CPUModeCustom || spec.GetCpuModel() != "x86-64-v3" {
		t.Fatalf("clone cpu_mode/cpu_model = %q/%q, want custom/x86-64-v3",
			spec.GetCpuMode(), spec.GetCpuModel())
	}
}

// The node's configured default is honored by the clone path too, not just by
// create — otherwise an operator who opted their fleet into host-passthrough
// would get host-model clones.
func TestCloneVM_HonorsConfiguredDefaultCPUMode(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	s.SetDefaultCPUMode(lv.CPUModeHostPassthrough)
	seedCloneSource(t, s, "tpl-cfg", "", "")

	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl-cfg", Target: "clone3", Mode: "full"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	if got := clonedSpec(t, s, "clone3").GetCpuMode(); got != lv.CPUModeHostPassthrough {
		t.Fatalf("clone cpu_mode = %q, want the configured %q", got, lv.CPUModeHostPassthrough)
	}
}
