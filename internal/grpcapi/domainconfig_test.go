package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// TestBaseDomainConfig_BalloonAndHostdevs proves the shared builder populates the
// memory bounds (balloon ceiling) and PCI hostdevs — the two fields the old inline
// redefine builder dropped, collapsing the balloon and detaching passthrough.
func TestBaseDomainConfig_BalloonAndHostdevs(t *testing.T) {
	spec := &pb.VMSpec{
		Name: "vm1", Uuid: "11111111-1111-1111-1111-111111111111",
		Cpu: 4, MemoryMib: 4096, MinMemoryMib: 2048, MaxMemoryMib: 8192,
		Machine: "q35",
	}
	cfg := baseDomainConfig(spec,
		[]lv.DiskConfig{{Name: "root", Path: "/var/lib/x.qcow2", Bus: "virtio"}},
		nil,
		[]lv.HostdevConfig{{Address: "0000:01:00.0"}})

	if cfg.MinMemoryMiB != 2048 || cfg.MaxMemoryMiB != 8192 {
		t.Errorf("mem bounds not carried: min=%d max=%d", cfg.MinMemoryMiB, cfg.MaxMemoryMiB)
	}
	if len(cfg.Hostdevs) != 1 || cfg.Hostdevs[0].Address != "0000:01:00.0" {
		t.Errorf("hostdevs not carried: %+v", cfg.Hostdevs)
	}

	xml, err := lv.GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	// Balloon ceiling set ⇒ <currentMemory> emitted (boot alloc < ceiling).
	if !strings.Contains(xml, "currentMemory") {
		t.Errorf("balloon ceiling collapsed — no <currentMemory>:\n%s", xml)
	}
	// Passthrough device present.
	if !strings.Contains(xml, "<hostdev") || !strings.Contains(xml, "0x01") {
		t.Errorf("hostdev dropped from generated XML:\n%s", xml)
	}
}
