package grpcapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// ── test helpers ──────────────────────────────────────────────────────────

// backfillServer returns a Server with a fake libvirt backend wired so the PCI
// compatibility audit can read inactive domain XML.
func backfillServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := testServer(t)
	f := libvirtfake.New()
	s.virt = f
	return s, f
}

// hostdevXML renders one <hostdev> whose source address is bdf, in the exact
// 0x-attribute form libvirt emits (see xmlgen's marshalNewHostdev).
func hostdevXML(bdf string) string {
	p := libvirt.ParsePCIAddress(bdf)
	return fmt.Sprintf(
		`<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='%s' bus='%s' slot='%s' function='%s'/></source></hostdev>`,
		p.Domain, p.Bus, p.Slot, p.Function)
}

// domainXMLWith wraps zero or more device fragments in a minimal but
// structurally-valid persistent domain document.
func domainXMLWith(name string, devices ...string) string {
	return `<domain type='kvm'><name>` + name + `</name><devices>` +
		strings.Join(devices, "") + `</devices></domain>`
}

// specJSON marshals a VMSpec exactly the way CreateVM persists it: encoding/json
// (NOT protojson) — the blob format the backfill parses.
func specJSON(t *testing.T, spec *pb.VMSpec) string {
	t.Helper()
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("json.Marshal(spec): %v", err)
	}
	return string(b)
}

// ── Test 1: duplicate identical selectors → distinct intent ids ─────────────

// TestBackfillHardwareTables_DuplicateSelectors_DistinctIDs: a VM whose blob has
// two identical type=gpu DeviceSpecs (both present in the inactive XML) backfills
// to two vm_pci_intent rows with DISTINCT device_ids (occurrence ordinal), not
// one collapsed row.
func TestBackfillHardwareTables_DuplicateSelectors_DistinctIDs(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{Devices: []*pb.DeviceSpec{
		{Type: "gpu"},
		{Type: "gpu"},
	}}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "dup-gpu", HostName: "test-host", State: "running", Spec: specJSON(t, spec),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Two GPU hostdevs present in the persistent definition.
	f.SetInactiveXML("dup-gpu", domainXMLWith("dup-gpu",
		hostdevXML("0000:41:00.0"), hostdevXML("0000:42:00.0")))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}

	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "dup-gpu")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 2 {
		t.Fatalf("got %d intents, want 2 (distinct occurrence ids): %+v", len(intents), intents)
	}
	if intents[0].DeviceID == intents[1].DeviceID {
		t.Fatalf("duplicate selectors collapsed to one device_id %q", intents[0].DeviceID)
	}
	for _, in := range intents {
		if in.SelectorKind != "type" {
			t.Errorf("selector_kind = %q, want type", in.SelectorKind)
		}
		if in.ExclusiveKey != nil {
			t.Errorf("portable type selector must not host-pin (exclusive_key=%v)", *in.ExclusiveKey)
		}
	}
	if state, _, _ := corrosion.GetHardwareAdoptionState(ctx, s.db, "dup-gpu"); state != "adopted" {
		t.Errorf("adoption state = %q, want adopted", state)
	}
}

// ── Test 2: blob device absent from inactive XML is NOT resurrected ─────────

func TestBackfillHardwareTables_ResurrectionPrevented(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{Devices: []*pb.DeviceSpec{{Address: "0000:99:00.0"}}}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "detached", HostName: "test-host", State: "stopped", Spec: specJSON(t, spec),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Device was legacy-detached: the persistent definition has NO hostdev.
	f.SetInactiveXML("detached", domainXMLWith("detached"))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}

	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "detached")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 0 {
		t.Fatalf("resurrected a detached device: got %d intents, want 0: %+v", len(intents), intents)
	}
	if state, _, _ := corrosion.GetHardwareAdoptionState(ctx, s.db, "detached"); state != "adopted" {
		t.Errorf("adoption state = %q, want adopted (nothing to import is clean)", state)
	}
}

// ── Test 3: lease-only device (owned, absent from XML) is quarantined ───────

func TestBackfillHardwareTables_LeaseOnlyQuarantine(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "leaky", HostName: "test-host", State: "stopped", Spec: "",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// The VM owns a device in host_pci_devices, but it is NOT in the inactive XML
	// (a stale/incomplete-detach remnant).
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:aa:00.0", Type: "gpu",
	}); err != nil {
		t.Fatalf("ObservePCIDevice: %v", err)
	}
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", "0000:aa:00.0", "leaky"); err != nil {
		t.Fatalf("AssignPCIDevice: %v", err)
	}
	f.SetInactiveXML("leaky", domainXMLWith("leaky"))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}

	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "leaky")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 0 {
		t.Fatalf("lease-only remnant imported as intent: got %d, want 0: %+v", len(intents), intents)
	}
	// VM is still classifiable — the quarantine does not block adoption.
	if state, _, _ := corrosion.GetHardwareAdoptionState(ctx, s.db, "leaky"); state != "adopted" {
		t.Errorf("adoption state = %q, want adopted", state)
	}
}

// ── Test 4: no inactive def → blocked; another VM in the same pass adopts ───

func TestBackfillHardwareTables_NoInactiveDef_Blocked_PerVMIsolation(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "nodef", HostName: "test-host", State: "running", Spec: "",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM nodef: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "healthy", HostName: "test-host", State: "running", Spec: "",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM healthy: %v", err)
	}
	// nodef: NO inactive XML seeded → DumpXMLInactive errors.
	f.SetInactiveXML("healthy", domainXMLWith("healthy"))

	// Backfill must still return nil even though one VM blocks.
	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables returned error on a blocked VM: %v", err)
	}

	st, reason, _ := corrosion.GetHardwareAdoptionState(ctx, s.db, "nodef")
	if st != "blocked" {
		t.Errorf("nodef adoption state = %q, want blocked", st)
	}
	if reason == "" {
		t.Errorf("nodef blocked with empty reason")
	}
	if st, _, _ := corrosion.GetHardwareAdoptionState(ctx, s.db, "healthy"); st != "adopted" {
		t.Errorf("healthy adoption state = %q, want adopted (pass continued past the blocked VM)", st)
	}
}

// ── Test 5: mapping-backed device (mapping + resolved address) → mapping ────

func TestBackfillHardwareTables_MappingClassification(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{Devices: []*pb.DeviceSpec{
		{Mapping: "gpu-pool", Address: "0000:41:00.0"}, // resolved address frozen back
	}}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "mapped", HostName: "test-host", State: "running", Spec: specJSON(t, spec),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	f.SetInactiveXML("mapped", domainXMLWith("mapped", hostdevXML("0000:41:00.0")))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}

	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "mapped")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("got %d intents, want 1: %+v", len(intents), intents)
	}
	if intents[0].SelectorKind != "mapping" {
		t.Errorf("selector_kind = %q, want mapping", intents[0].SelectorKind)
	}
	if intents[0].ExclusiveKey != nil {
		t.Errorf("mapping-backed device must not host-pin (exclusive_key=%v)", *intents[0].ExclusiveKey)
	}
}

// ── Test 6: NIC backfill deterministic + idempotent + two-peer convergence ──

func TestBackfillHardwareTables_NICDeterministicIdempotent(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "netvm", HostName: "test-host", State: "running", Spec: "",
	}, []corrosion.InterfaceRecord{
		{VMName: "netvm", NetworkName: "lan", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: "10.0.0.5", TapDevice: "tap0", SecurityGroups: []string{"web"}},
		{VMName: "netvm", NetworkName: "dmz", Ordinal: 1, MAC: "52:54:00:aa:bb:02"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	f.SetInactiveXML("netvm", domainXMLWith("netvm"))

	// Run twice — must be idempotent (identical rows, no duplicates).
	for i := 0; i < 2; i++ {
		if err := s.BackfillHardwareTables(ctx); err != nil {
			t.Fatalf("BackfillHardwareTables run %d: %v", i, err)
		}
	}

	nics, err := corrosion.GetVMNICsRaw(ctx, s.db, "vm_nics", "netvm")
	if err != nil {
		t.Fatalf("GetVMNICsRaw: %v", err)
	}
	var live []corrosion.NICRecord
	for _, n := range nics {
		if n.DeletedAt == "" {
			live = append(live, n)
		}
	}
	if len(live) != 2 {
		t.Fatalf("got %d live vm_nics rows, want 2 (idempotent): %+v", len(live), live)
	}
	byMAC := map[string]corrosion.NICRecord{}
	for _, n := range live {
		byMAC[n.MAC] = n
		wantID := corrosion.DeterministicNICID("netvm", n.MAC)
		if n.ID != wantID {
			t.Errorf("nic %s id = %q, want deterministic %q", n.MAC, n.ID, wantID)
		}
		if n.Model != "virtio" {
			t.Errorf("nic %s model = %q, want virtio", n.MAC, n.Model)
		}
	}
	if got := byMAC["52:54:00:aa:bb:01"]; got.IP != "10.0.0.5" || got.TapDevice != "tap0" || got.NetworkName != "lan" {
		t.Errorf("nic carry-through wrong: %+v", got)
	}
	if got := byMAC["52:54:00:aa:bb:01"].SecurityGroups; got == "" || !strings.Contains(got, "web") {
		t.Errorf("security_groups not carried: %q", got)
	}
}

// TestBackfillHardwareTables_TwoPeerConvergence: two peers (distinct hostNames)
// on a shared DB backfill the SAME VM's NIC. Because the NIC id is a pure
// function of (vmName, mac) — host-independent — both derive the byte-identical
// id and converge to ONE vm_nics row, never a per-peer duplicate.
func TestBackfillHardwareTables_TwoPeerConvergence(t *testing.T) {
	ctx := adminCtx()
	suffix := "hwbackfill-converge"

	clientA, err := corrosion.NewSharedTestClient(suffix, "host-a")
	if err != nil {
		t.Fatalf("NewSharedTestClient A: %v", err)
	}
	if err := corrosion.InitSchema(ctx, clientA); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	clientB, err := corrosion.NewSharedTestClient(suffix, "host-b")
	if err != nil {
		t.Fatalf("NewSharedTestClient B: %v", err)
	}

	fA, fB := libvirtfake.New(), libvirtfake.New()
	fA.SetInactiveXML("shared", domainXMLWith("shared"))
	fB.SetInactiveXML("shared", domainXMLWith("shared"))
	sA := &Server{hostName: "host-a", db: clientA, virt: fA, events: events.NewBus()}
	sB := &Server{hostName: "host-b", db: clientB, virt: fB, events: events.NewBus()}

	if err := corrosion.InsertVM(ctx, clientA, corrosion.VMRecord{
		Name: "shared", HostName: "host-a", State: "running", Spec: "",
	}, []corrosion.InterfaceRecord{
		{VMName: "shared", NetworkName: "lan", Ordinal: 0, MAC: "52:54:00:cc:dd:ee"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Peer A (owner) backfills.
	if err := sA.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("A backfill: %v", err)
	}
	// Ownership moves to peer B; B backfills the same VM.
	if err := corrosion.UpdateVMHost(ctx, clientB, "shared", "host-b", "running"); err != nil {
		t.Fatalf("UpdateVMHost: %v", err)
	}
	if err := sB.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("B backfill: %v", err)
	}

	nics, err := corrosion.GetVMNICsRaw(ctx, clientA, "vm_nics", "shared")
	if err != nil {
		t.Fatalf("GetVMNICsRaw: %v", err)
	}
	var live int
	for _, n := range nics {
		if n.DeletedAt == "" {
			live++
			if n.ID != corrosion.DeterministicNICID("shared", "52:54:00:cc:dd:ee") {
				t.Errorf("converged id mismatch: %q", n.ID)
			}
		}
	}
	if live != 1 {
		t.Fatalf("two peers produced %d live vm_nics rows, want 1 (converged): %+v", live, nics)
	}
}

// ── Test 7: disk-bus backfill from VMSpec.Disks (+ legacy heuristic) ────────

func TestBackfillHardwareTables_DiskBusFromSpec(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{Disks: []*pb.DiskSpec{
		{Name: "root", Bus: "sata"}, // explicit spec bus
		{Name: "data"},              // no spec bus → legacy target-dev heuristic
	}}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "diskvm", HostName: "test-host", State: "running", Spec: specJSON(t, spec),
	}, nil, []corrosion.DiskRecord{
		{VMName: "diskvm", DiskName: "root", HostName: "test-host", Path: "/d/root.qcow2", TargetDev: "vda"}, // Bus empty
		{VMName: "diskvm", DiskName: "data", HostName: "test-host", Path: "/d/data.qcow2", TargetDev: "sdb"}, // Bus empty
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	f.SetInactiveXML("diskvm", domainXMLWith("diskvm"))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}

	disks, err := corrosion.GetVMDisks(ctx, s.db, "diskvm")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	got := map[string]string{}
	for _, d := range disks {
		got[d.DiskName] = d.Bus
	}
	if got["root"] != "sata" {
		t.Errorf("root bus = %q, want sata (from spec)", got["root"])
	}
	if got["data"] != "scsi" {
		t.Errorf("data bus = %q, want scsi (sdb heuristic)", got["data"])
	}

	// Idempotent: a second run must not change the (now-populated) buses.
	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables rerun: %v", err)
	}
	disks2, _ := corrosion.GetVMDisks(ctx, s.db, "diskvm")
	for _, d := range disks2 {
		if d.Bus != got[d.DiskName] {
			t.Errorf("disk %s bus changed on rerun: %q -> %q", d.DiskName, got[d.DiskName], d.Bus)
		}
	}
}

// ── Test 8: selector_payload is protojson and round-trips through the resolver

func TestBackfillHardwareTables_SelectorPayloadProtojsonRoundTrip(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{Devices: []*pb.DeviceSpec{{Type: "gpu", Vendor: "10de"}}}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "rtvm", HostName: "test-host", State: "running", Spec: specJSON(t, spec),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// A matching host device + a hostdev present in the inactive definition.
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de",
	}); err != nil {
		t.Fatalf("ObservePCIDevice: %v", err)
	}
	f.SetInactiveXML("rtvm", domainXMLWith("rtvm", hostdevXML("0000:41:00.0")))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}

	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "rtvm")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("got %d intents, want 1: %+v", len(intents), intents)
	}
	// selector_payload must decode via protojson (the resolver's contract).
	var decoded pb.DeviceSpec
	if err := protojson.Unmarshal([]byte(intents[0].SelectorPayload), &decoded); err != nil {
		t.Fatalf("selector_payload not protojson-decodable: %v\npayload=%s", err, intents[0].SelectorPayload)
	}
	if decoded.Type != "gpu" || decoded.Vendor != "10de" {
		t.Errorf("decoded spec = %+v, want type=gpu vendor=10de", &decoded)
	}
	// End-to-end: the pure resolver decodes the backfilled intent and resolves it.
	members, err := s.resolveDeviceIntents(ctx, "rtvm", intents)
	if err != nil {
		t.Fatalf("resolveDeviceIntents on backfilled intent: %v", err)
	}
	if len(members) != 1 || members[0].Address != "0000:41:00.0" {
		t.Fatalf("resolver members = %+v, want one at 0000:41:00.0", members)
	}
}

// ── Test 9: ambiguous portable ↔ member grouping → blocked (fail-closed) ────

// A single portable selector cannot account for two unclaimed XML members
// (e.g. an IOMMU-group sibling): the pairing is ambiguous, so the VM is blocked
// rather than coalesced into a wrong intent set. The backfill still returns nil.
func TestBackfillHardwareTables_AmbiguousPortableGrouping_Blocked(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{Devices: []*pb.DeviceSpec{{Type: "gpu"}}}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "ambig", HostName: "test-host", State: "running", Spec: specJSON(t, spec),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	f.SetInactiveXML("ambig", domainXMLWith("ambig",
		hostdevXML("0000:41:00.0"), hostdevXML("0000:41:00.1")))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}
	if st, _, _ := corrosion.GetHardwareAdoptionState(ctx, s.db, "ambig"); st != "blocked" {
		t.Errorf("adoption state = %q, want blocked (ambiguous grouping)", st)
	}
	// Nothing imported on a block.
	intents, _ := corrosion.ListVMPCIIntents(ctx, s.db, "ambig")
	if len(intents) != 0 {
		t.Errorf("blocked VM imported %d intents, want 0", len(intents))
	}
}

// ── Test 10: multifunction GPU adopts as ONE portable intent (IOMMU-aware) ──

// TestAuditVMPCICompatibility_MultifunctionGPUAdoptsAsOnePortableIntent guards the
// COMMON default "GPU Passthrough" profile: a bare {Type:"gpu"} selector whose
// primary is a multifunction card (GPU + HDMI-audio function share one IOMMU
// group). At create, resolveDeviceSpec expands the primary to its IOMMU-group
// siblings, so the persistent definition carries TWO <hostdev>s. The audit must
// attribute BOTH members to the ONE portable intent (they are the primary + its
// IOMMU-group sibling) and adopt — NOT block as "1 selector < 2 members".
func TestAuditVMPCICompatibility_MultifunctionGPUAdoptsAsOnePortableIntent(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{Devices: []*pb.DeviceSpec{{Type: "gpu"}}} // default profile: bare type selector
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "mfgpu", HostName: "test-host", State: "running", Spec: specJSON(t, spec),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// GPU + its HDMI-audio function share ONE IOMMU group (the discrete-card norm).
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:41:00.0", Type: "gpu", IOMMUGroup: 21,
	}); err != nil {
		t.Fatalf("ObservePCIDevice gpu: %v", err)
	}
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:41:00.1", Type: "audio", IOMMUGroup: 21,
	}); err != nil {
		t.Fatalf("ObservePCIDevice audio: %v", err)
	}
	f.SetInactiveXML("mfgpu", domainXMLWith("mfgpu",
		hostdevXML("0000:41:00.0"), hostdevXML("0000:41:00.1")))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}

	if st, reason, _ := corrosion.GetHardwareAdoptionState(ctx, s.db, "mfgpu"); st != "adopted" {
		t.Fatalf("adoption state = %q (reason %q), want adopted (multifunction GPU is one portable intent)", st, reason)
	}
	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "mfgpu")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("got %d intents, want exactly 1 portable intent: %+v", len(intents), intents)
	}
	if intents[0].SelectorKind != "type" {
		t.Errorf("selector_kind = %q, want type", intents[0].SelectorKind)
	}
	if intents[0].ExclusiveKey != nil {
		t.Errorf("portable type selector must not host-pin (exclusive_key=%v)", *intents[0].ExclusiveKey)
	}
	// The ONE intent re-expands to primary + IOMMU-group sibling (both members).
	members, err := s.resolveDeviceIntents(ctx, "mfgpu", intents)
	if err != nil {
		t.Fatalf("resolveDeviceIntents on adopted intent: %v", err)
	}
	got := map[string]bool{}
	for _, m := range members {
		got[m.Address] = true
	}
	if len(got) != 2 || !got["0000:41:00.0"] || !got["0000:41:00.1"] {
		t.Fatalf("intent resolved to %v, want both 0000:41:00.0 and 0000:41:00.1", got)
	}
}

// ── Test 11: mapping selector's IOMMU sibling absorbed, not host-pinned ─────

// TestAuditVMPCICompatibility_MappingSiblingAbsorbedNotHostPinned guards the Minor:
// a {Mapping,Address} selector resolved onto a multifunction card produces a second
// <hostdev> for the audio sibling. That sibling belongs to the SAME (portable)
// mapping intent — it re-expands from the mapping's resolved primary — NOT a
// separate host-pinned concrete-address intent.
func TestAuditVMPCICompatibility_MappingSiblingAbsorbedNotHostPinned(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{Devices: []*pb.DeviceSpec{
		{Mapping: "gpu-pool", Address: "0000:41:00.0"}, // resolved address frozen back
	}}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "mapsib", HostName: "test-host", State: "running", Spec: specJSON(t, spec),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:41:00.0", Type: "gpu", IOMMUGroup: 21,
	}); err != nil {
		t.Fatalf("ObservePCIDevice gpu: %v", err)
	}
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:41:00.1", Type: "audio", IOMMUGroup: 21,
	}); err != nil {
		t.Fatalf("ObservePCIDevice audio: %v", err)
	}
	f.SetInactiveXML("mapsib", domainXMLWith("mapsib",
		hostdevXML("0000:41:00.0"), hostdevXML("0000:41:00.1")))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}
	if st, reason, _ := corrosion.GetHardwareAdoptionState(ctx, s.db, "mapsib"); st != "adopted" {
		t.Fatalf("adoption state = %q (reason %q), want adopted", st, reason)
	}
	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "mapsib")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("got %d intents, want exactly 1 mapping intent (sibling absorbed): %+v", len(intents), intents)
	}
	if intents[0].SelectorKind != "mapping" {
		t.Errorf("selector_kind = %q, want mapping (portable)", intents[0].SelectorKind)
	}
	if intents[0].ExclusiveKey != nil {
		t.Errorf("mapping intent must not host-pin (exclusive_key=%v)", *intents[0].ExclusiveKey)
	}
}

// ── Test 12: genuinely-ambiguous non-sibling members STILL block ────────────

// TestAuditVMPCICompatibility_NonSiblingMembersStillBlock guards the preserved
// fail-closed posture: two XML members in DIFFERENT IOMMU groups are two
// independent passthrough units, which one portable selector cannot account for.
// This is genuine ambiguity (not a multifunction expansion) and must still block.
func TestAuditVMPCICompatibility_NonSiblingMembersStillBlock(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{Devices: []*pb.DeviceSpec{{Type: "gpu"}}}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "genambig", HostName: "test-host", State: "running", Spec: specJSON(t, spec),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Two members in DISTINCT IOMMU groups: NOT a multifunction unit.
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:41:00.0", Type: "gpu", IOMMUGroup: 21,
	}); err != nil {
		t.Fatalf("ObservePCIDevice gpu: %v", err)
	}
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:60:00.0", Type: "nic", IOMMUGroup: 33,
	}); err != nil {
		t.Fatalf("ObservePCIDevice nic: %v", err)
	}
	f.SetInactiveXML("genambig", domainXMLWith("genambig",
		hostdevXML("0000:41:00.0"), hostdevXML("0000:60:00.0")))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}
	if st, _, _ := corrosion.GetHardwareAdoptionState(ctx, s.db, "genambig"); st != "blocked" {
		t.Errorf("adoption state = %q, want blocked (two independent IOMMU-group units, one selector)", st)
	}
	intents, _ := corrosion.ListVMPCIIntents(ctx, s.db, "genambig")
	if len(intents) != 0 {
		t.Errorf("blocked VM imported %d intents, want 0", len(intents))
	}
}

// TestBackfillHardwareTables_ConcreteMembersNoSpec: XML members with no matching
// rich spec (e.g. an IOMMU sibling, or an address device the blob doesn't carry)
// import as concrete-address intents when there are no portable selectors.
func TestBackfillHardwareTables_ConcreteMembersNoSpec(t *testing.T) {
	s, f := backfillServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "bare", HostName: "test-host", State: "running", Spec: "",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	f.SetInactiveXML("bare", domainXMLWith("bare",
		hostdevXML("0000:07:00.0"), hostdevXML("0000:07:00.1")))

	if err := s.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("BackfillHardwareTables: %v", err)
	}
	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "bare")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 2 {
		t.Fatalf("got %d intents, want 2 concrete-address: %+v", len(intents), intents)
	}
	for _, in := range intents {
		if in.SelectorKind != "address" {
			t.Errorf("selector_kind = %q, want address", in.SelectorKind)
		}
		if in.ExclusiveKey == nil {
			t.Errorf("concrete-address intent must host-pin (exclusive_key nil) for %s", in.DeviceID)
		}
	}
}

// ── Bridge: continuous legacy vm_interfaces → vm_nics materialization ────────

// liveNICs returns the LIVE (non-tombstoned) vm_nics rows for vm.
func liveNICs(t *testing.T, s *Server, vm string) []corrosion.NICRecord {
	t.Helper()
	all, err := corrosion.GetVMNICsRaw(adminCtx(), s.db, "vm_nics", vm)
	if err != nil {
		t.Fatalf("GetVMNICsRaw(vm_nics): %v", err)
	}
	var live []corrosion.NICRecord
	for _, n := range all {
		if n.DeletedAt == "" {
			live = append(live, n)
		}
	}
	return live
}

// TestHardwareBridge_MaterializesLegacyInterfaceIntoVMNics: an OLD peer that still
// writes only vm_interfaces (never vm_nics) has its live NIC materialized into
// vm_nics by one bridge pass, under the deterministic (vm_name, mac) id. The NIC is
// already visible through the MergedVMNICs overlay BEFORE the bridge runs (the
// overlay's job — a sanity check). The pass is idempotent: a second run rewrites
// nothing (identical rows, same updated_at).
func TestHardwareBridge_MaterializesLegacyInterfaceIntoVMNics(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// A VM owned by a DIFFERENT host models an old peer's VM.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "old-peer", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	mac := "52:54:00:aa:bb:cc"
	if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
		VMName: "vm1", NetworkName: "net0", Ordinal: 0, MAC: mac, IP: "10.0.0.5",
	}); err != nil {
		t.Fatalf("InsertInterface: %v", err)
	}

	// Sanity (late-write visibility): the overlay shows the legacy NIC even before
	// the bridge materializes it into vm_nics.
	pre, err := corrosion.MergedVMNICs(ctx, s.db, "vm1")
	if err != nil {
		t.Fatalf("MergedVMNICs: %v", err)
	}
	if len(pre) != 1 || !strings.EqualFold(pre[0].MAC, mac) {
		t.Fatalf("overlay must show the legacy NIC before materialization: %+v", pre)
	}
	if len(liveNICs(t, s, "vm1")) != 0 {
		t.Fatal("vm_nics must be empty before the bridge runs")
	}

	// One bridge pass materializes it.
	if err := s.hardwareBridgeOnce(ctx); err != nil {
		t.Fatalf("hardwareBridgeOnce: %v", err)
	}
	live := liveNICs(t, s, "vm1")
	if len(live) != 1 {
		t.Fatalf("want 1 live vm_nics row after bridge, got %d: %+v", len(live), live)
	}
	if want := corrosion.DeterministicNICID("vm1", mac); live[0].ID != want {
		t.Fatalf("vm_nics id = %q, want deterministic %q", live[0].ID, want)
	}
	if live[0].NetworkName != "net0" || live[0].IP != "10.0.0.5" || live[0].Model != "virtio" {
		t.Fatalf("materialized fields mismatch: %+v", live[0])
	}

	// Idempotent: a second pass must not rewrite (same updated_at).
	beforeTS := live[0].UpdatedAt
	if err := s.hardwareBridgeOnce(ctx); err != nil {
		t.Fatalf("hardwareBridgeOnce (2nd): %v", err)
	}
	live2 := liveNICs(t, s, "vm1")
	if len(live2) != 1 || live2[0].UpdatedAt != beforeTS {
		t.Fatalf("bridge not idempotent: beforeTS=%q after=%+v", beforeTS, live2)
	}
}

// TestHardwareBridge_TombstonePropagatesToVMNics: after materialization, an old
// peer tombstoning the vm_interfaces row (a NIC detach) is propagated to vm_nics by
// the next bridge pass; the overlay then reports zero live NICs. Idempotent: a
// further pass rewrites nothing (the vm_nics row is already tombstoned).
func TestHardwareBridge_TombstonePropagatesToVMNics(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "old-peer", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	mac := "52:54:00:de:ad:be"
	if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
		VMName: "vm1", NetworkName: "net0", Ordinal: 0, MAC: mac,
	}); err != nil {
		t.Fatalf("InsertInterface: %v", err)
	}
	if err := s.hardwareBridgeOnce(ctx); err != nil {
		t.Fatalf("hardwareBridgeOnce (materialize): %v", err)
	}
	if len(liveNICs(t, s, "vm1")) != 1 {
		t.Fatal("expected the NIC materialized into vm_nics")
	}

	// Old peer detaches → tombstones the legacy row only.
	if err := corrosion.SoftDeleteInterfaceByMAC(ctx, s.db, "vm1", mac); err != nil {
		t.Fatalf("SoftDeleteInterfaceByMAC: %v", err)
	}
	// Bridge propagates the tombstone to vm_nics.
	if err := s.hardwareBridgeOnce(ctx); err != nil {
		t.Fatalf("hardwareBridgeOnce (tombstone): %v", err)
	}
	if live := liveNICs(t, s, "vm1"); len(live) != 0 {
		t.Fatalf("vm_nics NIC must be tombstoned after the legacy tombstone: %+v", live)
	}
	merged, err := corrosion.MergedVMNICs(ctx, s.db, "vm1")
	if err != nil {
		t.Fatalf("MergedVMNICs: %v", err)
	}
	if len(merged) != 0 {
		t.Fatalf("overlay must report 0 live NICs after tombstone: %+v", merged)
	}

	// Idempotent: another pass rewrites nothing.
	rawBefore, _ := corrosion.GetVMNICsRaw(ctx, s.db, "vm_nics", "vm1")
	if err := s.hardwareBridgeOnce(ctx); err != nil {
		t.Fatalf("hardwareBridgeOnce (idempotent): %v", err)
	}
	rawAfter, _ := corrosion.GetVMNICsRaw(ctx, s.db, "vm_nics", "vm1")
	if len(rawBefore) != 1 || len(rawAfter) != 1 || rawBefore[0].UpdatedAt != rawAfter[0].UpdatedAt {
		t.Fatalf("tombstone bridge not idempotent: before=%+v after=%+v", rawBefore, rawAfter)
	}
}

// TestHardwareBridge_DoesNotRegressNewerVMNics: the bridge must NEVER clobber a
// vm_nics row that a hardware_v2 writer produced MORE RECENTLY than the legacy
// vm_interfaces row (LWW guard). A stale legacy row must not overwrite a fresh
// vm_nics row's fields.
func TestHardwareBridge_DoesNotRegressNewerVMNics(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "old-peer", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	mac := "52:54:00:11:22:33"
	// Stale legacy row (written first → older updated_at).
	if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
		VMName: "vm1", NetworkName: "old-net", Ordinal: 0, MAC: mac, IP: "10.0.0.9",
	}); err != nil {
		t.Fatalf("InsertInterface: %v", err)
	}
	// A newer authoritative vm_nics row (as a hardware_v2 writer would produce),
	// same deterministic id, different network.
	id := corrosion.DeterministicNICID("vm1", mac)
	if err := corrosion.UpsertNIC(ctx, s.db, corrosion.NICRecord{
		VMName: "vm1", ID: id, NetworkName: "new-net", Model: "virtio", MAC: mac, Ordinal: 0, IP: "10.0.0.10",
	}); err != nil {
		t.Fatalf("UpsertNIC: %v", err)
	}
	beforeTS := liveNICs(t, s, "vm1")[0].UpdatedAt

	if err := s.hardwareBridgeOnce(ctx); err != nil {
		t.Fatalf("hardwareBridgeOnce: %v", err)
	}
	live := liveNICs(t, s, "vm1")
	if len(live) != 1 {
		t.Fatalf("want 1 vm_nics row, got %d: %+v", len(live), live)
	}
	if live[0].NetworkName != "new-net" || live[0].IP != "10.0.0.10" || live[0].UpdatedAt != beforeTS {
		t.Fatalf("bridge regressed a newer vm_nics row with stale legacy data: %+v", live[0])
	}
}
