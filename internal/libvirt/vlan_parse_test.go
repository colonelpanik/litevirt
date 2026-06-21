package libvirt

import "testing"

func TestParseTapDevice_Found(t *testing.T) {
	xmlStr := `<domain type='kvm'>
  <devices>
    <interface type='bridge'>
      <mac address='52:54:00:aa:bb:cc'/>
      <source bridge='br0'/>
      <target dev='vnet3'/>
    </interface>
    <interface type='bridge'>
      <mac address='52:54:00:dd:ee:ff'/>
      <source bridge='br0'/>
      <target dev='vnet4'/>
    </interface>
  </devices>
</domain>`
	dev, err := parseTapDevice(xmlStr, "test-vm", "52:54:00:dd:ee:ff")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev != "vnet4" {
		t.Errorf("dev = %q, want vnet4", dev)
	}
}

func TestParseTapDevice_CaseInsensitiveMAC(t *testing.T) {
	xmlStr := `<domain type='kvm'>
  <devices>
    <interface type='bridge'>
      <mac address='52:54:00:AA:BB:CC'/>
      <target dev='vnet0'/>
    </interface>
  </devices>
</domain>`
	dev, err := parseTapDevice(xmlStr, "test-vm", "52:54:00:aa:bb:cc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev != "vnet0" {
		t.Errorf("dev = %q, want vnet0", dev)
	}
}

func TestParseTapDevice_MACNotFound(t *testing.T) {
	xmlStr := `<domain type='kvm'>
  <devices>
    <interface type='bridge'>
      <mac address='52:54:00:aa:bb:cc'/>
      <target dev='vnet0'/>
    </interface>
  </devices>
</domain>`
	_, err := parseTapDevice(xmlStr, "test-vm", "52:54:00:11:22:33")
	if err == nil {
		t.Fatal("expected error for MAC not found")
	}
}

func TestParseTapDevice_EmptyTargetDev(t *testing.T) {
	xmlStr := `<domain type='kvm'>
  <devices>
    <interface type='bridge'>
      <mac address='52:54:00:aa:bb:cc'/>
      <target dev=''/>
    </interface>
  </devices>
</domain>`
	_, err := parseTapDevice(xmlStr, "test-vm", "52:54:00:aa:bb:cc")
	if err == nil {
		t.Fatal("expected error for empty target dev")
	}
}

func TestParseTapDevice_NoInterfaces(t *testing.T) {
	xmlStr := `<domain type='kvm'><devices></devices></domain>`
	_, err := parseTapDevice(xmlStr, "test-vm", "52:54:00:aa:bb:cc")
	if err == nil {
		t.Fatal("expected error for no interfaces")
	}
}

func TestParseTapDevice_InvalidXML(t *testing.T) {
	_, err := parseTapDevice("<<<not xml>>>", "test-vm", "52:54:00:aa:bb:cc")
	if err == nil {
		t.Fatal("expected error for invalid XML")
	}
}

func TestParseTapDevice_NoTargetElement(t *testing.T) {
	xmlStr := `<domain type='kvm'>
  <devices>
    <interface type='bridge'>
      <mac address='52:54:00:aa:bb:cc'/>
      <source bridge='br0'/>
    </interface>
  </devices>
</domain>`
	_, err := parseTapDevice(xmlStr, "test-vm", "52:54:00:aa:bb:cc")
	if err == nil {
		t.Fatal("expected error for missing target element")
	}
}
