package libvirt

import "testing"

func TestParseConsolePTYPath_Found(t *testing.T) {
	xmlStr := `<domain type='kvm'>
  <devices>
    <console type='pty'>
      <source path='/dev/pts/3'/>
      <target type='serial' port='0'/>
    </console>
  </devices>
</domain>`
	path, err := parseConsolePTYPath(xmlStr, "test-vm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/dev/pts/3" {
		t.Errorf("path = %q, want /dev/pts/3", path)
	}
}

func TestParseConsolePTYPath_MultipleConsoles(t *testing.T) {
	xmlStr := `<domain type='kvm'>
  <devices>
    <console type='virtio'>
      <target type='virtio' port='0'/>
    </console>
    <console type='pty'>
      <source path='/dev/pts/7'/>
      <target type='serial' port='0'/>
    </console>
  </devices>
</domain>`
	path, err := parseConsolePTYPath(xmlStr, "test-vm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/dev/pts/7" {
		t.Errorf("path = %q, want /dev/pts/7", path)
	}
}

func TestParseConsolePTYPath_NoPTY(t *testing.T) {
	xmlStr := `<domain type='kvm'>
  <devices>
    <console type='virtio'>
      <target type='virtio' port='0'/>
    </console>
  </devices>
</domain>`
	_, err := parseConsolePTYPath(xmlStr, "test-vm")
	if err == nil {
		t.Fatal("expected error for missing PTY console")
	}
}

func TestParseConsolePTYPath_NoSourcePath(t *testing.T) {
	xmlStr := `<domain type='kvm'>
  <devices>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
  </devices>
</domain>`
	_, err := parseConsolePTYPath(xmlStr, "test-vm")
	if err == nil {
		t.Fatal("expected error for PTY console without source path")
	}
}

func TestParseConsolePTYPath_NoDevices(t *testing.T) {
	xmlStr := `<domain type='kvm'><name>test</name></domain>`
	_, err := parseConsolePTYPath(xmlStr, "test-vm")
	if err == nil {
		t.Fatal("expected error for domain with no devices")
	}
}

func TestParseConsolePTYPath_InvalidXML(t *testing.T) {
	_, err := parseConsolePTYPath("<<<not xml>>>", "test-vm")
	if err == nil {
		t.Fatal("expected error for invalid XML")
	}
}
