package libvirt

import (
	"strings"
	"testing"
)

func TestGeneratePoolXML_Dir(t *testing.T) {
	xml, err := generatePoolXML("mypool", "local", "", "/var/lib/litevirt/disks", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(xml, "type='dir'") {
		t.Errorf("expected dir pool type, got:\n%s", xml)
	}
	if !strings.Contains(xml, "<name>mypool</name>") {
		t.Errorf("expected pool name, got:\n%s", xml)
	}
	if !strings.Contains(xml, "<path>/var/lib/litevirt/disks</path>") {
		t.Errorf("expected target path, got:\n%s", xml)
	}
}

func TestGeneratePoolXML_DirNoTarget(t *testing.T) {
	_, err := generatePoolXML("mypool", "dir", "", "", nil)
	if err == nil {
		t.Fatal("expected error for dir pool without target")
	}
}

func TestGeneratePoolXML_NFS(t *testing.T) {
	xml, err := generatePoolXML("nfspool", "nfs", "nas.local:/export/vms", "/mnt/vms", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(xml, "type='netfs'") {
		t.Errorf("expected netfs pool type, got:\n%s", xml)
	}
	if !strings.Contains(xml, "<host name='nas.local'/>") {
		t.Errorf("expected host element, got:\n%s", xml)
	}
	if !strings.Contains(xml, "<dir path='/export/vms'/>") {
		t.Errorf("expected dir path element, got:\n%s", xml)
	}
	if !strings.Contains(xml, "<path>/mnt/vms</path>") {
		t.Errorf("expected target path, got:\n%s", xml)
	}
}

func TestGeneratePoolXML_NFSBadSource(t *testing.T) {
	_, err := generatePoolXML("nfspool", "nfs", "invalid", "/mnt/vms", nil)
	if err == nil {
		t.Fatal("expected error for bad NFS source")
	}
}

func TestGeneratePoolXML_NFSNoTarget(t *testing.T) {
	_, err := generatePoolXML("nfspool", "netfs", "nas:/export", "", nil)
	if err == nil {
		t.Fatal("expected error for NFS pool without target")
	}
}

func TestGeneratePoolXML_DirDefaultDriver(t *testing.T) {
	// Empty driver string defaults to dir
	xml, err := generatePoolXML("mypool", "", "", "/data", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(xml, "type='dir'") {
		t.Errorf("expected dir pool type, got:\n%s", xml)
	}
}

func TestGeneratePoolXML_Ceph(t *testing.T) {
	xml, err := generatePoolXML("cephpool", "ceph", "libvirt-pool", "", map[string]string{"id": "admin"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(xml, "type='rbd'") {
		t.Errorf("expected rbd pool type, got:\n%s", xml)
	}
	if !strings.Contains(xml, "<name>libvirt-pool</name>") {
		t.Errorf("expected source name, got:\n%s", xml)
	}
	if !strings.Contains(xml, "username='admin'") {
		t.Errorf("expected auth username, got:\n%s", xml)
	}
}

func TestGeneratePoolXML_CephNoAuth(t *testing.T) {
	xml, err := generatePoolXML("cephpool", "rbd", "libvirt-pool", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(xml, "auth") {
		t.Errorf("expected no auth element, got:\n%s", xml)
	}
}

func TestGeneratePoolXML_CephNoSource(t *testing.T) {
	_, err := generatePoolXML("cephpool", "ceph", "", "", nil)
	if err == nil {
		t.Fatal("expected error for ceph pool without source")
	}
}

func TestGeneratePoolXML_ISCSI(t *testing.T) {
	xml, err := generatePoolXML("iscsipool", "iscsi", "san.local:iqn.2024-01.com.example:storage", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(xml, "type='iscsi'") {
		t.Errorf("expected iscsi pool type, got:\n%s", xml)
	}
	if !strings.Contains(xml, "<host name='san.local'/>") {
		t.Errorf("expected host element, got:\n%s", xml)
	}
	if !strings.Contains(xml, "<device path='iqn.2024-01.com.example:storage'/>") {
		t.Errorf("expected device path, got:\n%s", xml)
	}
}

func TestGeneratePoolXML_ISCSIWithOpts(t *testing.T) {
	xml, err := generatePoolXML("iscsipool", "iscsi", "san.local", "", map[string]string{"iqn": "iqn.2024-01.com.example:vol"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(xml, "<device path='iqn.2024-01.com.example:vol'/>") {
		t.Errorf("expected device path from opts, got:\n%s", xml)
	}
}

func TestGeneratePoolXML_ISCSINoIQN(t *testing.T) {
	_, err := generatePoolXML("iscsipool", "iscsi", "san.local", "", nil)
	if err == nil {
		t.Fatal("expected error for iscsi pool without IQN")
	}
}

func TestGeneratePoolXML_UnsupportedDriver(t *testing.T) {
	_, err := generatePoolXML("pool", "zfs", "", "", nil)
	if err == nil {
		t.Fatal("expected error for unsupported driver")
	}
}

func TestSplitNFSSource(t *testing.T) {
	tests := []struct {
		input    string
		host     string
		path     string
		wantOK   bool
	}{
		{"nas:/export", "nas", "/export", true},
		{"10.0.0.1:/mnt/data", "10.0.0.1", "/mnt/data", true},
		{"nopath", "", "", false},
		{":", "", "", false},
		{"host:", "", "", false},
	}
	for _, tt := range tests {
		host, path, ok := splitNFSSource(tt.input)
		if ok != tt.wantOK || host != tt.host || path != tt.path {
			t.Errorf("splitNFSSource(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.input, host, path, ok, tt.host, tt.path, tt.wantOK)
		}
	}
}
