package libvirt

import (
	"strings"
	"testing"
)

// A Ceph locator carrying options libvirt cannot express must not be silently
// reduced to one it can.
//
// The ceph driver's CreateDisk appends the pool's configured connection
// settings to the identifier it returns — ":conf=<path>" and ":keyring=<path>"
// (internal/storage/ceph.go). parseRBDLocator read only mon_host and dropped
// the rest, and libvirt's <source protocol='rbd'> has nowhere to put them:
// monitors are <host> elements and authentication is a sibling <auth> element
// naming a secret in libvirt's own store, not a keyring path on disk.
//
// So a pool configured with a non-default conf or keyring allocated its image
// successfully and then produced a domain pointing at the same image with the
// DEFAULT credentials and configuration. The failure surfaces at start time as
// an unreachable image, after the allocation has already happened, and nothing
// in between says the settings were discarded.
//
// Failing here is the honest answer: these settings were asked for, they
// cannot be honoured, and a domain that ignores them is not a smaller version
// of what was requested — it is a different thing that happens to look fine.
func TestDiskBacking_RefusesCephOptionsLibvirtCannotExpress(t *testing.T) {
	for _, tc := range []struct {
		name, path, wantIn string
	}{
		{"conf", "rbd:pool/img:conf=/etc/ceph/custom.conf", "conf"},
		{"keyring", "rbd:pool/img:keyring=/etc/ceph/custom.keyring", "keyring"},
		{"both names the first", "rbd:pool/img:conf=/a.conf:keyring=/b.key", "conf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := diskBacking(tc.path)
			if err == nil {
				t.Fatalf("diskBacking(%q) returned no error; the domain would be built with "+
					"default Ceph credentials and the disk would be unreachable at start",
					tc.path)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error must name the option an operator has to act on: got %v", err)
			}
		})
	}
}

// What libvirt CAN express still works, and the ordinary locator is unaffected.
func TestDiskBacking_AcceptsWhatLibvirtCanExpress(t *testing.T) {
	t.Run("plain rbd locator", func(t *testing.T) {
		dt, src, drv, err := diskBacking("rbd:pool/img")
		if err != nil {
			t.Fatalf("plain locator must be accepted: %v", err)
		}
		if dt != "network" || src.Protocol != "rbd" || src.Name != "pool/img" || drv != "raw" {
			t.Errorf("got type=%q protocol=%q name=%q driver=%q", dt, src.Protocol, src.Name, drv)
		}
	})

	t.Run("mon_host is representable as <host> elements", func(t *testing.T) {
		_, src, _, err := diskBacking("rbd:pool/img:mon_host=10.0.0.1,10.0.0.2")
		if err != nil {
			t.Fatalf("mon_host is expressible and must be accepted: %v", err)
		}
		if len(src.Hosts) != 2 {
			t.Fatalf("got %d monitors, want 2", len(src.Hosts))
		}
	})

	t.Run("file and block backings are untouched", func(t *testing.T) {
		if dt, _, drv, err := diskBacking("/var/lib/litevirt/d.qcow2"); err != nil || dt != "file" || drv != "qcow2" {
			t.Errorf("file: type=%q driver=%q err=%v", dt, drv, err)
		}
		if dt, _, drv, err := diskBacking("/dev/vg0/lv"); err != nil || dt != "block" || drv != "raw" {
			t.Errorf("block: type=%q driver=%q err=%v", dt, drv, err)
		}
	})
}
