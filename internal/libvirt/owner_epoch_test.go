package libvirt

import "testing"

// The parse contract for the domain owner-epoch marker: corrupt content is an
// ERROR, never epoch 0 — garbage read as the zero generation would authorize
// exactly the stale actions the marker exists to refuse.
func TestParseOwnerEpochMetadata(t *testing.T) {
	if got, ok, err := parseOwnerEpochMetadata("vm1", "<owner-epoch>7</owner-epoch>"); err != nil || !ok || got != 7 {
		t.Fatalf("valid: (%d,%v,%v), want (7,true,nil)", got, ok, err)
	}
	if got, ok, err := parseOwnerEpochMetadata("vm1", "<owner-epoch> 12 </owner-epoch>"); err != nil || !ok || got != 12 {
		t.Fatalf("whitespace: (%d,%v,%v), want (12,true,nil)", got, ok, err)
	}
	if _, _, err := parseOwnerEpochMetadata("vm1", "<owner-epoch>garbage</owner-epoch>"); err == nil {
		t.Fatal("garbage content must be an error, not a value")
	}
	if _, _, err := parseOwnerEpochMetadata("vm1", "not-xml-at-all<"); err == nil {
		t.Fatal("non-XML must be an error")
	}
}
