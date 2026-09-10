package libvirt

import (
	"errors"
	"testing"
)

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

// TestParseOwnerEpochMetadata_AZeroIsCorruptNotValid: the rule the comment above
// states, actually checked.
//
// The parse accepted any parseable integer, so a domain carrying
// <owner-epoch>0</owner-epoch> read back as (0, true, nil) — a VALID marker at
// the zero generation. Against a vms row still at the column default that
// satisfies the dual-run detector's marker/epoch equality test and suppresses
// condition 7 silently. This is the domain-metadata twin of the same hole closed
// at the host-local file marker: epoch allocation starts at 1, so 0 is the DB
// column's "no epoch assigned" sentinel and never a marker value.
func TestParseOwnerEpochMetadata_AZeroIsCorruptNotValid(t *testing.T) {
	epoch, found, err := parseOwnerEpochMetadata("vm1", "<owner-epoch>0</owner-epoch>")
	if err == nil {
		t.Fatalf("a zero marker parsed cleanly as (%d,%v) — it must be an error, because a "+
			"zero that reads as valid suppresses the owner-epoch check against any row "+
			"still at the pre-epoch default", epoch, found)
	}
	if found {
		t.Error("found = true for a zero marker; a value that cannot name a generation is not a reading")
	}
}

// TestParseOwnerEpochMetadata_ANegativeIsCorrupt: same rule, other side of zero.
func TestParseOwnerEpochMetadata_ANegativeIsCorrupt(t *testing.T) {
	if _, _, err := parseOwnerEpochMetadata("vm1", "<owner-epoch>-5</owner-epoch>"); err == nil {
		t.Error("a negative marker parsed cleanly; allocation starts at 1, so it is garbage")
	}
}

// TestSetDomainOwnerEpoch_RefusesAPreEpochValue: the writer must not create the
// metadata this parse now rejects — and must refuse it WITHOUT a libvirt
// round-trip, which is what letting a zero-value Client reach the refusal pins.
func TestSetDomainOwnerEpoch_RefusesAPreEpochValue(t *testing.T) {
	c := &Client{}
	for _, epoch := range []int64{0, -1} {
		if err := c.SetDomainOwnerEpoch("vm1", epoch, true); err == nil {
			t.Errorf("SetDomainOwnerEpoch accepted epoch %d; a marker that cannot name a "+
				"generation must never reach domain metadata", epoch)
		}
	}
}

// TestParseOwnerEpochMetadata_ZeroAndNegativeAreDifferentKindsOfCorrupt is the
// metadata twin of the file marker's rule: exactly 0 carries the sentinel, a
// negative is plain garbage.
func TestParseOwnerEpochMetadata_ZeroAndNegativeAreDifferentKindsOfCorrupt(t *testing.T) {
	_, _, zeroErr := parseOwnerEpochMetadata("vm1", "<owner-epoch>0</owner-epoch>")
	if !errors.Is(zeroErr, ErrPreEpochOwnerEpoch) {
		t.Errorf("a zero must carry ErrPreEpochOwnerEpoch; got %v", zeroErr)
	}
	_, _, negErr := parseOwnerEpochMetadata("vm1", "<owner-epoch>-5</owner-epoch>")
	if negErr == nil {
		t.Fatal("a negative must still be corrupt")
	}
	if errors.Is(negErr, ErrPreEpochOwnerEpoch) {
		t.Error("a negative must NOT carry the pre-epoch sentinel; it is garbage")
	}
}
