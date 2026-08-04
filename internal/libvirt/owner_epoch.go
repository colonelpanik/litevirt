package libvirt

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// Phase 4 runtime markers, VM half: the owner epoch is mirrored into the
// domain's <metadata> under a litevirt namespace, so a rejoined node can read
// which ownership generation its LOCAL runtime belongs to without trusting its
// own — possibly stale — replica. Written through the executor when a claimed
// transition lands; the reconciler converges a missing/stale marker toward the
// DB row. Enforcement gates on owner_epoch_v1.

const (
	// ownerEpochMetadataURI namespaces the element; the key is the libvirt
	// namespace prefix registered for it.
	ownerEpochMetadataURI = "https://litevirt.dev/xmlns/owner-epoch/1"
	ownerEpochMetadataKey = "litevirt-owner-epoch"
	// virDomainMetadataElement is VIR_DOMAIN_METADATA_ELEMENT: the per-namespace
	// application XML slot (0/1 are title/description).
	virDomainMetadataElement = 2
)

// SetDomainOwnerEpoch records the epoch in the domain metadata. running
// selects the flag set: a running domain takes LIVE|CONFIG so the value
// survives both the live domain and its persisted definition; a stopped one
// takes CONFIG only (LIVE on an inactive domain is a libvirt error).
func (c *Client) SetDomainOwnerEpoch(name string, epoch int64, running bool) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", name, err)
	}
	flags := golibvirt.DomainAffectConfig
	if running {
		flags |= golibvirt.DomainAffectLive
	}
	meta := fmt.Sprintf("<owner-epoch>%d</owner-epoch>", epoch)
	if err := c.virt.DomainSetMetadata(dom, virDomainMetadataElement,
		golibvirt.OptString{meta}, golibvirt.OptString{ownerEpochMetadataKey},
		golibvirt.OptString{ownerEpochMetadataURI}, flags); err != nil {
		return fmt.Errorf("set owner-epoch metadata on %q: %w", name, err)
	}
	return nil
}

// GetDomainOwnerEpoch reads the marker. (0,false,nil) when the domain carries
// none — pre-epoch domains are normal until the backfill stamps them. Corrupt
// content is an ERROR, never epoch 0 (garbage must not read as the zero
// generation).
func (c *Client) GetDomainOwnerEpoch(name string) (int64, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return 0, false, fmt.Errorf("lookup domain %q: %w", name, err)
	}
	raw, err := c.virt.DomainGetMetadata(dom, virDomainMetadataElement,
		golibvirt.OptString{ownerEpochMetadataURI}, golibvirt.DomainAffectCurrent)
	if err != nil {
		// libvirt reports an absent metadata element as an error
		// (VIR_ERR_NO_DOMAIN_METADATA); treat any lookup miss as "no marker".
		if strings.Contains(strings.ToLower(err.Error()), "metadata") {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("get owner-epoch metadata on %q: %w", name, err)
	}
	return parseOwnerEpochMetadata(name, raw)
}

// parseOwnerEpochMetadata decodes the stored element. Split out so the parse
// contract is unit-testable without a libvirt connection.
func parseOwnerEpochMetadata(name, raw string) (int64, bool, error) {
	var el struct {
		Value string `xml:",chardata"`
	}
	if err := xml.Unmarshal([]byte(raw), &el); err != nil {
		return 0, false, fmt.Errorf("corrupt owner-epoch metadata on %q: %w", name, err)
	}
	epoch, err := strconv.ParseInt(strings.TrimSpace(el.Value), 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("corrupt owner-epoch metadata on %q: %w", name, err)
	}
	return epoch, true, nil
}
