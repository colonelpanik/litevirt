package netbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// IPAddress is one ipam.ip-address as litevirt cares about it.
//
// VRFID is carried because an identity match alone is not enough to adopt an
// object: a uniquely-matching address that has been MOVED into another VRF is
// not the one this binding claims, and adopting it would write a lease
// pointing outside the bound prefix.
type IPAddress struct {
	ID       int
	Address  string
	Identity string
	VRFID    int
	// AssignedObjectID is the object this address is attached to, or 0.
	// Assignment lives on the ADDRESS in NetBox, not on the interface — an
	// interface can carry several addresses — so P2's mirror reads assignment
	// from here rather than from a synthetic field on the interface.
	AssignedObjectID int
	// Created is when NetBox first recorded this object, or the zero time when
	// it could not be read.
	//
	// The orphan sweeper's grace window is the only consumer, and it treats the
	// zero value as "not old enough" — an object whose age is unknown is never
	// reclaimed. That is why an unparseable timestamp is silently zeroed rather
	// than raised: every failure mode of this field must land on the side that
	// keeps an address, not the side that frees one.
	//
	// Which is why the DATE-only form NetBox 3.x serves is deliberately NOT
	// parsed. Reading "2026-01-02" as midnight UTC does not lose a little
	// precision, it collapses the grace window: every object created after 00:30
	// UTC is instantly older than a 30-minute cutoff, so the window that exists
	// to protect an in-flight create protects nothing for most of the day. Left
	// unparsed the field stays zero, the sweeper reclaims nothing on 3.x, and
	// the addresses are freed by hand — inert, which is the side of this field
	// every failure belongs on. Reclamation therefore requires a NetBox that
	// serves a full RFC3339 `created` (4.x).
	Created time.Time
}

// ipAddressesPath is the ipam address collection. It is a const because the
// virtualization mirror reaches for the same endpoint: assignment lives on the
// ADDRESS object, not on the interface.
const ipAddressesPath = "/api/ipam/ip-addresses/"

type ipJSON struct {
	ID      int    `json:"id"`
	Address string `json:"address"`
	VRF     *struct {
		ID int `json:"id"`
	} `json:"vrf"`
	AssignedObjectID *int           `json:"assigned_object_id"`
	CustomFields     map[string]any `json:"custom_fields"`
	// Created is NetBox's own creation timestamp. 4.x serializes a full RFC3339
	// datetime; NetBox 3.x serialized a DATE ("2026-01-02"), which is NOT
	// accepted — see createdLayouts. Anything else yields the zero time.
	Created string `json:"created"`
}

// createdLayouts are the shapes NetBox has served in the `created` field, most
// specific first. RFC3339 covers both the "Z" and the "+01:00" offset forms.
//
// The date-only "2006-01-02" that NetBox 3.x serves is deliberately absent. It
// parses to midnight UTC, which is not a coarse timestamp but a systematically
// EARLY one: against a 30-minute grace window every object created after 00:30
// UTC reads as already past it, so the window that keeps the sweeper off an
// in-flight create would be open for 23 and a half hours of every day. Refusing
// it leaves Created zero, olderThan reads zero as "not old enough", and the
// sweeper stays inert on 3.x — the conservative outcome this field's contract
// demands.
var createdLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999",
	"2006-01-02T15:04:05",
}

// parseCreated is deliberately lenient AND fail-closed: an unrecognised or
// missing value returns the zero time, which the sweeper reads as "age unknown"
// and therefore never reclaims.
func parseCreated(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range createdLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func (j ipJSON) toIP() IPAddress {
	out := IPAddress{ID: j.ID, Address: j.Address}
	if j.VRF != nil {
		out.VRFID = j.VRF.ID
	}
	if j.AssignedObjectID != nil {
		out.AssignedObjectID = *j.AssignedObjectID
	}
	if v, ok := j.CustomFields[IdentityField].(string); ok {
		out.Identity = v
	}
	out.Created = parseCreated(j.Created)
	return out
}

// ClaimAvailableIP claims the next free address in a prefix. NetBox serializes
// this endpoint with a PostgreSQL advisory lock, so it is atomic across entry
// nodes and litevirt needs no distributed locking of its own.
//
// NOTE: on a timeout this call does NOT reveal which address NetBox picked, so
// recovery is by identity lookup only — never by address.
//
// RESPONSE SHAPE: NetBox mirrors the request. A single-object POST returns a
// single object; only a LIST request returns a list. We send a single object,
// so we expect an object — but decode tolerantly, because the shape has varied
// across NetBox versions and guessing wrong here fails at runtime against a
// real server while passing against a fake that shares the guess.
func (c *Client) ClaimAvailableIP(ctx context.Context, prefixID int, identity string) (IPAddress, error) {
	body := map[string]any{
		"custom_fields": map[string]string{IdentityField: identity},
	}
	var raw json.RawMessage
	path := fmt.Sprintf("/api/ipam/prefixes/%d/available-ips/", prefixID)
	if err := c.do(ctx, http.MethodPost, path, body, &raw); err != nil {
		return IPAddress{}, err
	}
	return decodeOneOrMany(raw, prefixID)
}

// decodeOneOrMany accepts either a single ip object or a one-element array.
func decodeOneOrMany(raw json.RawMessage, prefixID int) (IPAddress, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var many []ipJSON
		if err := json.Unmarshal(raw, &many); err != nil {
			return IPAddress{}, fmt.Errorf("netbox: decode available-ips array: %w", err)
		}
		if len(many) == 0 {
			return IPAddress{}, fmt.Errorf("netbox: available-ips returned no address for prefix %d", prefixID)
		}
		return many[0].toIP(), nil
	}
	var one ipJSON
	if err := json.Unmarshal(raw, &one); err != nil {
		return IPAddress{}, fmt.Errorf("netbox: decode available-ips object: %w", err)
	}
	if one.ID == 0 {
		return IPAddress{}, fmt.Errorf("netbox: available-ips returned no address for prefix %d", prefixID)
	}
	return one.toIP(), nil
}

// ClaimSpecificIP creates one exact address in a VRF.
func (c *Client) ClaimSpecificIP(ctx context.Context, address string, vrfID int, identity string) (IPAddress, error) {
	body := map[string]any{
		"address":       address,
		"vrf":           vrfID,
		"custom_fields": map[string]string{IdentityField: identity},
	}
	var out ipJSON
	if err := c.do(ctx, http.MethodPost, ipAddressesPath, body, &out); err != nil {
		return IPAddress{}, err
	}
	return out.toIP(), nil
}

// LookupByAddress finds addresses matching an exact address within one VRF.
// Used only for EXPLICIT claims — a dynamic claim has no address to look up.
func (c *Client) LookupByAddress(ctx context.Context, address string, vrfID int) ([]IPAddress, error) {
	q := url.Values{}
	q.Set("address", address)
	q.Set("vrf_id", strconv.Itoa(vrfID))
	return c.list(ctx, q)
}

// LookupByIdentity finds addresses carrying our identity custom field, SCOPED to
// one VRF and prefix. This is the only recovery path for an ambiguous dynamic
// claim.
//
// The scope is not optional. An unscoped lookup would adopt a uniquely-matching
// object that has since been moved into a different VRF or prefix — which is not
// the address this binding claims.
func (c *Client) LookupByIdentity(ctx context.Context, identity string, vrfID int, prefixCIDR string) ([]IPAddress, error) {
	q := url.Values{}
	q.Set("cf_"+IdentityField, identity)
	q.Set("vrf_id", strconv.Itoa(vrfID))
	// parent takes a CIDR, not a prefix id. NetBox's IPAddressFilterSet.parent
	// parses the value as a network — an address has no parent-prefix FK — so
	// passing an id here silently filters on nonsense.
	q.Set("parent", prefixCIDR)
	return c.list(ctx, q)
}

// list walks EVERY page of the address endpoint. NetBox paginates at 50 by
// default; a truncated list would make the full sweep believe live objects had
// vanished and delete them. The walk itself lives in paginate, which every list
// operation in this package shares.
func (c *Client) list(ctx context.Context, q url.Values) ([]IPAddress, error) {
	return paginate(ctx, c, ipAddressesPath, q, ipJSON.toIP)
}

// ListIPsByPrefix enumerates every litevirt-tagged address in a prefix. The
// orphan sweeper needs this to find candidates; without it there is no way to
// discover an address whose local row was lost.
func (c *Client) ListIPsByPrefix(ctx context.Context, prefixCIDR string, vrfID int) ([]IPAddress, error) {
	q := url.Values{}
	q.Set("parent", prefixCIDR) // a CIDR, not an id — see LookupByIdentity
	q.Set("vrf_id", strconv.Itoa(vrfID))
	q.Set("cf_"+IdentityField+"__n", "") // has a non-empty litevirt identity
	return c.list(ctx, q)
}

// ReleaseIP deletes one address by id.
func (c *Client) ReleaseIP(ctx context.Context, id int) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf(ipAddressesPath+"%d/", id), nil, nil)
}

// SetIPIdentity rewrites ONE address's litevirt identity custom field.
//
// It is the CA re-key's only write. PATCH, not PUT: NetBox's PUT is a full
// replace, so an omitted `address` or `vrf` would be blanked — a re-key would
// then destroy the very objects it exists to preserve. The body carries nothing
// but the custom field for the same reason.
func (c *Client) SetIPIdentity(ctx context.Context, id int, identity string) error {
	body := map[string]any{
		"custom_fields": map[string]string{IdentityField: identity},
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(ipAddressesPath+"%d/", id), body, nil)
}
