package fleet

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NetBoxFake is an in-process NetBox serving the real REST shapes.
//
// IMPORTANT: it allocates from a DISTINCTIVE band (.100+), never the .2/.3/.4
// the builtin allocator produces. If both handed out the same addresses, a test
// asserting "the VM got 10.0.5.2" would pass with the NetBox allocator entirely
// unwired — the assertion could not tell who supplied the address. Giving the
// wiring a different answer to produce is what makes these tests non-vacuous.
//
// It is also STRICT about query parameters: an unrecognised filter is a 400,
// never a silently ignored one. NetBox's own filtersets reject unknown
// parameters, and a fake that ignored them would let a query NetBox does not
// implement — or one whose scoping parameter we misspelled — pass locally while
// silently losing its scope against a real server.
type NetBoxFake struct {
	mu       sync.Mutex
	srv      *httptest.Server
	next     int
	byID     map[int]*fakeIP
	prefixes map[int]fakePrefix
	vrfs     map[int]bool

	// released records every id deleted through the REST API, in order.
	released []int

	// OnClaim runs INSIDE the claim handler, before the address is committed.
	// It is the only way to reach failures a caller-side check would catch
	// first — a POST that commits and then loses its response, for instance.
	OnClaim func(prefixID int) error

	// OnBeforeDelete runs on the IDENTITY LOOKUP a caller makes immediately
	// before deleting an address — the sweeper's time-of-check-to-time-of-use
	// re-read, and the only interception point a REST fake has for "somebody
	// changed this object between the proof and the delete".
	//
	// It deliberately does NOT hang off the DELETE: a NetBox delete is by id and
	// succeeds whatever the object now contains, so a hook there could only
	// observe the damage, never model the race that has to prevent it. Firing on
	// the re-read is what lets a scenario mutate the object at the one instant
	// the sweeper is required to notice. It is passed the id being looked at.
	OnBeforeDelete func(id int)

	// OnPatch runs before an identity rewrite is applied. A non-nil error fails
	// the request WITHOUT applying the change — a definite refusal (403), not a
	// lost connection — which is the only way to reach a re-key that rewrote
	// some of a prefix's objects and not the rest.
	OnPatch func(id int) error

	// Down makes every request fail at the transport layer.
	Down bool
}

type fakeIP struct {
	ID       int
	Address  string
	Identity string
	VRFID    int
	// AssignedObjectID mirrors NetBox: assignment lives on the ADDRESS, not on
	// the interface.
	AssignedObjectID int
	// Created is NetBox's own creation timestamp, served in the `created` field.
	// The orphan sweeper's grace window is the only reader, so a fake that never
	// emitted one would make every address look ageless and let a grace-window
	// bug pass unnoticed.
	Created time.Time
}

type fakePrefix struct {
	ID     int
	Prefix string
	VRFID  int
}

// NewNetBoxFake starts a fake NetBox. Call Close when done.
func NewNetBoxFake() *NetBoxFake {
	f := &NetBoxFake{
		next:     100, // the distinctive band
		byID:     map[int]*fakeIP{},
		prefixes: map[int]fakePrefix{},
		vrfs:     map[int]bool{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *NetBoxFake) URL() string { return f.srv.URL }
func (f *NetBoxFake) Close()      { f.srv.Close() }

// AddPrefix registers a prefix in a VRF. enforceUnique controls whether bind
// validation will accept it; vrfID 0 makes it a global-table prefix.
func (f *NetBoxFake) AddPrefix(id int, cidr string, vrfID int, enforceUnique bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prefixes[id] = fakePrefix{ID: id, Prefix: cidr, VRFID: vrfID}
	if vrfID != 0 {
		f.vrfs[vrfID] = enforceUnique
	}
}

// RecidrPrefix rewrites a registered prefix's CIDR, leaving its id and VRF
// alone. That is the drift a bound network can experience under an operator's
// hands in NetBox, and the addresses already handed out do NOT move with it.
func (f *NetBoxFake) RecidrPrefix(id int, newCIDR string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.prefixes[id]
	if !ok {
		return
	}
	p.Prefix = newCIDR
	f.prefixes[id] = p
}

// Identities returns every identity currently recorded, for assertions.
func (f *NetBoxFake) Identities() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, ip := range f.byID {
		if ip.Identity != "" {
			out = append(out, ip.Identity)
		}
	}
	sort.Strings(out) // map iteration order is not an assertion
	return out
}

// Released returns the ids deleted through the API, in call order.
func (f *NetBoxFake) Released() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.released...)
}

// Addresses returns every live address as "ip/len", sorted, for assertions.
func (f *NetBoxFake) Addresses() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, ip := range f.byID {
		out = append(out, ip.Address)
	}
	sort.Strings(out)
	return out
}

func (f *NetBoxFake) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	down := f.Down
	f.mu.Unlock()
	if down {
		// Closing the connection without a response is a TRANSPORT failure,
		// which is what an unreachable NetBox actually looks like. A 5xx would
		// be a SERVER that answered, which classifies differently and would
		// exercise the wrong branch.
		panic(http.ErrAbortHandler)
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/available-ips/"):
		f.claimAvailable(w, r)
	case r.URL.Path == "/api/ipam/ip-addresses/" && r.Method == http.MethodPost:
		f.claimSpecific(w, r)
	case r.URL.Path == "/api/ipam/ip-addresses/" && r.Method == http.MethodGet:
		f.lookup(w, r)
	// The id-scoped ip-address route must be matched BEFORE the prefix/vrf
	// prefixes below, and its DELETE before any collection handler, or a
	// release would fall through to the 404.
	case strings.HasPrefix(r.URL.Path, "/api/ipam/ip-addresses/") && r.Method == http.MethodDelete:
		f.release(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/ipam/ip-addresses/") && r.Method == http.MethodPatch:
		f.patchIdentity(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/ipam/prefixes/"):
		f.getPrefix(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/ipam/vrfs/"):
		f.getVRF(w, r)
	default:
		writeErr(w, http.StatusNotFound, "no such endpoint: %s %s", r.Method, r.URL.Path)
	}
}

// ── handlers ────────────────────────────────────────────────────────────────

// claimAvailable is POST /api/ipam/prefixes/{id}/available-ips/.
//
// It mirrors the request shape, as NetBox does: we send a single object, so a
// single OBJECT comes back — not an array. A fake that returned an array while
// the client expected one would make both agree with each other and disagree
// with the real server.
func (f *NetBoxFake) claimAvailable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "available-ips accepts POST only")
		return
	}
	prefixID, ok := idFromPath(r.URL.Path, "/api/ipam/prefixes/")
	if !ok {
		writeErr(w, http.StatusNotFound, "unparseable prefix id in %s", r.URL.Path)
		return
	}
	var body struct {
		CustomFields map[string]string `json:"custom_fields"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body: %v", err)
		return
	}

	f.mu.Lock()
	p, known := f.prefixes[prefixID]
	f.mu.Unlock()
	if !known {
		writeErr(w, http.StatusNotFound, "no prefix %d", prefixID)
		return
	}
	addr, err := f.nextAddressIn(p.Prefix)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	// The hook runs BEFORE the commit, but a hook failure still COMMITS and
	// then fails the response. That is the "committed then lost the response"
	// case: NetBox did the write and the caller never learned the address.
	var hookErr error
	if f.OnClaim != nil {
		hookErr = f.OnClaim(prefixID)
	}

	ip := f.commit(addr, p.VRFID, body.CustomFields["litevirt_identity"])
	if hookErr != nil {
		writeErr(w, http.StatusInternalServerError, "%v", hookErr)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, ipJSON(ip))
}

// claimSpecific is POST /api/ipam/ip-addresses/ with an explicit address.
func (f *NetBoxFake) claimSpecific(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Address      string            `json:"address"`
		VRF          int               `json:"vrf"`
		CustomFields map[string]string `json:"custom_fields"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body: %v", err)
		return
	}
	if body.Address == "" {
		writeErr(w, http.StatusBadRequest, `{"address":["This field is required."]}`)
		return
	}
	if _, _, err := net.ParseCIDR(body.Address); err != nil {
		writeErr(w, http.StatusBadRequest, `{"address":["Enter a valid CIDR address."]}`)
		return
	}

	f.mu.Lock()
	for _, existing := range f.byID {
		if existing.Address == body.Address && existing.VRFID == body.VRF {
			f.mu.Unlock()
			// The real duplicate refusal: a 400, which classifies as a DEFINITE
			// answer even though our own earlier POST may be what created it.
			writeErr(w, http.StatusBadRequest, `{"address":["Duplicate IP address found in VRF"]}`)
			return
		}
	}
	f.mu.Unlock()

	ip := f.commit(body.Address, body.VRF, body.CustomFields["litevirt_identity"])
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, ipJSON(ip))
}

// lookupParams is every query parameter this fake understands. Anything else is
// a 400 rather than a silent no-op filter.
var lookupParams = map[string]bool{
	"address":                 true,
	"vrf_id":                  true,
	"parent":                  true,
	"cf_litevirt_identity":    true,
	"cf_litevirt_identity__n": true,
	"vminterface_id":          true,
	"limit":                   true,
	"offset":                  true,
}

// lookup is GET /api/ipam/ip-addresses/.
func (f *NetBoxFake) lookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k := range q {
		if !lookupParams[k] {
			// NetBox's filtersets reject unknown parameters. Ignoring one here
			// would let a query that silently loses its scope against a real
			// server pass in the fleet.
			writeErr(w, http.StatusBadRequest, `{"%s":["Unknown filter field"]}`, k)
			return
		}
	}

	limit, err := intParam(q.Get("limit"), 50)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad limit: %v", err)
		return
	}
	offset, err := intParam(q.Get("offset"), 0)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad offset: %v", err)
		return
	}

	var parent *net.IPNet
	if raw := q.Get("parent"); raw != "" {
		_, n, perr := net.ParseCIDR(raw)
		if perr != nil {
			writeErr(w, http.StatusBadRequest, `{"parent":["Enter a valid CIDR address."]}`)
			return
		}
		parent = n
	}

	// A lookup BY IDENTITY is the pre-delete re-read (the sweeper's enumeration
	// uses the negated filter instead), so it is where OnBeforeDelete fires —
	// BEFORE matching, so a hook that changes the object changes what this very
	// response reports. See the field's comment for why the DELETE handler
	// cannot host this.
	if f.OnBeforeDelete != nil && q.Get("cf_litevirt_identity") != "" {
		f.fireBeforeDelete(q.Get("cf_litevirt_identity"))
	}

	f.mu.Lock()
	ids := make([]int, 0, len(f.byID))
	for id := range f.byID {
		ids = append(ids, id)
	}
	sort.Ints(ids) // stable order so pagination is deterministic
	var matched []*fakeIP
	for _, id := range ids {
		ip := f.byID[id]
		if !matchIP(ip, q, parent) {
			continue
		}
		copied := *ip
		matched = append(matched, &copied)
	}
	f.mu.Unlock()

	total := len(matched)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := matched[offset:end]

	out := struct {
		Count   int      `json:"count"`
		Next    string   `json:"next"`
		Results []ipView `json:"results"`
	}{Count: total, Results: []ipView{}}
	for _, ip := range page {
		out.Results = append(out.Results, ipJSON(*ip))
	}
	if end < total {
		out.Next = fmt.Sprintf("%s/api/ipam/ip-addresses/?limit=%d&offset=%d", f.srv.URL, limit, end)
	}
	writeJSON(w, out)
}

// matchIP applies every recognised filter. A filter that is present but matches
// nothing yields an EMPTY result, never an unfiltered one.
func matchIP(ip *fakeIP, q map[string][]string, parent *net.IPNet) bool {
	get := func(k string) (string, bool) {
		v, ok := q[k]
		if !ok || len(v) == 0 {
			return "", false
		}
		return v[0], true
	}
	if v, ok := get("address"); ok && ip.Address != v {
		return false
	}
	if v, ok := get("vrf_id"); ok {
		want, err := strconv.Atoi(v)
		if err != nil || ip.VRFID != want {
			return false
		}
	}
	if v, ok := get("cf_litevirt_identity"); ok && ip.Identity != v {
		return false
	}
	// "__n" is NetBox's negation lookup. cf_x__n= (empty) means "identity is
	// not empty", which is how the orphan sweeper enumerates our objects.
	if v, ok := get("cf_litevirt_identity__n"); ok && ip.Identity == v {
		return false
	}
	if v, ok := get("vminterface_id"); ok {
		want, err := strconv.Atoi(v)
		if err != nil || ip.AssignedObjectID != want {
			return false
		}
	}
	if parent != nil {
		host, _, err := net.ParseCIDR(ip.Address)
		if err != nil || !parent.Contains(host) {
			return false
		}
	}
	return true
}

// getPrefix is GET /api/ipam/prefixes/{id}/.
func (f *NetBoxFake) getPrefix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "prefixes accepts GET only")
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/ipam/prefixes/")
	if !ok {
		writeErr(w, http.StatusNotFound, "unparseable prefix id in %s", r.URL.Path)
		return
	}
	f.mu.Lock()
	p, known := f.prefixes[id]
	f.mu.Unlock()
	if !known {
		writeErr(w, http.StatusNotFound, "no prefix %d", id)
		return
	}
	out := struct {
		ID     int    `json:"id"`
		Prefix string `json:"prefix"`
		VRF    *struct {
			ID int `json:"id"`
		} `json:"vrf"`
	}{ID: p.ID, Prefix: p.Prefix}
	if p.VRFID != 0 {
		out.VRF = &struct {
			ID int `json:"id"`
		}{ID: p.VRFID}
	}
	writeJSON(w, out)
}

// getVRF is GET /api/ipam/vrfs/{id}/.
func (f *NetBoxFake) getVRF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "vrfs accepts GET only")
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/ipam/vrfs/")
	if !ok {
		writeErr(w, http.StatusNotFound, "unparseable vrf id in %s", r.URL.Path)
		return
	}
	f.mu.Lock()
	unique, known := f.vrfs[id]
	f.mu.Unlock()
	if !known {
		writeErr(w, http.StatusNotFound, "no vrf %d", id)
		return
	}
	writeJSON(w, struct {
		ID            int    `json:"id"`
		Name          string `json:"name"`
		EnforceUnique bool   `json:"enforce_unique"`
	}{ID: id, Name: fmt.Sprintf("vrf-%d", id), EnforceUnique: unique})
}

// release is DELETE /api/ipam/ip-addresses/{id}/.
func (f *NetBoxFake) release(w http.ResponseWriter, r *http.Request) {
	id, ok := idFromPath(r.URL.Path, "/api/ipam/ip-addresses/")
	if !ok {
		writeErr(w, http.StatusNotFound, "unparseable ip id in %s", r.URL.Path)
		return
	}
	f.mu.Lock()
	_, known := f.byID[id]
	if known {
		delete(f.byID, id)
		f.released = append(f.released, id)
	}
	f.mu.Unlock()
	if !known {
		// NetBox 404s a delete of something that is already gone. A compensating
		// caller must be able to tell that apart from a refusal.
		writeErr(w, http.StatusNotFound, "no ip-address %d", id)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// patchIdentity is PATCH /api/ipam/ip-addresses/{id}/ — the identity rewrite a
// CA re-key performs.
//
// It refuses a body carrying anything but the custom field. NetBox would accept
// one, and a re-key that had somehow started sending `address` or `vrf` would
// silently MOVE an address a guest is using; a fake that tolerated it would let
// that bug pass in the fleet and only surface against a real server.
func (f *NetBoxFake) patchIdentity(w http.ResponseWriter, r *http.Request) {
	id, ok := idFromPath(r.URL.Path, "/api/ipam/ip-addresses/")
	if !ok {
		writeErr(w, http.StatusNotFound, "unparseable ip id in %s", r.URL.Path)
		return
	}
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body: %v", err)
		return
	}
	raw, hasCF := body["custom_fields"]
	if len(body) != 1 || !hasCF {
		writeErr(w, http.StatusBadRequest,
			`{"detail":["an identity rewrite must send custom_fields and nothing else"]}`)
		return
	}
	var cf map[string]string
	if err := json.Unmarshal(raw, &cf); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed custom_fields: %v", err)
		return
	}
	identity, present := cf["litevirt_identity"]
	if !present {
		writeErr(w, http.StatusBadRequest, `{"custom_fields":["litevirt_identity is required"]}`)
		return
	}

	// Before the write, so a refusal leaves the object exactly as it was.
	if f.OnPatch != nil {
		if err := f.OnPatch(id); err != nil {
			writeErr(w, http.StatusForbidden, "%v", err)
			return
		}
	}

	f.mu.Lock()
	ip, known := f.byID[id]
	var updated fakeIP
	if known {
		ip.Identity = identity
		updated = *ip
	}
	f.mu.Unlock()
	if !known {
		writeErr(w, http.StatusNotFound, "no ip-address %d", id)
		return
	}
	writeJSON(w, ipJSON(updated))
}

// SetVRFEnforceUnique flips a VRF's enforce_unique flag. An operator can do this
// in NetBox at any time after a bind validated it, and nothing in NetBox tells
// litevirt it happened — which is why the binding has to re-ask.
func (f *NetBoxFake) SetVRFEnforceUnique(vrfID int, unique bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vrfs[vrfID] = unique
}

// MovePrefixToGlobalTable drops a prefix out of its VRF. The addresses already
// handed out keep their own VRF, exactly as NetBox leaves them.
func (f *NetBoxFake) MovePrefixToGlobalTable(id int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.prefixes[id]
	if !ok {
		return
	}
	p.VRFID = 0
	f.prefixes[id] = p
}

// ── internals ───────────────────────────────────────────────────────────────

// commit records one address and returns it.
func (f *NetBoxFake) commit(address string, vrfID int, identity string) fakeIP {
	return f.commitAt(address, vrfID, identity, time.Now().UTC())
}

// commitAt records one address with an explicit creation time.
func (f *NetBoxFake) commitAt(address string, vrfID int, identity string, created time.Time) fakeIP {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextID()
	ip := &fakeIP{ID: id, Address: address, Identity: identity, VRFID: vrfID, Created: created}
	f.byID[id] = ip
	return *ip
}

// SeedIP plants an address NO litevirt operation created — the shape a leaked
// object has: a real identity, a real address, and no local row anywhere
// pointing at it. `created` is explicit because age is the sweeper's grace
// input, and a seeded orphan usually has to be older than the window.
func (f *NetBoxFake) SeedIP(address string, vrfID int, identity string, created time.Time) int {
	return f.commitAt(address, vrfID, identity, created).ID
}

// fireBeforeDelete invokes the hook once per object currently carrying the
// looked-up identity. The lock is released around the call so the hook can
// mutate the fake (Reassign takes the same mutex).
func (f *NetBoxFake) fireBeforeDelete(identity string) {
	f.mu.Lock()
	var ids []int
	for id, ip := range f.byID {
		if ip.Identity == identity {
			ids = append(ids, id)
		}
	}
	hook := f.OnBeforeDelete
	f.mu.Unlock()
	sort.Ints(ids)
	for _, id := range ids {
		hook(id)
	}
}

// Reassign rewrites one object's identity in place, as an operator (or another
// cluster) editing the custom field in NetBox would.
func (f *NetBoxFake) Reassign(id int, identity string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ip, ok := f.byID[id]; ok {
		ip.Identity = identity
	}
}

// nextID hands out object ids from a band that cannot collide with the address
// host numbers, so a test misreading one for the other fails loudly.
func (f *NetBoxFake) nextID() int {
	id := 9000 + len(f.byID)
	for {
		if _, taken := f.byID[id]; !taken {
			return id
		}
		id++
	}
}

// nextAddressIn picks the lowest free host in cidr at or above the .100 band.
//
// The band is the whole point: the builtin allocator starts at .2, so an
// address in the .100s could only have come from here.
func (f *NetBoxFake) nextAddressIn(cidr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("prefix %q is not a CIDR: %v", cidr, err)
	}
	v4 := ipnet.IP.To4()
	if v4 == nil {
		return "", fmt.Errorf("the fake allocates from IPv4 prefixes only, got %q", cidr)
	}
	ones, bits := ipnet.Mask.Size()
	size := 1 << uint(bits-ones)

	f.mu.Lock()
	taken := map[string]bool{}
	for _, ip := range f.byID {
		host, _, perr := net.ParseCIDR(ip.Address)
		if perr == nil {
			taken[host.String()] = true
		}
	}
	f.mu.Unlock()

	base := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	for host := f.next; host < size-1; host++ {
		candidate := net.IPv4(
			byte((base+uint32(host))>>24), byte((base+uint32(host))>>16),
			byte((base+uint32(host))>>8), byte(base+uint32(host)))
		if taken[candidate.String()] {
			continue
		}
		return fmt.Sprintf("%s/%d", candidate.String(), ones), nil
	}
	return "", fmt.Errorf("no available addresses in %s at or above host .%d", cidr, f.next)
}

// ipView is the ip-address JSON shape the real API returns.
type ipView struct {
	ID               int               `json:"id"`
	Address          string            `json:"address"`
	VRF              *vrfRef           `json:"vrf"`
	AssignedObjectID *int              `json:"assigned_object_id"`
	CustomFields     map[string]string `json:"custom_fields"`
	Created          string            `json:"created"`
}

type vrfRef struct {
	ID int `json:"id"`
}

func ipJSON(ip fakeIP) ipView {
	out := ipView{
		ID:      ip.ID,
		Address: ip.Address,
		// The custom field is ALWAYS present, even when empty: NetBox returns
		// every defined custom field on every object, and a fake that omitted
		// it would hide a decoder that only works when the key exists.
		CustomFields: map[string]string{"litevirt_identity": ip.Identity},
	}
	if !ip.Created.IsZero() {
		out.Created = ip.Created.UTC().Format(time.RFC3339)
	}
	if ip.VRFID != 0 {
		out.VRF = &vrfRef{ID: ip.VRFID}
	}
	if ip.AssignedObjectID != 0 {
		id := ip.AssignedObjectID
		out.AssignedObjectID = &id
	}
	return out
}

// idFromPath pulls the numeric id out of "<prefix><id>/..." paths.
func idFromPath(path, prefix string) (int, bool) {
	rest := strings.TrimPrefix(path, prefix)
	if rest == path {
		return 0, false
	}
	seg := strings.SplitN(strings.Trim(rest, "/"), "/", 2)[0]
	id, err := strconv.Atoi(seg)
	if err != nil {
		return 0, false
	}
	return id, true
}

func intParam(raw string, def int) (int, error) {
	if raw == "" {
		return def, nil
	}
	return strconv.Atoi(raw)
}

func writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, format string, args ...any) {
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"detail":%q}`, fmt.Sprintf(format, args...))
}
