// The virtualization + dcim half of NetBoxFake: cluster types, clusters,
// virtual machines, VM interfaces and DCIM device lookups.
//
// It is exactly as STRICT as the ipam half, and for the same reason: an
// unrecognised query parameter is a 400, never a silently ignored filter.
// NetBox's own filtersets reject unknown parameters, so a permissive fake would
// let a query that has lost its scope — a mirror listing EVERY cluster's VMs
// and then deleting the ones it does not recognise — pass in the fleet and fail
// only against a real server.
//
// Two behaviours are modelled deliberately because the mirror's convergence
// depends on them:
//
//   - A MAC is echoed UPPER-cased, as NetBox does. A diff that compared MACs
//     case-sensitively would see drift on every sweep and PATCH forever.
//   - Deleting a virtual machine CASCADES to its interfaces, and the addresses
//     those interfaces held are UNASSIGNED rather than deleted. That is what
//     makes a VM delete a single request instead of a cascade the mirror has to
//     drive itself.
//   - The two UNIQUENESS constraints are enforced: a VM name is unique within
//     its cluster, and an interface name is unique within its virtual machine.
//     Both are 400s, and both are constraints the mirror has code to avoid —
//     nicName's collision suffix exists for exactly the second one. A fake that
//     accepted duplicates would let that code be deleted with every fleet
//     scenario still green, and the sweep would abort on a 400 the first time a
//     real VM carried two NICs on the same ordinal.

package fleet

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// fakeVM is one virtualization.virtual_machine.
type fakeVM struct {
	ID        int
	Name      string
	ClusterID int
	DeviceID  int
	VCPUs     int
	Memory    int
	Disk      int
	Status    string
	Identity  string
}

// fakeIface is one virtualization.vminterface.
type fakeIface struct {
	ID       int
	VMID     int
	Name     string
	MAC      string
	Identity string
}

// ── named collections (cluster types, clusters, devices) ────────────────────

// namedParams is every query parameter a name lookup understands.
var namedParams = map[string]bool{"name": true, "limit": true, "offset": true}

// namedCollection serves the GET-by-name / POST-if-absent shape the client's
// ensureNamed and firstIDByName use.
func (f *NetBoxFake) namedCollection(w http.ResponseWriter, r *http.Request, store map[string]int, nextID func() int) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		for k := range q {
			if !namedParams[k] {
				writeErr(w, http.StatusBadRequest, `{"%s":["Unknown filter field"]}`, k)
				return
			}
		}
		name := q.Get("name")
		f.mu.Lock()
		id, ok := store[name]
		f.mu.Unlock()
		out := struct {
			Count   int     `json:"count"`
			Next    string  `json:"next"`
			Results []idRef `json:"results"`
		}{Results: []idRef{}}
		if ok && name != "" {
			out.Count, out.Results = 1, []idRef{{ID: id}}
		}
		writeJSON(w, out)
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed body: %v", err)
			return
		}
		if body.Name == "" {
			writeErr(w, http.StatusBadRequest, `{"name":["This field is required."]}`)
			return
		}
		f.mu.Lock()
		id, exists := store[body.Name]
		if !exists {
			id = nextID()
			store[body.Name] = id
		}
		f.mu.Unlock()
		if exists {
			// NetBox's unique-name constraint. The loser of a two-node race must
			// see a DEFINITE refusal, not a second object.
			writeErr(w, http.StatusBadRequest, `{"name":["This field must be unique."]}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, idRef{ID: id})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "%s not allowed here", r.Method)
	}
}

// AddDevice registers a DCIM device, so a scenario can model a host that IS
// modelled in NetBox. Absent devices resolve to 0, which is the untested-by-
// default case every existing scenario runs in.
func (f *NetBoxFake) AddDevice(name string, id int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices[name] = id
}

// ── virtual machines ────────────────────────────────────────────────────────

// vmParams is every query parameter the VM list understands.
var vmParams = map[string]bool{
	"cluster_id":           true,
	"cf_litevirt_identity": true,
	"name":                 true,
	"limit":                true,
	"offset":               true,
}

func (f *NetBoxFake) virtualMachines(w http.ResponseWriter, r *http.Request) {
	if id, ok := idFromPath(r.URL.Path, vmsAPIPath); ok {
		f.vmObject(w, r, id)
		return
	}
	switch r.Method {
	case http.MethodGet:
		f.listVMs(w, r)
	case http.MethodPost:
		f.createVM(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "%s not allowed on the VM collection", r.Method)
	}
}

func (f *NetBoxFake) listVMs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k := range q {
		if !vmParams[k] {
			writeErr(w, http.StatusBadRequest, `{"%s":["Unknown filter field"]}`, k)
			return
		}
	}
	limit, offset, ok := pageParams(w, q.Get("limit"), q.Get("offset"))
	if !ok {
		return
	}

	f.mu.Lock()
	ids := make([]int, 0, len(f.vms))
	for id := range f.vms {
		ids = append(ids, id)
	}
	sort.Ints(ids) // stable order so pagination is deterministic
	var matched []vmView
	for _, id := range ids {
		vm := f.vms[id]
		if v := q.Get("cluster_id"); v != "" {
			want, err := strconv.Atoi(v)
			if err != nil || vm.ClusterID != want {
				continue
			}
		}
		if v := q.Get("cf_litevirt_identity"); v != "" && vm.Identity != v {
			continue
		}
		if v := q.Get("name"); v != "" && vm.Name != v {
			continue
		}
		matched = append(matched, vmJSONOf(*vm))
	}
	f.mu.Unlock()

	writePage(w, f.srv.URL+vmsAPIPath, matched, limit, offset)
}

func (f *NetBoxFake) createVM(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeVMBody(w, r)
	if !ok {
		return
	}
	f.mu.Lock()
	// Built WITHOUT an id first, so a rejected create does not consume one.
	vm := &fakeVM{}
	applyVMBody(vm, body)
	if f.vmNameTakenLocked(vm.Name, vm.ClusterID, 0) {
		f.mu.Unlock()
		writeValidationErr(w, "name", vmNameClashMsg)
		return
	}
	vm.ID = f.nextVMID()
	f.vms[vm.ID] = vm
	out := vmJSONOf(*vm)
	f.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, out)
}

func (f *NetBoxFake) vmObject(w http.ResponseWriter, r *http.Request, id int) {
	switch r.Method {
	case http.MethodPatch:
		body, ok := decodeVMBody(w, r)
		if !ok {
			return
		}
		// The same identity-rewrite hook the address path fires, and for the
		// same reason: the CA re-key rewrites inventory identities too, and a
		// refusal HERE — definite, and without applying the change — is the only
		// way to reach a re-key that rewrote some of a cluster's objects and not
		// the rest.
		if h := f.takeOnPatch(); h != nil {
			if err := h(id); err != nil {
				writeErr(w, http.StatusForbidden, `{"detail":%q}`, err.Error())
				return
			}
		}
		f.mu.Lock()
		vm, known := f.vms[id]
		var out vmView
		var clash bool
		if known {
			// Applied to a COPY: a PATCH that would violate the constraint must
			// leave the stored object untouched, exactly as a rejected write does.
			next := *vm
			applyVMBody(&next, body)
			if clash = f.vmNameTakenLocked(next.Name, next.ClusterID, id); !clash {
				*vm = next
				out = vmJSONOf(*vm)
			}
		}
		f.mu.Unlock()
		if !known {
			writeErr(w, http.StatusNotFound, "no virtual-machine %d", id)
			return
		}
		if clash {
			writeValidationErr(w, "name", vmNameClashMsg)
			return
		}
		writeJSON(w, out)
	case http.MethodDelete:
		f.mu.Lock()
		_, known := f.vms[id]
		if known {
			delete(f.vms, id)
			// CASCADE, as NetBox does: the interfaces go, and every address
			// they held is unassigned rather than deleted. An address is an IPAM
			// object with a life of its own; only the assignment belonged to the
			// interface.
			for ifaceID, iface := range f.ifaces {
				if iface.VMID != id {
					continue
				}
				delete(f.ifaces, ifaceID)
				f.unassignFromLocked(ifaceID)
			}
		}
		f.mu.Unlock()
		if !known {
			writeErr(w, http.StatusNotFound, "no virtual-machine %d", id)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "%s not allowed on a VM object", r.Method)
	}
}

// vmBody is the write shape. Every key is a pointer so a PATCH can be told
// apart from an absent field — which is what makes `"device": null` mean "clear
// the link" instead of "leave it alone".
type vmBody struct {
	Name         *string            `json:"name"`
	Cluster      *int               `json:"cluster"`
	Device       *int               `json:"device"`
	VCPUs        *int               `json:"vcpus"`
	Memory       *int               `json:"memory"`
	Disk         *int               `json:"disk"`
	Status       *string            `json:"status"`
	CustomFields *map[string]string `json:"custom_fields"`
	hasDevice    bool
}

func decodeVMBody(w http.ResponseWriter, r *http.Request) (vmBody, bool) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body: %v", err)
		return vmBody{}, false
	}
	allowed := map[string]bool{
		"name": true, "cluster": true, "device": true, "vcpus": true,
		"memory": true, "disk": true, "status": true, "custom_fields": true,
	}
	for k := range raw {
		if !allowed[k] {
			writeErr(w, http.StatusBadRequest, `{"%s":["Unknown field."]}`, k)
			return vmBody{}, false
		}
	}
	var out vmBody
	// Re-marshalled rather than decoded twice so the pointer fields keep the
	// present/absent distinction the raw map just proved is legal.
	buf, _ := json.Marshal(raw)
	if err := json.Unmarshal(buf, &out); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body: %v", err)
		return vmBody{}, false
	}
	_, out.hasDevice = raw["device"]
	return out, true
}

func applyVMBody(vm *fakeVM, b vmBody) {
	if b.Name != nil {
		vm.Name = *b.Name
	}
	if b.Cluster != nil {
		vm.ClusterID = *b.Cluster
	}
	if b.hasDevice {
		// An explicit null clears the link; the key being absent leaves it.
		vm.DeviceID = 0
		if b.Device != nil {
			vm.DeviceID = *b.Device
		}
	}
	if b.VCPUs != nil {
		vm.VCPUs = *b.VCPUs
	}
	if b.Memory != nil {
		vm.Memory = *b.Memory
	}
	if b.Disk != nil {
		vm.Disk = *b.Disk
	}
	if b.Status != nil {
		vm.Status = *b.Status
	}
	if b.CustomFields != nil {
		vm.Identity = (*b.CustomFields)["litevirt_identity"]
	}
}

// ── VM interfaces ───────────────────────────────────────────────────────────

// ifaceParams is every query parameter the interface list understands.
var ifaceParams = map[string]bool{
	"cluster_id":           true,
	"cf_litevirt_identity": true,
	"limit":                true,
	"offset":               true,
}

func (f *NetBoxFake) vmInterfaces(w http.ResponseWriter, r *http.Request) {
	if id, ok := idFromPath(r.URL.Path, ifacesAPIPath); ok {
		f.ifaceObject(w, r, id)
		return
	}
	switch r.Method {
	case http.MethodGet:
		f.listIfaces(w, r)
	case http.MethodPost:
		f.createIface(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "%s not allowed on the interface collection", r.Method)
	}
}

func (f *NetBoxFake) listIfaces(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k := range q {
		if !ifaceParams[k] {
			writeErr(w, http.StatusBadRequest, `{"%s":["Unknown filter field"]}`, k)
			return
		}
	}
	limit, offset, ok := pageParams(w, q.Get("limit"), q.Get("offset"))
	if !ok {
		return
	}

	f.mu.Lock()
	ids := make([]int, 0, len(f.ifaces))
	for id := range f.ifaces {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var matched []ifaceView
	for _, id := range ids {
		iface := f.ifaces[id]
		if v := q.Get("cluster_id"); v != "" {
			// An interface has no cluster of its own; NetBox resolves it through
			// the parent VM, and so must this — a fake that ignored the filter
			// would hide a mirror reading another cluster's interfaces.
			want, err := strconv.Atoi(v)
			vm, known := f.vms[iface.VMID]
			if err != nil || !known || vm.ClusterID != want {
				continue
			}
		}
		if v := q.Get("cf_litevirt_identity"); v != "" && iface.Identity != v {
			continue
		}
		matched = append(matched, ifaceJSONOf(*iface))
	}
	f.mu.Unlock()

	writePage(w, f.srv.URL+ifacesAPIPath, matched, limit, offset)
}

func (f *NetBoxFake) createIface(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeIfaceBody(w, r)
	if !ok {
		return
	}
	if body.VirtualMachine == nil || *body.VirtualMachine == 0 {
		writeErr(w, http.StatusBadRequest, `{"virtual_machine":["This field is required."]}`)
		return
	}
	f.mu.Lock()
	_, parentKnown := f.vms[*body.VirtualMachine]
	if !parentKnown {
		f.mu.Unlock()
		writeErr(w, http.StatusBadRequest, `{"virtual_machine":["Invalid pk %d - object does not exist."]}`, *body.VirtualMachine)
		return
	}
	iface := &fakeIface{}
	applyIfaceBody(iface, body)
	if f.ifaceNameTakenLocked(iface.VMID, iface.Name, 0) {
		f.mu.Unlock()
		writeValidationErr(w, "non_field_errors", ifaceNameClashMsg)
		return
	}
	iface.ID = f.nextIfaceID()
	f.ifaces[iface.ID] = iface
	out := ifaceJSONOf(*iface)
	f.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, out)
}

func (f *NetBoxFake) ifaceObject(w http.ResponseWriter, r *http.Request, id int) {
	switch r.Method {
	case http.MethodPatch:
		body, ok := decodeIfaceBody(w, r)
		if !ok {
			return
		}
		if h := f.takeOnPatch(); h != nil {
			if err := h(id); err != nil {
				writeErr(w, http.StatusForbidden, `{"detail":%q}`, err.Error())
				return
			}
		}
		f.mu.Lock()
		iface, known := f.ifaces[id]
		var out ifaceView
		var clash bool
		if known {
			next := *iface
			applyIfaceBody(&next, body)
			// UpdateInterface never sends virtual_machine, so the parent that
			// scopes the constraint is the STORED one — which the copy carries.
			if clash = f.ifaceNameTakenLocked(next.VMID, next.Name, id); !clash {
				*iface = next
				out = ifaceJSONOf(*iface)
			}
		}
		f.mu.Unlock()
		if !known {
			writeErr(w, http.StatusNotFound, "no interface %d", id)
			return
		}
		if clash {
			writeValidationErr(w, "non_field_errors", ifaceNameClashMsg)
			return
		}
		writeJSON(w, out)
	case http.MethodDelete:
		f.mu.Lock()
		_, known := f.ifaces[id]
		if known {
			delete(f.ifaces, id)
			f.unassignFromLocked(id)
		}
		f.mu.Unlock()
		if !known {
			writeErr(w, http.StatusNotFound, "no interface %d", id)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "%s not allowed on an interface object", r.Method)
	}
}

type ifaceBody struct {
	VirtualMachine *int               `json:"virtual_machine"`
	Name           *string            `json:"name"`
	MAC            *string            `json:"mac_address"`
	CustomFields   *map[string]string `json:"custom_fields"`
}

func decodeIfaceBody(w http.ResponseWriter, r *http.Request) (ifaceBody, bool) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body: %v", err)
		return ifaceBody{}, false
	}
	allowed := map[string]bool{
		"virtual_machine": true, "name": true, "mac_address": true, "custom_fields": true,
	}
	for k := range raw {
		if !allowed[k] {
			writeErr(w, http.StatusBadRequest, `{"%s":["Unknown field."]}`, k)
			return ifaceBody{}, false
		}
	}
	var out ifaceBody
	buf, _ := json.Marshal(raw)
	if err := json.Unmarshal(buf, &out); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body: %v", err)
		return ifaceBody{}, false
	}
	return out, true
}

func applyIfaceBody(iface *fakeIface, b ifaceBody) {
	if b.VirtualMachine != nil {
		iface.VMID = *b.VirtualMachine
	}
	if b.Name != nil {
		iface.Name = *b.Name
	}
	if b.MAC != nil {
		iface.MAC = *b.MAC
	}
	if b.CustomFields != nil {
		iface.Identity = (*b.CustomFields)["litevirt_identity"]
	}
}

// ── uniqueness, as NetBox enforces it ───────────────────────────────────────

// The two messages NetBox itself returns. VirtualMachine.clean() raises a
// field-scoped error on `name`; VMInterface's (virtual_machine, name)
// unique_together surfaces through DRF as a non_field_errors entry.
const (
	vmNameClashMsg    = "A virtual machine with this name already exists in this cluster."
	ifaceNameClashMsg = "The fields virtual_machine, name must make a unique set."
)

// vmNameTakenLocked reports whether some OTHER virtual machine in clusterID
// already carries name. exclude is the id being written, so a PATCH that leaves
// the name alone does not collide with itself. Caller holds f.mu.
func (f *NetBoxFake) vmNameTakenLocked(name string, clusterID, exclude int) bool {
	for id, vm := range f.vms {
		if id != exclude && vm.Name == name && vm.ClusterID == clusterID {
			return true
		}
	}
	return false
}

// ifaceNameTakenLocked is the same predicate for an interface name within one
// virtual machine — the constraint netboxsync's nicName suffix exists to dodge.
// Caller holds f.mu.
func (f *NetBoxFake) ifaceNameTakenLocked(vmID int, name string, exclude int) bool {
	for id, iface := range f.ifaces {
		if id != exclude && iface.VMID == vmID && iface.Name == name {
			return true
		}
	}
	return false
}

// unassignFromLocked detaches every address pointing at ifaceID. Caller holds
// f.mu.
func (f *NetBoxFake) unassignFromLocked(ifaceID int) {
	for _, ip := range f.byID {
		if ip.AssignedObjectID == ifaceID {
			ip.AssignedObjectID = 0
		}
	}
}

// ── assertions ──────────────────────────────────────────────────────────────

// VMCount is how many virtual_machine objects carry this name. Anything but 1
// after a sweep is the failure that matters: 0 is a mirror that did not run, and
// 2 is one that duplicated on retry.
func (f *NetBoxFake) VMCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, vm := range f.vms {
		if vm.Name == name {
			n++
		}
	}
	return n
}

// VMCountAll is every virtual_machine object.
func (f *NetBoxFake) VMCountAll() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.vms)
}

// InterfaceCount is every vminterface object.
func (f *NetBoxFake) InterfaceCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ifaces)
}

// VMIdentities returns every virtual_machine's identity custom field, sorted.
//
// The counterpart of Identities(), which covers ADDRESSES only. A re-key
// assertion needs both: rewriting addresses while leaving inventory behind is
// exactly the bug, and an assertion that could not see inventory identities
// would pass through it.
func (f *NetBoxFake) VMIdentities() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, vm := range f.vms {
		if vm.Identity != "" {
			out = append(out, vm.Identity)
		}
	}
	sort.Strings(out)
	return out
}

// InterfaceIdentities returns every vminterface's identity custom field, sorted.
func (f *NetBoxFake) InterfaceIdentities() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, iface := range f.ifaces {
		if iface.Identity != "" {
			out = append(out, iface.Identity)
		}
	}
	sort.Strings(out)
	return out
}

// VMIDs returns every virtual_machine's NetBox id, sorted.
//
// A scenario that has to refuse ONE object's rewrite needs its id: the patch
// hook is passed an id, and picking one out of the fake's disjoint bands by
// arithmetic would silently target the wrong kind the moment a band moved.
func (f *NetBoxFake) VMIDs() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []int{}
	for id := range f.vms {
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}

// InterfaceIDs returns every interface's NetBox id, sorted.
//
// The IDS, not the count: a rename or a migration must UPDATE the interface it
// already has, and an object deleted and re-created keeps the count at one while
// silently dropping everything that referenced the old id.
func (f *NetBoxFake) InterfaceIDs() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []int{}
	for id := range f.ifaces {
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}

// VMDevice is the DCIM device the named virtual machine is linked to, or 0 when
// it carries no link. It returns -1 when the name matches anything other than
// exactly one object, so a scenario cannot read "no link" out of "no VM".
func (f *NetBoxFake) VMDevice(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	found := -1
	for _, vm := range f.vms {
		if vm.Name != name {
			continue
		}
		if found != -1 {
			return -1 // duplicated; a device assertion would be arbitrary
		}
		found = vm.DeviceID
	}
	return found
}

// VMDisk is the value the named virtual machine carries on
// `virtual_machine.disk`, VERBATIM — the fake stores what was written and
// normalises nothing, so a scenario asserting a unit is asserting what the
// mirror actually sent.
//
// It returns -1 when the name matches anything other than exactly one object,
// so a scenario cannot read a disk size out of "no VM".
func (f *NetBoxFake) VMDisk(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	found := -1
	for _, vm := range f.vms {
		if vm.Name != name {
			continue
		}
		if found != -1 {
			return -1 // duplicated; a size assertion would be arbitrary
		}
		found = vm.Disk
	}
	return found
}

// InterfaceNames returns every interface's name, sorted.
//
// The names, not just the count: NetBox rejects two interfaces sharing a name
// on one VM, so a scenario that only counted objects could not tell "both were
// created under distinct names" from "the second create was refused and the
// sweep swallowed it".
func (f *NetBoxFake) InterfaceNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, iface := range f.ifaces {
		out = append(out, iface.Name)
	}
	sort.Strings(out)
	return out
}

// InterfaceMACs returns every interface's MAC as NetBox holds it, sorted.
func (f *NetBoxFake) InterfaceMACs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, iface := range f.ifaces {
		out = append(out, iface.MAC)
	}
	sort.Strings(out)
	return out
}

// DistinctWriters returns the API tokens that have issued an INVENTORY write,
// sorted.
//
// Each fleet node carries its own token (see wireNetBox), so this is the only
// thing that distinguishes "one node mirrored" from "three nodes mirrored the
// same object and NetBox merged them by name". Scoped to the virtualization
// paths on purpose: an IPAM claim is issued by whichever node happens to create
// a VM, and counting those would make every multi-node scenario read as several
// writers whatever the mirror's leader gate did.
func (f *NetBoxFake) DistinctWriters() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.writers))
	for tok := range f.writers {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// SeedVM plants one virtual_machine directly in the store, bypassing the REST
// path — an object this cluster did not write and never will.
//
// The inventory counterpart of SeedIP. A co-tenant's inventory can also be
// modelled with a second real cluster, and where the scenario is about two
// installations that is the better fixture. What a second cluster cannot
// produce is an identity carrying a fingerprint that appears in NO cluster's
// local index, which is exactly what a pin-DERIVATION assertion needs: the
// object has to be enumerable by the re-key and still left unmatched by it.
//
// It takes the cluster id rather than resolving one, because a seed outside the
// cluster the re-key enumerates would be left alone whatever the pin logic did.
func (f *NetBoxFake) SeedVM(name string, clusterID int, identity string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextVMID()
	f.vms[id] = &fakeVM{
		ID:        id,
		Name:      name,
		ClusterID: clusterID,
		Status:    "active",
		Identity:  identity,
	}
	return id
}

// ClusterID is the id the fake assigned the named cluster, or 0 when no mirror
// pass has created it yet.
func (f *NetBoxFake) ClusterID(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clusters[name]
}

// VMIdentity is one virtual_machine's identity custom field, by id. It answers
// "was THIS object left alone", which VMIdentities() — a set with no ids in it
// — cannot.
func (f *NetBoxFake) VMIdentity(id int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	vm, ok := f.vms[id]
	if !ok {
		return ""
	}
	return vm.Identity
}

// VMIdentityByName is the identity carried by the object holding this NAME, or
// "" when no object — or more than one — does.
//
// It answers the question a reused name raises and VMCount cannot: WHICH
// incarnation ended up with the name. A scenario that frees a name for another
// object converges just as well by removing the wrong one, and a count of 1
// cannot tell the two apart.
func (f *NetBoxFake) VMIdentityByName(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var found string
	seen := 0
	for _, vm := range f.vms {
		if vm.Name == name {
			found, seen = vm.Identity, seen+1
		}
	}
	if seen != 1 {
		return ""
	}
	return found
}

// PatchCount is how many PATCH requests the fake has served, over every
// endpoint.
//
// A converged mirror issues none. It is the generic catch for a field written
// in one unit and read back in another: whatever the mismatch, the diff sees
// drift on unchanged state and the same PATCH repeats on every sweep.
func (f *NetBoxFake) PatchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.patches
}

// ── JSON views ──────────────────────────────────────────────────────────────

type idRef struct {
	ID int `json:"id"`
}

type choiceRef struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// decimalView renders a whole count the way NetBox renders a DecimalField:
// `2.0`, never a bare `2`.
//
// It matters because the mirror DECODES this. `virtual_machine.vcpus` is a
// decimal on the model and NetBox does not coerce decimals to strings, so a fake
// that echoed the integer it was given would let a decoder that demands an int
// pass every scenario here while failing against every real server.
type decimalView int

func (d decimalView) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatFloat(float64(d), 'f', 1, 64)), nil
}

type vmView struct {
	ID           int               `json:"id"`
	Name         string            `json:"name"`
	VCPUs        decimalView       `json:"vcpus"`
	Memory       int               `json:"memory"`
	Disk         int               `json:"disk"`
	Status       *choiceRef        `json:"status"`
	Cluster      *idRef            `json:"cluster"`
	Device       *idRef            `json:"device"`
	CustomFields map[string]string `json:"custom_fields"`
}

func vmJSONOf(vm fakeVM) vmView {
	out := vmView{
		ID: vm.ID, Name: vm.Name, VCPUs: decimalView(vm.VCPUs), Memory: vm.Memory, Disk: vm.Disk,
		// NetBox always serializes status as a choice object, never as the bare
		// string it accepts on a write. A fake echoing the string back would let
		// a decoder that never unwrapped it pass.
		Status: &choiceRef{Value: vm.Status, Label: strings.ToUpper(vm.Status)},
		// Always present, even when empty: NetBox returns every defined custom
		// field on every object.
		CustomFields: map[string]string{"litevirt_identity": vm.Identity},
	}
	if vm.ClusterID != 0 {
		out.Cluster = &idRef{ID: vm.ClusterID}
	}
	if vm.DeviceID != 0 {
		out.Device = &idRef{ID: vm.DeviceID}
	}
	return out
}

type ifaceView struct {
	ID             int               `json:"id"`
	Name           string            `json:"name"`
	MAC            string            `json:"mac_address"`
	VirtualMachine *idRef            `json:"virtual_machine"`
	CustomFields   map[string]string `json:"custom_fields"`
}

func ifaceJSONOf(iface fakeIface) ifaceView {
	// UPPER-cased, as NetBox does. A mirror comparing MACs case-sensitively
	// would see drift on every sweep and PATCH the same interface forever.
	out := ifaceView{
		ID: iface.ID, Name: iface.Name, MAC: strings.ToUpper(iface.MAC),
		CustomFields: map[string]string{"litevirt_identity": iface.Identity},
	}
	if iface.VMID != 0 {
		out.VirtualMachine = &idRef{ID: iface.VMID}
	}
	return out
}

// ── shared paging ───────────────────────────────────────────────────────────

func pageParams(w http.ResponseWriter, rawLimit, rawOffset string) (limit, offset int, ok bool) {
	limit, err := intParam(rawLimit, 50)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad limit: %v", err)
		return 0, 0, false
	}
	offset, err = intParam(rawOffset, 0)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad offset: %v", err)
		return 0, 0, false
	}
	return limit, offset, true
}

// writePage serves one page of a list endpoint in NetBox's envelope, including
// the `next` URL that makes the client's paginate loop terminate.
func writePage[T any](w http.ResponseWriter, base string, matched []T, limit, offset int) {
	total := len(matched)
	if offset > total {
		offset = total
	}
	end := min(offset+limit, total)

	out := struct {
		Count   int    `json:"count"`
		Next    string `json:"next"`
		Results []T    `json:"results"`
	}{Count: total, Results: []T{}}
	out.Results = append(out.Results, matched[offset:end]...)
	if end < total {
		out.Next = fmt.Sprintf("%s?limit=%d&offset=%d", base, limit, end)
	}
	writeJSON(w, out)
}
