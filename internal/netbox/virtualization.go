package netbox

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The virtualization and dcim collections this mirror touches.
const (
	vmsPath          = "/api/virtualization/virtual-machines/"
	vmInterfacesPath = "/api/virtualization/interfaces/"
	clusterTypesPath = "/api/virtualization/cluster-types/"
	clustersPath     = "/api/virtualization/clusters/"
	devicesPath      = "/api/dcim/devices/"
	// macAddressesPath exists only on NetBox 4.2+, where a MAC became an object
	// of its own. Reached only when a write shows the server is on that shape —
	// see repairDroppedMAC.
	macAddressesPath = "/api/dcim/mac-addresses/"
)

// VirtualMachine is one virtualization.virtual_machine.
type VirtualMachine struct {
	ID        int
	Name      string
	ClusterID int
	DeviceID  int // 0 when the host is not modelled as a DCIM device
	VCPUs     VCPUs
	MemoryMB  int
	// DiskMB is `virtual_machine.disk`, which NetBox counts in MEGABYTES.
	// Named for its unit because the field it feeds is the whole trap: while
	// this was DiskGB the mirror wrote gibibytes into a megabyte column, so a
	// 20 GiB disk was recorded as 20 MB and read back as 20 GiB. Build it with
	// DiskMBFromBytes rather than converting at a call site.
	DiskMB   int
	Status   string
	Identity string
}

// bytesPerMB is NetBox's megabyte: DECIMAL, 1 MB = 1,000,000 bytes — not the
// binary mebibyte litevirt uses for memory. `virtual_machine.disk` and
// `virtual_disk.size` are both counted in it.
const bytesPerMB = 1_000_000

// DiskMBFromBytes converts a provisioned byte count to NetBox's disk unit.
//
// THE ONLY conversion into that unit, and it takes BYTES: routing through a
// gibibyte figure first — project quota's DiskQuotaGiB, say, which rounds each
// disk up to whole GiB because quota admission must never under-charge — throws
// away most of the value's precision before the unit is even reached.
//
// Rounds UP, so a recorded size never understates the provisioned disk: an
// inventory record that says a machine has less disk than it has is the reading
// that gets someone paged.
func DiskMBFromBytes(sizeBytes int64) int {
	if sizeBytes <= 0 {
		return 0
	}
	// Divide first, then carry the remainder: adding bytesPerMB-1 up front
	// overflows int64 for a size near the maximum.
	mb := sizeBytes / bytesPerMB
	if sizeBytes%bytesPerMB != 0 {
		mb++
	}
	return int(mb)
}

// VCPUs is NetBox's `vcpus`, which is a DECIMAL on the model and an integer
// count everywhere in litevirt.
//
// It is not an int here because it cannot be: `virtual_machine.vcpus` is a
// DecimalField and NetBox does not coerce decimals to strings, so a real
// response carries `"vcpus": 2.0`. Decoding that into an int fails the WHOLE
// response — the create-response decode and every page of the inventory
// enumeration — so an int made the mirror unable to read a live NetBox at all,
// while the fake, which emitted a bare `2`, could not show it.
//
// FLOAT, not a rounded int, because the value has to survive the round trip for
// the diff to be right: a NetBox that somehow holds 2.5 must compare UNEQUAL to
// a desired 2 and be patched back to it. Truncating on decode would make the
// two compare equal and leave the fractional value in NetBox forever.
//
// Only `vcpus` is decimal. `memory` (mebibytes) and `disk` (DECIMAL megabytes)
// are PositiveIntegerFields on the same model and arrive as JSON integers, so
// they stay ints — and a null in any of the three is simply the zero value,
// which is what an unset field means to the diff.
type VCPUs float64

// UnmarshalJSON accepts what NetBox and its neighbours actually put on the wire:
// a JSON number (`2` or `2.0`), a JSON null, or a QUOTED decimal ("2.00").
//
// The quoted form is not hypothetical: it is what DRF emits for every decimal
// field when COERCE_DECIMAL_TO_STRING is left at its framework default, which
// NetBox overrides but an install fronting it need not. Accepting both costs one
// branch and removes a whole class of "cannot read the server" failure.
func (v *VCPUs) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		*v = 0
		return nil
	}
	s = strings.Trim(s, `"`)
	if s == "" {
		*v = 0
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("netbox: vcpus %s is neither a number nor a decimal string: %w", b, err)
	}
	*v = VCPUs(f)
	return nil
}

// VMInterface is one virtualization.vminterface. It is keyed on MAC, never on
// the litevirt NIC id, which is derived from the VM name and re-derived on
// rename.
type VMInterface struct {
	ID       int
	VMID     int
	Name     string
	MAC      string
	Identity string
}

type vmJSON struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	VCPUs  VCPUs  `json:"vcpus"`
	Memory int    `json:"memory"`
	// Megabytes on the wire, and megabytes in the field it lands in: the two
	// names must not drift apart again.
	DiskMB int `json:"disk"`
	Status *struct {
		Value string `json:"value"`
	} `json:"status"`
	Cluster *struct {
		ID int `json:"id"`
	} `json:"cluster"`
	Device *struct {
		ID int `json:"id"`
	} `json:"device"`
	CustomFields map[string]any `json:"custom_fields"`
}

// toVM maps EVERY field the diff compares.
//
// Omitting one is not a cosmetic bug: if Status is never populated, a desired
// Status of "active" differs from an actual "" on every sweep, so every VM looks
// changed forever and write-on-change never fires. Any field added to the diff
// must be added here too.
func (j vmJSON) toVM() VirtualMachine {
	out := VirtualMachine{
		ID: j.ID, Name: j.Name,
		VCPUs: j.VCPUs, MemoryMB: j.Memory, DiskMB: j.DiskMB,
		Status: j.statusValue(),
	}
	if j.Cluster != nil {
		out.ClusterID = j.Cluster.ID
	}
	if j.Device != nil {
		out.DeviceID = j.Device.ID
	}
	if v, ok := j.CustomFields[IdentityField].(string); ok {
		out.Identity = v
	}
	return out
}

// statusValue unwraps NetBox's {"value": "...", "label": "..."} choice object.
func (j vmJSON) statusValue() string {
	if j.Status == nil {
		return ""
	}
	return j.Status.Value
}

type ifaceJSON struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	MAC            string `json:"mac_address"`
	VirtualMachine *struct {
		ID int `json:"id"`
	} `json:"virtual_machine"`
	CustomFields map[string]any `json:"custom_fields"`
}

func (j ifaceJSON) toIface() VMInterface {
	// NetBox echoes a MAC upper-cased. The identity is built from the
	// lower-cased form, so a MAC left as NetBox returned it would never compare
	// equal to the one litevirt holds.
	out := VMInterface{ID: j.ID, Name: j.Name, MAC: strings.ToLower(j.MAC)}
	if j.VirtualMachine != nil {
		out.VMID = j.VirtualMachine.ID
	}
	if v, ok := j.CustomFields[IdentityField].(string); ok {
		out.Identity = v
	}
	return out
}

// ListVMsByCluster enumerates every VM in one cluster, paginated. The diff needs
// the COMPLETE set: a truncated list makes live VMs look vanished, and the sweep
// would delete them.
func (c *Client) ListVMsByCluster(ctx context.Context, clusterID int) ([]VirtualMachine, error) {
	q := url.Values{}
	q.Set("cluster_id", strconv.Itoa(clusterID))
	return paginate(ctx, c, vmsPath, q, vmJSON.toVM)
}

// ListInterfacesByCluster enumerates every interface in one cluster, paginated.
func (c *Client) ListInterfacesByCluster(ctx context.Context, clusterID int) ([]VMInterface, error) {
	q := url.Values{}
	q.Set("cluster_id", strconv.Itoa(clusterID))
	return paginate(ctx, c, vmInterfacesPath, q, ifaceJSON.toIface)
}

// ipBatchSize is how many interface ids go into one address query. A URL
// carrying every interface in a large cluster would exceed what servers and
// proxies accept, so the query is batched rather than sent whole.
const ipBatchSize = 50

// ListOwnedIPsForInterfaces enumerates litevirt-owned addresses assigned to the
// given interfaces, paginated and batched.
//
// The interface set IS the cluster scope. NetBox's IPAddressFilterSet has
// vminterface_id and virtual_machine_id but NO cluster filter, so there is no
// single query for "every address in this cluster"; inventing one would either
// error or, worse, be ignored — silently dropping the scope and returning every
// litevirt address in the install.
//
// The mirror reads ASSIGNMENT from these objects rather than from the interface,
// because assignment lives on the address in NetBox and an interface can carry
// several. Only addresses carrying a non-empty litevirt identity are returned,
// which is what keeps an operator-owned address structurally out of the clear
// path.
func (c *Client) ListOwnedIPsForInterfaces(ctx context.Context, ifaceIDs []int) ([]IPAddress, error) {
	var out []IPAddress
	for i := 0; i < len(ifaceIDs); i += ipBatchSize {
		end := min(i+ipBatchSize, len(ifaceIDs))
		q := url.Values{}
		for _, id := range ifaceIDs[i:end] {
			q.Add("vminterface_id", strconv.Itoa(id))
		}
		q.Set("cf_"+IdentityField+"__n", "") // has a non-empty litevirt identity
		batch, err := paginate(ctx, c, ipAddressesPath, q, ipJSON.toIP)
		if err != nil {
			return nil, err
		}
		out = append(out, batch...)
	}
	return out, nil
}

// vmBody is the write body for a VM, shared by create and update so a PATCH can
// never send a different field set than the CREATE it is reconciling towards.
func vmBody(vm VirtualMachine) map[string]any {
	b := map[string]any{
		"name":          vm.Name,
		"cluster":       vm.ClusterID,
		"vcpus":         vm.VCPUs,
		"memory":        vm.MemoryMB,
		"disk":          vm.DiskMB,
		"status":        vm.Status,
		"custom_fields": map[string]string{IdentityField: vm.Identity},
	}
	// Send device EXPLICITLY, including nil.
	//
	// Omitting the key when the link is absent makes a PATCH leave a stale link
	// in place, so the diff keeps seeing 9 != 0 and emits the same update
	// forever. An explicit null is what actually clears it.
	if vm.DeviceID != 0 {
		b["device"] = vm.DeviceID
	} else {
		b["device"] = nil
	}
	return b
}

// CreateVM creates one virtual machine.
func (c *Client) CreateVM(ctx context.Context, vm VirtualMachine) (VirtualMachine, error) {
	var out vmJSON
	if err := c.do(ctx, http.MethodPost, vmsPath, vmBody(vm), &out); err != nil {
		return VirtualMachine{}, err
	}
	return out.toVM(), nil
}

// UpdateVM patches one virtual machine. Callers must diff first — an
// unconditional PATCH every sweep buries NetBox's changelog in noise.
func (c *Client) UpdateVM(ctx context.Context, id int, vm VirtualMachine) error {
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(vmsPath+"%d/", id), vmBody(vm), nil)
}

// DeleteVM removes one virtual machine. Its interfaces and their IP assignments
// go with it.
func (c *Client) DeleteVM(ctx context.Context, id int) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf(vmsPath+"%d/", id), nil, nil)
}

// FindVMByIdentity searches by the identity custom field. Called BEFORE every
// create: NetBox has no idempotency key, so a timeout after creation but before
// the identity-map write would otherwise duplicate the object on retry.
//
// It returns every match rather than the first, because more than one is the
// ambiguity a caller has to refuse instead of guessing at.
func (c *Client) FindVMByIdentity(ctx context.Context, identity string) ([]VirtualMachine, error) {
	q := url.Values{}
	q.Set("cf_"+IdentityField, identity)
	return paginate(ctx, c, vmsPath, q, vmJSON.toVM)
}

// FindInterfaceByIdentity searches interfaces by identity custom field. Like
// FindVMByIdentity it returns every match, so a duplicate is visible to the
// caller rather than silently resolved to whichever object sorted first.
func (c *Client) FindInterfaceByIdentity(ctx context.Context, identity string) ([]VMInterface, error) {
	q := url.Values{}
	q.Set("cf_"+IdentityField, identity)
	return paginate(ctx, c, vmInterfacesPath, q, ifaceJSON.toIface)
}

// CreateInterface creates one VM interface.
func (c *Client) CreateInterface(ctx context.Context, i VMInterface) (VMInterface, error) {
	body := map[string]any{
		"virtual_machine": i.VMID,
		"name":            i.Name,
		"mac_address":     i.MAC,
		"custom_fields":   map[string]string{IdentityField: i.Identity},
	}
	var out ifaceJSON
	if err := c.do(ctx, http.MethodPost, vmInterfacesPath, body, &out); err != nil {
		return VMInterface{}, err
	}
	got := out.toIface()
	if err := c.repairDroppedMAC(ctx, got.ID, i.MAC, got.MAC); err != nil {
		return VMInterface{}, err
	}
	if i.MAC != "" {
		got.MAC = i.MAC
	}
	return got, nil
}

// UpdateInterface patches one VM interface. Diff before calling — an
// unconditional PATCH per sweep buries NetBox's changelog.
//
// The identity is not rewritten: it is derived from the MAC, so an interface
// whose MAC changed is a different identity and therefore a different object,
// not an update.
func (c *Client) UpdateInterface(ctx context.Context, id int, i VMInterface) error {
	body := map[string]any{
		"name":        i.Name,
		"mac_address": i.MAC,
	}
	// The response is decoded rather than discarded so a dropped MAC is visible
	// here: this is the call the mirror makes once a diff has noticed the MAC
	// missing, so it is the call that has to be able to put it back.
	var out ifaceJSON
	if err := c.do(ctx, http.MethodPatch, fmt.Sprintf(vmInterfacesPath+"%d/", id), body, &out); err != nil {
		return err
	}
	return c.repairDroppedMAC(ctx, id, i.MAC, out.toIface().MAC)
}

// repairDroppedMAC records `want` on the interface when the server answered a
// write with `got` — that is, did not honour the `mac_address` field.
//
// NetBox 4.2 moved the MAC off the interface: `vminterface.mac_address` is
// READ-ONLY there, and a MAC is a `dcim.MACAddress` object assigned to the
// interface which the interface points at with `primary_mac_address`. Such a
// server accepts an interface write carrying `mac_address` with a 2xx and
// SILENTLY DROPS the field, so a caller that does not compare what came back
// cannot tell the shapes apart. That silence is the whole hazard: nothing fails,
// and the mirror's NIC diff then sees the MAC missing on every single sweep,
// emits an update, and has that update dropped in turn — one write per NIC per
// sweep against a mirror that can never converge.
//
// Comparing the response, rather than the server's version string, is what keeps
// this correct in both directions: a pre-4.2 server echoes the MAC back and
// never has its (nonexistent) MACAddress collection touched.
//
// An interface's MAC never changes — a NIC's identity is (fingerprint, uuid,
// MAC), so a changed MAC is a different identity and therefore a different
// object — which makes this a create-once repair, not a value to reconcile.
func (c *Client) repairDroppedMAC(ctx context.Context, ifaceID int, want, got string) error {
	if want == "" || ifaceID == 0 || strings.EqualFold(want, got) {
		return nil
	}
	macID, err := c.findAssignedMACAddress(ctx, ifaceID, want)
	if err != nil {
		return err
	}
	if macID == 0 {
		// NetBox permits SEVERAL MACAddress objects carrying the same MAC, so a
		// repair that only ever created would add one more on every retry after
		// a failed PATCH below. Hence the lookup above: adopt, then create.
		var created struct {
			ID int `json:"id"`
		}
		body := map[string]any{
			"mac_address":          want,
			"assigned_object_type": "virtualization.vminterface",
			"assigned_object_id":   ifaceID,
		}
		if err := c.do(ctx, http.MethodPost, macAddressesPath, body, &created); err != nil {
			return fmt.Errorf("netbox: record MAC %s for interface %d: %w", want, ifaceID, err)
		}
		macID = created.ID
	}
	patch := map[string]any{"primary_mac_address": macID}
	if err := c.do(ctx, http.MethodPatch, fmt.Sprintf(vmInterfacesPath+"%d/", ifaceID), patch, nil); err != nil {
		return fmt.Errorf("netbox: set primary MAC of interface %d to %s: %w", ifaceID, want, err)
	}
	return nil
}

// findAssignedMACAddress returns the id of the MACAddress object carrying mac
// and already assigned to this interface, or 0. NetBox matches the address
// case-insensitively, so the lower-cased form litevirt holds is the right query.
func (c *Client) findAssignedMACAddress(ctx context.Context, ifaceID int, mac string) (int, error) {
	q := url.Values{}
	q.Set("mac_address", mac)
	q.Set("assigned_object_type", "virtualization.vminterface")
	q.Set("assigned_object_id", strconv.Itoa(ifaceID))
	var page struct {
		Results []struct {
			ID int `json:"id"`
		} `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, macAddressesPath+"?"+q.Encode(), nil, &page); err != nil {
		return 0, fmt.Errorf("netbox: look up MAC %s of interface %d: %w", mac, ifaceID, err)
	}
	if len(page.Results) == 0 {
		return 0, nil
	}
	return page.Results[0].ID, nil
}

// SetVMIdentity rewrites ONE virtual machine's litevirt identity custom field.
//
// It is the CA re-key's inventory write, and the exact counterpart of
// SetIPIdentity. PATCH, not PUT: NetBox's PUT is a full replace, so an omitted
// `name` or `cluster` would be blanked and the re-key would destroy the objects
// it exists to preserve. The body carries nothing but the custom field for the
// same reason — anything else could rename a VM or move it between clusters
// while re-stamping it.
//
// It deliberately does NOT reuse UpdateVM. That sends the whole mirrored field
// set, so a re-key would have to know a VM's desired name, size and status to
// rewrite its identity — and would silently reconcile them on the way past, in
// an operation whose whole contract is that it changes one field.
func (c *Client) SetVMIdentity(ctx context.Context, id int, identity string) error {
	body := map[string]any{
		"custom_fields": map[string]string{IdentityField: identity},
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(vmsPath+"%d/", id), body, nil)
}

// SetInterfaceIdentity rewrites ONE VM interface's litevirt identity custom
// field. Same shape, same reasons, as SetVMIdentity.
//
// UpdateInterface is not it: that one deliberately never touches the identity,
// because a NIC whose MAC changed is a different object rather than an update.
// The re-key is the one caller that rewrites the identity while the MAC stays
// put, so it needs a write of its own.
func (c *Client) SetInterfaceIdentity(ctx context.Context, id int, identity string) error {
	body := map[string]any{
		"custom_fields": map[string]string{IdentityField: identity},
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(vmInterfacesPath+"%d/", id), body, nil)
}

// DeleteInterface removes one VM interface. Without it a hotplug detach never
// converges in NetBox.
func (c *Client) DeleteInterface(ctx context.Context, id int) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf(vmInterfacesPath+"%d/", id), nil, nil)
}

// AssignIPToInterface attaches an existing address to an interface. NetBox's
// convention is IPs on interfaces, not on the VM.
func (c *Client) AssignIPToInterface(ctx context.Context, ipID, ifaceID int) error {
	body := map[string]any{
		"assigned_object_type": "virtualization.vminterface",
		"assigned_object_id":   ifaceID,
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(ipAddressesPath+"%d/", ipID), body, nil)
}

// ClearIPAssignment detaches an address from whatever holds it.
//
// It takes the ADDRESS id, not the interface id — assignment lives on the
// address object. Callers must have proven litevirt ownership of that address
// first; clearing an operator-owned one is destructive.
func (c *Client) ClearIPAssignment(ctx context.Context, ipID int) error {
	// Both halves go explicitly, and as null: an omitted key is a no-op on a
	// PATCH, which would leave the address attached to an interface that is
	// about to disappear.
	body := map[string]any{
		"assigned_object_type": nil,
		"assigned_object_id":   nil,
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(ipAddressesPath+"%d/", ipID), body, nil)
}

// FindDeviceByName resolves a DCIM device id by name, returning 0 when absent.
// Absence is NOT an error: the host link is best-effort by design, and an
// operator who does not model hosts in NetBox must still get a working mirror.
func (c *Client) FindDeviceByName(ctx context.Context, name string) (int, error) {
	return c.firstIDByName(ctx, devicesPath, name)
}

// FindCluster resolves a cluster id by exact name, returning 0 when absent.
//
// The READ half of EnsureCluster, for the callers that must not create. The CA
// re-key enumerates a cluster's inventory to re-stamp it; bringing the cluster
// object into existence as a side effect of that question would have a re-key on
// a cluster that never mirrored anything leave a NetBox object behind. Absence
// is not an error — an absent cluster holds no inventory to re-key.
func (c *Client) FindCluster(ctx context.Context, name string) (int, error) {
	return c.firstIDByName(ctx, clustersPath, name)
}

// EnsureClusterType creates the litevirt cluster type if absent, returning its id.
func (c *Client) EnsureClusterType(ctx context.Context, name string) (int, error) {
	return c.ensureNamed(ctx, clusterTypesPath, name, map[string]any{
		"name": name, "slug": slugify(name),
	})
}

// EnsureCluster creates the cluster if absent, returning its id.
func (c *Client) EnsureCluster(ctx context.Context, name string, typeID int) (int, error) {
	return c.ensureNamed(ctx, clustersPath, name, map[string]any{
		"name": name, "type": typeID,
	})
}

// ensureNamed resolves an object by exact name, creating it once if absent.
//
// The lookup is not idempotent against a concurrent create on another node: two
// nodes can both miss and both POST. NetBox's unique-name constraint turns the
// loser into a 4xx, which Classify reports as ClassClient — a caller retrying
// the whole ensure then finds the winner's object.
func (c *Client) ensureNamed(ctx context.Context, path, name string, body map[string]any) (int, error) {
	id, err := c.firstIDByName(ctx, path, name)
	if err != nil || id != 0 {
		return id, err
	}
	var created struct {
		ID int `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, path, body, &created); err != nil {
		return 0, err
	}
	return created.ID, nil
}

// firstIDByName reads the first object with an exact name, or 0.
//
// It deliberately does NOT paginate: name is an exact filter and only the first
// match is ever consumed, so limit=1 states that truncation is the intent rather
// than leaving an unbounded request that silently stops at NetBox's default page
// size.
func (c *Client) firstIDByName(ctx context.Context, path, name string) (int, error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("limit", "1")
	var out struct {
		Results []struct {
			ID int `json:"id"`
		} `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, path+"?"+q.Encode(), nil, &out); err != nil {
		return 0, err
	}
	if len(out.Results) == 0 {
		return 0, nil
	}
	return out.Results[0].ID, nil
}

// slugify renders a name as a NetBox slug. NetBox requires one on create and
// does not derive it for API callers.
func slugify(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
