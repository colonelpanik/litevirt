package corrosion

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/randid"
)

// BindingRecord is one litevirt network bound to one NetBox prefix.
type BindingRecord struct {
	Network            string
	PrefixID           int
	ObservedCIDR       string
	VRFID              int
	ClusterFingerprint string
	// NetBoxCluster is the NetBox virtualization.cluster name the FIRST bind
	// resolved, pinned here so a node whose own netbox.cluster_name resolves to
	// a different one can discover the disagreement and refuse to mirror.
	//
	// It belongs on this row for the same reason ClusterFingerprint does: the
	// row replicates, and a node has no other way to learn what a peer's config
	// says. Unlike every enforcement.* flag this setting has no latch to make it
	// uniform — a capability token carries a name, not a value — and the mirror
	// sweep runs on whichever node holds the netbox leader lease, so a
	// non-uniform value would move the whole inventory between two cluster
	// objects as leadership moved.
	//
	// EMPTY means "not pinned", not "the empty name": the resolution always
	// yields a non-empty string (the override, the local cluster name, or the
	// placeholder), so the only row that reads back empty is one written before
	// this column existed. Such a row cannot disagree with anything, so the
	// mismatch check passes it over rather than refusing on it.
	NetBoxCluster string
	Suspended     bool
	SuspendReason string
}

// ClaimBinding inserts a binding ONLY if the prefix is unbound, then confirms
// by read-back. Returns false when another network already holds the prefix.
//
// A read-then-upsert is not enough: two concurrent binds both see nil from
// GetBindingByPrefix, both upsert, and the second silently steals the prefix
// from the first. A conflict clause that cannot touch a LIVE row, plus the
// read-back, makes the first writer win.
//
// The conflict target is the prefix_id PRIMARY KEY, which a TOMBSTONED row
// still occupies — so a released prefix (DeleteBinding) would conflict forever
// and read back nil. The guarded DO UPDATE resurrects a tombstone and only a
// tombstone: `WHERE netbox_bindings.deleted_at IS NOT NULL` leaves a live row
// untouched, exactly as DO NOTHING did. Same shape as the reclaim guard in
// internal/network/ipam.go's AllocateIPFor.
func ClaimBinding(ctx context.Context, c *Client, r BindingRecord) (bool, error) {
	if err := c.Execute(ctx,
		`INSERT INTO netbox_bindings
		   (prefix_id, network, observed_cidr, vrf_id, cluster_fingerprint,
		    netbox_cluster, suspended, suspend_reason, validated_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 0, '', ?, ?, ?)
		 ON CONFLICT(prefix_id) DO UPDATE SET
		   network = excluded.network,
		   observed_cidr = excluded.observed_cidr,
		   vrf_id = excluded.vrf_id,
		   cluster_fingerprint = excluded.cluster_fingerprint,
		   netbox_cluster = excluded.netbox_cluster,
		   suspended = 0,
		   suspend_reason = '',
		   validated_at = excluded.validated_at,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL
		 WHERE netbox_bindings.deleted_at IS NOT NULL`,
		r.PrefixID, r.Network, r.ObservedCIDR, r.VRFID, r.ClusterFingerprint,
		r.NetBoxCluster, c.NowWall(), c.NowWall(), c.NowTS()); err != nil {
		return false, fmt.Errorf("claim binding: %w", err)
	}
	got, err := GetBindingByPrefix(ctx, c, r.PrefixID)
	if err != nil {
		return false, err
	}
	if got == nil {
		return false, fmt.Errorf("binding for prefix %d vanished after insert", r.PrefixID)
	}
	return got.Network == r.Network, nil
}

// UpsertBinding rewrites an EXISTING binding — used by revalidation and re-key,
// never to create one. Use ClaimBinding for a new bind. It refuses (returns an
// error) when no row exists for the prefix, rather than silently creating one
// — a silent create would bypass ClaimBinding's uniqueness read-back.
func UpsertBinding(ctx context.Context, c *Client, r BindingRecord) error {
	susp := 0
	if r.Suspended {
		susp = 1
	}
	n, err := c.ExecuteRows(ctx,
		`UPDATE netbox_bindings SET
		   network = ?,
		   observed_cidr = ?,
		   vrf_id = ?,
		   cluster_fingerprint = ?,
		   netbox_cluster = ?,
		   suspended = ?,
		   suspend_reason = ?,
		   validated_at = ?,
		   updated_at = ?,
		   deleted_at = NULL
		 WHERE prefix_id = ?`,
		r.Network, r.ObservedCIDR, r.VRFID, r.ClusterFingerprint, r.NetBoxCluster,
		susp, r.SuspendReason, c.NowWall(), c.NowTS(), r.PrefixID)
	if err != nil {
		return fmt.Errorf("update binding: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("binding for prefix %d does not exist; use ClaimBinding", r.PrefixID)
	}
	return nil
}

// SuspendBinding marks a binding unusable for NEW allocations. Running VMs are
// untouched — suspension is about refusing further claims, not about disturbing
// workloads that already hold an address.
func SuspendBinding(ctx context.Context, c *Client, prefixID int, reason string) error {
	return c.Execute(ctx,
		`UPDATE netbox_bindings SET suspended = 1, suspend_reason = ?, updated_at = ?
		 WHERE prefix_id = ?`,
		reason, c.NowTS(), prefixID)
}

// DeleteBinding RELEASES a prefix: the network behind the binding is gone (or
// never landed), so nothing may keep holding the NetBox prefix. It tombstones
// rather than hard-deletes, because a hard DELETE does not replicate as an LWW
// row — and the tombstone is what ClaimBinding reclaims when the prefix is
// bound again. Releasing an already-released (or never-created) binding is a
// no-op, so a compensating caller can retry it.
func DeleteBinding(ctx context.Context, c *Client, prefixID int) error {
	if err := c.Execute(ctx,
		`UPDATE netbox_bindings SET deleted_at = ?, updated_at = ?
		 WHERE prefix_id = ? AND deleted_at IS NULL`,
		c.NowWall(), c.NowTS(), prefixID); err != nil {
		return fmt.Errorf("delete binding for prefix %d: %w", prefixID, err)
	}
	return nil
}

// bindingCols is every column a BindingRecord carries, COALESCEd where a row an
// older peer wrote could leave one null. netbox_cluster is among them: it is
// v51-and-later, and a row that predates it reads back as "" — which the
// mismatch check treats as "not pinned" rather than as a disagreement.
const bindingCols = `prefix_id, network, observed_cidr, vrf_id, cluster_fingerprint,
	 COALESCE(netbox_cluster, '') AS netbox_cluster,
	 COALESCE(suspended, 0) AS suspended, COALESCE(suspend_reason, '') AS suspend_reason`

func scanBinding(r Row) BindingRecord {
	return BindingRecord{
		PrefixID:           r.Int("prefix_id"),
		Network:            r.String("network"),
		ObservedCIDR:       r.String("observed_cidr"),
		VRFID:              r.Int("vrf_id"),
		ClusterFingerprint: r.String("cluster_fingerprint"),
		NetBoxCluster:      r.String("netbox_cluster"),
		Suspended:          r.Int("suspended") == 1,
		SuspendReason:      r.String("suspend_reason"),
	}
}

// GetBindingByPrefix reads the binding for a NetBox prefix, or nil.
func GetBindingByPrefix(ctx context.Context, c *Client, prefixID int) (*BindingRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+bindingCols+` FROM netbox_bindings WHERE prefix_id = ? AND deleted_at IS NULL`,
		prefixID)
	if err != nil {
		return nil, fmt.Errorf("query binding by prefix: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	b := scanBinding(rows[0])
	return &b, nil
}

// GetBindingByNetwork reads the binding for a litevirt network, or nil.
func GetBindingByNetwork(ctx context.Context, c *Client, network string) (*BindingRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+bindingCols+` FROM netbox_bindings WHERE network = ? AND deleted_at IS NULL`,
		network)
	if err != nil {
		return nil, fmt.Errorf("query binding by network: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	b := scanBinding(rows[0])
	return &b, nil
}

// ListBindings returns every live binding.
func ListBindings(ctx context.Context, c *Client) ([]BindingRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+bindingCols+` FROM netbox_bindings WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	out := make([]BindingRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, scanBinding(r))
	}
	return out, nil
}

// QueueItem is one pending sync/orphan-check unit.
type QueueItem struct {
	ID       string
	Kind     string
	Key      string
	Op       string
	Attempts int
}

// EnqueueSync records work for the reconciler. The queue is a LATENCY
// optimisation only — the full sweep is what makes the mirror correct — so
// callers log an enqueue failure and continue rather than failing the operation.
func EnqueueSync(ctx context.Context, c *Client, kind, key, op string) error {
	id := randid.New()
	return c.Execute(ctx,
		`INSERT INTO netbox_sync_queue (id, kind, key, op, attempts, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 0, ?, ?)`,
		id, kind, key, op, c.NowWall(), c.NowTS())
}

// DrainSyncQueue reads up to limit pending items OF ONE KIND.
//
// The kind is a required parameter, not an optional filter, because the queue
// has more than one producer and a consumer only ever owns its own kind. An
// unfiltered drain takes the oldest items whatever they are, and a consumer
// that skips a foreign kind without acking it (as the orphan sweeper must —
// acking another component's work silently drops it) then makes no progress at
// all once a full batch of somebody else's items sits at the head. The orphan
// sweeper is the cluster's only stuck-lease detector, so that starvation is
// silent and unbounded.
func DrainSyncQueue(ctx context.Context, c *Client, kind string, limit int) ([]QueueItem, error) {
	rows, err := c.Query(ctx,
		`SELECT id, kind, key, op, COALESCE(attempts, 0) AS attempts
		 FROM netbox_sync_queue WHERE kind = ? AND deleted_at IS NULL
		 ORDER BY created_at LIMIT ?`, kind, limit)
	if err != nil {
		return nil, fmt.Errorf("drain sync queue: %w", err)
	}
	out := make([]QueueItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, QueueItem{
			ID: r.String("id"), Kind: r.String("kind"),
			Key: r.String("key"), Op: r.String("op"), Attempts: r.Int("attempts"),
		})
	}
	return out, nil
}

// BumpSyncAttempts counts ONE failed resolution of a queued item, so a lookup
// that can never succeed is bounded instead of retried on every pass forever.
//
// The increment is an SQL expression, not a value the caller computed: a
// read-modify-write in Go would lose one of two concurrent attempts, and the
// count is exactly what decides when an item is retired.
func BumpSyncAttempts(ctx context.Context, c *Client, id string) error {
	return c.Execute(ctx,
		`UPDATE netbox_sync_queue SET attempts = attempts + 1, updated_at = ?
		 WHERE id = ?`,
		c.NowTS(), id)
}

// AckSyncItem tombstones a completed item.
func AckSyncItem(ctx context.Context, c *Client, id string) error {
	return c.Execute(ctx,
		`UPDATE netbox_sync_queue SET deleted_at = ?, updated_at = ? WHERE id = ?`,
		c.NowWall(), c.NowTS(), id)
}

// LeaseRecord is one ip_allocations row with its NetBox join keys.
//
// The OWNER triple travels with it because bind-time adoption has to decide
// whether a lease it found is one it may account for, and every part of that
// answer is an owner question: a `ct` lease refuses the bind outright (containers
// are unsupported on a bound network, so adopting one would manufacture a state
// the rest of the system rejects), and a `vm` lease has to be matched against
// the NIC whose address it names. A record that carried only the address could
// not tell those apart.
type LeaseRecord struct {
	Network string
	IP      string
	MAC     string
	// VMName is the owner NAME (the legacy column name; see OwnerKind).
	VMName       string
	OwnerKind    string // "vm" | "ct"
	OwnerHost    string // "" for VMs (names are cluster-global); the host for CTs
	NetBoxIPID   int
	NetBoxPrefix int
}

// leaseCols is every column a LeaseRecord carries, COALESCEd where the schema
// allows a null. The NetBox columns are nullable — every pre-v51 lease has them
// empty — so a builtin lease reads back as id 0, which is what tells a release
// there is no remote object to delete.
const leaseCols = `network, ip, mac, vm_name,
	        COALESCE(owner_kind, 'vm') AS owner_kind,
	        COALESCE(owner_host, '') AS owner_host,
	        COALESCE(netbox_ip_id, 0) AS netbox_ip_id,
	        COALESCE(netbox_prefix_id, 0) AS netbox_prefix_id`

func scanLease(r Row) LeaseRecord {
	return LeaseRecord{
		Network:      r.String("network"),
		IP:           r.String("ip"),
		MAC:          r.String("mac"),
		VMName:       r.String("vm_name"),
		OwnerKind:    r.String("owner_kind"),
		OwnerHost:    r.String("owner_host"),
		NetBoxIPID:   r.Int("netbox_ip_id"),
		NetBoxPrefix: r.Int("netbox_prefix_id"),
	}
}

// ListLeasesByNetwork returns every LIVE lease on one litevirt network.
//
// LIVE ONLY, and that predicate is load-bearing in BOTH directions. A tombstoned
// lease RETAINS its netbox_ip_id (ReleaseLease sets deleted_at and leaves the
// join key alone), so admitting tombstones would let a released address read as
// "already adopted" and be skipped by the very pass that has to claim it — the
// address a new guest now holds would stay invisible to NetBox for good. And a
// tombstoned lease is not evidence anybody holds the address, so treating one as
// live would also have a bind reserve addresses nothing uses.
//
// Owner-BLIND, unlike GetLeaseByIPForOwner: the question here is not "may I
// retire this owner's row?" but "what does litevirt already believe about the
// addresses on this network?", and a lease whose owner no longer matches
// anything is exactly the half-finished state a bind must refuse rather than
// silently step over.
func ListLeasesByNetwork(ctx context.Context, c *Client, network string) ([]LeaseRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+leaseCols+`
		 FROM ip_allocations
		 WHERE network = ? AND deleted_at IS NULL`, network)
	if err != nil {
		return nil, fmt.Errorf("list leases on network %q: %w", network, err)
	}
	out := make([]LeaseRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, scanLease(r))
	}
	return out, nil
}

// GetLeaseByIP reads one LIVE lease by its (network, ip) PRIMARY KEY, whoever
// owns it, or nil.
//
// Owner-BLIND on purpose, and that is the whole difference from
// GetLeaseByIPForOwner below. That one answers "may I retire this owner's row?",
// and hides a foreign row behind a nil so the caller treats it as nothing to do.
// This one answers "is anything holding this address?" — a question whose only
// safe negative is a row that is genuinely absent. A caller that is about to
// destroy something OUTSIDE this database on the strength of an address being
// free has to ask it this way round: a foreign owner and an absent row are the
// same nil to an owner-scoped read, and they authorize opposite actions.
func GetLeaseByIP(ctx context.Context, c *Client, network, ip string) (*LeaseRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+leaseCols+`
		 FROM ip_allocations
		 WHERE network = ? AND ip = ? AND deleted_at IS NULL`,
		network, ip)
	if err != nil {
		return nil, fmt.Errorf("query lease: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	lease := scanLease(rows[0])
	return &lease, nil
}

// GetLeaseByIPForOwner reads one lease by its (network, ip) PRIMARY KEY, scoped
// to the owner that must hold it, or nil.
//
// Keyed on the ADDRESS, because a release has to name the exact row it is
// retiring and an owner-keyed read cannot distinguish two NICs of one workload.
// The owner triple is a PREDICATE on top of that key, matching ReleaseLease's:
// a read that returned a FOREIGN lease sharing (network, ip) would hand the
// caller a row it may not retire, and the owner-scoped release would then refuse
// it — turning someone else's address into a workload that cannot be deleted.
// Returning nil instead lets the caller treat it as "not ours, nothing to do".
//
// The NetBox columns are nullable — every pre-v51 lease has them empty — so they
// are COALESCEd, and a builtin lease reads back as id 0, which is what tells a
// release there is no remote object to delete.
func GetLeaseByIPForOwner(ctx context.Context, c *Client, network, ip, ownerKind, ownerHost, name string) (*LeaseRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+leaseCols+`
		 FROM ip_allocations
		 WHERE network = ? AND ip = ? AND vm_name = ?
		   AND owner_kind = ? AND owner_host = ? AND deleted_at IS NULL`,
		network, ip, name, ownerKind, ownerHost)
	if err != nil {
		return nil, fmt.Errorf("query lease: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	l := scanLease(rows[0])
	return &l, nil
}

// LeaseExistsByIP reports whether ANY live lease references (network, ip).
//
// Deliberately owner-BLIND, unlike GetLeaseByIPForOwner. The orphan sweeper asks
// a different question: not "may I retire this owner's row?" but "does litevirt
// still believe this address is taken?". A lease whose owner triple no longer
// matches anything is exactly the half-finished state a crashed release leaves —
// and it is still a lease, still standing between the sweeper and an address a
// guest may be using. Scoping this read to an owner would hide those rows and
// let the sweeper free an address the cluster still holds.
func LeaseExistsByIP(ctx context.Context, c *Client, network, ip string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT 1 AS hit FROM ip_allocations
		 WHERE network = ? AND ip = ? AND deleted_at IS NULL`,
		network, ip)
	if err != nil {
		return false, fmt.Errorf("query lease by ip: %w", err)
	}
	return len(rows) > 0, nil
}

// ListNetBoxLeases returns every LIVE lease that carries a NetBox address
// object — the join the inventory mirror needs to say which `ip_address` a NIC
// holds.
//
// Scoped to non-null netbox_ip_id rather than returning every lease: a builtin
// allocation has no remote object, and admitting it would put a NIC into the
// mirror's desired set with address id 0, which reads exactly like "this NIC
// has no address" and would make the two indistinguishable.
//
// One read per sweep, not one per NIC: a sweep touches every VM in the cluster,
// and a per-NIC lookup would turn a quiet sweep into thousands of queries.
func ListNetBoxLeases(ctx context.Context, c *Client) ([]LeaseRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+leaseCols+`
		 FROM ip_allocations
		 WHERE netbox_ip_id IS NOT NULL AND deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("list netbox leases: %w", err)
	}
	out := make([]LeaseRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, scanLease(r))
	}
	return out, nil
}

// ObjectRef maps one litevirt object to its NetBox counterpart. It is what
// makes the mirror idempotent: a retried create finds the existing NetBox id
// here instead of POSTing a duplicate.
//
// LitevirtKey is the IDENTITY string in both cases — Identity(fp, uuid, "") for
// kind "vm" and Identity(fp, uuid, mac) for kind "nic" — matching Action.Key so
// the applier resolves them directly.
//
// Identity, not name: two clusters can hold same-named VMs in one NetBox, and a
// reused name must not adopt a previous incarnation's object. The NIC component
// is the MAC rather than DeterministicNICID, which RenameVM re-derives from the
// VM name and which would therefore fork a duplicate vminterface on every
// rename.
type ObjectRef struct {
	LitevirtKind string
	LitevirtKey  string
	NetBoxKind   string
	NetBoxID     int
}

// PutObjectRef records or updates a mapping.
//
// Upsert on the PRIMARY KEY, clearing deleted_at: an object that is deleted and
// re-created reuses its row rather than leaving a tombstone the conflict clause
// would keep colliding with — the same reclaim shape as ClaimBinding, minus the
// live-row guard, because the identity key already names exactly one object.
func PutObjectRef(ctx context.Context, c *Client, r ObjectRef) error {
	if err := c.Execute(ctx,
		`INSERT INTO netbox_objects
		   (litevirt_kind, litevirt_key, netbox_kind, netbox_id, synced_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(litevirt_kind, litevirt_key) DO UPDATE SET
		   netbox_kind = excluded.netbox_kind,
		   netbox_id = excluded.netbox_id,
		   synced_at = excluded.synced_at,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		r.LitevirtKind, r.LitevirtKey, r.NetBoxKind, r.NetBoxID,
		c.NowWall(), c.NowTS()); err != nil {
		return fmt.Errorf("put object ref %s/%s: %w", r.LitevirtKind, r.LitevirtKey, err)
	}
	return nil
}

const objectRefCols = `litevirt_kind, litevirt_key, netbox_kind, netbox_id`

func scanObjectRef(r Row) ObjectRef {
	return ObjectRef{
		LitevirtKind: r.String("litevirt_kind"),
		LitevirtKey:  r.String("litevirt_key"),
		NetBoxKind:   r.String("netbox_kind"),
		NetBoxID:     r.Int("netbox_id"),
	}
}

// GetObjectRef reads one mapping, or nil. A tombstoned mapping reads as absent,
// so a re-created object is synced afresh rather than adopting the NetBox object
// its predecessor owned.
func GetObjectRef(ctx context.Context, c *Client, kind, key string) (*ObjectRef, error) {
	rows, err := c.Query(ctx,
		`SELECT `+objectRefCols+` FROM netbox_objects
		 WHERE litevirt_kind = ? AND litevirt_key = ? AND deleted_at IS NULL`,
		kind, key)
	if err != nil {
		return nil, fmt.Errorf("query object ref: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	o := scanObjectRef(rows[0])
	return &o, nil
}

// DeleteObjectRef tombstones one mapping. It never hard-deletes: a hard DELETE
// does not replicate as an LWW row, and the tombstone is what PutObjectRef
// reclaims when the object comes back. Retiring an already-retired (or never
// recorded) mapping is a no-op, so a compensating caller can retry it.
func DeleteObjectRef(ctx context.Context, c *Client, kind, key string) error {
	if err := c.Execute(ctx,
		`UPDATE netbox_objects SET deleted_at = ?, updated_at = ?
		 WHERE litevirt_kind = ? AND litevirt_key = ? AND deleted_at IS NULL`,
		c.NowWall(), c.NowTS(), kind, key); err != nil {
		return fmt.Errorf("delete object ref %s/%s: %w", kind, key, err)
	}
	return nil
}

// ListObjectRefs returns every live mapping of one kind — what the orphan sweep
// diffs against NetBox. Scoped to the kind because "vm" and "nic" identities
// share a key space (a VM identity is its NIC identity with an empty MAC).
func ListObjectRefs(ctx context.Context, c *Client, kind string) ([]ObjectRef, error) {
	rows, err := c.Query(ctx,
		`SELECT `+objectRefCols+` FROM netbox_objects
		 WHERE litevirt_kind = ? AND deleted_at IS NULL`, kind)
	if err != nil {
		return nil, fmt.Errorf("list object refs: %w", err)
	}
	out := make([]ObjectRef, 0, len(rows))
	for _, r := range rows {
		out = append(out, scanObjectRef(r))
	}
	return out, nil
}
