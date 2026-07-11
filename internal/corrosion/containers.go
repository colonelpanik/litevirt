package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrNoRowsAffected is returned by the strict container-lifecycle write helpers
// when the guarded UPDATE matches zero live rows — i.e. the container row is
// missing or already soft-deleted. Callers use errors.Is to distinguish "the
// row vanished" from a transient DB error (the former is a fail-closed signal,
// not a success). Mirrors the zero-row-consume-guard used for single-use tokens.
var ErrNoRowsAffected = errors.New("no rows affected")

// Reserved labels litevirt uses to manage compose-deployed containers. They
// live here (the lowest layer) so corrosion, compose, grpcapi, and the daemon
// can all reference them without an import cycle.
const (
	// LabelStack tags a container with the compose stack that created it. The
	// containers table has no stack_name column, so this label is the stack
	// association the deploy planner (current-state diff) and teardown use.
	LabelStack = "litevirt.stack"
	// LabelLXCCapable is the HOST label the daemon sets to advertise that the
	// container (LXC) runtime is available. Compose requires it when placing
	// container workloads so they never land on a non-LXC host.
	LabelLXCCapable = "litevirt.lxc"
	// LabelTPMCapable / LabelSecureBootCapable are HOST labels advertising vTPM
	// (swtpm) and Secure Boot (secboot/MS OVMF) support (G1). Independent because
	// their host dependencies differ. Placement requires whichever a VM spec needs.
	LabelTPMCapable        = "litevirt.tpm"
	LabelSecureBootCapable = "litevirt.secureboot"
	// LabelUnsafeAutoFailover, when "true" on a host, restores the LEGACY
	// proceed-anyway behavior for a failed best-effort fence even after the
	// safe-fence-default policy (capabilities.SafeFenceDefaultV1) is enforced. It
	// is the explicit operator opt-in to "reschedule my VMs off this host without
	// proof of power-off," accepting the split-brain risk. Absent/anything-else =
	// the safe default (require an operator fence-confirm).
	LabelUnsafeAutoFailover = "litevirt.unsafe_auto_failover"
	// LabelIP records a container's primary IPv4 so it can serve as a load
	// balancer backend cluster-wide (containers have no vm_interfaces table).
	// Set from a static compose NIC address at create; the LB host re-discovers
	// a DHCP address locally via lxc-info when this is empty.
	LabelIP = "litevirt.ip"
)

// ContainerRecord is one LXC/OCI container's cluster-state row.
// populated by the daemon owning the container; the
// `lv ct ls` query reads across the whole cluster.
type ContainerRecord struct {
	HostName string
	Name     string
	State    string
	Image    string
	CPULimit int
	MemMiB   int
	Labels   map[string]string
	// RestartPolicy is the JSON-encoded pb.RestartPolicy ('' = none). StateDetail
	// carries the stop cause / intent ('operator-stop' etc.), the container
	// analogue of vms.state_detail; both added in schema v24.
	RestartPolicy string
	StateDetail   string
	// Project is the tenancy bucket (mirrors vms.project); '' is normalized to
	// '_default' on write. Added in schema v25.
	Project string
	// IsTemplate marks a clone-source container that can't start (mirrors
	// vms.is_template). OnHostFailure is the host-loss relocation policy the
	// failover coordinator reads ('' / 'none' = leave; 'image-recreate' =
	// recreate from a re-pullable origin on another host). Both added in v28.
	IsTemplate    bool
	OnHostFailure string
	// CreateSpec is the JSON-encoded ContainerCreateSpec (schema v34): the
	// create-time intent (template/distro/release/arch/networks) not captured by
	// the other columns. '' for rows created before v34 — readers must tolerate
	// that. Carried verbatim by RelocateContainer; kept current by every path that
	// (re)creates a container (Create/Clone/Restore).
	CreateSpec string
	// RelocateToken is stamped by a restore-relocation (the coordinator's attempt
	// token) so the coordinator can prove a (host,name) row is ITS restore — names
	// aren't cluster-unique — before tombstoning the source. '' for normal
	// containers. Schema v34.
	RelocateToken string
	CreatedAt     string
	UpdatedAt     string
}

// ContainerCreateSpec captures a container's create-time intent so host-loss
// relocation + restore can faithfully rebuild it — including litevirt-managed
// networking, which the flat columns don't record. Persisted JSON-encoded in
// containers.create_spec (schema v34). Forward-only: an empty/zero value means
// "unknown" (a pre-v34 row or old backup), and callers fall back to a bare
// image-recreate.
type ContainerCreateSpec struct {
	Template string             `json:"template,omitempty"`
	Distro   string             `json:"distro,omitempty"`
	Release  string             `json:"release,omitempty"`
	Arch     string             `json:"arch,omitempty"`
	Networks []ContainerNetwork `json:"networks,omitempty"`
}

// ContainerNetwork is one NIC of a ContainerCreateSpec. It carries the create-
// time intent so relocate/restore/clone can faithfully rebuild the NIC:
// NetworkName (the managed logical network, "" = legacy raw bridge),
// SecurityGroups (SG names), MAC (the stable generated/assigned MAC), and IP —
// the EFFECTIVE address, static OR auto-allocated (stored back at create time),
// so a relocate/restore/migrate re-reserves the SAME address instead of losing an
// auto-allocated one. (A clone is the exception: it builds the spec with IP empty
// so the copy gets a fresh address.) The derived veth is NOT stored; it's
// recomputed deterministically from (host, ct, ordinal).
type ContainerNetwork struct {
	Name           string   `json:"name,omitempty"`
	Bridge         string   `json:"bridge,omitempty"`
	IP             string   `json:"ip,omitempty"`
	MAC            string   `json:"mac,omitempty"`
	NetworkName    string   `json:"network_name,omitempty"`
	SecurityGroups []string `json:"security_groups,omitempty"`
}

// EncodeCreateSpec marshals a create spec for storage. Returns "" for a
// zero/empty spec so it round-trips as "unknown".
func EncodeCreateSpec(s ContainerCreateSpec) string {
	if s.Template == "" && s.Distro == "" && s.Release == "" && s.Arch == "" && len(s.Networks) == 0 {
		return ""
	}
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(b)
}

// DecodeCreateSpec parses a stored create spec; a blank/garbage value yields a
// zero spec (treated as "unknown" by callers).
func DecodeCreateSpec(raw string) ContainerCreateSpec {
	var s ContainerCreateSpec
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	return s
}

// UpsertContainer creates or updates the cluster row for a container.
// Atomic: the (host_name, name) primary key plus a soft-delete-aware
// UPDATE keeps us from racing with concurrent List queries.
func UpsertContainer(ctx context.Context, c *Client, r ContainerRecord) error {
	stmt, err := upsertContainerStmt(c, r)
	if err != nil {
		return err
	}
	return c.ExecuteBatch(ctx, []Statement{stmt})
}

// upsertContainerStmt builds the container UPSERT as a Statement so it can be
// written in the SAME ExecuteBatch as the interface rows + IPAM leases (atomic
// create — a crash can't leave a tracked container with missing NIC/IPAM state).
func upsertContainerStmt(c *Client, r ContainerRecord) (Statement, error) {
	now := c.NowTS()
	if r.CreatedAt == "" {
		r.CreatedAt = now
	}
	if r.Project == "" {
		r.Project = "_default"
	}
	labelsJSON := ""
	if len(r.Labels) > 0 {
		b, err := json.Marshal(r.Labels)
		if err != nil {
			return Statement{}, err
		}
		labelsJSON = string(b)
	}
	// SQLite's UPSERT (INSERT... ON CONFLICT) is the right tool here;
	// we keep created_at on update so the original timestamp survives.
	return Statement{
		SQL: `INSERT INTO containers (host_name, name, state, image, cpu_limit, memory_mib, labels, restart_policy, state_detail, project, is_template, on_host_failure, create_spec, relocate_token, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(host_name, name) DO UPDATE SET
		   state = excluded.state,
		   image = excluded.image,
		   cpu_limit = excluded.cpu_limit,
		   memory_mib = excluded.memory_mib,
		   labels = excluded.labels,
		   restart_policy = excluded.restart_policy,
		   state_detail = excluded.state_detail,
		   project = excluded.project,
		   is_template = excluded.is_template,
		   on_host_failure = excluded.on_host_failure,
		   -- Keep an existing create_spec when the caller didn't supply one, so a
		   -- generic upsert can't wipe the create-time intent (it's "current
		   -- intent", forward-only).
		   create_spec = CASE WHEN excluded.create_spec <> '' THEN excluded.create_spec ELSE create_spec END,
		   relocate_token = excluded.relocate_token,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		Params: []interface{}{
			r.HostName, r.Name, r.State, r.Image, r.CPULimit, r.MemMiB,
			labelsJSON, r.RestartPolicy, r.StateDetail, r.Project, boolToInt(r.IsTemplate), r.OnHostFailure, r.CreateSpec, r.RelocateToken, r.CreatedAt, now,
		},
	}, nil
}

// CreateContainerAtomic writes the container row and its managed interface rows
// in ONE transaction, so a crash/kill never leaves a live tracked container with
// missing interface rows. IPAM leases are allocated separately (they need a
// conditional, tombstone/race-safe write that a plain batch can't express; the
// caller reserves them before this and rolls them back on failure).
func CreateContainerAtomic(ctx context.Context, c *Client, rec ContainerRecord, ifaces []ContainerInterfaceRecord) error {
	stmts := make([]Statement, 0, 1+len(ifaces))
	cs, err := upsertContainerStmt(c, rec)
	if err != nil {
		return err
	}
	stmts = append(stmts, cs)
	for _, ifc := range ifaces {
		s, err := containerInterfaceStmt(c, ifc)
		if err != nil {
			return err
		}
		stmts = append(stmts, s)
	}
	return c.ExecuteBatch(ctx, stmts)
}

// SetContainerTemplate flips a container's is_template flag (ConvertContainer-
// ToTemplate + its revert), mirroring SetVMTemplate.
func SetContainerTemplate(ctx context.Context, c *Client, hostName, name string, isTemplate bool) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE containers SET is_template = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		boolToInt(isTemplate), now, hostName, name)
}

// SetContainerState updates only the state + updated_at — used after
// Start/Stop calls so we don't have to round-trip the full record.
func SetContainerState(ctx context.Context, c *Client, hostName, name, state string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE containers SET state = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		state, now, hostName, name)
}

// SetContainerStateStrict is SetContainerState (no state_detail) that reports a
// zero-row UPDATE as ErrNoRowsAffected instead of a silent success — the no-detail
// twin of SetContainerStateDetailStrict, for must-exist writes that intentionally
// leave state_detail unchanged.
func SetContainerStateStrict(ctx context.Context, c *Client, hostName, name, state string) error {
	now := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE containers SET state = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		state, now, hostName, name)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// SetContainerStateDetail updates state + state_detail together (leaving
// restart_policy untouched). Used by StopContainer to record operator intent
// ('operator-stop') and by the container reconciler to sync the cluster row to
// the runtime's reality with a stop-cause hint. The detail is the channel the
// restart engine reads to decide whether a stop was intentional.
func SetContainerStateDetail(ctx context.Context, c *Client, hostName, name, state, detail string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE containers SET state = ?, state_detail = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		state, detail, now, hostName, name)
}

// SetContainerStateDetailStrict is SetContainerStateDetail that treats a zero-row
// UPDATE (the row is missing or already soft-deleted) as ErrNoRowsAffected
// instead of a silent success. The fail-closed container lifecycle uses it so a
// Stop/Start that can't record its state change surfaces, rather than leaving
// the runtime and the cluster row to diverge.
func SetContainerStateDetailStrict(ctx context.Context, c *Client, hostName, name, state, detail string) error {
	now := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE containers SET state = ?, state_detail = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		state, detail, now, hostName, name)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// ContainerRelocateRecreateDetail is the state_detail the failover coordinator
// stamps on a container it re-homes after a host loss. The target host's
// container reconciler reads it to recreate the container from its image (B5).
const ContainerRelocateRecreateDetail = "relocate-recreate"

// ContainerRuntimeRekeyDetail is the provenance marker the Phase-4 runtime re-key
// reconciler stamps on a container row it reclaims (a container running locally
// whose only live DB row pointed at another host). It is DISTINCT from
// relocate_token / relocate-restore (which the failover coordinator keys on), so
// the runtime-repair path never collides with an in-flight relocation —
// relocate_token is preserved if already present and NEVER minted by this path.
const ContainerRuntimeRekeyDetail = "runtime-owner-rekey"

// RekeyContainerOwner atomically re-homes a container's ENTIRE ownership
// footprint from src.HostName to toHost — the container's first-class identity
// after PR 2a is the row PLUS its managed interface rows PLUS its IPAM leases, so
// moving only the row would strand the NICs/leases on the old host and break
// firewall/SG binding, DNS/LB, quota, and IPAM ownership. In ONE transaction it:
//
//  1. tombstones the (src.HostName, name) container row;
//  2. re-keys the row onto (toHost, name) marked running with the runtime-rekey
//     provenance detail, via a DEDICATED INSERT OR REPLACE that writes exactly
//     src's repair-safe fields (no "keep existing" merge), so a stale
//     soft-deleted (toHost, name) row can't leak old create_spec/metadata;
//  3. tombstones the source's managed container_interfaces rows;
//  4. rebuilds this host's managed interface rows from create_spec (veth
//     recomputed deterministically for toHost), mirroring the migrate finaliser;
//  5. transfers the container's IPAM leases (owner_host src→toHost, allocated_at
//     reset so the target's orphan-GC doesn't immediately reclaim them).
//
// created_at and relocate_token are preserved from src (never minted). This is
// the container analogue of UpdateVMHost — but a PK CHANGE across three tables,
// because container ownership is part of the primary key (host_name, name).
//
// The whole thing is GUARDED (compare-and-swap): the preconditions are re-checked
// inside the write transaction against src.UpdatedAt (optimistic concurrency), so
// a source that was deleted, entered relocation/migration, or whose updated_at
// changed since the caller observed it — or a live target row that appeared, or a
// managed NIC IP the source doesn't actually hold the lease for — aborts the
// re-key WITHOUT writing anything. Returns applied=false (no error) on a declined
// guard; the caller skips and retries next sweep.
func RekeyContainerOwner(ctx context.Context, c *Client, src ContainerRecord, toHost string) (bool, error) {
	now := c.NowTS()
	rk, err := rekeyContainerStmt(c, src, toHost, now)
	if err != nil {
		return false, err
	}
	managedIPs := managedNICIPs(src)
	guard := func(tx *sql.Tx) (bool, error) {
		// (a) source row still live, unchanged since observed, not relocating.
		var state, detail, token, updatedAt string
		err := tx.QueryRowContext(ctx,
			`SELECT state, COALESCE(state_detail,''), COALESCE(relocate_token,''), updated_at
			 FROM containers WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
			src.HostName, src.Name).Scan(&state, &detail, &token, &updatedAt)
		if err == sql.ErrNoRows {
			return false, nil // source vanished
		}
		if err != nil {
			return false, err
		}
		if updatedAt != src.UpdatedAt || token != "" ||
			state == "migrating" || state == "relocating" || state == "pending" {
			return false, nil // changed / now under relocation
		}
		// (b) no LIVE target row may exist (only a soft-deleted one may be replaced).
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM containers WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
			toHost, src.Name).Scan(&n); err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil // a real local row appeared — abort, never clobber it
		}
		// (c) source must own the live IPAM lease for every managed NIC (network, ip)
		// we are about to assert on the target (mirror the migrate
		// ContainerLeasesOwnedBy invariant) — matched on BOTH network and ip, since
		// ip_allocations is keyed by (network, ip) and the rebuilt interface row
		// claims a specific network. Never claim an address IPAM doesn't back.
		for _, nic := range managedIPs {
			var ln int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM ip_allocations
				 WHERE owner_kind = 'ct' AND owner_host = ? AND vm_name = ? AND network = ? AND ip = ? AND deleted_at IS NULL`,
				src.HostName, src.Name, nic.network, nic.ip).Scan(&ln); err != nil {
				return false, err
			}
			if ln == 0 {
				return false, nil // a managed (network, ip) with no source lease — refuse
			}
		}
		return true, nil
	}

	stmts := []Statement{
		// (1) tombstone the source container row.
		{
			SQL:    `UPDATE containers SET deleted_at = ?, updated_at = ? WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
			Params: []interface{}{now, now, src.HostName, src.Name},
		},
		// (2) re-key the row onto the new host.
		rk,
		// (3) tombstone the source's managed interface rows.
		{
			SQL:    `UPDATE container_interfaces SET deleted_at = ?, updated_at = ? WHERE host_name = ? AND ct_name = ? AND deleted_at IS NULL`,
			Params: []interface{}{now, now, src.HostName, src.Name},
		},
	}
	// (4) rebuild the managed interface rows on the new host from create_spec.
	for _, ifc := range BuildContainerInterfacesFromSpec(toHost, src.Name, DecodeCreateSpec(src.CreateSpec)) {
		s, err := containerInterfaceStmt(c, ifc)
		if err != nil {
			return false, err
		}
		stmts = append(stmts, s)
	}
	// (5) transfer the IPAM leases (owner_host src→toHost), resetting allocated_at.
	stmts = append(stmts, Statement{
		SQL: `UPDATE ip_allocations SET owner_host = ?, allocated_at = ?, updated_at = ?
		      WHERE owner_kind = 'ct' AND owner_host = ? AND vm_name = ? AND deleted_at IS NULL`,
		Params: []interface{}{toHost, nowRFC3339(), now, src.HostName, src.Name},
	})
	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// managedNICIP is a managed NIC's (network, ip) — the FULL IPAM key. The lease
// precondition must match both: ip_allocations is keyed by (network, ip), and the
// rebuilt target interface row claims a specific network_name, so a lease for the
// same ip on a DIFFERENT network does not back it.
type managedNICIP struct{ network, ip string }

// managedNICIPs returns the (network, ip) of each MANAGED NIC (network_name set)
// with a non-empty static/effective IP, derived from create_spec — the addresses
// the re-key will assert on the target and must prove the source holds a lease for.
func managedNICIPs(src ContainerRecord) []managedNICIP {
	var out []managedNICIP
	for _, ifc := range BuildContainerInterfacesFromSpec(src.HostName, src.Name, DecodeCreateSpec(src.CreateSpec)) {
		if ifc.IP != "" {
			out = append(out, managedNICIP{network: ifc.NetworkName, ip: ifc.IP})
		}
	}
	return out
}

// rekeyContainerStmt builds the dedicated re-key row write: an INSERT OR REPLACE
// that writes EXACTLY src's repair-safe fields onto (toHost, name) marked running
// with the runtime-rekey marker. Unlike the generic upsert it has no
// keep-existing semantics, so a stale soft-deleted target row is fully replaced
// rather than leaking old create_spec / relocation metadata.
func rekeyContainerStmt(c *Client, src ContainerRecord, toHost, now string) (Statement, error) {
	labelsJSON := ""
	if len(src.Labels) > 0 {
		b, err := json.Marshal(src.Labels)
		if err != nil {
			return Statement{}, err
		}
		labelsJSON = string(b)
	}
	createdAt := src.CreatedAt
	if createdAt == "" {
		createdAt = now
	}
	return Statement{
		SQL: `INSERT OR REPLACE INTO containers
		 (host_name, name, state, image, cpu_limit, memory_mib, labels, restart_policy, state_detail, project, is_template, on_host_failure, create_spec, relocate_token, created_at, updated_at, deleted_at)
		 VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		Params: []interface{}{
			toHost, src.Name, src.Image, src.CPULimit, src.MemMiB, labelsJSON,
			src.RestartPolicy, ContainerRuntimeRekeyDetail, src.Project, boolToInt(src.IsTemplate),
			src.OnHostFailure, src.CreateSpec, src.RelocateToken, createdAt, now,
		},
	}, nil
}

// ContainerRelocateRestorePrefix marks a container the coordinator is relocating
// via restore-from-backup. Unlike relocate-recreate (an image path stamped on the
// TARGET row), this is stamped on the SOURCE (dead-host) row as
// state="relocating", detail="relocate-restore:<target>:<token>", and the row
// stays put until the restore lands — so a re-tick (e.g. after a coordinator
// crash) can re-derive progress (see RelocateRestoreMarker). The token is the
// attempt token: the same value the target stamps on its restored row's
// relocate_token, letting the coordinator prove a (target,name) row is THIS
// restore before tombstoning the source (names aren't cluster-unique).
const ContainerRelocateRestorePrefix = "relocate-restore:"

// RelocateRestoreDetail builds the source-row marker for a restore relocation.
func RelocateRestoreDetail(target, token string) string {
	return ContainerRelocateRestorePrefix + target + ":" + token
}

// RelocateRestoreMarker parses a relocate-restore marker into (target, token,
// ok). ok=false if the row isn't so marked. A legacy marker without a token
// (pre-token) parses with token="".
func RelocateRestoreMarker(state, detail string) (target, token string, ok bool) {
	if state != "relocating" || !strings.HasPrefix(detail, ContainerRelocateRestorePrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(detail, ContainerRelocateRestorePrefix)
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		return rest[:i], rest[i+1:], true
	}
	return rest, "", true
}

// ContainerRelocateSkippedDetail is the terminal state_detail the coordinator
// stamps on a container it could neither restore nor image-recreate after a host
// loss. The row is left VISIBLE (for operator recovery) rather than tombstoned,
// and the relocate loop skips rows already so marked so it can't loop.
const ContainerRelocateSkippedDetail = "relocate-skipped"

// RestoreOutcome classifies a container restore-from-backup attempt so the
// failover coordinator can decide between completing the handoff, falling back
// to image-recreate, or DEFERRING an indeterminate result to a later reconcile
// (never destructively falling back over a restore that may have landed). Lives
// in corrosion so both grpcapi (producer) and failover (consumer) share it
// without a new package edge.
type RestoreOutcome int

const (
	// RestoreNotAttempted: no manifest found, or the restore RPC never established
	// — nothing was written. Safe to fall back immediately.
	RestoreNotAttempted RestoreOutcome = iota
	// RestoreFailedBeforeRow: the target returned a definite pre-row failure (e.g.
	// it can't open the repo / find the manifest) before recording any row. Safe
	// to fall back immediately.
	RestoreFailedBeforeRow
	// RestoreLanded: the target recorded its cluster row (the restore took effect),
	// even if a later step (start) errored. Complete the handoff.
	RestoreLanded
	// RestoreUnknown: the RPC started but the outcome is indeterminate (the
	// row-recorded frame / stream was lost). The row MAY have been written — do not
	// fall back; leave the marker and let the resolve pass settle it.
	RestoreUnknown
)

// RelocateContainer re-homes a container from oldHost to newHost after a host
// loss: it soft-deletes the old (oldHost,name) row and inserts a fresh row on
// newHost in state 'pending' with detail 'relocate-recreate', preserving the
// container's spec fields. The container's PK is (host_name,name), so a move is
// a delete-old + insert-new (mirrors the migration re-key). The target's
// reconciler recreates the rootfs from the image. Only relocatable fields are
// carried; runtime state resets to pending.
func RelocateContainer(ctx context.Context, c *Client, oldHost, name, newHost string) error {
	return RelocateContainerWithToken(ctx, c, oldHost, name, newHost, "")
}

// RelocateContainerWithToken is RelocateContainer that also stamps a relocation
// token on the re-keyed row. When the split-brain gate is enforced, the
// coordinator mints a runtime_action_proofs row bound to this token and the
// target's reconciler claims it single-use by token before recreating. token=""
// is the unenforced/legacy path (no proof binding).
func RelocateContainerWithToken(ctx context.Context, c *Client, oldHost, name, newHost, token string) error {
	old, err := GetContainer(ctx, c, oldHost, name)
	if err != nil {
		return err
	}
	if old == nil {
		return fmt.Errorf("container %q not found on host %q", name, oldHost)
	}
	// Container names aren't cluster-unique (PK is (host_name,name)). Refuse to
	// re-key onto a target that already holds a LIVE container of the same name —
	// the UpsertContainer below would otherwise clobber an unrelated container.
	// Fail BEFORE deleting the source so nothing is lost.
	if existing, _ := GetContainer(ctx, c, newHost, name); existing != nil {
		return fmt.Errorf("target host %q already has a live container %q; refusing to clobber", newHost, name)
	}
	if err := DeleteContainer(ctx, c, oldHost, name); err != nil {
		return err
	}
	rec := *old
	rec.HostName = newHost
	rec.State = "pending"
	rec.StateDetail = ContainerRelocateRecreateDetail
	rec.RelocateToken = token
	rec.CreatedAt = "" // fresh row on the target
	return UpsertContainer(ctx, c, rec)
}

// DeleteContainer soft-deletes the row. We don't physically delete so
// "container vanished from gossip" can be distinguished from "host
// crashed and we just haven't heard yet" in audit views.
func DeleteContainer(ctx context.Context, c *Client, hostName, name string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE containers SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND name = ?`,
		nowRFC3339(), now, hostName, name)
}

// DeleteContainerStrict soft-deletes a LIVE row (WHERE deleted_at IS NULL) and
// reports ErrNoRowsAffected when nothing matched — i.e. the row was already gone.
// The fail-closed DeleteContainer handler uses it so a real DB failure surfaces
// (codes.Internal) while an already-tombstoned row is the idempotent no-op the
// caller can treat as success. (Plain DeleteContainer lacks the deleted_at guard,
// so it would "affect one row" re-deleting a tombstone and hide that case.)
func DeleteContainerStrict(ctx context.Context, c *Client, hostName, name string) error {
	now := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE containers SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		nowRFC3339(), now, hostName, name)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// GetContainer returns one container row (including soft-deleted, so
// audit tools can resurrect names).
func GetContainer(ctx context.Context, c *Client, hostName, name string) (*ContainerRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, name, state, COALESCE(image, '') AS image,
		        cpu_limit, memory_mib, COALESCE(labels, '') AS labels,
		        COALESCE(restart_policy, '') AS restart_policy,
		        COALESCE(state_detail, '') AS state_detail,
		        COALESCE(project, '_default') AS project,
		        COALESCE(is_template, 0) AS is_template,
		        COALESCE(on_host_failure, '') AS on_host_failure,
		        COALESCE(create_spec, '') AS create_spec,
		        COALESCE(relocate_token, '') AS relocate_token,
		        created_at, updated_at
		 FROM containers WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		hostName, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	rec := scanContainer(rows[0])
	return &rec, nil
}

// ListContainers returns every active container, optionally scoped to
// one host. Empty hostName = cluster-wide.
func ListContainers(ctx context.Context, c *Client, hostName string) ([]ContainerRecord, error) {
	sql := `SELECT host_name, name, state, COALESCE(image, '') AS image,
		   cpu_limit, memory_mib, COALESCE(labels, '') AS labels,
		   COALESCE(restart_policy, '') AS restart_policy,
		   COALESCE(state_detail, '') AS state_detail,
		   COALESCE(project, '_default') AS project,
		   COALESCE(is_template, 0) AS is_template,
		   COALESCE(on_host_failure, '') AS on_host_failure,
		   COALESCE(create_spec, '') AS create_spec,
		   COALESCE(relocate_token, '') AS relocate_token,
		   created_at, updated_at
		FROM containers WHERE deleted_at IS NULL`
	var params []interface{}
	if hostName != "" {
		sql += " AND host_name = ?"
		params = append(params, hostName)
	}
	sql += " ORDER BY host_name, name"
	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}
	out := make([]ContainerRecord, len(rows))
	for i, r := range rows {
		out[i] = scanContainer(r)
	}
	return out, nil
}

// ListContainersPage returns up to limit containers, ordered by (host_name, name),
// whose (host_name, name) sorts strictly after (afterHost, afterName) — keyset
// pagination for ListContainers. Containers are keyed by (host_name, name), so the
// composite is the stable cursor. Empty afterHost starts at the beginning; limit
// <= 0 returns all matching rows.
func ListContainersPage(ctx context.Context, c *Client, hostName, afterHost, afterName string, limit int) ([]ContainerRecord, error) {
	sql := `SELECT host_name, name, state, COALESCE(image, '') AS image,
		   cpu_limit, memory_mib, COALESCE(labels, '') AS labels,
		   COALESCE(restart_policy, '') AS restart_policy,
		   COALESCE(state_detail, '') AS state_detail,
		   COALESCE(project, '_default') AS project,
		   COALESCE(is_template, 0) AS is_template,
		   COALESCE(on_host_failure, '') AS on_host_failure,
		   COALESCE(create_spec, '') AS create_spec,
		   COALESCE(relocate_token, '') AS relocate_token,
		   created_at, updated_at
		FROM containers WHERE deleted_at IS NULL`
	var params []interface{}
	if hostName != "" {
		sql += " AND host_name = ?"
		params = append(params, hostName)
	}
	if afterHost != "" || afterName != "" {
		// Row-value comparison for a composite keyset cursor.
		sql += " AND (host_name, name) > (?, ?)"
		params = append(params, afterHost, afterName)
	}
	sql += " ORDER BY host_name, name"
	if limit > 0 {
		sql += " LIMIT ?"
		params = append(params, limit)
	}
	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}
	out := make([]ContainerRecord, len(rows))
	for i, r := range rows {
		out[i] = scanContainer(r)
	}
	return out, nil
}

// scanContainer builds a ContainerRecord from a row carrying the full
// container column set (used by GetContainer + ListContainers).
func scanContainer(r Row) ContainerRecord {
	return ContainerRecord{
		HostName: r.String("host_name"), Name: r.String("name"),
		State: r.String("state"), Image: r.String("image"),
		CPULimit: r.Int("cpu_limit"), MemMiB: r.Int("memory_mib"),
		Labels:        decodeContainerLabels(r.String("labels")),
		RestartPolicy: r.String("restart_policy"), StateDetail: r.String("state_detail"),
		Project:       r.String("project"),
		IsTemplate:    r.Int("is_template") == 1,
		OnHostFailure: r.String("on_host_failure"),
		CreateSpec:    r.String("create_spec"),
		RelocateToken: r.String("relocate_token"),
		CreatedAt:     r.String("created_at"), UpdatedAt: r.String("updated_at"),
	}
}

// ListContainersByStack returns active containers tagged with the given compose
// stack (via the LabelStack label set at deploy time). Compose uses this for
// idempotent re-apply (current state) and teardown — the containers table has
// no stack_name column, so the label is the association.
func ListContainersByStack(ctx context.Context, c *Client, stack string) ([]ContainerRecord, error) {
	all, err := ListContainers(ctx, c, "")
	if err != nil {
		return nil, err
	}
	out := make([]ContainerRecord, 0)
	for _, ct := range all {
		if ct.Labels[LabelStack] == stack {
			out = append(out, ct)
		}
	}
	return out, nil
}

// decodeContainerLabels parses the JSON labels column on the
// containers row. Distinct name from hosts.go's decodeLabels because
// they live in the same package.
func decodeContainerLabels(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}
