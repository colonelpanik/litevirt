# Web UI

The litevirt web UI runs on port 7445. It is built with Go templates and HTMX -- there is no JavaScript framework. All requests require authentication via a session cookie.

## VM Management

### Creating VMs

The "New VM" form accepts the following fields:

- Name
- Image (including a **"— none (blank disk)"** option for installing from an ISO)
- CPU count
- Memory
- Disk size
- **Installer ISO** (path on host) with a **Browse…** button that opens the
  storage content browser to pick an ISO from a pool, plus a **Boot from**
  selector (auto / disk / CD-ROM / network)
- Host
- **Headless** (disables VNC) and **Enable SPICE console**
- **Tags** (`key=value` or bare `key`, comma-separated)
- **Cloud-init** (collapsible): login user, password, SSH authorized keys,
  packages, "upgrade on first boot", and a raw `#cloud-config` override
- Networks, optimization profile, resource-tuning knobs, and PCI devices
- **Memory ballooning & startup** (collapsible): min/max memory (a max above the
  boot allocation enables the virtio balloon), plus **onboot** + startup-order and
  start/stop delays
- Per-device **Mapping** field on PCI devices (cluster-portable passthrough — see
  the Resource Mappings page)

### Lifecycle Actions

VMs can be started, stopped, restarted, and deleted directly from the UI.

### Editing VMs

An edit modal is accessible from the VM detail page. It has four tabs:

- **Resources** (CPU, memory, disable VNC) -- requires the VM to be stopped.
- **Disks** -- add or remove disks. Hotplug works on running VMs.
- **NICs** -- add or remove network interfaces. Hotplug works on running VMs.
- **PCI devices** -- add or remove PCI passthrough devices. The type selector loads available devices from the selected host.

## VNC Console

An in-browser VNC viewer is available using noVNC (vendored as a static asset under `internal/ui/static/`, served by the daemon — no external CDN). It opens in a new tab at `/vms/{name}/vnc` and is only available for running VMs that have VNC enabled (not headless).

Cross-host routing path:

    browser -> WebSocket -> UI server -> gRPC ProxyVNC -> daemon on VM's host -> local VNC port

Daemon-to-daemon forwarding uses mTLS, so the UI server does not need direct network access to every host.

## SPICE Console

VMs configured with `graphics: { spice: true }` in compose expose a SPICE
device alongside (or instead of) VNC. SPICE delivers higher-fidelity
graphics (better video, USB redirection, audio) and works with external
clients like `remote-viewer`, virt-manager, or the GTK SPICE client.

Enable SPICE at VM-create time (the "Enable SPICE console" checkbox) or via
`graphics: { spice: true }` in compose. A **SPICE** button then appears on the
detail page of a running SPICE-enabled VM; it opens a modal showing the
`spice://host:port` URI and a **Download .vv** button — a virt-viewer
connection file that `remote-viewer`/`virt-viewer` opens directly (the same
flow Proxmox uses).

The daemon does NOT proxy SPICE through the UI/REST gateway — clients reach the
host's SPICE port directly (via the `.vv` file or `lv spice <vm>`). If the
host's port isn't reachable externally, tunnel via SSH:

    ssh -L 5901:127.0.0.1:<port> root@<host>
    remote-viewer spice://127.0.0.1:5901

A bundled in-browser SPICE client (spice-html5) is on the long-term roadmap.

## VM Tags

Tag VMs with `key=value` pairs (or bare keys) for organization. Set them in the
create form or via an **Edit tags** button on the VM detail header; chips render
next to the VM name in the list and on the detail page. Backed by `SetVMLabels`,
which is metadata-only — it applies to **running** VMs without a redefine.

## Clone & Templates

From a stopped VM's detail page: **Clone** (linked on shared storage, full
copy otherwise) and **Convert to template** (an immutable, unstartable clone
source; **Revert to VM** undoes it). Templates clone with a fresh identity.

## Text Console

An in-browser terminal is available using xterm.js (vendored as a static asset under `internal/ui/static/`, served by the daemon — no external CDN). It opens as a modal overlay on the VM detail page and is available for any running VM.

Cross-host routing path:

    browser -> WebSocket -> UI server -> gRPC ConsoleVM -> daemon -> serial PTY

This uses the same daemon-to-daemon mTLS forwarding pattern as VNC.

## Migration

The migrate modal shows host compatibility information for VMs with PCI devices. PCI pre-flight validation checks that the target host has enough free devices of each required type. SR-IOV VFs are hot-detached before migration and reattached on the target host.

## Authentication

The UI requires login via username and password. Sessions are maintained with a cookie. Users are managed via `lv user create` (see [cli-reference.md](cli-reference.md#authentication)).

## VM Exec

Run commands inside a running VM via the guest agent. Available from the VM detail page as a modal with a command input and output display showing exit code, stdout, and stderr.

## VM Logs

Stream VM console output in real-time. Available from the VM detail page via a "Logs" button. Uses Server-Sent Events (SSE) to stream log chunks from the `GetVMLogs` gRPC call. Features auto-scroll with a "Follow" toggle and a "Clear" button.

Stack-level logs are accessible from the stack detail page, showing a tabbed view with one tab per VM, each streaming its own log output.

## Snapshots & live memory

- **Snapshots**: the snapshot modal (VM detail) has an **"Include memory (live
  snapshot)"** checkbox — when set, the revert resumes the running VM at the exact
  snapshot instant; otherwise it's disk-only. The snapshot list shows a TYPE
  (disk/memory) column.
- **Memory balloon**: for a VM with a max-memory ceiling, the Memory card on the VM
  detail page shows an inline setter to change the live balloon target (within the
  configured min/max).

## Notifications

The **Notifications** page (Observability nav) manages alerting **targets**
(webhook / Slack) and **routes** (event-pattern + min-severity → target), with a
per-target **Test** button that sends a live test notification. Mirrors the
`lv notify` CLI; writes are CRDT-replicated. See
[notifications.md](notifications.md).

## Resource Mappings

The **Resource Mappings** page (admin nav) manages cluster-wide aliases for
equivalent passthrough devices: create a mapping, then add one device per host
(host + PCI address + optional vendor/device). VMs reference a mapping by name so
they can run on / migrate to any host registered under it. CRDT-replicated; mirrors
the `lv mapping` CLI.

## VM Backup & Restore

- **Backup**: the backup modal includes a **"Skip in-guest fs-freeze"** option;
  by default a VM with a guest agent is frozen briefly for an application-consistent
  backup. Download a full VM backup as a file from the VM detail page via a "Backup" link.
- **Restore**: Upload a backup file to create a new VM. Available from the VMs list page via a "Restore VM" button. The restore modal allows specifying VM name, CPU, memory, network, and includes upload progress tracking.
- **Promote replica**: VM detail page → "Promote replica" opens a modal to bring the VM up from its newest replica (disaster recovery). Options: new name (take over vs. alongside), explicit pool/host, force (split-brain override), and a fast overlay mode. Drives the `PromoteReplica` stream and redirects to the recovered VM. Replication schedules (incremental + auto-promote toggles) are managed under `/schedules`.

## Boot Order

Configure VM boot order (disk, CD-ROM, network/PXE) from the VM edit modal.

## Dashboard

Cluster dashboard at `/` with:

- Summary cards (hosts active/total, VMs running/total, CPU/memory/disk utilization bars)
- Per-host resource table with CPU, memory, and disk progress bars (color-coded: green <70%, yellow <90%, red ≥90%)
- Recent VMs table
- Cluster events and active alerts
- Auto-refreshes every 5 seconds

## Storage Page

Storage pool inventory at `/storage`:

- All pools across all hosts with driver badge (local/nfs/ceph/iscsi)
- Per-pool capacity bar and used/total
- Pool state (active/error), create/delete pool
- Auto-refreshes every 10 seconds

### Content browser + ISO upload

A content browser (reachable from the VM-create **Browse…** button) lists the
files in any file-based pool — `ListStoragePoolContents`, forwarded to the
pool's owning host. Pick an ISO to fill the create form's installer field, or
**upload** a file straight into the pool: the browser streams it to
`UploadStoragePoolContent` (1 MiB chunks; written to a temp file then atomically
renamed) so admins no longer need to `scp` ISOs onto hosts.

## Load Balancer Management

Full LB lifecycle from the UI:

- **Create**: Multi-section form (name, VIP, algorithm, ports, backends, host selection). Dynamic rows for ports and backends.
- **Edit**: Pre-populated form from current LB config. Modify VIP, algorithm, add/remove backends.
- **Backend control**: Per-backend enable/disable/drain buttons on the LB detail page.

## Health Timeline

Unified health view at `/health` combining:

- **Health matrix**: Host-to-host health grid (observer × target) with colored status dots (green=healthy, yellow=suspect, red=failed)
- **Active alerts**: Severity-badged alert list from cluster status
- **Recent events**: Audit log timeline with timestamps, actions, targets, and usernames
- Auto-refreshes every 5 seconds

## Network Topology

Visual network topology at `/topology` showing:

- Each network as a section with type badge (bridge=blue, vxlan=purple, isolated=green, sriov=orange)
- Network metadata (subnet, gateway, VNI)
- Connected VMs displayed as clickable cards with IP addresses

## Cluster Diagnostics

State health inspection at `/diagnostics`:

- Per-table row count and hash display
- Drift detection (consistent vs drifted state)
- "Force Sync" button to trigger state synchronization
- Auto-refreshes every 10 seconds

## Mass Operations

The VMs and Hosts list pages have a checkbox column. Selecting any rows
reveals a sticky toolbar with bulk actions:

- **VMs**: start, stop, restart, delete (with confirmation).
- **Hosts**: drain, undrain.
- **Containers**: start, stop, delete.

Bulk actions fan-out concurrently (bounded at 8 in flight) and surface a
per-row partial-failure dialog if any operation fails — the failures don't
stop other rows from completing. Master-checkbox in the table header
selects/deselects the visible rows. The list's 5s auto-refresh pauses while a
selection is active so it doesn't clear your checkboxes mid-selection.

## Containers

`/containers` lists cluster-wide LXC/OCI workloads with full lifecycle from the
UI: **Create** (download-template distro/release/arch, CPU/memory, bridge),
per-row **Start/Stop/Delete** and **Exec** (a one-shot command modal), plus the
bulk toolbar above. Requires the LXC userspace tools on the target host.
Containers are a lightweight, host-local workload — migration, snapshots,
backup, clone, tags, and load-balancing are VM-only.

## Rebalance Proposals

The cluster page links to a rebalance section that shows pending placement-
engine proposals. Each row shows source host → target host, expected score
gain percentage, the VM's resolved policy, and per-row approve / reject
buttons. The rebalancer runs every 60 s on the leader-elected daemon;
proposals expire if neither approved nor applied within 30 minutes.
See [placement.md](placement.md) for the policy/mode matrix.

## Global Search

Keyboard-accessible search bar in the navigation. Searches across all resource types (VMs, hosts, networks, stacks, images, load balancers) by name substring match. Results appear in a dropdown with categorized links. Debounced at 300ms.

## Image Operations

- **Build from VM**: Create an image from an existing VM. Available from the images page.
- **Push to Host**: Push an image to a specific host. Available from the images page.

## Stack Export

Download a stack's compose YAML as a file. Available from the stack detail page via an "Export YAML" button.

## Host Upgrade

Upload a new litevirt binary to upgrade a host. Available from the host detail page via an "Upgrade" button. Features upload progress tracking and automatic daemon restart.

The upgrade flow runs `PreflightUpgrade` first; if any blocking findings
(active migrations, pending fences, replication backlog, clock skew, witness-
host risk) are detected, the upload is refused unless the operator explicitly
overrides. The host transitions to state `upgrading` before re-exec so peer
coordinators don't fence it during the restart window. If the new binary
panic-loops past the systemd `StartLimitBurst` threshold, the
`litevirt-rollback.service` companion unit automatically restores the
previous binary. See [upgrades.md](upgrades.md) for the full upgrade-safety
contract.

## Page index

The full set of routes mounted by `internal/ui/server.go`:

| Path | What |
|---|---|
| `/` | Cluster dashboard |
| `/hosts`, `/hosts/{name}` | Host list + detail |
| `/vms`, `/vms/{name}` | VM list + detail |
| `/stacks`, `/stacks/{name}` | Compose stack list + detail |
| `/networks` | Network list |
| `/lb`, `/lb/{name}` | Load-balancer list + detail |
| `/images` | Image inventory |
| `/events` | Cluster Events — recent operation history (vm_events) seeded server-side + a live SSE tail prepending new events. (`/activity` redirects here.) |
| `/audit` | Audit log (filterable by `?target=…&action=…`) |
| `/users` | User and token management |
| `/account/2fa` | Per-user TOTP + WebAuthn enrolment |
| `/storage` | Storage pool inventory |
| `/storage/ceph` | Ceph health + CRUSH tree (read-only) |
| `/security-groups` | Security-group definitions + NIC bindings |
| `/firewall` | Cluster/host-tier firewall rules, ipsets, and default-deny policy |
| `/notifications` | Alerting targets (webhook/Slack) + routes |
| `/resource-mappings` | Cluster-wide passthrough-device alias management |
| `/containers` | Cluster-wide LXC/OCI containers + lifecycle |
| `/backups` | Backup repos and snapshot manifests |
| `/schedules` | Backup **and replication** schedules |
| `/rebalance` | Pending rebalance proposals (approve / reject) |
| `/rbac` | Path-rooted role-binding tree |
| `/projects` | Tenancy: project tree, quotas, and usage |
| `/dashboards` | Bundled Grafana JSON dashboards (download links) |
| `/metrics-viewer` | Embedded Prometheus scrape, grouped by metric family |
| `/health` | Health matrix + active alerts + audit timeline |
| `/topology` | Network topology graph |
| `/diagnostics` | Per-table state hash + drift detection |
| `/pci` | PCI topology and device assignments |

## Keyboard + theme

- **⌘K / Ctrl-K** (or `/`) opens a command palette: fuzzy-matches every page
  client-side and folds in live resource hits via `/ui/search`; arrow keys move,
  Enter opens.
- `g` + key navigation: `g d` = dashboard, `g h` = hosts, `g v` = vms,
  `g s` = stacks, `g c` = containers, `g n` = networks, `g l` = LBs,
  `g i` = images, `g b` = backups, `g e` = events.
- Theme toggle in the navbar (sun/moon icon); persists in localStorage.

## Themed confirmation dialogs

Destructive actions (`hx-confirm`) are intercepted at the global `htmx:confirm`
event and rendered as an in-theme modal (Enter confirms, Esc/backdrop cancels;
the confirm button is danger-styled for deletes) instead of the browser's
native `confirm()`.

## Console & VNC

Each running VM exposes two in-app consoles from its detail page:

- **Terminal** — the guest serial console (xterm.js over a WebSocket bridged to
  the daemon's `ConsoleVM` stream).
- **VNC** — the graphical console (noVNC over `ProxyVNC`). Opens in an in-app
  modal; "Full screen" opens the standalone viewer in a new tab.

Both work across hosts: if the VM runs on a different host than the one serving
the UI, the daemon forwards the stream to the owning host. When a session can't
start, the console now shows the **reason** (instead of a bare "disconnected")
and a **Retry** button:

| Message | Cause / fix |
| --- | --- |
| `VM "x" is not running` | Start the VM first. |
| `VNC is not enabled for VM "x"` | The VM was created headless (`--disable-vnc` / `disable_vnc: true`). Recreate or edit the VM with VNC enabled. |
| `serial console not available for VM "x"` | No serial/pty device in the domain. |
| `host <h> unreachable: …` | The host running the VM is down or unreachable. Check the host's state and network. |

**Blank terminal on a running VM** is a different condition: the WebSocket
connects (no error banner) but nothing prints. The guest most likely has no
login getty on `ttyS0` — press Enter, or enable `serial-getty@ttyS0` in the
guest. The console modal shows this hint in its footer.
