# REST API

litevirt includes a lightweight HTTP/JSON gateway over the gRPC API. It exposes a subset of common operations so tools that can't speak gRPC (curl, CI scripts, monitoring) can interact with litevirt.

The REST gateway listens on port 7446 by default. Set `rest_port: 0` in `config.yaml` to disable it.

## Authentication

All requests require a `Bearer` token in the `Authorization` header. Use an API token created with `lv user token-create`:

```bash
curl -H "Authorization: Bearer <token>" http://10.0.50.10:7446/api/v1/health
```

## Streaming responses (Server-Sent Events)

Streaming gRPC RPCs (today: `MigrateVM`, `DrainHost`) can be consumed as
Server-Sent Events. Opt in via either:

- `Accept: text/event-stream` header, or
- `?stream=sse` query parameter (handy for curl).

```bash
curl -N -H "Accept: text/event-stream" -H "Authorization: Bearer $TOKEN" \
  -X POST "http://10.0.50.10:7446/api/v1/vms/web-1/migrate" \
  -d '{"target_host":"host-b"}'

# Output:
# event: progress
# data: {"step":"pre-copy","percent":10}
#
# event: progress
# data: {"step":"pre-copy","percent":50}
#
# event: complete
# data: {}
```

Without the SSE opt-in, streaming endpoints return the first message + an
ack (legacy compatibility). SSE is wired for many streaming RPCs today —
VM migrate, host drain, backup snapshot/restore, stack deploy, region
migrate, and volume move/replicate (see the streaming routes listed below);
widening it to every remaining streaming RPC is on the roadmap.

## Endpoints

### Health

```
GET /api/v1/health
```

Returns `{"status": "ok", "host": "<hostname>"}` if the daemon is running.

### Hosts

```
GET    /api/v1/hosts                       # List all hosts
GET    /api/v1/hosts/{name}                # Inspect a specific host
POST   /api/v1/hosts/{name}/drain          # Evacuate VMs off host
POST   /api/v1/hosts/{name}/undrain        # Return host to scheduling
PUT    /api/v1/hosts/{name}/labels         # Set or remove labels
POST   /api/v1/hosts/{name}/fence          # Manually fence a host
DELETE /api/v1/hosts/{name}                # Remove host from cluster (?force=true)
GET    /api/v1/hosts/{name}/devices        # List PCI devices (?type=gpu)
POST   /api/v1/hosts/{name}/rescan         # Rescan PCI devices
GET    /api/v1/hosts/{name}/health         # Host health matrix
GET    /api/v1/hosts/{name}/stats          # Host resource statistics
PUT    /api/v1/hosts/{name}/config         # Configure host settings
```

Set labels request body:

```json
{
  "labels": {"zone": "us-east", "gpu": "true"},
  "remove": ["old-label"]
}
```

Configure host request body (all fields optional):

```json
{
  "fence_strategy": "ipmi",
  "ipmi_address": "10.0.50.100",
  "ipmi_user": "admin",
  "ipmi_pass": "secret",
  "watchdog_dev": "/dev/watchdog"
}
```

### Virtual Machines

```
POST   /api/v1/vms                              # Create a VM
GET    /api/v1/vms                              # List VMs (?stack=<name>&host=<name>)
GET    /api/v1/vms/{name}                       # Inspect a VM
PUT    /api/v1/vms/{name}                       # Update VM resources (cpu, memory)
POST   /api/v1/vms/{name}/start                 # Start a VM
POST   /api/v1/vms/{name}/stop                  # Stop a VM (?force=true)
POST   /api/v1/vms/{name}/restart               # Restart a VM
DELETE /api/v1/vms/{name}                       # Delete a VM
POST   /api/v1/vms/{name}/exec                  # Run command via guest agent
POST   /api/v1/vms/{name}/migrate               # Live/cold migrate
POST   /api/v1/vms/{name}/attach                # Attach device (disk, nic, pci)
POST   /api/v1/vms/{name}/detach                # Detach device
POST   /api/v1/vms/{name}/set-ip                # Set VM IP address
POST   /api/v1/vms/{name}/rebuild               # Recreate from stored spec
POST   /api/v1/vms/{name}/disks/{disk}/resize   # Resize a disk
GET    /api/v1/vms/{name}/stats                 # VM resource statistics
```

Migrate request body (protobuf-JSON for `MigrateVMRequest`):

```json
{
  "target_host": "host-b",
  "strategy": "MIGRATE_LIVE",
  "with_storage": false
}
```

`strategy` is `MIGRATE_LIVE` (default) | `MIGRATE_COLD` | `MIGRATE_NONE`; set
`with_storage: true` to copy local disks during migration. (There is no `cold`
field — the CLI `lv migrate --cold` maps to `strategy: MIGRATE_COLD`.)

### Snapshots

```
POST   /api/v1/vms/{name}/snapshots                  # Create snapshot
GET    /api/v1/vms/{name}/snapshots                  # List snapshots
POST   /api/v1/vms/{name}/snapshots/{snap}/restore   # Restore snapshot
DELETE /api/v1/vms/{name}/snapshots/{snap}            # Delete snapshot
```

Create snapshot request body:

```json
{"name": "before-upgrade"}
```

### Images

```
GET    /api/v1/images                # List all images
DELETE /api/v1/images/{name}         # Delete an image
```

### Users & Auth

```
POST   /api/v1/auth/login            # Log in (returns token)
POST   /api/v1/users                 # Create a user
GET    /api/v1/users                 # List users
DELETE /api/v1/users/{name}          # Delete a user
POST   /api/v1/tokens                # Create an API token
DELETE /api/v1/tokens/{id}           # Revoke a token
```

Login request body:

```json
{"username": "admin", "password": "secret"}
```

Create user request body:

```json
{"username": "ops", "password": "secret", "role": "operator"}
```

### Monitoring

```
GET /api/v1/status                   # Cluster overview
GET /api/v1/audit                    # Audit log (?limit=50)
```

Query parameters for `GET /api/v1/vms`:

| Parameter | Description |
|-----------|-------------|
| `stack` | Filter by stack name |
| `host` | Filter by host name |

### Stacks

```
GET /api/v1/stacks             # List all stacks
```

### Load Balancers

```
GET    /api/v1/lbs                                    # List all load balancers
GET    /api/v1/lbs/{name}                             # Inspect a load balancer
POST   /api/v1/lbs                                    # Create a load balancer
PUT    /api/v1/lbs/{name}                             # Update a load balancer
DELETE /api/v1/lbs/{name}                             # Delete a load balancer
GET    /api/v1/lbs/{name}/stats                       # Get backend/frontend stats
POST   /api/v1/lbs/{name}/backends/{backend}/drain    # Drain a backend
POST   /api/v1/lbs/{name}/backends/{backend}/disable  # Disable a backend
POST   /api/v1/lbs/{name}/backends/{backend}/enable   # Enable a backend
```

Create request body:

```json
{
  "name": "my-lb",
  "vip": "10.0.100.50/24",
  "algorithm": "roundrobin",
  "ports": [{"listen": 80, "target": 8080, "protocol": "http"}],
  "hosts": ["host-a", "host-b"],
  "vm_backends": ["web-0", "web-1"]
}
```

Update request body (all fields optional, empty = no change):

```json
{
  "algorithm": "leastconn",
  "add_backends": [{"name": "web-2", "address": "10.0.1.5:8080"}],
  "remove_backends": ["web-0"]
}
```

### Networks

```
GET    /api/v1/networks              # List all networks
GET    /api/v1/networks/{name}       # Inspect a network
POST   /api/v1/networks              # Create a network
DELETE /api/v1/networks/{name}       # Delete a network (?force=true)
```

Create request body:

```json
{
  "name": "my-net",
  "type": "bridge",
  "subnet": "10.0.1.0/24",
  "dhcp": true
}
```

Query parameters for `DELETE /api/v1/networks/{name}`:

| Parameter | Description |
|-----------|-------------|
| `force` | Set to `true` to force-delete even if VMs are attached |

## Parity routes (mounted in `internal/restapi/parity.go` + `coverage.go`)

The REST gateway covers the long-tail gRPC surface. The following
routes mirror their gRPC counterparts 1-to-1 and accept the same
JSON-shaped protobuf messages:

Routes that wrap a verb (start/stop/delete/bind-sgs/…) take the target
name in the JSON body rather than a path segment, so they are
`POST /api/v1/<resource>/<verb>` rather than `…/{name}/<verb>`.

| Route | Method | gRPC RPC |
|---|---|---|
| `/api/v1/rebalance/proposals` | GET | `ListRebalanceProposals` |
| `/api/v1/rebalance/run` | POST | `RunRebalance` |
| `/api/v1/rebalance/proposals/{id}/approve` | POST | `ApproveRebalanceProposal` |
| `/api/v1/rebalance/proposals/{id}/reject` | POST | `RejectRebalanceProposal` |
| `/api/v1/2fa` | GET | `ListTwoFactors` |
| `/api/v1/2fa` | DELETE | `DisableTwoFactor` (body: `{method, label}`) |
| `/api/v1/2fa/totp/enroll` | POST | `EnrollTOTP` |
| `/api/v1/containers` | GET | `ListContainers` (?host=) |
| `/api/v1/containers/create` | POST | `CreateContainer` |
| `/api/v1/containers/start` | POST | `StartContainer` (name in body) |
| `/api/v1/containers/stop` | POST | `StopContainer` (name in body) |
| `/api/v1/containers/delete` | POST / DELETE | `DeleteContainer` (name in body) |
| `/api/v1/containers/exec` | POST | `ExecContainer` |
| `/api/v1/containers/pull` | POST | `PullOCIImage` |
| `/api/v1/firewall/reload` | POST | `ReloadFirewall` |
| `/api/v1/regions` | GET | `RegionStatus` (?region=) |
| `/api/v1/regions/list` | GET | `ListRegions` |
| `/api/v1/regions/migrate` | POST (SSE) | `CrossRegionMigrate` |
| `/api/v1/services` | GET / POST | `ListServiceEndpoints` / `UpsertServiceEndpoint` |
| `/api/v1/services` | DELETE | `DeleteServiceEndpoint` (body: `{service_name, ip}`) |
| `/api/v1/backup/schedules` | GET / POST | `ListBackupSchedules` / `CreateBackupSchedule` |
| `/api/v1/backup/schedules` | DELETE | `DeleteBackupSchedule` (body: `{vm_name, repo}`) |
| `/api/v1/backup/snapshot` | POST (SSE) | `BackupSnapshot` |
| `/api/v1/backup/restore` | POST (SSE) | `RestoreFromBackup` |
| `/api/v1/audit/verify` | POST | `VerifyAuditChain` |
| `/api/v1/audit/export` | GET | `ExportAuditChain` (?since=&until=) |
| `/api/v1/stacks/plan` | POST | `DiffStack` (full resolved plan) |
| `/api/v1/stacks/deploy` | POST (SSE) | `DeployStack` |
| `/api/v1/stacks/delete` | POST / DELETE | `DeleteStack` (name in body) |
| `/api/v1/stacks/export` | GET / POST | `ExportStack` (?name= or body) |
| `/api/v1/stacks/{name}/migrate-volumes` | POST (SSE) | `MigrateStackVolumes` |
| `/api/v1/realms` | GET | `ListRealms` |
| `/api/v1/sessions` | GET | `ListSessions` |
| `/api/v1/sessions/{id}` | DELETE | `RevokeSession` |
| `/api/v1/vms/bind-sgs` | POST | `BindSecurityGroups` (vm in body) |
| `/api/v1/vms/move-volume` | POST (SSE) | `MoveVolume` (vm in body) |
| `/api/v1/vms/replicate-volume` | POST (SSE) | `ReplicateVolume` (vm in body) |
| `/api/v1/pools` | GET / POST | `ListStoragePools` / `CreateStoragePool` |
| `/api/v1/pools/{name}` | GET / DELETE | `GetStoragePool` / `DeleteStoragePool` (?host=) |
| `/api/v1/hosts/preflight-upgrade` | POST | `PreflightUpgrade` |

POST routes that wrap streaming RPCs (`/api/v1/backup/snapshot`,
`/api/v1/backup/restore`, `/api/v1/vms/move-volume`, `/api/v1/stacks/deploy`,
`/api/v1/regions/migrate`, etc.) emit Server-Sent Events when the client
sends `Accept: text/event-stream` or appends `?stream=sse`. Otherwise
they return the first progress frame and close.

## Still gRPC-only

A handful of RPCs remain gRPC-only because they're bidirectional
streams that don't map cleanly onto SSE / chunked HTTP. These will
move to WebSocket in a later iteration:

- `StreamEvents`, `GetVMLogs`, `ConsoleVM`, `ProxyVNC` — bidirectional or
  WebSocket-shaped. (`ExecContainer` IS wired in REST — `POST
  /api/v1/containers/{name}/exec`.)
- `RestoreLive` — keeps an NBD server alive for the duration of the
  stream; modelling that over HTTP is awkward.
- `GetSpiceInfo` — short-lived URL handoff, but tied to a
  per-connection token; not worth duplicating yet.

## Response format

Responses are JSON. Protobuf fields use snake_case names. Errors return:

```json
{"error": "description of the problem"}
```

Successful `DELETE` returns HTTP 204 with no body. Action endpoints (`start`, `stop`, `restart`) return:

```json
{"status": "started", "vm": "my-vm"}
```

## Examples

```bash
# List all VMs on a specific host
curl -H "Authorization: Bearer $TOKEN" \
  "http://10.0.50.10:7446/api/v1/vms?host=host-a"

# Stop a VM
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://10.0.50.10:7446/api/v1/vms/my-vm/stop"

# Delete a VM
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "http://10.0.50.10:7446/api/v1/vms/my-vm"

# Create a load balancer
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"web-lb","vip":"10.0.100.50/24","algorithm":"roundrobin","ports":[{"listen":80,"target":8080,"protocol":"http"}],"vm_backends":["web-0","web-1"]}' \
  "http://10.0.50.10:7446/api/v1/lbs"

# Get LB stats
curl -H "Authorization: Bearer $TOKEN" \
  "http://10.0.50.10:7446/api/v1/lbs/web-lb/stats"

# Drain a backend before maintenance
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://10.0.50.10:7446/api/v1/lbs/web-lb/backends/web-0/drain"

# Create a network
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"app-net","type":"bridge","subnet":"10.0.1.0/24","dhcp":true}' \
  "http://10.0.50.10:7446/api/v1/networks"

# Force-delete a network
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "http://10.0.50.10:7446/api/v1/networks/app-net?force=true"

# Drain a host before maintenance
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://10.0.50.10:7446/api/v1/hosts/host-a/drain"

# Set labels on a host
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"labels":{"zone":"us-east"}}' \
  "http://10.0.50.10:7446/api/v1/hosts/host-a/labels"

# Migrate a VM
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_host":"host-b"}' \
  "http://10.0.50.10:7446/api/v1/vms/my-vm/migrate"

# Create a snapshot
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"before-upgrade"}' \
  "http://10.0.50.10:7446/api/v1/vms/my-vm/snapshots"

# Log in and get a token
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}' \
  "http://10.0.50.10:7446/api/v1/auth/login"

# View audit log
curl -H "Authorization: Bearer $TOKEN" \
  "http://10.0.50.10:7446/api/v1/audit?limit=20"

# Get cluster status
curl -H "Authorization: Bearer $TOKEN" \
  "http://10.0.50.10:7446/api/v1/status"
```
