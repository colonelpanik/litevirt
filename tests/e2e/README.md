# End-to-End Tests

Comprehensive tests that run against a live litevirt cluster. These exercise the full stack: CLI, gRPC handlers, REST API, state replication, networking, migration, and error handling.

## Prerequisites

- A running cluster with 4 hosts (2 minimum, 4 recommended)
- `lv` binary in PATH
- `LV_HOST` pointing to one cluster node
- A base image already pulled (default name: `ubuntu`)
- Admin-level credentials

## Quick start

```bash
# Build fresh binaries
make build-cli

# Set target
export LV_HOST=root@10.0.50.10

# Run all tests (30 min timeout)
go test ./tests/e2e/ -v -timeout 30m -count=1

# Run only fast tests (skip migration, failover, backup)
E2E_SKIP_SLOW=1 go test ./tests/e2e/ -v -timeout 15m -count=1

# Run specific phase
go test ./tests/e2e/ -v -timeout 10m -run TestREST
go test ./tests/e2e/ -v -timeout 10m -run TestCompose
go test ./tests/e2e/ -v -timeout 10m -run TestError
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LV_HOST` | (required) | SSH target for CLI, e.g. `root@10.0.50.10` |
| `LV_BIN` | `lv` | Path to lv binary |
| `E2E_IMAGE` | `ubuntu` | Base image name for test VMs |
| `E2E_HOSTS` | (auto-detected) | Comma-separated host names |
| `E2E_REST_URL` | `http://<first-host>:7446` | REST API base URL |
| `E2E_REST_TOKEN` | (skip REST tests) | API token for REST tests |
| `E2E_SKIP_SLOW` | `0` | Set to `1` to skip migration/backup tests |

## Test phases

| Phase | Tests | What it covers |
|-------|-------|----------------|
| 0 | Setup | Discover cluster topology |
| 1 | Cluster & hosts | status, health, digest, host inspect/drain/undrain/labels/config/stats |
| 2 | Images | list, push to other host |
| 3 | VM lifecycle | create, start, stop, restart, delete, force-stop, logs |
| 4 | VM hot-update | CPU/memory update on running VM |
| 5 | Snapshots | create, list, restore, delete |
| 6 | Migration | Live migrate, cold migrate between hosts |
| 7 | Networks | Create/delete bridge, VM with custom network |
| 8 | Compose stacks | Deploy, scale up/down, rolling update, teardown |
| 9 | Users & RBAC | User CRUD, token create/revoke |
| 10 | Monitoring | Audit log, Prometheus metrics |
| 11 | REST API | All endpoints: health, hosts, VMs, snapshots, users, auth |
| 12 | State convergence | VM visible from different hosts, digest consistency |
| 13 | Error handling | Nonexistent resources, duplicates, invalid images, bad auth |
| 14 | Concurrent ops | Parallel VM creation across hosts |
| 15 | Backup & restore | Full backup to file, restore to new VM |
| 16 | Disk/NIC ops | Attach/detach disk, attach/detach NIC |
| 17 | Web UI | Port reachability check |
| 18 | Ansible | Inventory output validation |

## Cleanup

Tests clean up after themselves via `t.Cleanup()`. All test resources use the prefix `e2e-` with a unique PID-based suffix for easy identification.

If tests are interrupted, clean up manually:

```bash
# Find and remove leftover test VMs
lv ls | grep e2e- | awk '{print $1}' | xargs -I{} lv rm {} --force

# Find and remove test networks
lv network ls | grep e2e- | awk '{print $1}' | xargs -I{} lv network rm {} --force

# Find and remove test users
lv user ls | grep e2e- | awk '{print $1}' | xargs -I{} lv user delete {}

# Remove test labels
for h in $(lv host ls | awk 'NR>1{print $1}'); do
  lv host label rm $h e2e-test e2e-rest 2>/dev/null
done
```
