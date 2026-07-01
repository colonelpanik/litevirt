# Model Context Protocol Server

`litevirt mcp` runs a stdio MCP server for operator assistants. It uses the same
connection path as the CLI: `LV_HOST`, `LV_TOKEN`, and the litevirt config/PKI
files. Run it on a cluster node or bastion with working credentials, or on a
workstation that can reach a daemon over TLS with a valid token.

stdout is reserved for MCP JSON-RPC. Diagnostics and logs go to stderr.

## Run

```bash
LV_HOST=root@node-1 LV_TOKEN=<token> litevirt mcp
```

Useful flags:

```bash
litevirt mcp --timeout 45s --max-list-items 100 --tool-prefix litevirt_
litevirt mcp --allow-write
LV_MCP_ALLOW_WRITE=1 litevirt mcp
```

`--allow-write` exposes the reversible write tools. It is a process-start
boundary outside the model's reach. Each write tool also requires `confirm: true`;
that is only an accidental-double-action guard. The real gates are litevirt RBAC
and the process flag.

## Output Safety

Read tools return curated allowlisted fields, not raw protobuf JSON. In
particular:

- VM specs are omitted, including cloud-init and injected user data.
- Audit and VM-event detail/user payloads are omitted.
- List tools are capped by `--max-list-items` and return `truncated: true` when
  more data exists.

## Tools

Read tools are available by default. Tool names use `--tool-prefix`, which
defaults to `litevirt_`; append these suffixes:

- `ping`, `whoami`
- `cluster_status`, `list_hosts`, `inspect_host`, `host_stats`, `host_health`
- `list_vms`, `inspect_vm`, `vm_stats`, `list_vm_events`
- `list_containers`
- `list_networks`, `get_network`
- `list_storage_pools`, `get_storage_pool`
- `list_load_balancers`, `inspect_lb`, `lb_stats`
- `list_audit_log`
- `list_rebalance_proposals`
- `list_projects`, `get_project_quota`, `get_project_usage`

With `--allow-write`, these additional single-object lifecycle tools are exposed:

- `start_vm`, `stop_vm`, `restart_vm`
- `start_container`, `stop_container`
- `enable_backend`, `disable_backend`, `drain_backend`

Destructive operations such as delete, force-stop, restore, migrate, fence, and
schema changes are intentionally not exposed through MCP.

## Resources

Live resources:

- `litevirt://cluster/status`
- `litevirt://cluster/hosts`
- `litevirt://cluster/vms`
- `litevirt://cluster/projects`

Docs are not exposed as MCP resources; a shipped binary usually has no repo tree.

## Prompts

Prompt handlers assemble safe read context only. They do not call mutation tools.

- `incident_triage`
- `capacity_review`
- `tenant_isolation_review`

## Errors

Tool errors are returned as structured content:

```json
{
  "error": {
    "code": "Unavailable",
    "message": "connection refused",
    "retryable": true,
    "hint": "The daemon is unavailable; retry after connectivity recovers."
  }
}
```

Retryable codes are `Unavailable` and `DeadlineExceeded`. Common non-retryable
codes include `Unauthenticated`, `PermissionDenied`, `InvalidArgument`,
`NotFound`, `FailedPrecondition`, and `Canceled`.

## Deployment Notes

The MCP server connects once at startup, validates with `Ping` and `Whoami`, and
reconnects on `Unavailable`. `LV_TOKEN` is static; if it expires or is revoked,
restart `litevirt mcp` after renewing credentials.

For Claude Desktop-style local configs, point the command at a reachable daemon
and make sure the local PKI/token are current. If workstation PKI is stale or the
cluster is not reachable from the workstation, run the MCP server on a node or
bastion instead.
