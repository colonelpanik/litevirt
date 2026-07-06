# Telemetry (logging + distributed tracing)

litevirt emits **structured logs** and **distributed traces** through
[provide-telemetry](https://github.com/provide-io/provide-telemetry) over OTLP.
The integration lives in one package, `internal/obs`, so the backend can be
swapped without touching call sites.

**Metrics are separate.** They stay on Prometheus (`internal/metrics`, scraped at
`:7444/metrics`). provide-telemetry has no Prometheus exporter, so keeping
metrics there avoids a duplicate metrics system. `obs` handles logs + traces
only.

| Signal | System | Protocol | Endpoint |
|---|---|---|---|
| Metrics | Prometheus (`internal/metrics`) | pull | `:7444/metrics` |
| Logs + traces | provide-telemetry (`internal/obs`) | OTLP push | your collector |

## Off by default

Tracing/OTLP export is **inert until you configure an endpoint**. With no
endpoint:

- logs still emit locally as structured JSON (via the default `slog` logger),
- traces are no-ops,
- **no otel handler is attached to any gRPC path** — zero overhead.

Set an OTLP endpoint to turn export on. That single switch also activates the
otelgrpc client/server handlers, so trace context propagates across the peer
mesh.

## Configuration

Two sources, `LITEVIRT_*` env wins. Precedence, highest first:

1. `LITEVIRT_*` operator env (below)
2. directly-exported vendor vars (`OTEL_*` / `PROVIDE_*`)
3. daemon config `telemetry:` block
4. library defaults

### Daemon config (`/etc/litevirt/config.yaml`)

```yaml
telemetry:
  otlp_endpoint: "http://otel-collector:5080/api/default"  # empty = export off
  environment: "prod"          # service.env label
  sample_rate: 1.0             # trace sampling 0.0–1.0
  log_level: "INFO"            # TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL
  log_format: "json"           # json|console|pretty
```

### Operator env (`LITEVIRT_*`)

Use these instead of the vendor `PROVIDE_*`/`OTEL_*` names — `obs` maps them
internally.

| litevirt env | Purpose |
|---|---|
| `LITEVIRT_OTEL_ENDPOINT` | OTLP endpoint (turns export on) |
| `LITEVIRT_OTEL_HEADERS` | OTLP headers, e.g. `Authorization=Basic <b64>` |
| `LITEVIRT_TELEMETRY_ENV` | deployment env label |
| `LITEVIRT_TELEMETRY_SERVICE` | service name (default `litevirt`) |
| `LITEVIRT_TELEMETRY_VERSION` | version label |
| `LITEVIRT_LOG_LEVEL` | `TRACE`\|`DEBUG`\|`INFO`\|`WARNING`\|`ERROR`\|`CRITICAL` |
| `LITEVIRT_LOG_FORMAT` | `json`\|`console`\|`pretty` |
| `LITEVIRT_TRACES_SAMPLE_RATE` | trace sample rate `0.0`–`1.0` |

The standard `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_HEADERS` are also
honored directly if you prefer them.

## What gets traced

- **Every gRPC RPC** — server and client spans are created automatically
  (otelgrpc), and W3C `traceparent` is injected on outbound peer calls, so a
  multi-hop operation across daemons renders as **one connected trace**.
- **Named business spans** on the high-value multi-hop paths: `vm.migrate` and
  `failover.host`. Replication (`PushMutations`) is covered by its automatic RPC
  span.
- **Logs carry `trace.id`/`span.id`** — a log line during a migration links back
  to its span.
- **Host identity** — each daemon tags its spans/logs with `host.name` and
  `service.instance.id` (= the cluster `host_name`) via the OTel-standard
  `OTEL_RESOURCE_ATTRIBUTES`, so a mesh trace is attributable to the host that
  produced each hop. (Active with provide-telemetry ≥ v0.5.0, whose resource
  layers framework-floor < `OTEL_*` env < explicit config.)

## Volume & sampling

Traces sample at **1.0 by default** (every real operation is captured — no
random drop, so a rare failover is never lost). To keep that from becoming a
flood, high-frequency machine-to-machine RPCs are **not traced at all**: WAL
replication (`PushMutations`/`AckMutations`), anti-entropy state sync
(`GetStateDigest`/`*StateDump`), health probes (`GetHostHealth`), keepalive
(`Ping`), and replica pushes. Real operations (`CreateVM`, `MigrateVM`,
`BackupVM`, failover, …) are always traced.

If even that is too much, lower `telemetry.sample_rate` (head sampling,
parent-based). This is a blunt instrument — it drops whole traces at random — so
prefer leaving it at `1.0` unless span volume is a proven problem.

## Operating & health

- **Startup line** — the daemon logs one line at boot stating export state:
  `telemetry: OTLP export enabled endpoint=… traces_sample_rate=…`, or
  `… export disabled — local structured logging only`. Check it first if traces
  aren't arriving.
- **Export-error metric** — `litevirt_telemetry_export_errors_total` (Prometheus,
  on `:7444/metrics`) counts dropped exports. **Nonzero and growing = the
  collector is unreachable or rejecting** (e.g. missing auth header). Because it
  lives on Prometheus, not OTLP, it's visible even when trace export is dead.
  Alert on `rate(litevirt_telemetry_export_errors_total[5m]) > 0`.
- **Fail-open, non-blocking** — a down/slow collector never blocks the control
  plane: emission is async-batched and shutdown is bounded (data is dropped, the
  daemon is not stalled). Last spans/logs are flushed even on an abnormal
  (upgrade-rollback) exit.
- **Invalid config fails fast** — a bad `telemetry` block (e.g. `log_level: WARN`,
  `sample_rate: 2`, non-http endpoint) fails daemon start with a clear message
  rather than silently degrading to local logging.

## Quick start with OpenObserve

[OpenObserve](https://openobserve.ai) ingests OTLP over HTTP at
`/api/<org>/v1/{traces,logs}` and requires HTTP basic auth. The otlphttp exporter
appends `/v1/traces` etc. to the endpoint, so point the endpoint at the org base.

```bash
# 1. Build the basic-auth header from your OpenObserve user/password:
AUTH="Authorization=Basic $(printf '%s' "$OPENOBSERVE_USER:$OPENOBSERVE_PASSWORD" | base64)"

# 2. Point litevirt at OpenObserve (org "default" here):
export LITEVIRT_OTEL_ENDPOINT="http://localhost:5080/api/default"
export LITEVIRT_OTEL_HEADERS="$AUTH"
export LITEVIRT_TRACES_SAMPLE_RATE=1.0

# 3. Start the daemon — traces + logs now flow to OpenObserve.
sudo -E litevirt daemon
```

Equivalent daemon-config form:

```yaml
telemetry:
  otlp_endpoint: "http://localhost:5080/api/default"
  sample_rate: 1.0
```
…with `LITEVIRT_OTEL_HEADERS` (the auth secret) supplied via the environment /
systemd drop-in rather than the config file.

### Verify export

Drive any traced operation (e.g. `lv migrate <vm> <host>`), then query
OpenObserve. Traces land in the `default` **traces** stream and logs in the
`default` **logs** stream, tagged `service.name = litevirt`:

```bash
NOW=$(python3 -c 'import time;print(int(time.time()*1e6))')
START=$(python3 -c 'import time;print(int((time.time()-600)*1e6))')

curl -s -u "$OPENOBSERVE_USER:$OPENOBSERVE_PASSWORD" \
  -H 'Content-Type: application/json' \
  "http://localhost:5080/api/default/_search?type=traces" \
  -d "{\"query\":{\"sql\":\"SELECT service_name, operation_name, trace_id FROM \\\"default\\\" WHERE service_name = 'litevirt' ORDER BY start_time DESC LIMIT 10\",\"start_time\":$START,\"end_time\":$NOW}}"
```

A migration shows a `vm.migrate` span with the source and target daemon's RPC
spans nested under the same `trace_id`. Set `type=logs` and the same window to
see the correlated log records.

## Security notes

- `LITEVIRT_OTEL_HEADERS` carries the collector credential — keep it in the
  environment / a systemd drop-in (`0600`), not the world-readable config file.
- Trace attributes include resource names (VM, host); point export at a
  collector you trust.
- Sampling below `1.0` reduces volume but can drop the one trace you need while
  debugging a rare failover — raise it when investigating.
