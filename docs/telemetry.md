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
  sample_rate: 1.0             # trace sampling 0.0–1.0; omit = default (100%), 0 = disabled
  log_level: "INFO"            # TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL
  log_format: "console"        # json|console|pretty (default console; json = structured)
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

### Turning export off

The endpoint **is** the switch: with no endpoint resolved, nothing exports, no
otel handler attaches to any gRPC path, and local logging stays on the stock
handler. But env wins over config — clearing `telemetry.otlp_endpoint` in
`config.yaml` does **not** disable export while `LITEVIRT_OTEL_ENDPOINT` (or
`OTEL_EXPORTER_OTLP_ENDPOINT`) is still set in the daemon's environment, e.g. in
the systemd unit. To turn export off, clear the config field **and** any
endpoint env vars, then restart the daemon.

### Exporter resilience (`LITEVIRT_OTEL_*`)

These bound the OTLP export calls themselves so a **slow or unreachable
collector** can't stall the daemon. Set them if your collector can be slow or
flap. Each knob fans out to both active signals (logs **and** traces) — one
value tunes the whole export path, no per-signal `PROVIDE_EXPORTER_*` fiddling.

When unset, the two signals default **differently**: logs ride the vendor's
exporter, which sets no caps of its own (unbounded until you set these knobs);
traces ride an obs-owned exporter (that's what makes `sample_rate` real — see
below), which falls back to the OTel SDK defaults — ~10s per-export timeout and
retries capped at about a minute. So an uncapped collector stall can hold a
**log** export open indefinitely, while a **trace** export self-bounds. Setting
`LITEVIRT_OTEL_TIMEOUT`/`RETRIES`/`BACKOFF` overrides both signals to the same
explicit values.

| litevirt env | Purpose | Example |
|---|---|---|
| `LITEVIRT_OTEL_TIMEOUT` | per-export deadline, seconds | `5` |
| `LITEVIRT_OTEL_RETRIES` | retry attempts on export failure | `2` |
| `LITEVIRT_OTEL_BACKOFF` | backoff between retries, seconds | `1` |
| `LITEVIRT_OTEL_FAIL_OPEN` | drop on failure instead of blocking | `true` |
| `LITEVIRT_OTEL_SHUTDOWN_TIMEOUT` | drain cap on daemon stop, seconds | `2` |

Boot and shutdown are already bounded structurally (the upgrade watchdog is armed
*before* telemetry init, and telemetry shutdown runs under a 2s cap), so these are
a **hardening layer**, not a requirement — reach for them when you see export
latency or a flapping collector.

`LITEVIRT_OTEL_SHUTDOWN_TIMEOUT` maps to the logs signal only (the vendor exposes
a shutdown-drain cap for logs alone; traces flush on the batch processor's own
timeout). Metrics have no knobs here — `obs` doesn't export OTLP metrics.

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
- **Export-health metrics** — on Prometheus (`:7444/metrics`). Logs stay on
  provide-telemetry's own exporter, so their health is sourced from the
  vendor's resilience snapshot (NOT an otel error handler: the fail-open
  wrapper swallows export failures before they reach otel's global handler, so
  a handler-based counter would silently read 0 against a dead collector for
  that signal). Traces run through an obs-owned `TracerProvider` (so the real
  `sample_rate` sampler applies — see above), which bypasses that vendor
  wrapper entirely; trace export failures are instead counted via an
  obs-installed otel error handler. Because these metrics live on Prometheus,
  not OTLP, they stay visible even when OTLP export is dead:

  | Metric | Meaning |
  |---|---|
  | `litevirt_telemetry_export_errors_total` | Failed OTLP export attempts (logs, vendor snapshot, + traces, obs error handler). **Nonzero and growing = collector unreachable/rejecting.** |
  | `litevirt_telemetry_export_retries_total` | Export retry attempts (logs+traces, vendor snapshot). |
  | `litevirt_telemetry_dropped_total` | Records shed because the async export queue was full (backpressure). **Logs only** — an obs-owned traces provider makes traces backpressure drops unobservable; reporting a stale vendor value would misrepresent it. |
  | `litevirt_telemetry_circuit_state{signal}` | Per-signal circuit breaker: `0`=closed, `1`=half-open, `2`=open, `-1`=unknown. `signal="traces"` is always `-1` (unknown) — the obs-owned provider has no vendor circuit to observe. |

  Alert on `rate(litevirt_telemetry_export_errors_total[5m]) > 0` (collector
  trouble) and `litevirt_telemetry_circuit_state{signal="logs"} > 0` (exporter
  tripped/probing).
- **Fail-open, non-blocking** — a down/slow collector never blocks the control
  plane: emission is async-batched and shutdown is bounded (data is dropped, the
  daemon is not stalled). Last spans/logs are flushed even on an abnormal
  (upgrade-rollback) exit.
- **Invalid config degrades, never bricks** — a bad `telemetry` value (e.g.
  `log_level: WARN` — it's `WARNING`; `sample_rate: 2`; a non-`http://` endpoint)
  is **logged as a warning and reset to its safe default** (the endpoint is
  cleared, disabling export), not treated as a fatal error. Telemetry is fail-open
  end to end: a typo in an optional block must never stop the daemon booting —
  critically, an in-place upgrade re-execs the daemon, so a config the running
  node tolerated must still boot the new binary. Watch the boot log for
  `config telemetry: …` warnings if a setting isn't taking effect.

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
