# Notifications

litevirt emits operator notifications for noteworthy cluster events to
configurable targets. It mirrors `internal/billing` in spirit — fire-and-log
delivery that never blocks or fails the operation that triggered it — but fans
out to multiple typed targets selected by **routes** (event-pattern + minimum
severity). The implementation is `internal/notify`; targets/routes are stored in
the `notification_targets` / `notification_routes` tables and replicated to
peers. Because their config can carry webhook tokens/URLs, they are excluded
from the operator-readable `GetStateDump` / `lv cluster sync` path, but daemon
peers repair missed pushes through a peer-mTLS-only sensitive anti-entropy lane.

## Model

- **Target** — a delivery destination. Types today: `webhook` (generic JSON
  POST of the notification) and `slack` (Slack incoming-webhook message with a
  severity emoji). Config is `{"url": "…"}`.
- **Route** — sends events whose **kind** matches an event-pattern glob and whose
  **severity** is at least `min_severity` to a target. A target receives nothing
  until a route points at it.

A notification has a `kind` (verb.noun), `severity` (`info` | `warn` | `error`),
`subject` (the resource), and `detail`.

## Events emitted

| Kind | Severity | When |
|---|---|---|
| `backup.failed` | error | a `lv backup snapshot` / scheduled backup fails |
| `host.fenced` | error / warn | the failover coordinator fences a host (warn = partial/manual) |
| `replication.failed` | error | a scheduled replication run fails |
| `ha.vip.no_holder` | error | a configured VIP is served by nobody (VIP HA enabled) — a VIP outage |
| `ha.vip.demotion_unfenced` | error | a minority node's VIP self-demote failed with no verified self-fence; the majority holds in the safe gap (VIP outage until an operator provides a fence / intervenes) |
| `ha.dualrun.vm` | error | a VM is an active disk-holder on more than one host — a split-brain that can corrupt the disk |
| `ha.dualrun.ct` | error | a container is running on more than one host |
| `ha.dualrun.vip` | error | a VIP is kernel-assigned on more than one host — a dual VIP holder |
| `ha.owner.mismatch` | error | a VM's DB owner is not its sole runtime holder — the DB and runtime disagree (ownership drift) |
| `ha.lww.unresolved` | warn | a node is tracking unresolved equal-timestamp LWW ties |
| `ha.dualrun.coverage` | warn | a workload-capable host could not be fully probed this pass — unreachable (segmented/down) OR returned a partial runtime (a local libvirt/container/ip probe errored, so its workload absence is unreliable); split-brain can't be ruled out there |
| `quota.exceeded` | warn | a CreateVM is rejected by a project quota |
| `test.notification` | info | `lv notify test` / the UI "Test" button |

> **Route the `ha.vip.*` kinds if you enable VIP HA** (`enforcement.vip_self_demote` /
> `enforcement.vip_proof_reclaim`). VIP Phase-2 deliberately converts a partition
> overlap into a VIP *outage* rather than a dual-VIP — that is only a safe trade if the
> outage pages. Add a route matching `ha.vip.*` (or `ha.*`) at `error` severity, or a
> silent VIP gap can go unnoticed. Recovery is `lv host fence-confirm <host>`.

> **The `ha.dualrun.*` / `ha.owner.mismatch` / `ha.lww.unresolved` kinds are alert-only**
> and always on — the leader-gated dual-run detector never destroys or reconciles; it
> turns a silent split-brain (the same workload/VIP live on two hosts, or a DB owner that
> disagrees with the runtime) into a page so an operator can act. A finding pages only
> after it persists across two consecutive passes (a migration cutover clears within one),
> and clears on its own when the condition heals. Route `ha.dualrun.*` at `error` (or
> `ha.*` broadly). Expect standing `ha.dualrun.coverage` alerts for any host that is
> genuinely down or network-segmented from the current leader — that is a real coverage
> gap, deduped to one page; do not mute the kind or a true split-brain on that host goes
> unseen. A host on an *older binary* (no `ReportRuntime` handler) during a rolling
> upgrade is deliberately **not** paged as a coverage gap — it still appears in the
> `litevirt_dual_run_probe_failed{host}` gauge, but the transient version skew of an
> upgrade window does not raise a page. The gauges
> `litevirt_dual_run_detected{kind,target}` and `litevirt_dual_run_probe_failed{host}`
> carry the same signal for dashboards.

Event-pattern globs: `*` (all), `backup.*` (a prefix), or an exact kind like
`host.fenced`.

## Configure

CLI (`lv notify`):

```bash
lv notify target add --name ops-slack --type slack --url https://hooks.slack.com/services/…
lv notify target ls
lv notify route add --pattern "*" --target <target-id> --min-severity warn
lv notify route add --pattern "backup.*" --target <target-id> --min-severity error
lv notify test <target-id>
lv notify route ls
lv notify route rm <id>
lv notify target rm <id>
```

UI: the **Notifications** page (Observability nav) manages targets + routes and
has a per-target **Test** button.

Config shortcut: set `notifications.default_webhook` to seed a catch-all webhook
target + route (min-severity `warn`) without the CLI/UI — see
[configuration.md](configuration.md).

Slack: paste an [incoming-webhook](https://api.slack.com/messaging/webhooks) URL
as a `slack` target. Slack channels render the severity emoji + cluster +
kind/subject at a glance.
