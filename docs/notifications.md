# Notifications

litevirt emits operator notifications for noteworthy cluster events to
configurable targets. It mirrors `internal/billing` in spirit — fire-and-log
delivery that never blocks or fails the operation that triggered it — but fans
out to multiple typed targets selected by **routes** (event-pattern + minimum
severity). The implementation is `internal/notify`; targets/routes are stored in
the `notification_targets` / `notification_routes` tables and **push-replicated**
to peers, so every daemon that received the mutation notifies consistently. These
tables are intentionally **excluded from full-state anti-entropy** (their config
can carry webhook tokens/URLs), so a host that missed the push — e.g. across a
partition or restart — is **not** auto-repaired; re-save the target/route on a
healthy host to re-replicate it.

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
| `quota.exceeded` | warn | a CreateVM is rejected by a project quota |
| `test.notification` | info | `lv notify test` / the UI "Test" button |

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
