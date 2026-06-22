# Distributed firewall

litevirt ships a Proxmox-style three-tier firewall:
named security groups attached to NICs, declared in compose, persisted
in cluster state, and applied as an **atomic** nftables ruleset on
every host. The implementation lives in `internal/firewall/`.

## Architecture

```
                cluster state (Corrosion)
                  security_groups
                  sg_rules
                       │
                       ▼
                ┌──────────────┐
                │ Reconciler   │   30s poll on every host
                │  (per host)  │
                └──────┬───────┘
                       │ Plan
                       ▼
                ┌──────────────┐
                │ Renderer     │   pure Go; deterministic output
                └──────┬───────┘
                       │ ruleset (string)
                       ▼
                ┌──────────────┐
                │ Applier      │   skips when bytes unchanged
                └──────┬───────┘
                       │ nft -f -
                       ▼
                kernel (atomic table replace)
```

Each host runs its own reconciler. The renderer is pure — same input
produces the same bytes, byte-for-byte — so the applier short-circuits
when the cluster state is steady, keeping idle clusters at "one
Corrosion query per 30s" overhead.

## Three policy tiers

Rules are evaluated top-to-bottom inside the kernel forward chain:

1. **Cluster default** (`cluster_default` chain) — applies to every
   NIC. Use it for blanket policy such as "block any forward to
   RFC1918 from the public VLAN".
2. **Host overrides** (`host_overrides` chain) — applies to every NIC
   on this host. Use it for host-local exceptions: "allow this NFS
   server to reach all OSDs."
3. **Per-NIC rules** (`nic_<dev>` chain) — security groups + per-NIC
   extras. This is the layer compose mostly cares about.

Each chain is a regular nftables chain; the forward chain hooks the
netfilter forward path and `jump`s into the three tiers in order.

## Stateful conntrack baked in

Every chain begins with:

```
ct state established,related accept
ct state invalid drop
```

So reply traffic is always allowed. Rules need only describe the
*new connection* direction. Default-deny mode is therefore safe: the
SSH SYN you allow keeps its reply path open without you writing a
matching egress rule.

## Direction semantics

litevirt follows the AWS / GCP / Proxmox convention:

| Direction | What it means | nftables match |
|---|---|---|
| `ingress` | traffic ARRIVING at the VM | `oifname <tap>`, `ip saddr` |
| `egress`  | traffic LEAVING the VM | `iifname <tap>`, `ip daddr` |

This is the inverse of the legacy `internal/network/acl.go` mapping —
the firewall package is the canonical implementation going forward.

## Compose

Per-NIC binding plus reusable group definitions:

```yaml
firewall:
  default-deny: true
  cluster-rules:
    - { direction: egress, proto: tcp, port: 25, action: drop, comment: "block outbound SMTP" }

ipsets:
  trusted_admins:
    cidrs:
      - 10.0.0.5/32
      - 10.0.0.6/32

security-groups:
  web:
    description: "HTTP/HTTPS from anywhere"
    rules:
      - { direction: ingress, proto: tcp, port: 80,  action: accept }
      - { direction: ingress, proto: tcp, port: 443, action: accept }
  ssh-admin:
    rules:
      - { direction: ingress, proto: tcp, port: 22, cidr: "@trusted_admins", action: accept }

vms:
  web-1:
    image: ubuntu-24.04
    network:
      - name: prod
        ip: 10.0.0.10
        security-groups: [web, ssh-admin]
```

Rules without a CIDR match `0.0.0.0/0` (any). `cidr: "@<ipset-name>"`
references a top-level `ipsets:` entry — useful for big admin lists.

## CLI

The CLI lives at `lv sg …` and `lv firewall …`:

```
# Per-NIC tier: CRUD on security groups (mutates Corrosion state directly)
lv sg create web
lv sg ls
lv sg rule-add <sg-id> --direction ingress --proto tcp --port 80 --action accept
lv sg rule-ls <sg-id>
lv sg rm <sg-id>
lv sg bind <vm> --network <net> --sg web        # bind SGs to a NIC at runtime

# Cluster tier: rules applied to every NIC on every host
lv firewall cluster-rule add --direction ingress --proto tcp --port 443 --action accept
lv firewall cluster-rule ls
lv firewall cluster-rule rm <id>

# Host tier: rules applied to every NIC on one host
lv firewall host-rule add --host node-1 --direction egress --proto tcp --port 25 --action drop
lv firewall host-rule ls [--host node-1]
lv firewall host-rule rm <id>

# Named CIDR lists (reference from a rule with --cidr @<name>)
lv firewall ipset add office --cidr 203.0.113.0/24 --cidr 198.51.100.0/24
lv firewall ipset ls
lv firewall ipset rm <id>

# Default forward policy (no --scope = cluster-wide; --scope <host> overrides one host)
lv firewall default-deny on [--scope node-1]

# Inspect the live ruleset on this host / force a reconcile now
lv firewall show
lv firewall reload
```

CLI mutations propagate via Corrosion's CRDT replication; every host's
reconciler picks them up on its next poll (or immediately via
`lv firewall reload`). Per-NIC security groups bind via compose
`network[].security-groups` or `lv sg bind --network`; the cluster-tier
rules, host-tier rules, ipsets, and default-deny policy are also persisted in
cluster state and loaded by the reconciler's `CorrosionPlanLoader`.

## Default-deny rollout

Switching a running cluster to default-deny is risky if a rule is
missing. Recommended order:

1. Define every needed SG with its rules; bind to NICs.
2. Run with `default-deny: false` for a few days. The reconciler
   applies all rules but the policy stays accept — every miss merely
   logs.
3. Audit `nft list table inet litevirt-fw` per host to confirm rules
   look right.
4. Flip `default-deny: true` and re-deploy the stack.

## Per-NIC SG binding + reload

- **Per-NIC SG binding** — `vm_interfaces.security_groups` JSON column.
  Compose `network[].security-groups: [web]` persists on VM create;
  `lv sg bind <vm> --network <net> --sg web` mutates at runtime. The
  reconciler's `CorrosionPlanLoader` resolves names to real taps every
  tick.
- **`lv firewall reload` actually forces** — `ReloadFirewall` RPC
  drives the local reconciler synchronously and returns a
  `FirewallStatus` snapshot.

## What's still in flight

- IPv6 is staged behind the IPv4-first matchers. Render emits
  `ip protocol`; an `ip6` parallel pass is mechanical. Until then, an IPv6
  CIDR in a rule or ipset is **rejected at validation** (rather than silently
  mis-rendered into an invalid rule that would poison the whole ruleset) — so
  security-group rules are IPv4-only for now.
- ICMPv6 + IGMP support.
- Application-aware logging (`log prefix`, `log group`) for
  rejected packets — useful in deny-by-default audits.
