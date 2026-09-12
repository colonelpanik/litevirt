# Working in this repo

## Before you push

```bash
go build ./... && go vet ./...
go test ./...
make ci-guards          # schema bump, writecheck, stmtshapecheck, docs truth
```

`make ci-guards` is the one people forget. It runs checks CI also runs, and a
couple that only exist there — notably `stmtshapecheck`, which fails any
replicated SQL builder whose statement shape is not in the compatibility ledger.

Commits follow conventional-commit style (`fix(cluster):`, `test(fleet):`,
`docs:`). Scope names match the package or subsystem.

## Test tiers

| Tier | Location | Needs | Covers |
|---|---|---|---|
| Unit | alongside the code | nothing | package-local logic |
| Fleet | `tests/fleet/` | nothing | multi-node spine: CLI → gRPC → mTLS → corrosion → replicator → LWW apply → scheduler |
| E2E | `tests/e2e/` | live 4-node cluster | real qemu / nftables / dnsmasq |

**`tests/fleet/` is the one to reach for.** It runs N real daemons in one `go test`
process over real gRPC and real CRDT replication, with `internal/libvirtfake`
injected — no external binaries, no root, sub-second without `-race`. Anything
whose failure mode is *multi-node* belongs here, because a single-package test
structurally cannot reach it. See `tests/fleet/cluster.go` for the harness and
`hardware_v2_latch_test.go` for the shape.

Each node gets two in-process backends: `n.Virt` (`internal/libvirtfake`) for VMs
and `n.CT` (`tests/fleet/ctfake.go`) for containers. `CTFake` keeps a real
on-disk container dir per node and does a real tar export/import, so a container
migrate genuinely moves bytes between two directories over gRPC — assert on
`n.CT.Payload(name)` and a migration that moved nothing cannot pass. It also has
an `OnExport` hook that runs mid-archive, which is the only way to reach the
target-side failures a source preflight would otherwise catch first.

`tests/e2e/` needs two variables that are easy to miss — without them it prints
one line and exits 0, which reads like a pass:

```bash
export LITEVIRT_E2E=1                 # opt in to touching a live cluster
export LV_BIN=$PWD/bin/litevirt       # pin the binary under test
```

## Mutation-verify anything you assert

A passing test proves nothing until you have seen it fail. Break the property,
confirm the test goes red, restore. The repo already institutionalises this —
see `make test-telemetry-mutation` and `scripts/ci/telemetry-mutation.sh`.

This catches vacuous tests, which are easy to write here. A real example: a test
asserted that a peer received the configured gossip advertise address, and passed
with the wiring deleted — because it bound `127.0.0.1`, and memberlist's
auto-detection derives its advertise address from a specific `BindAddr`, so it
produced the same answer either way. Binding `0.0.0.0` and advertising
`127.0.0.1` gave auto-detection a different answer to produce, and the mutation
finally failed.

## Capability tokens

Hardening features are gated on cluster-wide capability tokens
(`internal/capabilities`). The pattern is uniform:

- each has an `enforcement.*` config flag, default **false**
- **advertising is not enforcing.** Most tokens are advertised on the strength
  of the BUILD, whatever the local flag says, so the cluster can latch them —
  the node's own flag then decides whether it acts. A latched token therefore
  proves a uniform build, **not** config uniformity, and a cluster can have a
  token fully latched while members silently do not enforce it.
  `PingResponse.not_enforcing` is the only way to see that (diagnostic only).
  A token is withheld while its flag is off when some node RELIES on a peer
  honouring it — where a flag-off peer would corrupt rather than merely be
  permissive. `advertisedCapabilities` is the authority on the list
  (operation_protocol_v1, isolation_epoch_v1, owner_epoch_v1 and the others
  named there); for those, a latched token DOES mean config uniformity.
  **Ask where the guarantee is enforced before adding one.** A guarantee
  enforced at the point a dangerous action is CREATED does not need the peer
  to enforce anything, so withholding buys no safety and costs a great deal
- **`shared_storage_fence_v1` looks like it should be withheld and must not be**
  — it has been proposed twice, so the reasoning lives in
  `advertisedCapabilities` and in `TestAdvertise_SharedStorageFenceIsUnconditional`.
  It gates a corruption hazard, but the coordinator refuses to CREATE an
  unproven shared-disk transfer at the source, so no node relies on a peer. The
  cost of withholding is concrete: `internal/health/capability.go` has no role
  filter, so a **witness** with the flag off (its operator has no reason to set
  it) would hold the fence off fleet-wide forever; every node mid-rollout would
  stop enforcing; and a config-on token that cannot latch consumes
  `driveCapabilityActivation`'s one-token-per-cycle budget permanently, starving
  every later token in `Supported()`
- the latch is monotone and durable: once formed it survives a restart and does
  not re-open when a peer becomes unreachable (a partition fails **closed**)
- enabling on one node changes nothing

There are exceptions, of two different kinds, and neither is "the one":

- **Mandatory** — no config flag, `tokenEnabled` returns true unconditionally,
  so they latch on every cluster with no operator opt-in. The set is declared in
  one place, `capabilities.mandatory` (read it; prose copies of it have gone
  stale twice). They are reserved for a token stating a *fact about the binary*
  rather than a policy: `split_brain_gate_v1` and `lease_term_ledger_v1`.
  A mandatory token has no flag to turn off in an incident — see the
  per-token stand-down notes beside that declaration.
- **Conditionally advertised** — `hardware_v2` has no flag of its own either,
  but it is gated differently: each node's startup hardware audit plus a latched
  `operation_protocol_v1` decide whether it is advertised at all.

One mandatory token, `lease_term_ledger_v1`, is additionally
`capabilities.ReplicationGated`: its latch is a claim about which wire shapes
peers can *decode*, so it is confirmed against every host still receiving
replication — memberlist membership — and not merely against voting-eligible
members. A host parked in `maintenance` on an older build therefore holds that
latch off, which is the intended invariant and not a bug.

**`enforcement.operation_protocol` is required for all hotplug.** Disk, NIC, and
concrete-address PCI attach/detach are journaled and have no un-journaled path,
so they refuse outright while it is off. That is deliberate and pinned by tests
(`TestAttachDevice_ProtocolInactiveRejected`) — do not "fix" it by adding a
fallback.

## Traps

- **`lv host init --local` bakes a `127.0.0.1`-only certificate SAN.** Peers can
  never dial that node. For anything multi-node use the remote form
  (`lv host init root@<ip>`), which puts the real address in the SAN. A node
  cannot init *itself* remotely — the binary push becomes a same-file copy and
  fails; run it from another node.
- **Set `advertise_address` on any multi-homed host.** Auto-detection uses two
  different heuristics — default-route source IP for the host record, first
  private IP by interface enumeration order for gossip — which can disagree with
  each other and with reality. When the wrong address is identical on every node
  (a NAT'd lab), each node dials itself, gossip looks healthy, and the cluster
  never converges.
  never converges. It must be a bare IPv4 literal — the daemon refuses to start
  on a hostname, a host:port, or IPv6.
- **Cluster transport is IPv4-only.** Gossip and gRPC both bind `0.0.0.0`, so an
  IPv6 address anywhere in the peer path is a trap, not a feature: nothing fails
  at startup, every peer probe just fails forever and the failure detector fences
  a live host. `advertise_address` and `resolveHost` reject IPv6 at the two entry
  points; `corrosion.PeerTarget` / `corrosion.URIHost` (never `Sprintf("%s:%d")`)
  keep the dial paths correct if one gets in anyway.
- **`internal/pki` is not importable across modules.** External consumers build
  their own peer TLS config from `ca.crt` / `host.crt` / `host.key`.
- **Docs are guarded in both directions.** `cmd/litevirt/docs_triangulation_test.go`
  fails on a doc referencing a command that does not exist, a command or config
  key that no doc mentions, and a `litevirt_*` identifier absent from the code.
  Adding an operator-facing flag means documenting it.

## A local 4-node cluster

Nested VMs on plain qemu, no libvirt or root on the host. See the lab script
kept outside the repo (`~/litevirt-lab/lab.sh`) — nodes boot with `-cpu host` so
guests inside get real KVM, cloud-init is seeded over HTTP via the SMBIOS DMI
serial (a VVFAT seed disk does **not** work — the synthesized FAT volume carries
no `blkid` LABEL of `CIDATA`, so `ds-identify` finds no datasource and disables
cloud-init silently), and the cluster LAN is a qemu multicast socket.
