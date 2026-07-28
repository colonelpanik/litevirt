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
- a node advertises the token only while its flag is on, so the cluster-wide
  latch requires **config uniformity**, not just a uniform build
- the latch is monotone and durable: once formed it survives a restart and does
  not re-open when a peer becomes unreachable (a partition fails **closed**)
- enabling on one node changes nothing

`hardware_v2` is the exception: no flag of its own, activation gated on each
node's startup hardware audit plus a latched `operation_protocol_v1`.

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
