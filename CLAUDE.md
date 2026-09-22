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

**`-race` on `internal/corrosion` or `internal/grpcapi` needs an explicit
`-timeout`.** Both run past Go's 10-minute default under the race detector —
`internal/corrosion` takes ~40 minutes on a current laptop, and
**`internal/grpcapi` takes ~68** — so the plain command fails like this:

```
FAIL	github.com/litevirt/litevirt/internal/corrosion	600.588s
```

600s is the timeout, not a race. Nothing is wrong with the package; the run was
killed. Reach for a real budget:

```bash
go test -race -timeout 60m ./internal/corrosion/
go test -race -timeout 90m ./internal/grpcapi/
```

**Both numbers have been raised once already, and will drift again.** The
corrosion budget said 30m against a measured ~18½ minutes; the package has
since grown past it, and a run at 30m died at `FAIL ... 1817.560s` looking
exactly like a finding. A re-run at a real budget passed in 2358s — 39 minutes,
with zero warnings. When either package times out, measure before believing it.

**grpcapi is the one that catches people out**, because 30m is nowhere near
enough for it and the failure is indistinguishable from a real finding: a 45m
budget dies at `FAIL ... 2717.486s`, which is close enough to a plausible
runtime to look like the detector found something. It did not — the same package
passes at 90m in 4091s with no warnings. Anything under ~70m on grpcapi is a
budget failure.

Do not pipe a race run through `tail -N`. That discards the `panic: test timed
out` header and leaves only a goroutine dump, which is exactly the evidence you
need to tell the two apart. Redirect to a file and grep it.

Or, for a change confined to a few files, run the race detector over just the
tests that cover them — seconds instead of twenty minutes, and the same signal
for the code you touched:

```bash
go test -race -timeout 5m ./internal/corrosion/ -run 'TestStmtShape|TestLex_'
```

This trips people because a timeout and a detected race look identical at a
glance, and the honest reading of a 600s FAIL on a package you just edited is
"I broke something". Confirm which it is before chasing it: a real race prints a
`WARNING: DATA RACE` block, a timeout prints `panic: test timed out`.

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
