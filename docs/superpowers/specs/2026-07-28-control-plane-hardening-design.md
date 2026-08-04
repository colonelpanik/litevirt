# Control-Plane Hardening Design

**Date:** 2026-07-28

**Status:** Approved design, pending implementation plan

## Purpose

This project closes the lifecycle, admission, placement, notification, storage,
dependency, release, and quality risks identified by the 2026-07-28
architecture review. The implementation preserves existing CLI, REST, gRPC,
and Compose inputs and supports rolling upgrades across a mixed-version
cluster.

The principal safety invariant is:

> A workload runtime must never consume unreserved capacity or exist without
> durable desired state, ownership, and a recoverable operation record.

## Scope

The project will:

- Normalize and validate workload specifications before authorization,
  quota, placement, admission, request hashing, billing, or side effects.
- Make VM and container create/start capacity claims durable and serialized.
- Make VM creation recoverable and compensating.
- Ensure placement is resolved once and that pinned hosts satisfy all hard
  constraints.
- Replace the legacy global Compose webhook with scoped, persisted
  notification routing and bounded delivery.
- Bound NFS control commands and make storage tests independent of host mount
  behavior.
- Upgrade reachable vulnerable dependencies.
- Make releases depend on compatibility guardrails.
- Establish lint, targeted race, vulnerability, and asset-integrity gates.
- Extract focused service boundaries only where needed to enforce these
  invariants.

The project will not replace Corrosion with a consensus database, redesign
public workload APIs, or perform a repository-wide service rewrite.

## Compatibility

No existing public RPC, protobuf field, CLI flag, REST request, or Compose field
is removed. Existing CPU and memory defaults remain 2 vCPU and 4096 MiB.
Previously valid requests retain their public behavior. Invalid negative,
overflowing, malformed, or unsafe values are rejected at the boundary.

Schema changes are additive. New columns have legacy-compatible defaults. New
wire methods are additive internal executor/authority methods. Safety behavior
that requires every member to participate is activated by a durable
cluster-wide capability latch.

Before the capability latches, mixed-version clusters use the legacy execution
path. After it latches, the stronger protocol is mandatory and fails closed
when the selected executor or admission authority is unavailable.

## Architecture

### Public adapters

Existing gRPC methods remain the public entry points. CLI, REST, UI, MCP, and
peer callers continue to use the same public APIs. Public handlers perform
authentication and authorization, then delegate to focused internal
components:

- `WorkloadSpecNormalizer`
- `PlacementExecutor`
- `AdmissionCoordinator`
- `WorkloadCreateCoordinator`
- `NotificationDispatcher`
- `StorageCommandRunner`

These names describe responsibilities, not necessarily new Go packages. The
implementation plan will follow existing package boundaries and avoid import
cycles.

### Request normalization

Normalization is pure and happens once at the beginning of create:

1. Clone the incoming specification so server defaults do not mutate caller
   memory unexpectedly.
2. Apply CPU, memory, machine, and firmware defaults.
3. Mint server-owned identity fields at the correct execution stage.
4. Normalize the project.
5. Reject negative, overflowing, or unsupported resource values.
6. Construct quota, placement, reservation, billing, and request-hash inputs
   from the same normalized specification.

Direct gRPC and REST requests therefore receive the same semantics as CLI
requests.

### Placement

Placement is computed once by the entry node. Pinned and unpinned requests use
the same hard-filter pipeline for:

- active/non-witness state;
- CPU and memory capacity;
- required capability labels;
- LXC/OCI runtime availability;
- vTPM and Secure Boot capabilities;
- PCI device availability and topology;
- anti-affinity;
- maximum-per-node constraints; and
- strict spread constraints.

Pinning skips only scoring and tie-breaking.

The selected host receives an additive internal execution request containing
the resolved host and a decision fingerprint. The executor verifies that it is
the selected host and revalidates hard safety constraints, but does not rerun
global scoring. A bounded hop count protects mixed-version fallback behavior.

Each host advertises a fingerprint of the capacity policy that affects
placement and admission. Placement refuses ambiguous decisions when eligible
nodes disagree and reports the mismatched hosts and fingerprints.

### Admission coordination

The existing `operations`, `operation_steps`, reservation vectors,
`project_authority_epochs`, owner epochs, and capability-latch mechanisms are
the coordination model.

The selected workload host serializes host-capacity claims through a host
admission lock. The current project-authority holder serializes project quota
claims through a project admission lock. If no project authority exists, a
deterministically selected active non-witness host establishes the initial
authority. A stale authority epoch cannot create a valid reservation.

The resulting immutable operation header contains the requested host and
project reservation vector. The same operation identity and facts are made
visible to the executor before its host-admission lock is released, so the next
claim observes the reservation even if normal replication has not completed.

Admission applies to:

- VM create and start;
- container create and start; and
- positive CPU or memory resize.

Overcommit continues to bypass physical host admission only. It does not bypass
project quota, authorization, operation journaling, or auditing.

### Workload creation

The create state machine is:

`planned -> reserved -> prepared -> runtime_started -> committed`

Terminal alternatives are `failed`, `cancelled`, and `rolled_back`.

After admission, creation atomically inserts a provisional workload row in
`creating` state, linked to the active operation. The row contains normalized
desired state, project, owner host, owner epoch, and reservation identity. This
makes intent and ownership durable before disks or runtimes are created.

The coordinator then:

1. prepares storage and records created resources;
2. allocates network addresses and records leases;
3. claims and realizes hardware devices;
4. defines the runtime;
5. starts the runtime;
6. records resolved runtime facts; and
7. atomically writes hardware state, clears the operation barrier, and
   transitions the workload to `running`.

Every step records facts sufficient for idempotent recovery or compensation.
An authoritative read error fails closed. An existing runtime is never
destroyed merely because replicated state could not be read.

If the final state transaction fails after runtime start, the coordinator stops
and undefines the runtime, releases devices and leases, removes resources it
created, terminalizes the operation, and tombstones the provisional row. The
operation returns an error only after compensation has completed or reports
the incomplete compensation explicitly for startup recovery.

### Idempotency and recovery

Deterministic operation IDs and request hashes preserve the existing
idempotency contract:

- An identical retry resumes or returns the committed result.
- Reuse of an idempotency identity with different request content is rejected.

Startup recovery applies these rules:

- Before `runtime_started`, release recorded resources and remove the
  provisional workload.
- After `runtime_started` but before `committed`, inspect the actual runtime.
  Commit it only when runtime identity, desired state, owner epoch, and
  authority facts match. Otherwise stop it and compensate.
- Recovery and compensation require the current workload-owner and
  project-authority epochs.
- Terminal operations no longer contribute reservations.

Stale pre-runtime operations are terminalized after a bounded recovery horizon.
They are not silently ignored.

## Notifications

The legacy process-global `webhookURL` and `internal/webhook` delivery path are
removed. Operator and Compose notifications use the existing replicated
`internal/notify` target/route model.

Notification routes gain additive optional subject and project filters.
Existing routes default to wildcard subject and project behavior.

The Compose syntax remains:

```yaml
notifications:
  webhook: "https://hooks.example.com/litevirt"
```

Deploying this configuration upserts a deterministic notification target and a
`stack.*` route filtered to the exact project and stack. Updating the webhook
changes only that stack's target. Deleting the stack removes or tombstones its
managed route and target. It never changes notification delivery for another
stack.

A daemon-owned bounded dispatcher handles delivery. Queue insertion is
non-blocking for workload operations, but saturation increments metrics and
emits rate-limited logs. Shutdown stops accepting new work, drains for a
bounded interval, and cancels remaining deliveries.

Webhook and Slack URLs are validated centrally:

- only HTTP and HTTPS are accepted;
- embedded credentials are rejected;
- redirect destinations are revalidated;
- link-local and cloud metadata destinations are blocked;
- trusted private destinations require an explicit daemon allowlist; and
- logs contain target names or IDs, never complete URLs.

## Storage command execution

NFS `mount`, `mountpoint`, and `umount` calls use an injected command runner and
a storage-specific timeout derived from the caller context. The timeout is
configurable with a conservative default. Timeout errors identify the command
class and target without leaking credentials or unrestricted command output.

Unit tests use a fake runner. No unit test invokes the host's real NFS mount
binary or relies on unreachable network addresses.

## Dependency, release, and supply-chain controls

The implementation upgrades:

- `google.golang.org/grpc` to a release containing the fix for GO-2026-6061;
- `golang.org/x/text` to a release containing the fix for GO-2026-5970.

The release job depends on both the test and compatibility-guard jobs.

CI adds:

- configured production lint with zero findings;
- targeted race suites for fleet, admission, placement, lifecycle, and
  notification concurrency;
- `govulncheck`;
- checksum verification for embedded UI assets.

Asset versions and SHA-256 digests are stored in the repository. Downloads use
failure-reporting HTTP flags, write to temporary files, verify digests, and
move into place only after verification. Release builds cannot embed a CDN
error page or an unverified asset.

Existing lint findings are fixed or explicitly excluded only when a narrow,
documented reason demonstrates that the finding is not actionable. New
findings remain gated.

## Observability

Diagnostics and metrics expose:

- workload-operation state and age;
- stale reservations and operation IDs;
- capability supported/configured/latched state;
- capacity-policy fingerprints and mismatches;
- admission refusal dimensions;
- notification queue depth, drops, delivery failures, and shutdown
  cancellations; and
- storage command timeouts.

Secret-bearing notification configuration remains excluded from
operator-readable state dumps and uses the existing peer-mTLS sensitive
anti-entropy lane.

## Verification strategy

Every behavior change follows red-green-refactor. Required regression coverage
includes:

- defaults and invalid numeric values through gRPC and REST;
- concurrent same-name creates;
- concurrent distinct creates and starts competing for host capacity;
- concurrent projects competing for quota;
- database read and write failure compensation;
- crashes at every operation step;
- operation retry and request-hash conflict;
- mixed-version behavior before and after capability activation;
- placement loop prevention and pinned hard constraints;
- stack/project webhook isolation and data races;
- malformed URLs, redirects, metadata blocking, queue saturation, and shutdown;
- NFS timeout and cancellation with no real mounts;
- schema version, statement ledger, resolver, and release-corpus compatibility;
  and
- deterministic asset integrity failures.

Completion requires fresh successful runs of:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- targeted `go test -race` suites
- `golangci-lint run ./...`
- `make ci-guards`
- `govulncheck ./...`
- `git diff --check`

## Baseline failures

The isolated worktree was created from commit `b3502ed`. A baseline
`go test ./... -timeout=2m` run failed before production changes:

- `internal/storage` timed out in
  `TestNFSDriver_Prepare_MountDir`, blocked in the real NFS `mount` call. This
  is an accepted defect in this project's scope.
- `internal/cli` failed
  `TestHostUpgrade_NoArgRollsNewerBinaryToUniformCluster` because the locally
  built binary/version made the test report an already-uniform cluster.
- `internal/grpcapi` also reported a baseline failure; its verbose schema
  output obscured the individual test in the aggregate run, so the
  implementation plan must isolate and record it before modifying that
  package.

The implementation must not classify these as newly introduced regressions.
It must either repair them when they fall within this design or preserve a
separately documented baseline while validating affected packages directly.

## Delivery order

Work is delivered in independently testable slices:

1. isolate baseline failures and fix the NFS test/runtime timeout;
2. normalize and validate workload requests;
3. enforce pinned placement constraints and single-decision execution;
4. add capability-gated admission reservations and authority routing;
5. journal and recover VM creation;
6. extend the protocol to container create/start and VM start;
7. replace the legacy webhook with scoped bounded notification delivery;
8. upgrade dependencies and harden CI/release/assets;
9. eliminate configured lint findings and run full verification.

Each slice leaves the repository buildable and has focused regression tests.
