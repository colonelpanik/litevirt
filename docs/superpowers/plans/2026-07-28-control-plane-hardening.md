# Control-Plane Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make workload creation, admission, placement, notifications, storage commands, and releases safe under concurrency, failure, and rolling upgrades without breaking public interfaces.

**Architecture:** Extend the existing operation journal, reservation vectors, project-authority epochs, capability latches, and notification target/route model. Public gRPC methods remain adapters; new focused helpers normalize requests, coordinate admission, execute a single placement decision, journal lifecycle work, recover incomplete operations, and deliver bounded notifications.

**Tech Stack:** Go 1.26, gRPC/protobuf, Corrosion/SQLite, Cobra, libvirt/LXC adapters, GitHub Actions, golangci-lint, govulncheck.

---

## File map

New focused files:

- `internal/grpcapi/vm_create_normalize.go`: pure VM create normalization and validation.
- `internal/grpcapi/placement_executor.go`: resolved-placement envelope, hop protection, and capacity-policy checks.
- `internal/grpcapi/admission_coordinator.go`: host/project serialization and durable reservation claims.
- `internal/grpcapi/workload_create.go`: VM create operation orchestration and compensation.
- `internal/grpcapi/workload_recovery.go`: recovery of incomplete create/start operations.
- `internal/grpcapi/notification_dispatcher.go`: bounded lifecycle-owned notification queue.
- `internal/corrosion/create_operations.go`: atomic provisional workload/operation transactions.
- `internal/corrosion/capacity_policy.go`: stable policy fingerprint and mismatch helpers.
- `internal/notify/urlpolicy.go`: URL and redirect destination validation.
- `scripts/ci/vendor-assets.sh`: verified asset acquisition.

Primary modified files:

- `internal/storage/{runner.go,nfs.go,storage.go}` and storage tests.
- `internal/placement/{engine.go,selectbatch_test.go}`.
- `proto/litevirt/v1/{service.proto,types.proto}` and generated Go.
- `internal/capabilities/capabilities.go`.
- `internal/corrosion/{schema.go,operations_state.go,operations.go,reservation.go,notifications.go,hosts.go,containers.go}`.
- `internal/grpcapi/{server.go,vm.go,containers.go,notifications.go,stacks.go,streamevents.go}`.
- `internal/daemon/{config.go,daemon.go}`.
- `.github/workflows/ci.yml`, `Makefile`, `go.mod`, and `go.sum`.
- Documentation under `docs/`.

## Task 1: Stabilize the baseline and bound NFS commands

**Files:**

- Modify: `internal/storage/nfs.go`
- Modify: `internal/storage/storage.go`
- Test: `internal/storage/storage_extra_test.go`
- Test: `internal/storage/storage_round2_test.go`
- Test: `internal/storage/storage_test.go`
- Modify: `internal/grpcapi/auth_test.go`
- Modify: `internal/grpcapi/grpcapi_round2_test.go`
- Modify: `internal/cli/host_upgrade_test.go`

- [ ] **Step 1: Write failing NFS runner tests**

Add a table-driven test that injects `nfsDriver.run`, records calls, and proves
`Prepare` never invokes the real host commands:

```go
func TestNFSPrepareUsesRunnerAndTimeout(t *testing.T) {
	var calls []string
	d := &nfsDriver{
		source: "server:/export", targetOverride: t.TempDir(),
		opts: map[string]string{"command_timeout": "20ms"},
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if name == "mountpoint" {
				return nil, errors.New("not mounted")
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	err := d.Prepare(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Prepare error = %v, want deadline exceeded", err)
	}
	if got := strings.Join(calls, "\n"); !strings.Contains(got, "mountpoint -q") ||
		!strings.Contains(got, "mount -t nfs") {
		t.Fatalf("calls = %q", got)
	}
}
```

Replace existing NFS tests that use unreachable addresses with runner-backed
success/failure assertions.

- [ ] **Step 2: Run the storage test and verify RED**

Run:

```bash
go test ./internal/storage -run 'TestNFS' -count=1 -timeout=10s
```

Expected: FAIL because `Prepare` still calls `exec.CommandContext` directly.

- [ ] **Step 3: Route every NFS control command through the bounded runner**

Add:

```go
const defaultNFSCommandTimeout = 30 * time.Second

func (d *nfsDriver) commandContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	timeout := defaultNFSCommandTimeout
	if raw := strings.TrimSpace(d.opts["command_timeout"]); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return nil, nil, fmt.Errorf("invalid NFS command_timeout %q", raw)
		}
		timeout = parsed
	}
	return context.WithTimeout(parent, timeout)
}
```

Use `d.run` (falling back to `realCmd`) for `mountpoint`, `mount`, and
`umount`, all under the derived context. Remove the direct `os/exec` import
from `nfs.go`. Keep error messages bounded with `strings.TrimSpace` and an
output-length cap.

- [ ] **Step 4: Make baseline tests platform-independent**

In the shared grpcapi test server, inject a bridge-availability seam or fake
network provisioner so tests using `lo` do not execute Linux `ip` on macOS.
Keep production bridge validation unchanged.

In `host_upgrade_test.go`, make the built-version input explicit rather than
depending on the developer's current binary version. The failing assertion must
exercise a fixture in which the candidate version is strictly newer.

- [ ] **Step 5: Verify baseline packages**

Run:

```bash
go test ./internal/storage ./internal/grpcapi ./internal/cli -count=1 -timeout=3m
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/storage internal/grpcapi internal/cli
git commit -m "fix: bound storage commands and stabilize tests"
```

## Task 2: Normalize and validate VM create requests before admission

**Files:**

- Create: `internal/grpcapi/vm_create_normalize.go`
- Create: `internal/grpcapi/vm_create_normalize_test.go`
- Modify: `internal/grpcapi/vm.go`
- Test: `internal/grpcapi/vm_test.go`
- Test: `internal/restapi/handler_test.go`

- [ ] **Step 1: Write failing pure normalization tests**

Define the intended API in tests:

```go
func TestNormalizeCreateVMSpecDefaults(t *testing.T) {
	got, err := normalizeCreateVMSpec(&pb.VMSpec{Name: "vm1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Cpu != 2 || got.MemoryMib != 4096 || got.Machine != "q35" || got.Firmware != "uefi" {
		t.Fatalf("normalized spec = %+v", got)
	}
}

func TestNormalizeCreateVMSpecRejectsNegativeResources(t *testing.T) {
	for _, spec := range []*pb.VMSpec{
		{Name: "vm1", Cpu: -1, MemoryMib: 512},
		{Name: "vm1", Cpu: 1, MemoryMib: -1},
	} {
		if _, err := normalizeCreateVMSpec(spec); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("error = %v, want InvalidArgument", err)
		}
	}
}
```

Also prove the input proto is cloned, not mutated.

- [ ] **Step 2: Verify RED**

Run:

```bash
go test ./internal/grpcapi -run 'TestNormalizeCreateVMSpec' -count=1
```

Expected: build failure because `normalizeCreateVMSpec` does not exist.

- [ ] **Step 3: Implement the pure normalizer**

Implement:

```go
func normalizeCreateVMSpec(in *pb.VMSpec) (*pb.VMSpec, error) {
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "spec is required")
	}
	spec := proto.Clone(in).(*pb.VMSpec)
	if spec.Cpu < 0 || spec.MemoryMib < 0 {
		return nil, status.Error(codes.InvalidArgument, "cpu and memory_mib must be non-negative")
	}
	if spec.Cpu == 0 {
		spec.Cpu = 2
	}
	if spec.MemoryMib == 0 {
		spec.MemoryMib = 4096
	}
	if spec.Machine == "" {
		spec.Machine = "q35"
	}
	if spec.Firmware == "" {
		spec.Firmware = "uefi"
	}
	return spec, nil
}
```

Retain existing name, disk, network, and firmware validation, but run it against
the normalized clone.

- [ ] **Step 4: Move normalization to the first executable line of `CreateVM`**

Replace later defaulting with:

```go
spec, err := normalizeCreateVMSpec(req.GetSpec())
if err != nil {
	return nil, err
}
req = proto.Clone(req).(*pb.CreateVMRequest)
req.Spec = spec
```

Build quota, placement, reservation, request hash, audit detail, and billing
events from this normalized spec.

- [ ] **Step 5: Add gRPC and REST regressions**

Prove omitted resources are admitted and accounted as `2/4096`, and negative
resources return HTTP 400 / gRPC `InvalidArgument` before placement or runtime
calls.

- [ ] **Step 6: Verify and commit**

```bash
go test ./internal/grpcapi ./internal/restapi -run 'Normalize|Default|Negative|CreateVM' -count=1
git add internal/grpcapi internal/restapi
git commit -m "fix: normalize VM resources before admission"
```

## Task 3: Enforce pinned hard constraints and single-decision execution

**Files:**

- Modify: `internal/placement/engine.go`
- Test: `internal/placement/engine_test.go`
- Test: `internal/placement/engine_device_test.go`
- Modify: `proto/litevirt/v1/service.proto`
- Modify: `proto/litevirt/v1/types.proto`
- Regenerate: `gen/litevirt/v1/*.go`
- Create: `internal/grpcapi/placement_executor.go`
- Create: `internal/grpcapi/placement_executor_test.go`
- Modify: `internal/grpcapi/vm.go`
- Create: `internal/corrosion/capacity_policy.go`
- Test: `internal/corrosion/capacity_test.go`

- [ ] **Step 1: Write pinned-host hard-filter tests**

Create cases for pin plus required label, unavailable PCI device,
anti-affinity, max-per-node, strict spread, and insufficient capacity:

```go
func TestSelectPinnedHostStillRunsHardFilters(t *testing.T) {
	db := placementDB(t)
	seedHost(t, db, "h1", map[string]string{"lxc.capable": "false"})
	_, err := Select(context.Background(), db, Request{
		VMName: "ct1", PinHost: "h1",
		RequireLabels: map[string]string{"lxc.capable": "true"},
	})
	if err == nil || !strings.Contains(err.Error(), "required label") {
		t.Fatalf("error = %v", err)
	}
}
```

- [ ] **Step 2: Verify RED**

```bash
go test ./internal/placement -run 'PinnedHostStillRunsHardFilters' -count=1
```

Expected: FAIL because the pinned fast path returns `h1`.

- [ ] **Step 3: Filter a pinned singleton through `scoreCandidates`**

Build the normal snapshot, load devices/max-per-node state, restrict
`snap.HostsBy` to the pinned host, and call the same hard-filter path. Add an
explicit `pinned` flag only to suppress soft scoring, never hard filters.

- [ ] **Step 4: Add stable capacity-policy fingerprints**

Implement canonical JSON plus SHA-256:

```go
func CapacityPolicyFingerprint(p CapacityPolicy) string {
	p = p.normalize()
	b, _ := json.Marshal(struct {
		CPUOvercommit float64 `json:"cpu_overcommit"`
		MemOvercommit float64 `json:"mem_overcommit"`
		CPUReserve int         `json:"cpu_reserve"`
		MemReserveMiB int      `json:"mem_reserve_mib"`
		MemReservePct int      `json:"mem_reserve_pct"`
		VMMemOverhead int     `json:"vm_mem_overhead_mib"`
	}{
		p.CPUOvercommit, p.MemOvercommit, p.CPUReserve,
		p.MemReserveMiB, p.MemReservePct, p.VMMemOverheadMiB,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
```

Include every field that changes allocatable capacity and prove map/order
independence where host overrides are represented.

- [ ] **Step 5: Add the internal executor RPC**

Add:

```protobuf
message ExecuteCreateVMRequest {
  CreateVMRequest request = 1;
  string resolved_host = 2;
  string placement_fingerprint = 3;
  uint32 hop_count = 4;
}

rpc ExecuteCreateVM(ExecuteCreateVMRequest) returns (VM);
```

Regenerate with `make proto`. The executor rejects a mismatched host or
`hop_count > 1`, validates the policy fingerprint and hard constraints, and
calls the local create coordinator without rerunning global scoring.

- [ ] **Step 6: Preserve mixed-version fallback**

When the new capacity-admission capability is not latched, use the existing
`CreateVM` forward with a bounded forwarded-hop metadata value. Once latched,
require `ExecuteCreateVM`; `Unimplemented` is a failed precondition rather than
recursive fallback.

- [ ] **Step 7: Verify and commit**

```bash
go test ./internal/placement ./internal/corrosion ./internal/grpcapi -run 'Pinned|Placement|ExecuteCreate|CapacityPolicy' -count=1
make proto
git add proto gen internal/placement internal/corrosion internal/grpcapi
git commit -m "fix: pin placement decisions without bypassing constraints"
```

## Task 4: Add schema-v44 lifecycle and route fields

**Files:**

- Modify: `internal/corrosion/schema.go`
- Modify: `internal/corrosion/schema_test.go`
- Modify: `internal/corrosion/containers.go`
- Modify: `internal/corrosion/hosts.go`
- Modify: `internal/corrosion/notifications.go`
- Modify: `internal/corrosion/operations_state.go`
- Test: `internal/corrosion/operations_test.go`
- Modify: `internal/capabilities/capabilities.go`
- Test: `internal/capabilities/capabilities_test.go`
- Modify: `internal/grpcapi/server.go`
- Test: `internal/grpcapi/operation_protocol_test.go`
- Modify: `internal/daemon/config.go`
- Modify: `internal/daemon/daemon.go`
- Modify: `docs/configuration.md`

- [ ] **Step 1: Write RED tests for the new operation DAGs**

Add `OpWorkloadCreate` and `OpWorkloadStart` with:

```go
OpWorkloadCreate: {
	OpStepPlanned, OpStepReserved, OpStepDesiredPersisted,
	OpStepPrepared, OpStepRuntimeStarted, OpStepObserved,
},
OpWorkloadStart: {
	OpStepPlanned, OpStepReserved, OpStepRuntimeStarted, OpStepObserved,
},
```

Tests must prove legal ordering, terminal reservation release, rollback
precedence, and fault detection.

- [ ] **Step 2: Verify RED**

```bash
go test ./internal/corrosion -run 'OperationState|WorkloadCreate|WorkloadStart' -count=1
```

Expected: compile failure for missing constants.

- [ ] **Step 3: Add additive schema migration v44**

Bump `CurrentSchemaVersion` to 44 and add:

```sql
ALTER TABLE containers ADD COLUMN owner_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE containers ADD COLUMN spec_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE containers ADD COLUMN active_operation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN capacity_policy_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE notification_routes ADD COLUMN subject_pattern TEXT NOT NULL DEFAULT '*';
ALTER TABLE notification_routes ADD COLUMN project TEXT NOT NULL DEFAULT '';
```

Update table column lists, compatibility manifests, schema docs, release corpus,
resolver preservation tests, and statement ledgers.

- [ ] **Step 4: Register `capacity_admission_v1`**

Add the build capability token to `supported` and `all`. Advertise it only when
`operation_protocol` is configured, and define:

```go
func (s *Server) capacityAdmissionLatched() bool {
	return s.enfOperationProtocol && s.gate != nil &&
		s.gate.Latched(capabilities.OperationProtocolV1) &&
		s.gate.Latched(capabilities.CapacityAdmissionV1)
}
```

The health latch driver treats the new token as enabled when operation protocol
is enabled. No new public config flag is required.

- [ ] **Step 5: Run compatibility guards and commit**

```bash
make ci-guards
go test ./internal/capabilities ./internal/corrosion ./internal/grpcapi -run 'Capability|Schema|Operation' -count=1
git add internal/capabilities internal/corrosion internal/grpcapi internal/daemon docs
git commit -m "feat: add capability-gated workload operation schema"
```

## Task 5: Atomically claim provisional workload operations and reservations

**Files:**

- Create: `internal/corrosion/create_operations.go`
- Create: `internal/corrosion/create_operations_test.go`
- Modify: `internal/corrosion/operations.go`
- Modify: `internal/corrosion/reservation.go`
- Modify: `internal/corrosion/vms.go`
- Modify: `internal/corrosion/containers.go`

- [ ] **Step 1: Write failing transaction tests**

Specify:

```go
func TestBeginVMCreateOperationIsAtomic(t *testing.T) {
	db := openMem(t)
	op := OperationRecord{
		ID: "op1", Method: "CreateVM", Project: "default",
		ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpWorkloadCreate),
		RequestHash: "hash", ReservationJSON: `{"target_host":"h1","target_cpu":2,"target_mem_mib":4096}`,
	}
	applied, err := db.BeginVMCreateOperation(context.Background(), op, VMRecord{
		Name: "vm1", HostName: "h1", Spec: `{"cpu":2}`, State: "creating",
	})
	if err != nil || !applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
	vm, _ := GetVM(context.Background(), db, "vm1")
	if vm == nil || vm.ActiveOperationID != "op1" || vm.State != "creating" {
		t.Fatalf("vm = %+v", vm)
	}
}
```

Add rollback-on-statement-failure, duplicate-same-hash idempotency,
different-hash conflict, and container equivalents.

- [ ] **Step 2: Verify RED**

```bash
go test ./internal/corrosion -run 'Begin.*CreateOperation' -count=1
```

Expected: build failure for missing APIs.

- [ ] **Step 3: Implement guarded atomic APIs**

Add:

```go
func (c *Client) BeginVMCreateOperation(ctx context.Context, op OperationRecord, vm VMRecord) (bool, error)
func (c *Client) CommitVMCreateOperation(ctx context.Context, opID string, ownerEpoch int64, vm VMRecord, ifaces []InterfaceRecord, disks []DiskRecord, nics []NICRecord, intents []PCIIntentRecord) (bool, error)
func (c *Client) RollbackVMCreateOperation(ctx context.Context, name, opID string, ownerEpoch int64, facts string) (bool, error)
```

The begin transaction guards on no live VM, inserts the immutable operation,
its `planned`, `reserved`, and `desired_persisted` steps, and the provisional VM
row. Commit guards on the same active operation and owner epoch, writes hardware
rows, transitions to `running`, clears the barrier, and appends `observed` plus
`completed`. Rollback tombstones only the matching provisional row and appends
`rollback_completed` plus `failed`.

Implement container forms using the new container barrier columns.

- [ ] **Step 4: Make reservation aggregation authority-aware**

Encode reservation-step facts:

```go
type ReservationFacts struct {
	Project        string `json:"project"`
	AuthorityEpoch int64  `json:"authority_epoch"`
	AuthorityHost  string `json:"authority_host"`
}
```

Only count a reservation when its facts validate against the current project
authority. Return an error for malformed current-epoch facts rather than
silently dropping them.

- [ ] **Step 5: Verify and commit**

```bash
go test ./internal/corrosion -run 'CreateOperation|Reservation|ProjectAuthority' -count=1
make ci-guards
git add internal/corrosion
git commit -m "feat: persist provisional workload reservations atomically"
```

## Task 6: Serialize admission through host and project authorities

**Files:**

- Create: `internal/grpcapi/admission_coordinator.go`
- Create: `internal/grpcapi/admission_coordinator_test.go`
- Modify: `internal/grpcapi/admission.go`
- Modify: `internal/grpcapi/server.go`
- Modify: `proto/litevirt/v1/service.proto`
- Modify: `proto/litevirt/v1/types.proto`
- Regenerate: `gen/litevirt/v1/*.go`

- [ ] **Step 1: Write concurrent host-admission RED test**

Run two different claims against a host with only one workload's free
capacity. Use a barrier so both goroutines enter concurrently:

```go
func TestAdmissionCoordinatorSerializesDistinctCreates(t *testing.T) {
	s := admissionServer(t, 4, 4096)
	reqs := []ReservationRequest{
		{OperationID: "a", Host: "h1", Project: "p", CPU: 2, MemMiB: 3072},
		{OperationID: "b", Host: "h1", Project: "p", CPU: 2, MemMiB: 3072},
	}
	results := runConcurrentClaims(t, s.admission, reqs)
	if countAccepted(results) != 1 || countResourceExhausted(results) != 1 {
		t.Fatalf("results = %+v", results)
	}
}
```

Add a project-quota equivalent whose claims arrive at different entry nodes.

- [ ] **Step 2: Verify RED**

```bash
go test ./internal/grpcapi -run 'AdmissionCoordinatorSerializes' -count=1
```

Expected: build failure for missing coordinator.

- [ ] **Step 3: Implement lock registries and authority RPC**

Add bounded keyed mutex registries for host and project keys. Add internal RPC:

```protobuf
message ClaimProjectReservationRequest {
  string operation_id = 1;
  string request_hash = 2;
  string project = 3;
  int32 cpu = 4;
  int32 memory_mib = 5;
  string executor_host = 6;
}
rpc ClaimProjectReservation(ClaimProjectReservationRequest) returns (Operation);
```

The current authority holder alone handles the request under its project lock,
rechecks authority epoch and quota, and persists the immutable reservation
facts. The executor imports/verifies the identical header before releasing its
host lock.

- [ ] **Step 4: Make initial authority selection deterministic**

Hash normalized project name across active non-witness hosts. Only the selected
host can call `ClaimInitialProjectAuthority`; all others forward to it. On a
partition or unreachable holder, fail closed after the capability latch.

- [ ] **Step 5: Preserve pre-latch behavior**

Before `capacity_admission_v1`, keep legacy checks while still applying
normalization, per-name locks, read-error handling, and compensation. After the
latch, every positive create/start claim requires a durable reservation.

- [ ] **Step 6: Verify and commit**

```bash
make proto
go test ./internal/grpcapi ./internal/corrosion ./tests/fleet -run 'Admission|Reservation|Quota' -count=1
go test -race ./internal/grpcapi -run 'AdmissionCoordinatorSerializes' -count=1
git add proto gen internal/grpcapi internal/corrosion tests/fleet
git commit -m "feat: serialize host and project capacity claims"
```

## Task 7: Journal, compensate, and recover VM creation

**Files:**

- Create: `internal/grpcapi/workload_create.go`
- Create: `internal/grpcapi/workload_create_test.go`
- Create: `internal/grpcapi/workload_recovery.go`
- Create: `internal/grpcapi/workload_recovery_test.go`
- Modify: `internal/grpcapi/vm.go`
- Modify: `internal/grpcapi/server.go`
- Modify: `internal/daemon/daemon.go`

- [ ] **Step 1: Write read-error and same-name concurrency RED tests**

Inject a Corrosion read failure and assert no libvirt calls occur. Run two
same-name creates and assert exactly one `StartDomain`, no `DestroyDomain`, and
one `AlreadyExists`.

- [ ] **Step 2: Write commit-failure compensation RED test**

Inject a failure into final `CommitVMCreateOperation` and assert:

```go
if fake.DomainExists("vm1") {
	t.Fatal("runtime survived failed authoritative commit")
}
if got := fake.DestroyCalls("vm1"); got != 1 {
	t.Fatalf("DestroyDomain calls = %d, want 1", got)
}
view := mustOperation(t, s.db, opID)
if view.State != corrosion.OpStepFailed {
	t.Fatalf("state = %q", view.State)
}
```

- [ ] **Step 3: Verify RED**

```bash
go test ./internal/grpcapi -run 'CreateVM_(ReadError|ConcurrentSameName|CommitFailure)' -count=1
```

Expected: failures demonstrating ignored reads, missing lock, or surviving
runtime.

- [ ] **Step 4: Extract the local coordinator**

`CreateVM` becomes:

```go
func (s *Server) CreateVM(ctx context.Context, req *pb.CreateVMRequest) (*pb.VM, error) {
	normalized, err := s.prepareCreateVM(ctx, req)
	if err != nil {
		return nil, err
	}
	return s.createVMCoordinator().Create(ctx, normalized)
}
```

The local create path acquires `lockVM` before the authoritative read, fails
closed on read errors, claims admission/provisional state before disks, and
records step facts after every side effect. Remove the code that destroys a
running domain merely because the VM row appears absent.

- [ ] **Step 5: Implement a compensation stack**

Register idempotent compensators as each resource is created. Execute them in
reverse order on error. Persist compensation facts before reporting failure.
Never delete pre-existing disks, leases, devices, or domains; every
compensator checks the operation's recorded identity.

- [ ] **Step 6: Implement startup recovery**

List locally owned provisional VMs and active create operations. Apply:

- before runtime start: compensate and roll back;
- after runtime start: verify UUID, host, owner epoch, desired spec, and
  operation identity; then commit or compensate;
- stale epoch: append `superseded` and do not mutate runtime.

Wire recovery after database/runtime initialization and before accepting
mutating RPC traffic.

- [ ] **Step 7: Add crash-window table tests**

Create one test fixture for each step: planned, reserved, desired persisted,
prepared, runtime started, observed. Run recovery twice to prove idempotency.

- [ ] **Step 8: Verify and commit**

```bash
go test ./internal/grpcapi ./internal/corrosion ./internal/daemon -run 'CreateVM|WorkloadCreate|RecoverCreate' -count=1
go test -race ./internal/grpcapi -run 'ConcurrentSameName|RecoverCreate' -count=1
git add internal/grpcapi internal/corrosion internal/daemon
git commit -m "feat: make VM creation durable and recoverable"
```

## Task 8: Extend reservations to VM/container start and container create

**Files:**

- Modify: `internal/grpcapi/vm.go`
- Modify: `internal/grpcapi/containers.go`
- Create: `internal/grpcapi/workload_start_test.go`
- Create: `internal/grpcapi/container_admission_test.go`
- Modify: `internal/corrosion/create_operations.go`
- Modify: `internal/grpcapi/workload_recovery.go`

- [ ] **Step 1: Write concurrent distinct-start RED tests**

Seed two stopped workloads that individually fit but collectively exceed host
capacity. Concurrent starts must yield one success and one
`ResourceExhausted`. Add VM and container variants.

- [ ] **Step 2: Verify RED**

```bash
go test ./internal/grpcapi -run 'ConcurrentDistinctStarts|ContainerCreateAdmission' -count=1
```

Expected: both starts currently pass the read-only check.

- [ ] **Step 3: Claim start operations under host admission lock**

For stopped workloads, insert an `OpWorkloadStart` reservation before runtime
start. Append `runtime_started`, persist observed running state, then append
`completed`. On failure, append rollback and failed so the reservation releases.
Already-running starts remain idempotent and do not reserve again.

- [ ] **Step 4: Apply provisional create flow to containers**

Use container barrier columns and the same ordering:

`reservation -> provisional creating row -> runtime -> committed row`

Compensate runtime, leases, interfaces, and provisional state on failure.

- [ ] **Step 5: Recover incomplete start/container operations**

Reuse the operation reducer and authority validation. Do not start a runtime
during recovery unless ownership and split-brain gates authorize it.

- [ ] **Step 6: Verify and commit**

```bash
go test ./internal/grpcapi ./internal/corrosion ./tests/fleet -run 'Start|Container|Admission|Recovery' -count=1
go test -race ./internal/grpcapi -run 'ConcurrentDistinctStarts' -count=1
git add internal/grpcapi internal/corrosion tests/fleet
git commit -m "feat: reserve capacity for workload create and start"
```

## Task 9: Replace the global webhook with scoped bounded notifications

**Files:**

- Create: `internal/notify/urlpolicy.go`
- Create: `internal/notify/urlpolicy_test.go`
- Modify: `internal/notify/targets.go`
- Create: `internal/grpcapi/notification_dispatcher.go`
- Create: `internal/grpcapi/notification_dispatcher_test.go`
- Modify: `internal/corrosion/notifications.go`
- Test: `internal/corrosion/notifications_test.go`
- Modify: `internal/grpcapi/notifications.go`
- Modify: `internal/grpcapi/stacks.go`
- Modify: `internal/grpcapi/streamevents.go`
- Modify: `internal/grpcapi/server.go`
- Modify: `internal/daemon/config.go`
- Modify: `internal/daemon/daemon.go`
- Delete: `internal/webhook/webhook.go`
- Delete: `internal/webhook/webhook_test.go`
- Modify: `docs/compose.md`
- Modify: `docs/notifications.md`
- Modify: `docs/configuration.md`

- [ ] **Step 1: Write URL policy RED tests**

Cover malformed URLs, non-HTTP schemes, userinfo, redirect to blocked
destination, `169.254.169.254`, IPv6 link-local, allowed public endpoints, and
explicitly allowlisted private hosts.

- [ ] **Step 2: Verify RED**

```bash
go test ./internal/notify -run 'URLPolicy|Redirect' -count=1
```

Expected: build failure for missing URL policy.

- [ ] **Step 3: Implement central URL validation**

Define:

```go
type URLPolicy struct {
	AllowPrivateCIDRs []*net.IPNet
	Resolver          func(context.Context, string) ([]net.IP, error)
}

func (p URLPolicy) Validate(ctx context.Context, raw string) (*url.URL, error)
func (p URLPolicy) CheckRedirect(req *http.Request, via []*http.Request) error
```

Reject userinfo, link-local, unspecified, multicast, metadata endpoints, and
private addresses not covered by the allowlist. Build clients with the redirect
validator. Error/log strings contain target names, not raw URLs.

- [ ] **Step 4: Write dispatcher RED tests**

Use a blocking fake target to fill a two-item queue. Prove non-blocking enqueue,
drop count, bounded drain, cancellation, and no goroutine leak under `-race`.

- [ ] **Step 5: Implement the bounded dispatcher**

Define:

```go
type NotificationDispatcher struct {
	queue chan queuedNotification
	ctx context.Context
	cancel context.CancelFunc
	wg sync.WaitGroup
}

func (d *NotificationDispatcher) Enqueue(n notify.Notification)
func (d *NotificationDispatcher) Shutdown(ctx context.Context) error
```

Workers load matching routes/targets, apply event, severity, subject, and
project filters, and send with bounded contexts.

- [ ] **Step 6: Persist scoped Compose routes**

Extend `NotificationRoute` with `SubjectPattern` and `Project`. Existing rows
read as wildcard subject and project. Deploying a stack upserts deterministic
IDs derived from normalized project and stack:

```go
targetID := deterministicID("compose-webhook-target", project, stack)
routeID := deterministicID("compose-webhook-route", project, stack)
```

The route matches `stack.*`, exact stack subject, exact project. Stack deletion
tombstones only these managed IDs.

- [ ] **Step 7: Remove legacy global delivery**

Delete `Server.webhookURL`, `SetWebhookURL`, direct background goroutines, and
the `internal/webhook` package. `publish` continues event-bus delivery;
stack-lifecycle call sites enqueue scoped notifications explicitly.

- [ ] **Step 8: Wire lifecycle and configuration**

Add queue size, worker count, drain timeout, and trusted private CIDR settings
to `NotificationsConfig`. Construct/start the dispatcher in the daemon and
shut it down through the daemon context.

- [ ] **Step 9: Verify and commit**

```bash
go test ./internal/notify ./internal/corrosion ./internal/grpcapi ./internal/daemon -run 'Notif|Webhook|Stack' -count=1
go test -race ./internal/notify ./internal/grpcapi -run 'Dispatcher|StackWebhook' -count=1
git add internal/notify internal/corrosion internal/grpcapi internal/daemon docs
git rm -r internal/webhook
git commit -m "feat: scope and bound notification delivery"
```

## Task 10: Upgrade dependencies and harden release/assets/CI

**Files:**

- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `.github/workflows/ci.yml`
- Modify: `Makefile`
- Create: `scripts/ci/vendor-assets.sh`
- Create: `scripts/ci/vendor-assets_test.sh`
- Create: `scripts/ci/assets.sha256`
- Modify: `.golangci.yml`

- [ ] **Step 1: Add a failing asset-integrity test**

The test serves or copies a fixture with the wrong digest and asserts the vendor
script exits nonzero without replacing the existing destination. Add a success
case that atomically installs the verified fixture.

- [ ] **Step 2: Verify RED**

```bash
scripts/ci/vendor-assets_test.sh
```

Expected: FAIL because the verified vendor script does not exist.

- [ ] **Step 3: Implement verified asset acquisition**

The script must:

```bash
curl --fail --show-error --location --retry 3 "$url" --output "$tmp"
printf '%s  %s\n' "$expected_sha256" "$tmp" | shasum -a 256 --check -
mv "$tmp" "$destination"
```

Pin every package/font version, store every digest in
`scripts/ci/assets.sha256`, use `mktemp -d`, and clean it with a trap.

- [ ] **Step 4: Upgrade vulnerable dependencies**

Run:

```bash
go get google.golang.org/grpc@v1.82.1
go get golang.org/x/text@v0.39.0
go mod tidy
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Expected vulnerability result: no reachable vulnerabilities.

- [ ] **Step 5: Make release depend on all safety guards**

Set:

```yaml
release:
  needs: [test, ci-guards, security]
```

Add `security` jobs/steps for configured lint, targeted race, govulncheck, and
asset verification. Install tools at explicit versions. Pin action references
to reviewed commit SHAs and retain comments naming the upstream action version.

- [ ] **Step 6: Verify workflow and commit**

```bash
scripts/ci/vendor-assets_test.sh
make vendor-js
go build ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
git add go.mod go.sum .github Makefile scripts/ci .golangci.yml
git commit -m "build: gate releases on security and integrity"
```

## Task 11: Eliminate configured lint findings and update documentation

**Files:**

- Modify: `cmd/litevirt/vm.go`
- Modify: `internal/auth/oidc_test.go`
- Modify: `internal/auth/webauthn.go`
- Modify: `internal/billing/billing.go`
- Modify: `internal/cephdeploy/cephdeploy.go`
- Modify: `internal/cli/connect_test.go`
- Modify: `internal/cloudinit/cloudinit_coverage_test.go`
- Modify: `internal/compose/planner/planner.go`
- Modify: `internal/compose/planner/planner_test.go`
- Modify: `internal/compose/vmspec_test.go`
- Modify: `internal/corrosion/container_interfaces.go`
- Modify: `internal/corrosion/container_interfaces_test.go`
- Modify: `internal/corrosion/hardware_test.go`
- Modify: `internal/corrosion/lww_format_test.go`
- Modify: `internal/corrosion/merge_lww_test.go`
- Modify: `internal/corrosion/networks.go`
- Modify: `internal/corrosion/operations_test.go`
- Modify: `internal/corrosion/stmtlex.go`
- Modify: `internal/corrosion/sync.go`
- Modify: `internal/daemon/preflight.go`
- Modify: `internal/grpcapi/grpcapi_round2_test.go`
- Modify: `internal/grpcapi/hotplug_disk.go`
- Modify: `internal/grpcapi/lb.go`
- Modify: `internal/grpcapi/pci.go`
- Modify: `internal/grpcapi/realm_login_test.go`
- Modify: `internal/grpcapi/stacks.go`
- Modify: `internal/grpcapi/uninstall_test.go`
- Modify: `internal/grpcapi/vm.go`
- Modify: `internal/grpcapi/vmimport.go`
- Modify: `internal/lb/config_extra_test.go`
- Modify: `internal/lb/demote.go`
- Modify: `internal/lb/lb_coverage_test.go`
- Modify: `internal/lb/manager.go`
- Modify: `internal/lb/manager_ops_test.go`
- Modify: `internal/libvirt/backup_session.go`
- Modify: `internal/libvirt/client.go`
- Modify: `internal/libvirt/disk_source_rewrite.go`
- Modify: `internal/libvirt/hotplug_device.go`
- Modify: `internal/libvirt/ipdiscovery.go`
- Modify: `internal/libvirt/libvirt_round2_test.go`
- Modify: `internal/libvirt/vlan_test.go`
- Modify: `internal/libvirt/vtpmstate.go`
- Modify: `internal/libvirt/vtpmstate_test.go`
- Modify: `internal/libvirt/xmlpatch_devices.go`
- Modify: `internal/lxc/lxc.go`
- Modify: `internal/lxc/oci.go`
- Modify: `internal/mcpserver/server_test.go`
- Modify: `internal/obs/obs.go`
- Modify: `internal/pbsstore/chunkstore.go`
- Modify: `internal/qcow2/convert.go`
- Modify: `internal/qcow2/qcow2_test.go`
- Modify: `internal/restapi/server_test.go`
- Modify: `internal/safename/tar.go`
- Modify: `internal/scheduler/rebalancer_constraints_test.go`
- Modify: `internal/ssh/ssh_round2_test.go`
- Modify: `internal/ui/auth.go`
- Modify: `internal/ui/handle_vms.go`
- Modify: `internal/vfio/vfio.go`
- Modify: `internal/vfio/vfio_test.go`
- Modify: `internal/vmimport/mapping.go`
- Modify: `tests/e2e/container_migrate_test.go`
- Modify: `tests/e2e/e2e_test.go`
- Modify: `.golangci.yml`
- Modify: `docs/operating-model.md`
- Modify: `docs/diagnostics.md`
- Modify: `docs/placement.md`
- Modify: `docs/upgrades.md`

- [ ] **Step 1: Capture the exact lint inventory**

Run:

```bash
golangci-lint run ./...
```

Classify findings as production correctness, test correctness, dead code, or
documented false positive. Do not add broad package or linter exclusions.

- [ ] **Step 2: Fix production correctness findings first**

Handle ignored errors according to ownership semantics; remove ineffective
assignments and dead production functions; correct staticcheck defects. Where
an error is intentionally ignored, use an explicit `_ =` plus a narrow comment
or a line-specific directive such as
`//nolint:errcheck -- cleanup is best-effort after the primary failure`.

- [ ] **Step 3: Fix test findings**

Remove unused test helpers, correct nil dereferences/identical comparisons, and
check cleanup errors where they affect subsequent cases.

- [ ] **Step 4: Verify zero configured findings**

```bash
golangci-lint run ./...
```

Expected: exit 0 with no issues.

- [ ] **Step 5: Document the new operational model**

Document capability rollout, admission authority failure modes, stale
reservation diagnosis, capacity-policy mismatches, Compose webhook scoping,
private webhook allowlists, notification queue behavior, and NFS timeout
configuration.

- [ ] **Step 6: Commit**

```bash
git add .golangci.yml cmd internal tests docs
git commit -m "chore: enforce a clean static-analysis baseline"
```

## Task 12: Complete compatibility, race, security, and release verification

**Files:**

- Modify only if a verification failure identifies a defect in this plan's
  implementation.

- [ ] **Step 1: Run formatting and generated-code checks**

```bash
gofmt -w $(git diff --name-only --diff-filter=ACM -- '*.go')
make proto
git diff --check
```

- [ ] **Step 2: Run build, vet, guards, and lint**

```bash
go build ./...
go vet ./...
make ci-guards
golangci-lint run ./...
```

Expected: all exit 0.

- [ ] **Step 3: Run the full test suite**

```bash
go test ./... -count=1 -timeout=15m
```

Expected: PASS with no real NFS mounts and no platform-dependent Linux bridge
calls from unit tests.

- [ ] **Step 4: Run targeted race suites**

```bash
go test -race ./tests/fleet -count=1 -timeout=15m
go test -race ./internal/grpcapi -run 'Admission|CreateVM|Workload|Dispatcher|Placement' -count=1 -timeout=15m
go test -race ./internal/notify ./internal/placement ./internal/corrosion -count=1 -timeout=15m
```

Expected: PASS with no race reports.

- [ ] **Step 5: Run vulnerability and asset-integrity checks**

```bash
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
scripts/ci/vendor-assets_test.sh
```

Expected: no reachable vulnerabilities; asset test passes.

- [ ] **Step 6: Review the final diff against the design**

Check every requirement in
`docs/superpowers/specs/2026-07-28-control-plane-hardening-design.md`, ensure
public compatibility, inspect schema/ledger changes, and run:

```bash
git status --short
git diff --check HEAD^
```

- [ ] **Step 7: Commit verification-only corrections if needed**

```bash
git add -u
git commit -m "fix: close control-plane verification gaps"
```
