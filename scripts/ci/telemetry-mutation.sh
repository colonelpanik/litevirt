#!/usr/bin/env bash
# Mutation-prove load-bearing telemetry guards: each case breaks one fix,
# asserts the pinning test goes RED, then restores the tree.
#
# Usage (from repo root):
#   ./scripts/ci/telemetry-mutation.sh
#
# Exit 0 only if every mutation killed its test AND the tree is clean again.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree must be clean before mutation run (uncommitted changes would be mixed with reverts)" >&2
  exit 1
fi

restore() {
  git checkout -- \
    cmd/litevirt/daemon.go \
    internal/obs/obs.go \
    internal/grpcapi/migrate.go \
    2>/dev/null || true
}
trap restore EXIT

pass=0
fail=0

# run_mut name file sed_expr test_pkg test_run
# Applies a single-line sed replacement, expects `go test` to FAIL, restores file.
run_mut() {
  local name="$1" file="$2" expr="$3" pkg="$4" run="$5"
  echo ""
  echo "=== mutation: $name ==="
  echo "    break: $file"
  echo "    expect RED: go test $pkg -run $run"

  # Apply mutation (portable sed -i).
  if [[ "$(uname -s)" == "Darwin" ]]; then
    sed -i '' -e "$expr" "$file"
  else
    sed -i -e "$expr" "$file"
  fi

  set +e
  go test "$pkg" -count=1 -timeout 60s -run "$run" >/tmp/telem-mut-out.txt 2>&1
  local rc=$?
  set -e

  # Restore immediately so the next mutation starts clean.
  git checkout -- "$file"

  if [[ $rc -eq 0 ]]; then
    echo "    FAIL: test stayed GREEN after mutation — guard is hollow or sed missed"
    echo "    ---- test output (tail) ----"
    tail -40 /tmp/telem-mut-out.txt | sed 's/^/    /'
    fail=$((fail + 1))
    return 0
  fi
  # Confirm it was a test failure, not a build break from a bad sed.
  if ! grep -qE 'FAIL|--- FAIL' /tmp/telem-mut-out.txt; then
    echo "    FAIL: go test exited $rc but no test FAIL line (build error? bad sed?)"
    tail -40 /tmp/telem-mut-out.txt | sed 's/^/    /'
    fail=$((fail + 1))
    return 0
  fi
  echo "    OK: test went RED (exit $rc) — guard is load-bearing"
  pass=$((pass + 1))
}

# 1. re-exec passes live env (findings 1 & 2)
run_mut "reexec_live_environ" \
  "cmd/litevirt/daemon.go" \
  's/return execFn(binary, os.Args, pristineEnv)/return execFn(binary, os.Args, os.Environ())/' \
  "./cmd/litevirt/" \
  "TestReExecSelfUsesPristineEnv|TestChecklist_C"

# 2. bare env presence activates tracing (finding 5)
run_mut "tracing_active_bare_presence" \
  "internal/obs/obs.go" \
  's/active := validEndpoint(endpoint)/active := endpoint != ""/' \
  "./internal/obs/" \
  "TestSetup_InvalidEndpointEnv_TracingOffAndUnset"

# 3. drop real sampler (finding 3)
run_mut "drop_with_sampler" \
  "internal/obs/obs.go" \
  's/sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(rate))),/\/\/ mutated: sampler removed/' \
  "./internal/obs/" \
  "TestSetup_SamplerWired_ZeroRateNeverSamples"

# 4. skip injecting the obs-owned provider (finding 3 promotion)
run_mut "skip_tracer_provider_inject" \
  "internal/obs/obs.go" \
  's/setupOpts = append(setupOpts, telemetry.WithTracerProvider(tp))/_ = tp \/\/ mutated: skip inject/' \
  "./internal/obs/" \
  "TestSetup_InjectedTracerProviderBecomesGlobal|TestSetup_SamplerWired_ZeroRateNeverSamples"

# 5. migrate notify keeps inbound metadata (finding 6)
run_mut "notify_keeps_inbound_md" \
  "internal/grpcapi/migrate.go" \
  's/base := metadata.NewIncomingContext(context.WithoutCancel(ctx), metadata.MD{})/base := context.WithoutCancel(ctx)/' \
  "./internal/grpcapi/" \
  "TestNotifyDetachedContext_StripsInboundMetadataKeepsSpanAndTimeout"

# 6. fake healthy traces circuit (finding 3 fallout honesty)
run_mut "fake_traces_circuit" \
  "internal/obs/obs.go" \
  's/TracesCircuit:  "unknown",/TracesCircuit:  h.TracesCircuitState,/' \
  "./internal/obs/" \
  "TestHealth_TracesCircuitUnknown_WhenTracingActive"

# Baseline: unmutated suite still green (guards not permanently broken).
echo ""
echo "=== baseline: unmutated pinning tests still green ==="
go test ./cmd/litevirt/ ./internal/obs/ ./internal/grpcapi/ -count=1 -timeout 180s \
  -run 'TestReExecSelfUsesPristineEnv|TestChecklist_C|TestSetup_InvalidEndpointEnv|TestSetup_SamplerWired_ZeroRate|TestSetup_InjectedTracerProvider|TestNotifyDetachedContext_Strips|TestHealth_TracesCircuitUnknown' \
  >/tmp/telem-mut-baseline.txt 2>&1 || {
  echo "FAIL: baseline green run failed after mutations restored"
  tail -40 /tmp/telem-mut-baseline.txt
  exit 1
}
echo "    OK: baseline green"

echo ""
echo "mutation summary: $pass killed their tests, $fail did not"
if [[ $fail -ne 0 ]]; then
  exit 1
fi
if [[ $pass -lt 6 ]]; then
  echo "error: expected 6 mutations; got $pass" >&2
  exit 1
fi
echo "all $pass mutations are load-bearing"
