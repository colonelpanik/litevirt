#!/usr/bin/env bash
# Synthetic N-step rolling-upgrade drill.
#
# Stands up ONE EPHEMERAL real `litevirt daemon` on localhost at the current
# schema, then upgrades it across an ARTIFICIAL >1-version schema bump
# (28 -> 31: +2 tables, +1 column) via a real `lv host upgrade` — proving the
# real upgrade path (pre-stage schema-migrate of a big delta -> binary swap ->
# re-exec -> ledger bootstrap at the new version) end-to-end with genuinely
# different binary schema versions. The mixed-window REPLICATION handshake is
# covered separately by tests/fleet/nstep_upgrade_test.go.
#
# Requires libvirtd reachable (it is on a dev box) + python3 + sqlite3. Never
# creates VMs. Cleans up on exit.
#
#   bash scripts/test/nstep-upgrade-drill.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d /tmp/litevirt-nstep.XXXXXX)"
G=18443; M=18444; U=18445; GO=18446; DN=18453   # ports
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "  PASS: $*"; }
bad(){ FAIL=$((FAIL+1)); echo "  **FAIL**: $*"; }
PID=""
cleanup(){ [ -n "$PID" ] && kill "$PID" 2>/dev/null; sleep 1
  git -C "$REPO" worktree remove --force "$WORK/wt" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
lv(){ LV_HOST="127.0.0.1:$G" LV_CONFIG_DIR="$WORK/pki/n1" "$WORK/litevirt-v28" "$@"; }
sq(){ python3 -c 'import sys,sqlite3; c=sqlite3.connect(sys.argv[1],timeout=5); print(c.execute(sys.argv[2]).fetchone()[0])' "$WORK/data/state.db" "$1" 2>/dev/null; }

echo "== build base (v28) =="
( cd "$REPO" && CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=drill-v28" -o "$WORK/litevirt-v28" ./cmd/litevirt ) || exit 1
"$WORK/litevirt-v28" --version

echo "== build synthetic bumped (v31: +2 tables, +1 column) =="
git -C "$REPO" worktree add -q --detach "$WORK/wt" HEAD || exit 1
python3 - "$WORK/wt/internal/corrosion/schema.go" <<'PY' || exit 1
import sys
p=sys.argv[1]; s=open(p).read()
def rep(a,b):
    global s
    if a not in s: sys.exit(f"anchor missing: {a[:50]!r}")
    s=s.replace(a,b,1)
rep("const CurrentSchemaVersion = 28","const CurrentSchemaVersion = 31")
rep("\t`ALTER TABLE containers ADD COLUMN on_host_failure TEXT`,\n}",
    "\t`ALTER TABLE containers ADD COLUMN on_host_failure TEXT`,\n\t`ALTER TABLE hosts ADD COLUMN zz_synth_note TEXT`,\n}")
rep("\t28, 28, // containers.is_template/on_host_failure\n}",
    "\t28, 28, // containers.is_template/on_host_failure\n\t29, // zz_synth\n}")
rep('\t{26, "container_backups"}, {27, "container_snapshots"},\n}',
    '\t{26, "container_backups"}, {27, "container_snapshots"},\n\t{30, "zz_synth_a"}, {31, "zz_synth_b"},\n}')
i=s.index("var schemaIndexes"); c=s.rindex("\n}",0,i)
s=s[:c]+'\n\t`CREATE TABLE IF NOT EXISTS zz_synth_a (id TEXT PRIMARY KEY, note TEXT)`,\n\t`CREATE TABLE IF NOT EXISTS zz_synth_b (id TEXT PRIMARY KEY, note TEXT)`,'+s[c:]
open(p,"w").write(s)
PY
( cd "$WORK/wt" && CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=drill-v31" -o "$WORK/litevirt-v31" ./cmd/litevirt ) || exit 1
"$WORK/litevirt-v31" --version

echo "== mint PKI =="
( cd "$REPO" && go run ./scripts/test/mkpki "$WORK/pki" "127.0.0.1" n1 ) || exit 1

echo "== config + per-node binary copy =="
mkdir -p "$WORK/data" "$WORK/run"
cp "$WORK/litevirt-v28" "$WORK/run/litevirtd"   # daemon runs this copy; upgrade swaps IT (binaryPath=os.Executable)
cat > "$WORK/n1.yaml" <<EOF
host_name: n1
grpc_port: $G
gossip_port: $GO
metrics_port: $M
ui_port: $U
rest_port: 0
dns_port: $DN
pki_dir: $WORK/pki/n1/pki
data_dir: $WORK/data
dns_domain: litevirt.local
watchdog_dev: ""
join_peers: []
EOF

echo "== start daemon (v28) =="
LITEVIRT_CONFIG="$WORK/n1.yaml" LITEVIRT_UNSAFE_NO_KILLMODE_CHECK=1 "$WORK/run/litevirtd" daemon > "$WORK/n1.log" 2>&1 &
PID=$!; echo "  started n1 (pid $PID, grpc $G)"
for t in $(seq 1 40); do lv host ls 2>/dev/null | grep -q HOST_ACTIVE && break; sleep 2; done
lv host ls 2>&1 | sed 's/^/  /' | head -3
lv host ls 2>/dev/null | grep -q "n1.*HOST_ACTIVE" && ok "daemon up on v28" || { bad "daemon did not come up"; tail -25 "$WORK/n1.log"; exit 1; }

echo "== baseline schema =="
v=$(sq "SELECT version FROM schema_state WHERE id=1;"); [ "$v" = "28" ] && ok "schema_state=28" || bad "schema=$v want 28"
[ "$(sq "SELECT COUNT(*) FROM sqlite_master WHERE name='zz_synth_a';")" = "0" ] && ok "synthetic tables absent pre-upgrade" || bad "zz_synth_a already present?!"

echo "== UPGRADE across gap-3 (28 -> 31) =="
lv host upgrade --binary "$WORK/litevirt-v31" -y n1 2>&1 | sed 's/^/  /'

echo "== wait for re-exec -> drill-v31 =="
for t in $(seq 1 40); do lv host ls 2>/dev/null | grep -q "drill-v31" && break; sleep 3; done
lv host ls 2>&1 | sed 's/^/  /' | head -3
lv host ls 2>/dev/null | grep -q "n1.*drill-v31" && ok "daemon re-exec'd to drill-v31" || bad "did not converge to v31"

echo "== verify schema 31 + synthetic artifacts =="
v=$(sq "SELECT version FROM schema_state WHERE id=1;"); [ "$v" = "31" ] && ok "schema_state=31 (gap-3 applied)" || bad "schema_state=$v want 31"
ta=$(sq "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='zz_synth_a';")
tb=$(sq "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='zz_synth_b';")
[ "$ta" = "1" ] && [ "$tb" = "1" ] && ok "synthetic tables created by pre-stage" || bad "synthetic tables missing (a=$ta b=$tb)"
col=$(sq "SELECT COUNT(*) FROM pragma_table_info('hosts') WHERE name='zz_synth_note';")
[ "$col" = "1" ] && ok "hosts.zz_synth_note column added" || bad "zz_synth_note column missing"
led=$(sq "SELECT COUNT(*) FROM applied_migrations WHERE id IN ('t_zz_synth_a','t_zz_synth_b');")
[ "$led" = "2" ] && ok "ledger recorded the synthetic migrations" || bad "ledger missing synthetic units ($led)"

echo "== pre-stage actually ran (schema-migrate of the big delta) =="
grep -q "schema forward-migrated" "$WORK/n1.log" && ok "pre-stage schema-migrate logged" || bad "no pre-stage in log"

echo "== daemon still healthy + serving on v31 =="
lv host ls 2>/dev/null | grep -q "n1.*HOST_ACTIVE" && ok "daemon HOST_ACTIVE after upgrade" || bad "daemon unhealthy post-upgrade"

echo "================ DRILL RESULT: PASS=$PASS FAIL=$FAIL ================"
[ "$FAIL" -eq 0 ] && echo "DRILL PASSED" || echo "DRILL FAILED"
exit "$FAIL"
