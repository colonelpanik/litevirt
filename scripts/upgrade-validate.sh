#!/usr/bin/env bash
# Plan §schema-upgrade-validation
#
# Run on EACH node of a litevirt cluster *before* upgrading the binary.
# Prints daemon version, persisted schema_state.version, presence of
# every table/column the new binary expects, and the row counts that
# would be at risk if a schema migration were to fail.
#
# Read-only. Safe to run while the daemon is up — modernc-sqlite
# tolerates concurrent readers as long as no writer holds an EXCLUSIVE.
#
# Usage:  sudo ./upgrade-validate.sh [/var/lib/litevirt/state.db]

set -eu
DB="${1:-/var/lib/litevirt/state.db}"
SQLITE=${SQLITE:-sqlite3}

if [ ! -f "$DB" ]; then
  echo "ERR: db not found at $DB" >&2
  echo "     pass the correct path as arg 1, or set 'data_dir' in" >&2
  echo "     /etc/litevirt/config.yaml to see where state lives" >&2
  exit 2
fi

hr() { printf '%s\n' "----------------------------------------"; }

echo "=========================================="
echo "litevirt upgrade preflight"
echo "host:    $(hostname)"
echo "db file: $DB"
echo "db size: $(du -h "$DB" | awk '{print $1}')"
echo "=========================================="

hr
echo "[1] Daemon version (running process)"
if command -v litevirtd >/dev/null 2>&1; then
  litevirtd --version 2>/dev/null || echo "  litevirtd refused --version; try systemctl status litevirtd"
else
  echo "  litevirtd not on PATH"
fi
echo
echo "  (currently-running binary; from --version embedded ldflags)"

hr
echo "[2] schema_state — what version does this node's DB think it is?"
"$SQLITE" "$DB" \
  "SELECT version, updated_at FROM schema_state WHERE id = 1" \
  -header -column 2>&1 || echo "  ERR: schema_state row missing (pre-Phase-0.7 DB?)"

hr
echo "[3] Critical tables — must exist before a new binary starts pushing"
for t in \
  hosts vms vm_disks vm_interfaces \
  security_groups sg_rules \
  containers sessions user_2fa recovery_codes \
  roles role_bindings tokens users \
  backup_schedules service_endpoints \
  schema_state mutation_log mutation_seen replication_watermarks \
  leader_election fencing_log vm_locks
do
  count=$("$SQLITE" "$DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$t'" 2>/dev/null || echo "ERR")
  if [ "$count" = "1" ]; then
    rows=$("$SQLITE" "$DB" "SELECT COUNT(*) FROM \"$t\"" 2>/dev/null || echo "?")
    printf "  OK  %-30s rows=%s\n" "$t" "$rows"
  else
    printf "  ABSENT  %-26s ← new binary will run CREATE TABLE; verify it succeeds on first start\n" "$t"
  fi
done

hr
echo "[4] Critical columns — must exist before a new binary INSERTs them"
check_col() {
  local table="$1" col="$2"
  if ! "$SQLITE" "$DB" "PRAGMA table_info(\"$table\")" 2>/dev/null \
      | awk -F'|' -v c="$col" '$2==c{found=1} END{exit !found}'; then
    printf "  ABSENT  %s.%s ← new binary will run ALTER; verify it succeeds on first start\n" "$table" "$col"
  else
    printf "  OK      %s.%s\n" "$table" "$col"
  fi
}
check_col hosts          region
check_col hosts          role
check_col hosts          version
check_col vm_interfaces  security_groups
check_col tokens         scope_paths
check_col users          realm
check_col users          display_name
check_col users          email
check_col vm_disks       target_dev
check_col lb_configs     ports
check_col lb_configs     stack_name
check_col image_hosts    progress_pct
check_col host_pci_devices pcie_root_port

hr
echo "[5] Replication backlog — entries waiting to be acked by peers"
"$SQLITE" "$DB" \
  "SELECT peer_name, last_seq, updated_at FROM replication_watermarks ORDER BY peer_name" \
  -header -column 2>&1 || echo "  (table missing — pre-Crescent DB)"
echo
echo "  Compare each peer's last_seq to your local MAX(seq) below."
"$SQLITE" "$DB" \
  "SELECT COALESCE(MAX(seq),0) AS local_max_seq, COUNT(*) AS log_rows FROM mutation_log" \
  -header -column 2>&1 || true

hr
echo "[6] In-flight work that would be hostile to a restart"
echo "  vm_locks (live migrations / backups holding a lease):"
"$SQLITE" "$DB" \
  "SELECT vm_name, holder, expires_at FROM vm_locks WHERE expires_at > datetime('now')" \
  -header -column 2>&1 || echo "  (no vm_locks table — pre-1.7)"
echo
echo "  leader_election (active leases):"
"$SQLITE" "$DB" \
  "SELECT key, holder, expires_at FROM leader_election WHERE expires_at > datetime('now')" \
  -header -column 2>&1 || echo "  (no leader_election table — pre-Phase-1)"

hr
echo "[7] Cross-host clock skew that would block PushMutations after upgrade"
"$SQLITE" "$DB" \
  "SELECT observer, target, skew_seconds, updated_at FROM clock_skew
   WHERE updated_at > datetime('now','-5 minutes')
   ORDER BY ABS(skew_seconds) DESC LIMIT 5" \
  -header -column 2>&1 || echo "  (no clock_skew rows — fine)"

hr
echo "=========================================="
echo "Done. Repeat on every node BEFORE upgrading."
echo "If [2] reports version < binary's CurrentSchemaVersion, new binary"
echo "will run the missing migrations on first start (idempotent)."
echo "If [4] reports any ABSENT columns AND this node is the LAST to be"
echo "upgraded, expect schema-missing replication errors from already-"
echo "upgraded peers — they will retry until you upgrade this node."
echo "=========================================="
