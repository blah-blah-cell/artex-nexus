#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_DIR="$REPO_ROOT/.run"
LOG_DIR="$RUN_DIR/logs"
CMD="${1:-start}"

if [[ -f "$REPO_ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$REPO_ROOT/.env"
  set +a
fi

HOST="${MCP_HOST:-127.0.0.1}"
DB_PATH="${CVE_DB_PATH:-$REPO_ROOT/data/cve_kb_med_plus.sqlite}"
CONFIG_DIR="${SCOPE_CONFIG_DIR:-$REPO_ROOT/config}"
STATE_DIR="${SCOPE_STATE_DIR:-$REPO_ROOT/data/receipts}"
WORKSPACE_DIR="${ATTACK_SURFACE_ROOT:-$REPO_ROOT/workspace}"
KNOWLEDGE_DIR="$REPO_ROOT/knowledge"
CORS_ORIGINS="${NEXUS_CORS_ORIGINS:-http://127.0.0.1:8787,http://localhost:8787}"

start_svc() {
  local name="$1"
  shift
  local pid_file="$RUN_DIR/$name.pid"
  if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    echo "[*] $name already running (pid $(cat "$pid_file"))"
    return
  fi
  nohup "$@" >"$LOG_DIR/$name.log" 2>&1 &
  echo $! >"$pid_file"
  echo "[+] started $name (pid $!)"
}

stop_svc() {
  local name="$1"
  local pid_file="$RUN_DIR/$name.pid"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      echo "[-] stopped $name (pid $pid)"
    fi
    rm -f "$pid_file"
  fi
}

status_svc() {
  local name="$1"
  local url="$2"
  local pid_file="$RUN_DIR/$name.pid"
  local pid_state="stopped"
  if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    pid_state="pid=$(cat "$pid_file")"
  fi
  local http_state="down"
  if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
    http_state="healthy"
  fi
  printf "  %-20s %-14s %s (%s)\n" "$name" "$pid_state" "$http_state" "$url"
}

case "$CMD" in
  start)
    mkdir -p "$RUN_DIR" "$LOG_DIR" "$STATE_DIR" "$WORKSPACE_DIR"
    for bin in \
      "$REPO_ROOT/target/release/cve-intel-mcp" \
      "$REPO_ROOT/target/release/nexus-sync" \
      "$REPO_ROOT/go/bin/patch-diff-mcp" \
      "$REPO_ROOT/go/bin/scope-guard-mcp" \
      "$REPO_ROOT/go/bin/attack-surface-mcp"; do
      if [[ ! -x "$bin" ]]; then
        echo "Missing binary $bin. Run ./scripts/install.sh first." >&2
        exit 1
      fi
    done

    start_svc cve-intel-mcp "$REPO_ROOT/target/release/cve-intel-mcp" \
      --transport http --host "$HOST" --port 8901 --db-path "$DB_PATH"
    start_svc patch-diff-mcp "$REPO_ROOT/go/bin/patch-diff-mcp" \
      -transport http -host "$HOST" -port 8902

    scope_args=(-transport http -host "$HOST" -port 8903 -config-dir "$CONFIG_DIR" -state-dir "$STATE_DIR")
    if [[ -n "${SCOPE_DEFAULT_POLICY:-}" ]]; then
      scope_args+=(-default-policy "$SCOPE_DEFAULT_POLICY")
    fi
    start_svc scope-guard-mcp "$REPO_ROOT/go/bin/scope-guard-mcp" "${scope_args[@]}"

    start_svc attack-surface-mcp "$REPO_ROOT/go/bin/attack-surface-mcp" \
      -transport http -host "$HOST" -port 8904 -workspace-dir "$WORKSPACE_DIR"

    if [[ -f "$DB_PATH" ]]; then
      start_svc nexus-console "$REPO_ROOT/target/release/nexus-sync" serve \
        --host "$HOST" --port 8088 --db "$DB_PATH" \
        --receipts-dir "$STATE_DIR" --knowledge-dir "$KNOWLEDGE_DIR" \
        --cors-origin "$CORS_ORIGINS"
    else
      echo "[!] Skipping nexus-console (:8088): DB not found at $DB_PATH (run nexus-sync fetch)"
    fi

    sleep 1
    "$0" status
    ;;
  stop)
    for svc in nexus-console attack-surface-mcp scope-guard-mcp patch-diff-mcp cve-intel-mcp; do
      stop_svc "$svc"
    done
    ;;
  status)
    echo "ARTEX-Nexus HTTP services:"
    status_svc cve-intel-mcp "http://$HOST:8901/health"
    status_svc patch-diff-mcp "http://$HOST:8902/health"
    status_svc scope-guard-mcp "http://$HOST:8903/health"
    status_svc attack-surface-mcp "http://$HOST:8904/health"
    status_svc nexus-console "http://$HOST:8088/api/stats"
    ;;
  *)
    echo "Usage: $0 [start|stop|status]" >&2
    exit 1
    ;;
esac
