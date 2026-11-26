#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="native"
SKIP_DB=0
CLIENT=""

usage() {
  cat <<'EOF'
Usage: ./scripts/install.sh [options]

Options:
  --mode native|docker   Build local binaries (default) or start the Docker Compose stack
  --skip-db              Skip downloading the prebuilt CVE SQLite DB (cve-db-latest)
  --client <name>        Print MCP config JSON for: antigravity|claude|cursor|zcode|freebuff|artex
  -h, --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --skip-db)
      SKIP_DB=1
      shift
      ;;
    --client)
      CLIENT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$MODE" != "native" && "$MODE" != "docker" ]]; then
  echo "Invalid --mode '$MODE' (expected native or docker)" >&2
  exit 1
fi

gen_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets; print(secrets.token_hex(24))'
  else
    LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 48
  fi
}

ensure_env() {
  if [[ -f "$REPO_ROOT/.env" ]]; then
    echo "[*] Keeping existing .env"
    return
  fi
  echo "[*] Creating .env from .env.example with generated secrets..."
  local pg_pass mcp_tok
  pg_pass="$(gen_hex)"
  mcp_tok="$(gen_hex)"
  cp "$REPO_ROOT/.env.example" "$REPO_ROOT/.env"
  chmod 600 "$REPO_ROOT/.env"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$REPO_ROOT/.env" "$pg_pass" "$mcp_tok" <<'PY'
import sys
path, pg, tok = sys.argv[1:4]
text = open(path, encoding="utf-8").read()
text = text.replace("POSTGRES_PASSWORD=change-me-to-a-strong-password", f"POSTGRES_PASSWORD={pg}")
text = text.replace("MCP_AUTH_TOKEN=change-me-to-a-random-bearer-token", f"MCP_AUTH_TOKEN={tok}")
open(path, "w", encoding="utf-8").write(text)
PY
  else
    sed -i.bak \
      -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$pg_pass|" \
      -e "s|^MCP_AUTH_TOKEN=.*|MCP_AUTH_TOKEN=$mcp_tok|" \
      "$REPO_ROOT/.env"
    rm -f "$REPO_ROOT/.env.bak"
  fi
}

cd "$REPO_ROOT"
mkdir -p data data/receipts workspace

if [[ -d .git && ! -f vendor/ARTEX/go.mod ]]; then
  echo "[*] Initializing vendor/ARTEX git submodule..."
  git submodule update --init --recursive
fi

ensure_env

if [[ "$MODE" == "docker" ]]; then
  command -v docker >/dev/null 2>&1 || { echo "Missing required tool: docker" >&2; exit 1; }
  docker compose version >/dev/null 2>&1 || { echo "Missing required plugin: docker compose" >&2; exit 1; }

  if [[ "$SKIP_DB" -eq 0 && ! -f data/cve_kb_med_plus.sqlite ]]; then
    echo "[*] Building nexus-sync image to fetch the CVE DB into ./data..."
    docker compose build cve-intel-mcp
    docker compose run --rm -v "$REPO_ROOT/data:/data" cve-intel-mcp \
      nexus-sync fetch --out /data/cve_kb_med_plus.sqlite
  fi

  echo "[*] Starting Docker Compose stack..."
  docker compose up -d --build
  echo "[*] Stack is starting. Check container health with: docker compose ps"
  echo "[*] Once ARTEX (:8787) is up, wire MCPs/skills/prompts with:"
  echo "    set -a && source .env && set +a && docker compose run --rm --network host cve-intel-mcp nexus-sync bootstrap --docker-network --artex-url http://127.0.0.1:\${ARTEX_PORT:-8787}"
  exit 0
fi

command -v cargo >/dev/null 2>&1 || { echo "Missing required tool: cargo (install Rust from https://rustup.rs)" >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "Missing required tool: go (install Go 1.26+ from https://go.dev/dl/)" >&2; exit 1; }

echo "[*] Building Rust workspace (nexus-sync, cve-intel-mcp)..."
cargo build --release --locked --workspace

echo "[*] Building Go MCP servers (patch-diff-mcp, scope-guard-mcp, attack-surface-mcp)..."
mkdir -p go/bin
(
  cd go
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/patch-diff-mcp ./cmd/patch-diff-mcp
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/scope-guard-mcp ./cmd/scope-guard-mcp
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/attack-surface-mcp ./cmd/attack-surface-mcp
)

if [[ "$SKIP_DB" -eq 0 ]]; then
  echo "[*] Fetching prebuilt Medium+ CVE/OSV SQLite database..."
  ./target/release/nexus-sync fetch --out data/cve_kb_med_plus.sqlite
  ./target/release/nexus-sync doctor --db data/cve_kb_med_plus.sqlite
else
  echo "[*] Skipping CVE DB fetch (--skip-db). Run './target/release/nexus-sync fetch' or 'seed-kev' before querying."
fi

if [[ -n "$CLIENT" ]]; then
  echo ""
  echo "[*] MCP client config ($CLIENT):"
  ./target/release/nexus-sync init-mcp --client "$CLIENT" --repo-root "$REPO_ROOT"
fi

echo ""
echo "[+] ARTEX-Nexus native install complete."
echo "    - Print MCP config:  ./target/release/nexus-sync init-mcp --client claude"
echo "    - Local web console: ./target/release/nexus-sync serve --host 127.0.0.1 --port 8088"
echo "    - Start HTTP MCPs:   ./scripts/start-mcps.sh start"
echo "    - Full setup guide:  SETUP.md"
