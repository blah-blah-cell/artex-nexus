# Setup Guide (Humans & Coding Agents)

This file has everything a human operator or coding agent needs to install, configure, and verify ARTEX-Nexus cleanly on Linux, macOS, or Windows.

## Choose Your Mode

| Goal | Command | Prerequisites |
|---|---|---|
| **IDE / CLI agent MCP tools (`stdio`)** | `./scripts/install.sh --client claude` (or `.\scripts\install.ps1 -Client claude`) | Rust (`cargo` 1.88+), Go (1.24+) |
| **Full Docker stack (ARTEX + Postgres + 4 HTTP MCPs + Console)** | `./scripts/install.sh --mode docker` (or `.\scripts\install.ps1 -Mode docker`) | Docker + `docker compose` |
| **Native HTTP MCPs + local Web Console (`:8088`)** | `./scripts/install.sh && ./scripts/start-mcps.sh start` | Rust, Go |
| **Native ARTEX with embedded `/nexus` UI** | `./scripts/build-artex-ui.sh` (or `.\scripts\build-artex-ui.ps1`) | Go, Node.js 20+ / npm |

---

## 1. Clone With Submodules

```bash
git clone --recurse-submodules https://github.com/blah-blah-cell/artex-nexus.git
cd artex-nexus
```

If already cloned without `--recurse-submodules`:

```bash
git submodule update --init --recursive
```

---

## 2. One-Command Installation

### Linux / macOS
```bash
./scripts/install.sh
# Or with MCP JSON printed immediately:
./scripts/install.sh --client claude    # antigravity | claude | cursor | zcode | freebuff | artex
# Or Docker Compose mode:
./scripts/install.sh --mode docker
```

### Windows (PowerShell)
```powershell
.\scripts\install.ps1
# Or print MCP client JSON:
.\scripts\install.ps1 -Client claude
# Or Docker Compose mode:
.\scripts\install.ps1 -Mode docker
```

What the installer does:
1. Initializes `vendor/ARTEX` if empty.
2. Creates `data/`, `data/receipts/`, and `workspace/`.
3. Creates `.env` from `.env.example` with fresh random `POSTGRES_PASSWORD` and `MCP_AUTH_TOKEN` (if `.env` does not already exist).
4. In `native` mode: compiles Rust (`target/release/nexus-sync`, `target/release/cve-intel-mcp`) and Go (`go/bin/patch-diff-mcp`, `go/bin/scope-guard-mcp`, `go/bin/attack-surface-mcp`), downloads the prebuilt SQLite database (`cve-db-latest`) with SHA-256 verification, and runs `nexus-sync doctor`.
5. In `docker` mode: fetches the CVE DB into `./data` and runs `docker compose up -d --build`.

Skip the DB download during offline testing with `--skip-db` (`-SkipDb` on Windows). For a lightweight KEV-only starter DB without downloading the full snapshot, run `nexus-sync seed-kev`.

---

## 3. Wiring Into an IDE or CLI Agent (`stdio`)

Generate ready-to-paste JSON for your client:

```bash
./target/release/nexus-sync init-mcp --client claude       # Claude Code / Desktop
./target/release/nexus-sync init-mcp --client cursor       # Cursor
./target/release/nexus-sync init-mcp --client antigravity  # Antigravity
./target/release/nexus-sync init-mcp --client zcode        # ZCode
./target/release/nexus-sync init-mcp --client freebuff     # Freebuff
./target/release/nexus-sync init-mcp --client artex        # ARTEX HTTP MCP map
```

Notes for agents configuring `stdio` servers:
- `cve-intel-mcp` reads `--db-path` (default `data/cve_kb_med_plus.sqlite`).
- `scope-guard-mcp` confines policy reads to `--config-dir` (`SCOPE_CONFIG_DIR`, default `config/`) and stores receipts in `--state-dir` (`SCOPE_STATE_DIR`, default `data/receipts/`). Put engagement scope YAML/JSON files inside `config/` (see `config/scope.example.yaml`).
- `attack-surface-mcp` confines ALL file reads to `--workspace-dir` (`ATTACK_SURFACE_ROOT`, default `.`). Always point `--workspace-dir` at the directory containing code, OpenAPI specs, or JS bundles you want audited.
- `patch-diff-mcp` works without a token; set `GITHUB_TOKEN` to raise GitHub API rate limits (the token is only ever sent to `api.github.com`).

---

## 4. Wiring Into `BaaRai/ARTEX` (HTTP MCPs + UI Overlay)

### Option A: Docker Compose (Recommended)
```bash
./scripts/install.sh --mode docker
docker compose ps
```
All four MCP containers expose `/health` and require `Authorization: Bearer $MCP_AUTH_TOKEN` on `/mcp`. Once `artex` is healthy on `http://127.0.0.1:8787`, attach the 4 MCPs, 8 skills, prompts, and proxy traffic binding automatically:

```bash
set -a && source .env && set +a
export ARTEX_UI_PASSWORD="<your-artex-ui-password>"
./target/release/nexus-sync bootstrap \
  --docker-network \
  --artex-url "http://127.0.0.1:${ARTEX_PORT:-8787}" \
  --mcp-auth-token "$MCP_AUTH_TOKEN"
```

### Option B: Native Host Services + Embedded `/nexus` UI
1. Build ARTEX with the `/nexus` UI overlay embedded (leaves `vendor/ARTEX` clean):
   ```bash
   ./scripts/build-artex-ui.sh linux amd64 ./dist/artex-nexus-server
   # Windows: .\scripts\build-artex-ui.ps1 -TargetOS windows -TargetArch amd64 -Output .\dist\artex-nexus-server.exe
   ```
2. Start the 4 HTTP MCP servers (`:8901`–`:8904`) and local console (`:8088`):
   ```bash
   ./scripts/start-mcps.sh start
   ./scripts/start-mcps.sh status
   ```
3. Start your PostgreSQL instance and `./dist/artex-nexus-server`, then run `nexus-sync bootstrap`:
   ```bash
   set -a && source .env && set +a
   export ARTEX_UI_PASSWORD="<your-artex-ui-password>"
   ./target/release/nexus-sync bootstrap \
     --artex-url http://127.0.0.1:8787 \
     --mcp-host 127.0.0.1 \
     --mcp-auth-token "$MCP_AUTH_TOKEN" \
     --knowledge-dir "$PWD/knowledge" \
     --data-dir "$PWD/data" \
     --config-dir "$PWD/config"
   ```
   Pass `--password-file /path/to/pass` or `--password-stdin` instead of `--password` so credentials do not appear in process listings. If targeting a remote non-loopback ARTEX host, use `https://` (or explicitly pass `--allow-insecure-http` for an isolated lab).

---

## 5. Optional Smart API Fuzzers (`skills/smart-api-fuzzing`)

If you use the `smart-api-fuzzing` skill, install the two upstream open-source fuzzers:
- **Schemathesis** (Python): `python3 -m venv .venv-fuzz && .venv-fuzz/bin/pip install schemathesis`
- **Endava CATS**: download the native binary from [github.com/Endava/cats/releases](https://github.com/Endava/cats/releases) and place `cats` on `PATH`.

---

## 6. Key Environment Variables

| Variable | Used By | Purpose |
|---|---|---|
| `CVE_DB_PATH` | `cve-intel-mcp`, `nexus-sync` | Path to SQLite DB (default `data/cve_kb_med_plus.sqlite`) |
| `CVE_DB_SHA256` | `nexus-sync fetch` | Optional out-of-band SHA-256 pin for DB authenticity |
| `MCP_AUTH_TOKEN` | All 4 HTTP MCPs, `bootstrap`, Compose | Bearer token required on HTTP `/mcp` when set |
| `MCP_HOST` / `MCP_TRANSPORT` | All 4 MCP servers | Bind host (`127.0.0.1`) and transport (`stdio` or `http`) |
| `GITHUB_TOKEN` | `patch-diff-mcp` | Optional GitHub token (sent only to `api.github.com`) |
| `SCOPE_CONFIG_DIR` | `scope-guard-mcp` | Confined directory for YAML/JSON scope policies |
| `SCOPE_STATE_DIR` | `scope-guard-mcp`, `nexus-sync serve` | Directory for `scopes.json` and `receipts.jsonl` |
| `SCOPE_DEFAULT_POLICY` | `scope-guard-mcp` | Optional policy filename inside `SCOPE_CONFIG_DIR` preloaded into `default` |
| `SCOPE_LEDGER_HMAC_KEY` | `scope-guard-mcp` | Optional HMAC-SHA256 key for ledger tamper/rewrite protection |
| `ATTACK_SURFACE_ROOT` | `attack-surface-mcp` | Confined root directory for all file-reading tools |
| `NEXUS_CORS_ORIGINS` | `nexus-sync serve` | Comma-separated origin allowlist for `:8088` API |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `docker-compose.yml` | Passed to ARTEX via discrete `ARTEX_PG_*` vars (special chars safe) |

---

## 7. Verification Checklist & Common Pitfalls

Run these checks after installation:

```bash
# 1. Verify DB integrity and live counts
./target/release/nexus-sync doctor --db data/cve_kb_med_plus.sqlite

# 2. Run Rust + Go test suites
make test

# 3. Check HTTP MCP health (when running HTTP mode)
for p in 8901 8902 8903 8904; do curl -fsS "http://127.0.0.1:$p/health" && echo " :$p ok"; done
```

Common pitfalls:
- **`CVE database not found`**: Run `nexus-sync fetch` (or `nexus-sync seed-kev` for a small KEV-only DB).
- **`path escapes workspace root` in `attack-surface-mcp`**: Place target files under `ATTACK_SURFACE_ROOT` (or restart with `--workspace-dir <dir>`).
- **`corrupt scopes.json` in `scope-guard-mcp`**: `scope-guard-mcp` refuses to wipe a corrupt `scopes.json`; inspect or back up and remove the broken file in `SCOPE_STATE_DIR`.
- **Docker Compose fails with `Set MCP_AUTH_TOKEN in .env`**: Run `./scripts/install.sh` (or `.\scripts\install.ps1`) or set `MCP_AUTH_TOKEN` and `POSTGRES_PASSWORD` in `.env`.
- **Console `/api/*` returns `403`**: The browser origin or `Host` header is not in `NEXUS_CORS_ORIGINS` / `--cors-origin`. Add your UI origin (for example `http://127.0.0.1:8787`).
- **`*.example.com` scope rule didn't match `example.com`**: Wildcard rules match subdomains only; list `example.com` explicitly if the apex domain is also in scope.
