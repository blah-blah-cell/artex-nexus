# CLAUDE.md

See [AGENTS.md](AGENTS.md) for operating rules, [SETUP.md](SETUP.md) for full install/troubleshooting steps, and `skills/*/SKILL.md` for task-specific playbooks.

## Fast Setup
- One-command install (Linux/macOS): `./scripts/install.sh` (add `--mode docker` for Compose, `--client claude` for MCP JSON)
- One-command install (Windows): `.\scripts\install.ps1` (add `-Mode docker`, `-Client claude`)
- If `vendor/ARTEX` is empty: `git submodule update --init --recursive`

## Common Commands
- Build Rust and Go binaries: `make build`
- Pull and verify the latest CVE/OSV SQLite DB: `./target/release/nexus-sync fetch && ./target/release/nexus-sync doctor`
- Run the local web console: `./target/release/nexus-sync serve --host 127.0.0.1 --port 8088`
- Start/stop/check all 4 HTTP MCP servers + console (Linux/macOS): `./scripts/start-mcps.sh start|status|stop`
- Scan local lockfiles (10 formats, SARIF export): `./target/release/nexus-sync scan --path . --sarif sbom.sarif --fail-on high`
- Print MCP config JSON: `./target/release/nexus-sync init-mcp --client claude`
- Bootstrap a running ARTEX instance: `ARTEX_UI_PASSWORD=... ./target/release/nexus-sync bootstrap --artex-url http://127.0.0.1:8787 --mcp-auth-token "$MCP_AUTH_TOKEN"`
- Build ARTEX with embedded `/nexus` UI: `./scripts/build-artex-ui.sh` (or `.\scripts\build-artex-ui.ps1`)
- Run Rust + Go tests & lints: `make test && make lint`
- Start ARTEX + MCP containers (requires `.env` with `POSTGRES_PASSWORD` and `MCP_AUTH_TOKEN`): `docker compose up -d --build`

## MCP Servers (stdio and HTTP `/mcp`)
- `cve-intel-mcp` (Rust, `:8901`): FTS5 CVE/writeup search (`bm25`), OSV SemVer/Maven/PEP 440 checks, exact CWE lookups, KEV/EPSS metadata. Reads `CVE_DB_PATH`.
- `patch-diff-mcp` (Go, `:8902`): no-redirect HTTPS diff fetcher for GitHub and GitLab commits/PRs with private/reserved IP blocking. Optional `GITHUB_TOKEN` (only sent to `api.github.com`).
- `scope-guard-mcp` (Go, `:8903`): confined policy loader (`SCOPE_CONFIG_DIR`), per-`scope_id` host/port/path allowlists, hash-chained `receipts.jsonl` (`SCOPE_STATE_DIR`, optional `SCOPE_LEDGER_HMAC_KEY`).
- `attack-surface-mcp` (Go, `:8904`): workspace-confined (`ATTACK_SURFACE_ROOT` / `--workspace-dir`) OpenAPI auditor, JS endpoint extractor, CWE sink scanner with secret redaction, JWT and header checker.
