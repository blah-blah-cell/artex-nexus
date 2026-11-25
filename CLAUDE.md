# CLAUDE.md — ARTEX-Nexus (Rust + Go)

Follow all directives in `AGENTS.md` and the modular skills in `skills/*/SKILL.md`.

## Quick Commands
- Build native Rust + Go binaries: `make build`
- Fetch latest Medium+ CVE + OSV + Writeups DB (ETag + SHA-256 + atomic swap): `./target/release/nexus-sync fetch`
- Launch local offline CVE/OSV Web Console: `./target/release/nexus-sync serve --port 8088`
- Offline SBOM/lockfile scan (10 formats + SARIF + CI gate): `./target/release/nexus-sync scan --path . --sarif sbom.sarif --fail-on high`
- Generate MCP JSON config for any client: `./target/release/nexus-sync init-mcp --client claude`
- Run full Rust + Go test suite: `make test`
- Launch ARTEX + MCP HTTP stack: `docker compose up -d --build`

## Native Compiled MCP Servers (Dual: stdio + ARTEX Streamable HTTP `/mcp`)
- `cve-intel-mcp` (Rust): Medium+ CVEs, unscored KEVs, EPSS, OSV SemVer checks, exact CWE joins, dual-FTS5 writeup search, `whats_new`
- `patch-diff-mcp` (Go): SSRF-hardened no-redirect GitHub/GitLab commit & PR diff extraction
- `scope-guard-mcp` (Go): Config-dir confined scope loader, multi-tenant persisted scopes, cryptographically hash-chained append-only evidence ledger (`verify_ledger_chain`)
- `attack-surface-mcp` (Go): Offline OpenAPI security auditor, CWE source sink & secret scanner, JWT & HTTP header inspector
