# CLAUDE.md — ARTEX-Nexus (Rust + Go)

Follow all directives in `AGENTS.md` and the modular skills in `skills/*/SKILL.md`.

## Quick Commands
- Build native Rust + Go binaries: `make build`
- Fetch latest Medium+ CVE + OSV + Writeups DB (ETag + SHA-256 + atomic swap): `./target/release/nexus-sync fetch`
- Build instant local KEV starter DB: `./target/release/nexus-sync seed-kev`
- Run full Rust + Go test suite: `make test`
- Launch ARTEX + MCP HTTP stack: `docker compose up -d --build`

## Native Compiled MCP Servers (Dual: stdio + ARTEX Streamable HTTP `/mcp`)
- `cve-intel-mcp` (Rust): Medium+ CVEs, unscored KEVs, EPSS, OSV package ranges, exact CWE joins, dual-FTS5 writeup search, `whats_new`
- `patch-diff-mcp` (Go): SSRF-hardened no-redirect GitHub/GitLab commit & PR diff extraction
- `scope-guard-mcp` (Go): Config-dir confined scope loader, multi-tenant persisted scopes, cryptographically hash-chained append-only evidence ledger (`verify_ledger_chain`)
