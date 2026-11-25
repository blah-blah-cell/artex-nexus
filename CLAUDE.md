# CLAUDE.md

See `AGENTS.md` for workflow rules and `skills/*/SKILL.md` for task-specific playbooks.

## Common Commands
- Build Rust and Go binaries: `make build`
- Pull the latest CVE/OSV SQLite DB: `./target/release/nexus-sync fetch`
- Run the local web console: `./target/release/nexus-sync serve --port 8088`
- Scan local lockfiles (10 formats, SARIF export): `./target/release/nexus-sync scan --path . --sarif sbom.sarif --fail-on high`
- Print MCP config JSON: `./target/release/nexus-sync init-mcp --client claude`
- Run Rust + Go tests: `make test`
- Start ARTEX + MCP containers: `docker compose up -d --build`

## MCP Servers (stdio and HTTP `/mcp`)
- `cve-intel-mcp` (Rust, `:8901`): FTS5 CVE/writeup search, OSV SemVer checks, exact CWE lookups, KEV/EPSS metadata.
- `patch-diff-mcp` (Go, `:8902`): no-redirect HTTPS diff fetcher for GitHub and GitLab commits/PRs with private-IP blocking.
- `scope-guard-mcp` (Go, `:8903`): confined policy loader, per-`scope_id` allowlists, SHA-256 hash-chained `receipts.jsonl`.
- `attack-surface-mcp` (Go, `:8904`): workspace-confined OpenAPI auditor, JS endpoint extractor, CWE sink scanner, JWT and header checker.
