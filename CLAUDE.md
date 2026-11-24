# CLAUDE.md — ARTEX-Nexus

Follow all directives in `AGENTS.md` and the modular skills in `skills/*/SKILL.md`.

## Quick Commands
- Bootstrap CVE DB (full nightly release): `python -m pipeline.bootstrap`
- Bootstrap fast KEV starter DB: `python -m pipeline.bootstrap --kev-seed`
- Run test suite: `pytest -v`
- Lint: `ruff check .`
- Launch ARTEX + MCP HTTP stack: `docker compose up -d --build`

## Connected MCP Tools
- `cve-intel-mcp`: Medium+ CVE (CVSS >= 4.0), CISA KEV, EPSS, and writeup search
- `patch-diff-mcp`: Allowlisted GitHub/GitLab CVE patch diff extraction & hunk analysis
- `scope-guard-mcp`: Authorized scope allow/deny enforcement and SHA-256 evidence receipts
