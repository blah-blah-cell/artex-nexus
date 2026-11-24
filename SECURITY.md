# Security Policy & Coordinated Disclosure

## Supported Versions

| Version | Supported | Notes |
|---|---|---|
| `main` / `v0.3.x` | Yes | Active Rust + Go release branch |
| `v0.2.x` | Yes | Security fixes backported where applicable |
| `< v0.2.0` | No | Legacy Python prototype (retired) |

---

## 1. Authorized Use & Dual-Use Policy

ARTEX-Nexus and its integrated `BaaRai/ARTEX` submodule are developed strictly for:
- Authorized penetration testing and bug bounty programs operating strictly within declared program scope
- Owned infrastructure, isolated lab environments, and defensive engineering
- White-box open-source security auditing, patch-diff analysis, and coordinated vulnerability disclosure

**Prohibited use:** Never run active security testing against third-party systems without explicit written authorization. Always configure and enforce `scope-guard-mcp` before any active testing.

---

## 2. Reporting a Vulnerability in ARTEX-Nexus Itself

If you discover a security flaw in any ARTEX-Nexus binary, MCP server, or workflow (for example: an SSRF bypass in `patch-diff-mcp`, a path-confinement escape in `scope-guard-mcp`, or a SQL/FTS injection bug in `cve-intel-mcp`):

1. **Do NOT open a public GitHub Issue.**
2. Report it privately using [**GitHub Security Advisories**](https://github.com/blah-blah-cell/artex-nexus/security/advisories/new).
3. Include:
   - Affected component (`nexus-sync`, `cve-intel-mcp`, `patch-diff-mcp`, `scope-guard-mcp`, or workflow)
   - Minimal reproducible test case or failing unit test
   - Expected vs. observed security boundary behavior
4. **Response Targets:**
   - Initial acknowledgment: within **48 hours**
   - Triage & fix plan: within **7 days**
   - Coordinated disclosure & credit upon patch release (and CVE request if warranted)

---

## 3. Reporting CVEs Discovered *Using* ARTEX-Nexus

If you used ARTEX-Nexus to discover a vulnerability in **another** project or product:
- First follow the **target vendor's** coordinated disclosure policy or bug bounty program rules.
- **Never post undisclosed zero-days or private findings** in ARTEX-Nexus issues, discussions, or PRs.
- Once publicly disclosed or assigned a CVE, feel free to share it in [TROPHIES.md](TROPHIES.md) via the [**CVE Trophy Issue Form**](https://github.com/blah-blah-cell/artex-nexus/issues/new?template=cve-trophy.yml)!

---

## 4. Built-In MCP Security Boundaries

- **`cve-intel-mcp` (Rust):** Opens the SQLite database strictly with `SQLITE_OPEN_READ_ONLY` + `PRAGMA query_only = ON`, sanitizes all FTS5 tokens, and executes zero shell or network calls.
- **`patch-diff-mcp` (Go):** Enforces HTTPS-only allowlisted hosts (`github.com`, `api.github.com`, `gitlab.com`), refuses all HTTP redirects (`http.ErrUseLastResponse`), resolves DNS at `DialContext` time to block loopback/RFC1918/CGNAT/link-local/metadata IPs (`169.254.169.254`), and caps patch bodies at 256 KiB.
- **`scope-guard-mcp` (Go):** Strictly confines `load_scope_policy` inside `SCOPE_CONFIG_DIR` via symlink-resolved path checks, isolates per-task scopes by `scope_id`, and records findings in a SHA-256 hash-chained append-only JSONL ledger verified by `verify_ledger_chain`.
