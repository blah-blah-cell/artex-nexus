# ARTEX-Nexus

[![CI](https://github.com/blah-blah-cell/artex-nexus/actions/workflows/ci.yml/badge.svg)](https://github.com/blah-blah-cell/artex-nexus/actions/workflows/ci.yml)
[![Nightly CVE DB](https://github.com/blah-blah-cell/artex-nexus/actions/workflows/sync-cve-db.yml/badge.svg)](https://github.com/blah-blah-cell/artex-nexus/releases/tag/cve-db-latest)
[![Rust](https://img.shields.io/badge/Rust-engine-orange?logo=rust)](crates/)
[![Go](https://img.shields.io/badge/Go-MCP_services-00ADD8?logo=go)](go/)
[![Trophy Case](https://img.shields.io/badge/CVE_Trophies-Submit_Yours-blueviolet)](TROPHIES.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**High-performance Rust + Go cybersecurity research platform uniting all public Medium+ CVEs, OSV/GHSA advisory writeups & package version ranges, offline SBOM lockfile scanning, [`BaaRai/ARTEX`](https://github.com/BaaRai/ARTEX), dual-transport native MCP servers, and universal agent instructions.**

> **Authorized Use Only:** Built strictly for authorized security research, bug bounty programs within declared scope, white-box auditing, and defensive engineering. See [SECURITY.md](SECURITY.md).

---

## Discovered a Vulnerability or Got a CVE Using ARTEX-Nexus?

If ARTEX-Nexus helped you discover a real vulnerability or earn a CVE assignment in an authorized target or open-source project, **please report it to our [CVE Trophy Case](TROPHIES.md)**!
- Submit once publicly disclosed/patched via the [**CVE / Vulnerability Discovery Issue Form**](https://github.com/blah-blah-cell/artex-nexus/issues/new?template=cve-trophy.yml) or open a PR to [TROPHIES.md](TROPHIES.md).
- Need a CNA-ready disclosure writeup? Use [`knowledge/templates/cve-disclosure-template.md`](knowledge/templates/cve-disclosure-template.md).
- **Important:** Never post undisclosed zero-days or confidential bug bounty details in public issues.

---

## Live Knowledge Base Scale (Nightly Rust v2 Build)

| Metric | Live Coverage (`cve-db-latest`) |
|---|---|
| **Medium+ CVEs (CVSS ≥ 4.0 + Unscored KEV)** | `227,942+` |
| **CISA KEV Entries** | `1,792+` |
| **Writeup, Advisory, Nuclei & Patch Links** | `1,055,517+` |
| **Full Indexed GHSA/OSV Technical Writeups** | `21,871+` (`writeups_fts`) |
| **Exact OSV/GHSA Package Version Ranges** | `43,536+` (`npm`, `PyPI`, `Go`, `Maven`, `crates.io`, etc.) |
| **Measured Local Search Latency (`cve-intel-mcp`)** | `~1.2 ms` (FTS5 + 256 MiB mmap SQLite) |

---

## Architecture (Native Rust + Go)

```mermaid
flowchart TB
    ARTEX["BaaRai/ARTEX (Go + Next.js + Postgres)\nAutonomous Planner & Workers"]
    IDE["AI Coding Agents\n(Antigravity / ZCode / Freebuff / Claude / Cursor)"]

    subgraph Rust["Rust Engine (Cargo Workspace)"]
        SYNC["nexus-sync\nRayon Builder · ETag Fetcher · SARIF SBOM Scan · Offline Web UI"]
        CVE["cve-intel-mcp (:8901)\n9 Tools: Dual-FTS5 CVEs, Writeups, SemVer OSV, Exact CWEs"]
    end

    subgraph Go["Go Hardened Services (CGO_ENABLED=0)"]
        PATCH["patch-diff-mcp (:8902)\nSSRF-Proof No-Redirect Diff Analyzer"]
        SCOPE["scope-guard-mcp (:8903)\nConfined Per-Task Scope + Hash-Chained Ledger"]
        SURFACE["attack-surface-mcp (:8904)\nOpenAPI Auditor · CWE Sinks · JWT/Headers"]
    end

    DB[("data/cve_kb_med_plus.sqlite\nv2 SQLite + Dual FTS5")]
    SKILLS["skills/*/SKILL.md + AGENTS.md + CLAUDE.md"]

    SYNC -. "ETag + SHA-256 + atomic swap" .-> DB
    ARTEX -- "mcphttp (Streamable HTTP /mcp)" --> CVE
    ARTEX -- "mcphttp (Streamable HTTP /mcp)" --> PATCH
    ARTEX -- "mcphttp (Streamable HTTP /mcp)" --> SCOPE
    ARTEX -- "mcphttp (Streamable HTTP /mcp)" --> SURFACE
    ARTEX -- "ARTEX_SKILL_DIR" --> SKILLS
    IDE -- "stdio JSON-RPC 2.0" --> CVE
    IDE -- "stdio JSON-RPC 2.0" --> PATCH
    IDE -- "stdio JSON-RPC 2.0" --> SCOPE
    IDE -- "stdio JSON-RPC 2.0" --> SURFACE
    CVE --> DB
```

---

## Features & Components

1. **Rust Ingestion, Streaming Fetcher, Offline Web UI & SBOM Scanner (`crates/nexus-sync`)**
   - `nexus-sync fetch`: HTTP ETag caching (`304 Not Modified`), streaming download with on-the-fly SHA-256 verification, streaming Zstd decompression, `PRAGMA quick_check`, and atomic swap.
   - `nexus-sync serve --port 8088`: Built-in zero-dependency **Offline CVE/OSV Web Console** (`http://127.0.0.1:8088`) to search all 227k+ CVEs, 21k+ writeups, and test SemVer package ranges in your browser.
   - `nexus-sync scan --path <dir-or-lockfile> --sarif out.sarif --fail-on high`: Offline SemVer/OSV vulnerability scanner & CI gate supporting **10 formats** (`package-lock.json`, `package.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `go.mod`, `Cargo.lock`, `composer.lock`, `pom.xml`) with **SARIF 2.1.0** export.
   - `nexus-sync init-mcp --client <antigravity|claude|cursor|zcode|freebuff|artex>`: Generates ready-to-paste MCP client JSON configs for all 4 servers.
   - `nexus-sync doctor`: Instant DB integrity, schema version, and coverage diagnostics.
   - `nexus-sync build`: Multi-threaded `rayon` ingestion of `CVEProject/cvelistV5`, CISA KEV, FIRST EPSS, `github/advisory-database` (OSV/GHSA), `trickest/cve`, and `nuclei-templates` — zero fabricated CVSS scores (`NULL` + `KEV_UNSCORED`).
2. **Rust Native `cve-intel-mcp` (`crates/cve-intel-mcp`, 9 MCP Tools)**
   - Dual transport: `stdio` + ARTEX Streamable HTTP (`POST /mcp`, protocol `2025-11-25`).
   - Tools: `search_cves`, `search_writeups`, `get_cve_details`, `match_product_cves`, `check_package_version`, `scan_dependencies`, `list_cwe_writeups`, `whats_new`, `get_kb_stats`.
3. **Go Hardened `patch-diff-mcp` (`go/cmd/patch-diff-mcp`)**
   - Direct `api.github.com` diff endpoint (`Accept: application/vnd.github.diff`), **all HTTP redirects refused**, and DNS-resolving `DialContext` blocking loopback, RFC1918, CGNAT, and cloud metadata IPs (`169.254.169.254`).
4. **Go Hardened `scope-guard-mcp` (`go/cmd/scope-guard-mcp`)**
   - Symlink-safe `SCOPE_CONFIG_DIR` confinement, multi-tenant persisted `scope_id` isolation, and a cryptographically hash-chained append-only ledger (`receipts.jsonl`) verified by `verify_ledger_chain` and exportable to Markdown or SARIF 2.1.0.
5. **Go Offline `attack-surface-mcp` (`go/cmd/attack-surface-mcp`, 3 MCP Tools)**
   - `audit_openapi_spec`: Flags unauthenticated writes (`CWE-306`), BOLA/IDOR object IDs (`CWE-639`), SSRF params (`CWE-918`), and mass-assignment fields (`CWE-915`).
   - `scan_source_sinks`: Static CWE sink & hardcoded secret scan mapped directly to `cve-intel-mcp:list_cwe_writeups`.
   - `inspect_jwt_and_headers`: Offline JWT (`alg=none`, `jku`/`x5u`/`kid`, missing `exp`) and CORS/CSP/`Set-Cookie` auditing.
6. **Universal Skills, Playbooks & `BaaRai/ARTEX` Stack**
   - Modular skills (`skills/*/SKILL.md`), CWE & Web/API playbooks (`knowledge/playbooks/`), CNA disclosure template (`knowledge/templates/`), and unified `docker-compose.yml` mounting `vendor/ARTEX`.

---

## Quick Start

### 1. Clone with the `BaaRai/ARTEX` submodule
```bash
git clone --recurse-submodules https://github.com/blah-blah-cell/artex-nexus.git
cd artex-nexus
```

### 2. Build native binaries, fetch the CVE/OSV DB & launch the Offline Web Console
```bash
make build
./target/release/nexus-sync fetch
./target/release/nexus-sync doctor

# Launch local offline Web Console at http://127.0.0.1:8088
./target/release/nexus-sync serve

# Offline dependency scan (10 lockfile formats) + SARIF export + CI gate
./target/release/nexus-sync scan --path . --sarif sbom.sarif --fail-on high
```

### 3. Launch `BaaRai/ARTEX` + Native MCP HTTP Stack
```bash
cp .env.example .env   # Set POSTGRES_PASSWORD
docker compose up -d --build
```
- ARTEX Web Console: `http://localhost:8787`
- Native Streamable HTTP MCP Endpoints (`mcphttp`):
  - `http://cve-intel-mcp:8901/mcp`
  - `http://patch-diff-mcp:8902/mcp`
  - `http://scope-guard-mcp:8903/mcp`
  - `http://attack-surface-mcp:8904/mcp`

### 4. Connect to IDE Agents (`stdio` MCP)
Generate config automatically for your client (or copy [`config/mcp.client.example.json`](config/mcp.client.example.json)):
```bash
./target/release/nexus-sync init-mcp --client antigravity   # or claude | cursor | zcode | freebuff | artex
```

---

## Governance, Security & Licensing

- **Security & Coordinated Disclosure:** [SECURITY.md](SECURITY.md)
- **CVE Trophy Hall of Fame:** [TROPHIES.md](TROPHIES.md)
- **Contributing & Code of Conduct:** [CONTRIBUTING.md](CONTRIBUTING.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- **Licensing:**
  - ARTEX-Nexus Rust/Go code, MCP servers, templates, and skills: **MIT** ([LICENSE](LICENSE))
  - `vendor/ARTEX` submodule (`BaaRai/ARTEX`): **AGPL-3.0** ([THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md))
  - Upstream public vulnerability feeds & advisories retain their respective upstream licenses ([THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md))
