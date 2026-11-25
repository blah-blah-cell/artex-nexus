---
name: spa-js-endpoint-hunting
description: Extract hidden API endpoints, GraphQL operations, Next.js build manifests, custom auth headers, library versions, and secret candidates from downloaded SPA JavaScript bundles offline using attack-surface-mcp and cve-intel-mcp.
---

# SPA & JavaScript Bundle Endpoint Hunting

Use this skill whenever an authorized target serves a React, Next.js, Angular, Vue, or webpack Single-Page Application (SPA).

## Why This Skill Exists
Ad-hoc `grep` / Python loops over minified chunks burn dozens of turns and miss structured signals. Use `attack-surface-mcp` (`extract_js_endpoints`) to parse an entire directory of downloaded chunks in milliseconds.

## Workflow
1. **Verify Scope First:** Call `mcp__scope-guard-mcp__check_target_in_scope` on the target host before downloading bundles.
2. **Collect Chunks Cleanly (Respecting Rate Limits):**
   - Route fetches through ARTEX's capture proxy (`http://127.0.0.1:8788`) so required program headers are injected automatically and HTTP traffic is archived.
   - Save HTML + `_next/static/chunks/*.js` (or `katana` JS URLs) into a local task working directory (e.g., `./chunks/`).
3. **Run Offline Extraction (`attack-surface-mcp`):**
   - Call `mcp__attack-surface-mcp__extract_js_endpoints(target_path="./chunks")`.
   - Also run `mcp__attack-surface-mcp__scan_source_sinks(target_path="./chunks")` for DOM XSS (`dangerouslySetInnerHTML`, `document.write`, `innerHTML`) and secret patterns.
4. **Correlate Library Versions (`cve-intel-mcp`):**
   - Feed every extracted `package_versions` entry (e.g., `next@15.1.0`, `lodash@4.17.20`) into `mcp__cve-intel-mcp__check_package_version` or `match_product_cves`.
5. **Verify High-Signal Endpoints Through Proxy:**
   - Prioritize unauthenticated `/api/*`, `/internal/*`, `/admin/*`, BOLA/IDOR `{id}` paths, and GraphQL mutations.
   - Send verification requests through `-x http://127.0.0.1:8788 -k` so `get_finding_traffic` binds concrete HTTP proof to any confirmed finding.
   - Record confirmed findings with `mcp__scope-guard-mcp__record_evidence_receipt`.
