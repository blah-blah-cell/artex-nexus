---
name: spa-js-endpoint-hunting
description: Pull API routes, GraphQL operations, custom headers, Next.js buildIds, library versions, and secret hits from downloaded SPA JS bundles using attack-surface-mcp and cve-intel-mcp.
---

# SPA & JavaScript Bundle Endpoint Hunting

Use this when a target serves a React, Next.js, Angular, Vue, or webpack frontend. Writing throwaway grep scripts over minified chunks wastes turns and misses structured clues; `attack-surface-mcp` parses a directory of chunks offline in one call.

1. Confirm the host is in scope (`mcp__scope-guard-mcp__check_target_in_scope`).
2. Fetch HTML and JS chunks (`_next/static/chunks/*.js`, etc.) through ARTEX's capture proxy (`http://127.0.0.1:8788`) while respecting rate limits, and save them under your workspace directory (for example `./chunks/`).
3. Run `mcp__attack-surface-mcp__extract_js_endpoints(target_path="./chunks")` and `mcp__attack-surface-mcp__scan_source_sinks(target_path="./chunks")`.
4. Check extracted `package_versions` (like `next@15.1.0` or `lodash@4.17.20`) with `mcp__cve-intel-mcp__check_package_version` or `match_product_cves`.
5. Test interesting endpoints (`/api/*`, `/internal/*`, `/admin/*`, `{id}` paths, GraphQL mutations) through `-x http://127.0.0.1:8788 -k` so captured traffic can be bound to findings, then record confirmed issues via `mcp__scope-guard-mcp__record_evidence_receipt`.
