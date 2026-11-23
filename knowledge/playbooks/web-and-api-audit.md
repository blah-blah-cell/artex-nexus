# Web, API & Authorization Audit Playbook

Combine this checklist with `cve-intel-mcp` (historical framework CVEs), `patch-diff-mcp` (incomplete upstream fixes), and `scope-guard-mcp` (strict scope enforcement).

## 1. Object & Function Level Authorization (BOLA / BFLA — CWE-639 / CWE-862)
- Map every REST, GraphQL, gRPC, and WebSocket route along with its required role/tenant boundary.
- Verify tenant/owner enforcement on **every** HTTP verb (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`) and batch/export endpoints.
- Check path-normalization differentials between reverse proxies/gateways and backend routers (`/api/v1/public/../admin`, encoded `%2f`, trailing slashes, matrix parameters).

## 2. Identity, Sessions, OAuth & JWT (CWE-287 / CWE-347)
- Verify JWT signature algorithm pinning (reject `none`, RS256→HS256 confusion, untrusted `jku`/`x5u`/`kid` path/SQL injection).
- Verify OAuth `redirect_uri` exact matching (no prefix/subdomain/open-redirect bypass), strict `state` & PKCE validation, and single-use authorization codes.
- Check password reset / magic link tokens for host-header poisoning, predictable entropy, or missing invalidation after use.

## 3. Server-Side Request Forgery & Parser Differentials (CWE-918)
- Test URL parsers across webhooks, metadata fetchers, PDF/HTML renderers, and file importers.
- Verify protection against DNS rebinding, IPv6-mapped IPv4 (`::ffff:127.0.0.1`), 302 redirect chains to internal hosts, and cloud metadata endpoints (`169.254.169.254`).

## 4. Dependency & N-Day Variant Triage
- Run `nexus-sync scan --path <repo>` or `cve-intel-mcp:scan_dependencies` to flag exact OSV/GHSA vulnerable ranges offline.
- Pull patch commits for high-EPSS/KEV CVEs via `patch-diff-mcp:fetch_cve_patch_diff` and inspect sibling handlers for identical unpatched patterns.
