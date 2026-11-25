---
name: attack-surface-auditing
description: Run offline OpenAPI, JS bundle, source sink, and JWT/header checks with attack-surface-mcp, then correlate hits against cve-intel-mcp and patch-diff-mcp.
---

# Attack-Surface Auditing

Check scope first with `scope-guard-mcp:load_scope_policy` and `scope-guard-mcp:check_target_in_scope`.

Pick the `attack-surface-mcp` tool that fits what you have on disk (paths stay inside the configured workspace root):

- OpenAPI or Swagger specs: `attack-surface-mcp:audit_openapi_spec(spec_path)` flags unauthenticated writes (`CWE-306`), object ID path params (`CWE-639`), SSRF-like params (`CWE-918`), and mass-assignment fields (`CWE-915`, including `$ref` targets).
- Source trees: `attack-surface-mcp:scan_source_sinks(target_path)` scans for command exec, SQL string concat, unsafe deserialization, DOM HTML sinks, path joins, and hardcoded secrets.
- Downloaded SPA bundles: `attack-surface-mcp:extract_js_endpoints(target_path)` pulls API routes, GraphQL ops, custom headers, Next.js buildIds, library versions, and redacted secret hits from minified JS/HTML.
- Tokens and response headers: `attack-surface-mcp:inspect_jwt_and_headers(jwt, headers)` checks `alg=none`, `jku`/`x5u`/`kid`, missing `exp`, CORS, CSP, and each `Set-Cookie` header individually.

Take any CWE or package version you find into `cve-intel-mcp` (`list_cwe_writeups`, `check_package_version`, `scan_dependencies`) and pull upstream fix commits through `patch-diff-mcp:fetch_cve_patch_diff`. Verify reachability in an authorized environment before logging a receipt with `scope-guard-mcp:record_evidence_receipt`.
