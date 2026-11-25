---
name: attack-surface-auditing
description: Audit OpenAPI specs, multi-language source sinks, JWT tokens, and HTTP security headers offline using attack-surface-mcp, then pivot to cve-intel-mcp, patch-diff-mcp, and scope-guard-mcp for verification.
---

# Attack-Surface Auditing Skill

1. **Scope Gate First:** Load and validate your authorized target via `scope-guard-mcp:load_scope_policy` and `scope-guard-mcp:check_target_in_scope`.
2. **Contract & Code Surface Mapping:**
   - For API repositories or specs, run `attack-surface-mcp:audit_openapi_spec(spec_path)` to flag unauthenticated state-changing endpoints (`CWE-306`), BOLA/IDOR object IDs (`CWE-639`), SSRF parameters (`CWE-918`), and mass-assignment schema properties (`CWE-915`).
   - For source trees, run `attack-surface-mcp:scan_source_sinks(target_path)` to locate `CWE-78`, `CWE-89`, `CWE-502`, `CWE-79`, `CWE-22`, and `CWE-798` sinks.
   - For auth tokens or captured responses, run `attack-surface-mcp:inspect_jwt_and_headers(jwt, headers)`.
3. **CVE & Patch Pivot:**
   - Feed flagged CWEs into `cve-intel-mcp:list_cwe_writeups(cwe_id)` and inspect upstream fix commits via `patch-diff-mcp:fetch_cve_patch_diff`.
   - Run `cve-intel-mcp:scan_dependencies` (or `nexus-sync scan --sarif out.sarif`) to surface vulnerable third-party dependencies.
4. **Falsify & Record:** Verify reachability and control boundaries against an authorized lab/staging environment before recording a hash-chained receipt via `scope-guard-mcp:record_evidence_receipt`.
