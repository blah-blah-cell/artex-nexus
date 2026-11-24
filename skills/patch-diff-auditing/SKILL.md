---
name: patch-diff-auditing
description: Analyze public CVE security commits and PRs using patch-diff-mcp to identify root causes, incomplete fixes, and regression surfaces.
---

# Patch-Diff Auditing Skill

1. Resolve patch URLs via `cve-intel-mcp:get_cve_details(cve_id)` (filtering `writeups` where `has_patch_diff == true`).
2. Fetch the unified diff via `patch-diff-mcp:fetch_cve_patch_diff(url)` and inspect `analysis.security_signals`.
3. Classify the fix mechanism:
   - Input validation / canonicalization added?
   - Authorization / tenant ownership check added?
   - Sink replaced with a parameterized or memory-safe API?
4. Check for incomplete fixes:
   - Are alternative encodings, alternate HTTP methods, batch endpoints, or GraphQL resolvers still missing the new guard?
5. Document reproducible regression test cases for any verified gap.
