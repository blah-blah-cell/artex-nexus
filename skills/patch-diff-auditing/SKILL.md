---
name: patch-diff-auditing
description: Inspect public CVE fix commits and PRs with patch-diff-mcp to understand the root cause and check for incomplete fixes.
---

# Patch-Diff Auditing

Pull reference URLs with `cve-intel-mcp:get_cve_details(cve_id)` (look for entries where `has_patch_diff` is true), then fetch the unified diff using `patch-diff-mcp:fetch_cve_patch_diff(url)` and read `analysis.security_signals`.

Figure out what the patch changed: did it add input canonicalization, enforce a tenant or role check, or swap an unsafe sink for a parameterized API? Then check whether alternate encodings, other HTTP methods, batch routes, or GraphQL resolvers still bypass the new guard. Write a minimal regression test for any gap you confirm.
