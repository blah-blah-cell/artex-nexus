---
name: defensive-remediation
description: Translate verified findings into minimal secure patches, regression tests, and detection engineering rules.
---

# Defensive Remediation Skill

For every confirmed finding:
1. Identify the **root cause** (not just a symptom filter).
2. Propose a minimal, idiomatic code fix that enforces the security invariant at the trust boundary.
3. Supply a deterministic **regression test** that fails before the fix and passes after the fix.
4. Add a detection/monitoring signal (log field, WAF/IDS signature, or alert query) for defense in depth.
5. Export the final report cleanly via `scope-guard-mcp:export_report(report_format="markdown"|"sarif")`.
