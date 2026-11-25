---
name: defensive-remediation
description: Turn verified findings into minimal patches, regression tests, and detection signals, then export reports through scope-guard-mcp.
---

# Defensive Remediation

For each confirmed issue:
- Fix the root cause at the trust boundary instead of patching one payload string.
- Write a regression test that fails on the unpatched code and passes with the fix.
- Note one practical detection signal (log field, alert query, or proxy rule) so operators can spot attempts in production.
- Export the verified ledger with `scope-guard-mcp:export_report(report_format="markdown"|"sarif")`.
