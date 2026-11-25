---
name: evidence-based-triage
description: Verify input control, reachability, active controls, and reproducible output before calling a candidate finding confirmed.
---

# Evidence-Based Triage

Try to disprove every candidate finding before reporting it. Check five things:

1. Input control: can an attacker at the stated privilege level actually set the value?
2. Reachability: is the route or code path live in the target deployment?
3. Active defenses: does middleware, ORM parameterization, CSRF protection, a WAF, or a sandbox stop it?
4. Reproduction: did you run a minimal, non-destructive check against an authorized target or local harness?
5. Receipt: log the exact command and observed output via `scope-guard-mcp:record_evidence_receipt`.

If any check fails or cannot be run, keep the item as a hypothesis or drop it.
