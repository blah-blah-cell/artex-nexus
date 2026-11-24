---
name: evidence-based-triage
description: Ruthless falsification and evidence verification protocol to eliminate false positives before reporting any vulnerability.
---

# Evidence-Based Triage Skill

Every candidate finding must survive all 5 falsification gates:
1. **Input Control:** Is the input genuinely attacker-controlled at the stated privilege level?
2. **Reachability:** Is the code path live, routed, and enabled in default/target configuration?
3. **Control Verification:** Does upstream middleware, WAF, CSRF protection, ORM parameterization, or sandbox boundary neutralize it?
4. **Reproducible Verification:** Was a minimal, non-destructive verification executed against an authorized target or local test harness?
5. **Immutable Receipt:** Record the exact command and observed output via `scope-guard-mcp:record_evidence_receipt`. If any gate fails, downgrade to `HYPOTHESIS` or `REFUTED`.
