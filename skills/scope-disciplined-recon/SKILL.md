---
name: scope-disciplined-recon
description: Keep asset discovery and fingerprinting inside authorized scope policies enforced by scope-guard-mcp.
---

# Scope-Disciplined Recon

Load the scope policy first (`scope-guard-mcp:load_scope_policy("scope.yaml")`). Check every newly discovered subdomain, IP, or API host with `scope-guard-mcp:check_target_in_scope(target)` before sending active requests.

Fingerprint software versions on allowed assets only, then look up known exposures with `cve-intel-mcp:match_product_cves` (KEV and high-EPSS first). Keep request rates within program limits and stop if a host resolves outside allowed domains or CIDRs.
