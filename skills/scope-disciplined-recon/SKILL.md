---
name: scope-disciplined-recon
description: Asset discovery and attack-surface mapping strictly bound to authorized scope policies enforced by scope-guard-mcp.
---

# Scope-Disciplined Recon Skill

1. Load the engagement policy first: `scope-guard-mcp:load_scope_policy("config/scope.yaml")`.
2. Before probing any discovered subdomain, IP, or API endpoint, verify `scope-guard-mcp:check_target_in_scope(target)`.
3. Fingerprint software versions and technology stacks on in-scope assets only.
4. Feed discovered product/version pairs into `cve-intel-mcp:match_product_cves` to prioritize high-EPSS and CISA KEV exposures.
5. Respect rate limits and stop immediately if an asset resolves outside authorized CIDR/domain boundaries.
