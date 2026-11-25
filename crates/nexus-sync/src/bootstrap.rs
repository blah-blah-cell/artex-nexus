use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Duration;

pub const CONTEXT_MARKER: &str = "<!-- ARTEX-NEXUS-CONTEXT-V2 -->";
const LEGACY_MARKER: &str = "<!-- ARTEX-NEXUS-CONTEXT-V1 -->";

#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    pub artex_url: String,
    pub password: String,
    pub setup_token: Option<String>,
    pub mcp_host: String,
    pub docker_network: bool,
    pub knowledge_dir: String,
    pub data_dir: String,
    pub config_dir: String,
    pub proxy_url: String,
    pub planner_profile_id: Option<i64>,
    pub worker_profile_id: Option<i64>,
    pub reporter_max_turns: i64,
    pub reporter_run_seconds: i64,
    pub retester_max_turns: i64,
    pub retester_run_seconds: i64,
    pub rewrite_host: Option<String>,
    pub rewrite_header: Option<String>,
    pub dry_run: bool,
}

fn mcp_endpoints(cfg: &BootstrapConfig) -> Vec<(&'static str, String)> {
    if cfg.docker_network {
        vec![
            ("cve-intel-mcp", "http://cve-intel-mcp:8901/mcp".to_string()),
            ("patch-diff-mcp", "http://patch-diff-mcp:8902/mcp".to_string()),
            ("scope-guard-mcp", "http://scope-guard-mcp:8903/mcp".to_string()),
            ("attack-surface-mcp", "http://attack-surface-mcp:8904/mcp".to_string()),
        ]
    } else {
        let h = cfg.mcp_host.trim();
        vec![
            ("cve-intel-mcp", format!("http://{h}:8901/mcp")),
            ("patch-diff-mcp", format!("http://{h}:8902/mcp")),
            ("scope-guard-mcp", format!("http://{h}:8903/mcp")),
            ("attack-surface-mcp", format!("http://{h}:8904/mcp")),
        ]
    }
}

pub fn build_role_context(role: &str, cfg: &BootstrapConfig) -> Option<String> {
    let common = format!(
        r#"{CONTEXT_MARKER}
## ARTEX-Nexus Platform Context, MCP Servers & Knowledge Base
You operate inside **ARTEX-Nexus** with four compiled Streamable HTTP MCP servers attached as deferred tools. ARTEX withholds MCP schemas until queried, so **explicitly call `SearchExtraTools` and `ExecuteExtraTool`** instead of guessing in raw shell:

1. **`cve-intel-mcp`** (offline SQLite dual-FTS5 KB: 227k+ Medium+ CVEs, CISA KEVs, 21k+ GHSA/OSV full writeups, 43k+ OSV SemVer ranges):
   - Tools: `search_cves`, `search_writeups`, `get_cve_details`, `match_product_cves`, `check_package_version`, `scan_dependencies`, `list_cwe_writeups`, `whats_new`, `get_kb_stats`.
   - Call whenever you fingerprint any product, framework, JS/Go/Python/Java package version, or CWE class.
2. **`patch-diff-mcp`** (SSRF-hardened commit/PR diff analyzer):
   - Tools: `fetch_cve_patch_diff`, `extract_diff_hunks`.
   - Use to inspect upstream security fix commits and hunt sibling variants.
3. **`scope-guard-mcp`** (deterministic scope allowlist + SHA-256 hash-chained evidence ledger):
   - Tools: `load_scope_policy`, `check_target_in_scope`, `list_in_scope_assets`, `record_evidence_receipt`, `verify_ledger_chain`, `export_report`.
   - Scope policies directory: `{config_dir}`. Always verify unfamiliar hosts before active probing and log confirmed findings.
4. **`attack-surface-mcp`** (offline API, SPA JS bundle, source sink, JWT & header analyzers):
   - Tools: `audit_openapi_spec`, `scan_source_sinks`, `inspect_jwt_and_headers`, `extract_js_endpoints`.
   - Call `extract_js_endpoints` on downloaded JS/HTML/Next.js chunks instead of writing repetitive grep scripts in Bash.

### Local Playbooks, Templates & Offline DB
- Playbooks: `{knowledge_dir}/playbooks/cwe-top-patterns.md`, `{knowledge_dir}/playbooks/web-and-api-audit.md`
- Disclosure template: `{knowledge_dir}/templates/cve-disclosure-template.md`
- Offline CVE DB: `{data_dir}/cve_kb_med_plus.sqlite` (CLI: `nexus-sync`)"#,
        config_dir = cfg.config_dir,
        knowledge_dir = cfg.knowledge_dir,
        data_dir = cfg.data_dir,
    );

    let addon = match role {
        "planner" => format!(
            r#"
### ARTEX-Nexus Planning & Parallel Fan-Out Rules
- **Parallel saturation (CRITICAL):** Whenever multiple independent untested subdomains, endpoints, JS bundles, OpenAPI specs, or vulnerability hypotheses exist and concurrent workers are available, **emit 2–3 non-overlapping intents in the same planning round** so all parallel workers run simultaneously instead of idling behind a single intent.
- Verify unfamiliar hosts via `scope-guard-mcp` (`check_target_in_scope`) before issuing active probing intents.
- Whenever a worker discovers a JS bundle, OpenAPI spec, JWT, or software version, emit focused intents using `attack-surface-mcp` (`extract_js_endpoints`, `audit_openapi_spec`, `inspect_jwt_and_headers`) and `cve-intel-mcp` (`check_package_version`, `match_product_cves`).
- Remind workers to send HTTP verification requests through ARTEX's capture proxy (`{proxy_url}`) so every finding has bound proof traffic."#,
            proxy_url = cfg.proxy_url,
        ),
        "worker" | "pentest" | "retester" => format!(
            r#"
### ARTEX-Nexus Execution, Toolchain & Proof-Traffic Rules
- **SPA / JS Efficiency:** When inspecting web apps or downloaded JS chunks, save chunks locally and call `mcp__attack-surface-mcp__extract_js_endpoints` + `mcp__attack-surface-mcp__scan_source_sinks` first, then check discovered library versions with `mcp__cve-intel-mcp__check_package_version` (`ecosystem`, `package_name`, `version`).
- **CLI Toolchain:** Prefer **`rustscan`** over `nmap` when port scanning is in-scope and allowed by program rules. **Never** run unthrottled scans against rate-limited VDPs (`ARTEX_NOISE_PROFILE=quiet`). Available tools: `rustscan`, `katana`, `dalfox`, `nuclei`, `httpx`, `subfinder`, `ffuf`, `sqlmap`, `nexus-sync`.
- **Mandatory Proof-Traffic Capture & Binding:** Route HTTP verification probes in `Bash` (`curl` / Python) through ARTEX's local capture proxy (`-x {proxy_url} -k` or `HTTPS_PROXY={proxy_url}`) so required VDP headers are auto-injected AND raw HTTP exchanges are captured. Before calling `report_finding`, run `traffic_search` to get the exact real `traffic_id`s for your proof request(s) and pass them in `traffic_refs` (with `role: "proof"`) AND cite them in `evidence` so findings verify cleanly (`evidence_version >= 1`)."#,
            proxy_url = cfg.proxy_url,
        ),
        "mainagent" | "auto" => format!(
            r#"
### ARTEX-Nexus Manager & Operations Directives
- You are the operator-facing Manager/Ops interface for **ARTEX-Nexus**. You have full visibility into all 4 MCP servers (`cve-intel-mcp`, `patch-diff-mcp`, `scope-guard-mcp`, `attack-surface-mcp`) and all 7 ARTEX-Nexus skills.
- When asked about CVEs, package versions, scope allowlists, or evidence receipts, query the MCP tools directly via `SearchExtraTools` + `ExecuteExtraTool` rather than guessing.
- When steering active tasks, remind the planner to fan out parallel intents across all workers and verify proof traffic is captured through `{proxy_url}`."#,
            proxy_url = cfg.proxy_url,
        ),
        "reporter" => format!(
            r#"
### ARTEX-Nexus Reporting, Traffic Binding & Receipt Rules
- Structure reports concisely following `{knowledge_dir}/templates/cve-disclosure-template.md` (Executive Summary, Affected Asset, Deterministic Reproduction with exact captured HTTP traffic, Impact, CWE/CVSS, Defensive Remediation).
- **Bind Proof Traffic First:** Call `get_finding_traffic` for the standalone `finding_id`. If no proof traffic is bound yet, call `traffic_search` + `traffic_get` to locate the real captured proof request/response, call `bind_finding_traffic(finding_id, traffic_refs)` (with `role: "proof"`), then re-call `get_finding_traffic` to read the updated `evidence_version` and verbatim response body lines.
- Pass that exact `evidence_version`, honest `poe_level` (0–4), and verbatim `evidence_quotes` copied from `get_finding_traffic` to `update_finding_report` (whose `finding_id` takes `finding_node_id`).
- Enrich CWE/CVE references via `cve-intel-mcp` when applicable, optionally record a hash-chained receipt via `scope-guard-mcp` (`record_evidence_receipt`), and finish in <= 12 tool calls."#,
            knowledge_dir = cfg.knowledge_dir,
        ),
        _ => return None,
    };

    Some(format!("{common}\n{addon}\n"))
}

pub fn merge_prompt(existing: &str, nexus_block: &str) -> String {
    let base = if let Some(idx) = existing.find(CONTEXT_MARKER) {
        &existing[..idx]
    } else if let Some(idx) = existing.find(LEGACY_MARKER) {
        &existing[..idx]
    } else {
        existing
    };
    format!("{}\n\n{}\n", base.trim_end(), nexus_block.trim())
}

fn api_call(
    client: &Client,
    base: &str,
    method: reqwest::Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Result<(u16, Value)> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let mut req = client.request(method, &url).header("Origin", base.trim_end_matches('/'));
    if let Some(tok) = token {
        req = req.header("Authorization", format!("Bearer {tok}"));
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().with_context(|| format!("requesting {url}"))?;
    let status = resp.status().as_u16();
    let text = resp.text().unwrap_or_default();
    let parsed = if text.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}))
    };
    Ok((status, parsed))
}

pub fn cmd_bootstrap(cfg: &BootstrapConfig) -> Result<Value> {
    let all_skills = vec![
        "attack-surface-auditing",
        "cve-variant-analysis",
        "defensive-remediation",
        "evidence-based-triage",
        "patch-diff-auditing",
        "scope-disciplined-recon",
        "spa-js-endpoint-hunting",
    ];
    let reporter_skills = vec!["evidence-based-triage", "defensive-remediation"];
    let endpoints = mcp_endpoints(cfg);

    if cfg.dry_run {
        return Ok(json!({
            "dry_run": true,
            "artex_url": cfg.artex_url,
            "mcps": endpoints,
            "skills": all_skills,
            "roles_updated": ["goals", "planner", "mainagent", "worker", "auto", "pentest", "reporter", "retester"],
            "planner_profile_id": cfg.planner_profile_id,
            "worker_profile_id": cfg.worker_profile_id,
        }));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let base = cfg.artex_url.trim_end_matches('/');

    // 1. Optional first-boot init if setup_token is provided
    if let Some(stoken) = &cfg.setup_token {
        let _ = api_call(
            &client,
            base,
            reqwest::Method::POST,
            "/api/auth/init",
            None,
            Some(json!({"password": cfg.password, "setup_token": stoken})),
        )?;
    }

    // 2. Login as ARTEX
    let (login_st, login_val) = api_call(
        &client,
        base,
        reqwest::Method::POST,
        "/api/auth/login",
        None,
        Some(json!({"username": "ARTEX", "password": cfg.password})),
    )?;
    if login_st != 200 {
        bail!("ARTEX login failed (HTTP {login_st}): {login_val}");
    }
    let token = login_val["token"]
        .as_str()
        .context("ARTEX login response missing JWT token")?
        .to_string();

    // 2b. Ensure HTTP traffic capture + automatic finding traffic binding are enabled
    let (set_st, set_val) = api_call(
        &client,
        base,
        reqwest::Method::PUT,
        "/api/settings",
        Some(&token),
        Some(json!({
            "traffic_capture": true,
            "agent_traffic_binding": true
        })),
    )?;
    if set_st != 200 {
        bail!("ARTEX settings update failed (HTTP {set_st}): {set_val}");
    }

    // 3. Register & refresh all 4 artex-nexus HTTP MCPs
    let (_, existing_mcps_val) = api_call(&client, base, reqwest::Method::GET, "/api/mcp", Some(&token), None)?;
    let existing_list = existing_mcps_val
        .as_array()
        .or_else(|| existing_mcps_val.get("servers").and_then(|v| v.as_array()))
        .cloned()
        .unwrap_or_default();
    let mut mcp_ids: HashMap<String, i64> = HashMap::new();
    for m in &existing_list {
        if let (Some(name), Some(id)) = (m.get("name").and_then(|v| v.as_str()), m.get("id").and_then(|v| v.as_i64())) {
            mcp_ids.insert(name.to_string(), id);
        }
    }

    let mut mcp_summary = serde_json::Map::new();
    for (name, url) in &endpoints {
        let id = if let Some(&existing_id) = mcp_ids.get(*name) {
            existing_id
        } else {
            let (st, created) = api_call(
                &client,
                base,
                reqwest::Method::POST,
                "/api/mcp",
                Some(&token),
                Some(json!({
                    "name": name,
                    "transport": "http",
                    "url": url,
                    "args": [],
                    "env": {},
                    "enabled": true,
                    "timeout_seconds": 60
                })),
            )?;
            if st != 200 && st != 201 {
                bail!("failed to register MCP {name} (HTTP {st}): {created}");
            }
            let new_id = created["id"].as_i64().context("MCP create missing id")?;
            mcp_ids.insert((*name).to_string(), new_id);
            new_id
        };

        let (rst, rval) = api_call(
            &client,
            base,
            reqwest::Method::POST,
            &format!("/api/mcp/{id}/refresh"),
            Some(&token),
            Some(json!({})),
        )?;
        let tool_cnt = rval
            .get("tools")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        mcp_summary.insert((*name).to_string(), json!({"id": id, "refresh_status": rst, "tools": tool_cnt}));
    }

    let all_nexus_ids: Vec<i64> = ["cve-intel-mcp", "patch-diff-mcp", "scope-guard-mcp", "attack-surface-mcp"]
        .iter()
        .filter_map(|k| mcp_ids.get(*k).copied())
        .collect();
    let reporter_ids: Vec<i64> = ["cve-intel-mcp", "scope-guard-mcp"]
        .iter()
        .filter_map(|k| mcp_ids.get(*k).copied())
        .collect();

    // 4. Clean MCP + skill visibility across all 8 roles
    let vis_roles: [(&str, &[i64], &[&str]); 8] = [
        ("goals", &[], &[]),
        ("planner", &all_nexus_ids, &all_skills),
        ("mainagent", &all_nexus_ids, &all_skills),
        ("worker", &all_nexus_ids, &all_skills),
        ("auto", &all_nexus_ids, &all_skills),
        ("pentest", &all_nexus_ids, &all_skills),
        ("reporter", &reporter_ids, &reporter_skills),
        ("retester", &all_nexus_ids, &all_skills),
    ];
    for (role, mids, sks) in vis_roles {
        let (st, res) = api_call(
            &client,
            base,
            reqwest::Method::PUT,
            &format!("/api/agents/{role}/visibility"),
            Some(&token),
            Some(json!({"mcp": mids, "skill": sks})),
        )?;
        if st != 200 {
            bail!("visibility update failed for {role} (HTTP {st}): {res}");
        }
    }

    // 5. Configure safety turn/time caps + optional model bindings
    if let Some(wid) = cfg.worker_profile_id {
        let _ = api_call(
            &client,
            base,
            reqwest::Method::POST,
            "/api/llm/profiles/active",
            Some(&token),
            Some(json!({"id": wid})),
        )?;
    }

    for role in ["goals", "planner", "mainagent", "worker", "auto", "pentest", "reporter", "retester"] {
        let mut patch = serde_json::Map::new();
        match role {
            "planner" | "mainagent" => {
                if let Some(pid) = cfg.planner_profile_id {
                    patch.insert("llm_profile_id".to_string(), json!(pid));
                }
            }
            _ => {
                if let Some(wid) = cfg.worker_profile_id {
                    patch.insert("llm_profile_id".to_string(), json!(wid));
                }
            }
        }
        if role == "reporter" {
            patch.insert("max_turns".to_string(), json!(cfg.reporter_max_turns));
            patch.insert("run_seconds".to_string(), json!(cfg.reporter_run_seconds));
        } else if role == "retester" {
            patch.insert("max_turns".to_string(), json!(cfg.retester_max_turns));
            patch.insert("run_seconds".to_string(), json!(cfg.retester_run_seconds));
        }
        if !patch.is_empty() {
            let (st, res) = api_call(
                &client,
                base,
                reqwest::Method::PUT,
                &format!("/api/agents/{role}/config"),
                Some(&token),
                Some(Value::Object(patch)),
            )?;
            if st != 200 {
                bail!("config update failed for {role} (HTTP {st}): {res}");
            }
        }
    }

    // 6. Inject ARTEX-Nexus context into all 7 operational prompts (preserving upstream templates)
    let mut prompt_versions = serde_json::Map::new();
    for role in ["planner", "worker", "mainagent", "auto", "pentest", "reporter", "retester"] {
        if let Some(block) = build_role_context(role, cfg) {
            let (gst, agent_val) = api_call(
                &client,
                base,
                reqwest::Method::GET,
                &format!("/api/agents/{role}"),
                Some(&token),
                None,
            )?;
            if gst != 200 {
                continue;
            }
            let cur = agent_val.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
            let merged = merge_prompt(cur, &block);
            let (pst, pval) = api_call(
                &client,
                base,
                reqwest::Method::PUT,
                &format!("/api/agents/{role}/prompt"),
                Some(&token),
                Some(json!({
                    "template": merged,
                    "note": "ARTEX-Nexus v0.5.0 bootstrap: MCPs, CVE KB, playbooks, parallel fan-out, proxy proof capture"
                })),
            )?;
            if pst != 200 {
                bail!("prompt update failed for {role} (HTTP {pst}): {pval}");
            }
            prompt_versions.insert(role.to_string(), pval);
        }
    }

    // 7. Optional capture-proxy header rewrite rule (e.g., X-Intigriti-Username)
    let mut rewrite_info = Value::Null;
    if let (Some(rhost), Some(rhdr)) = (&cfg.rewrite_host, &cfg.rewrite_header)
        && let Some((hname, hval)) = rhdr.split_once(':')
    {
        let hname = hname.trim();
        let hval = hval.trim();
        let rule_name = format!("Nexus-Header-{hname}");
        let (_, rw_val) = api_call(&client, base, reqwest::Method::GET, "/api/traffic/rewrite-rules", Some(&token), None)?;
        let rules = rw_val
            .as_array()
            .or_else(|| rw_val.get("rules").and_then(|v| v.as_array()))
            .cloned()
            .unwrap_or_default();
        let existing_id = rules.iter().find_map(|r| {
            if r.get("name").and_then(|v| v.as_str()) == Some(rule_name.as_str()) {
                r.get("id").and_then(|v| v.as_i64())
            } else {
                None
            }
        });
        let rid = if let Some(id) = existing_id {
            id
        } else {
            let (st, created) = api_call(
                &client,
                base,
                reqwest::Method::POST,
                "/api/traffic/rewrite-rules",
                Some(&token),
                Some(json!({
                    "name": rule_name,
                    "phase": "request",
                    "priority": 10,
                    "matchers": {"host": rhost},
                    "actions": [{"type": "set_header", "name": hname, "value": hval}],
                    "note": "Configured by nexus-sync bootstrap"
                })),
            )?;
            if st != 200 && st != 201 {
                bail!("rewrite rule create failed (HTTP {st}): {created}");
            }
            created["id"].as_i64().unwrap_or(0)
        };
        if rid > 0 {
            let (_, tval) = api_call(
                &client,
                base,
                reqwest::Method::POST,
                &format!("/api/traffic/rewrite-rules/{rid}/toggle"),
                Some(&token),
                Some(json!({"enabled": true})),
            )?;
            rewrite_info = json!({"id": rid, "name": rule_name, "enabled": tval.get("enabled")});
        }
    }

    Ok(json!({
        "status": "ok",
        "artex_url": base,
        "mcps": mcp_summary,
        "prompt_versions": prompt_versions,
        "rewrite_rule": rewrite_info,
    }))
}
