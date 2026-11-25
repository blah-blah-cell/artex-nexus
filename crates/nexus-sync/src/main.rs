mod bootstrap;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use flate2::read::GzDecoder;
use nexus_common::version::is_version_affected;
use nexus_common::{
    AffectedProduct, CveRecord, PackageRange, SCHEMA_SQL, SCHEMA_VERSION, WriteupRecord,
    detect_schema_version, open_readonly, sanitize_fts_query, severity_from_score,
};
use rayon::prelude::*;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{ETAG, IF_NONE_MATCH, USER_AGENT};
use rusqlite::{Connection, params, params_from_iter};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Response, Server};
use walkdir::WalkDir;

const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_CSV_GZ_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const DEFAULT_REPO: &str = "blah-blah-cell/artex-nexus";
const DEFAULT_TAG: &str = "cve-db-latest";

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum SeverityThreshold {
    Medium,
    High,
    Critical,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum McpClientKind {
    Antigravity,
    Claude,
    Cursor,
    Zcode,
    Freebuff,
    Artex,
}

#[derive(Parser)]
#[command(
    name = "nexus-sync",
    about = "High-throughput Rust CVE, OSV, KEV, EPSS & writeups DB builder, scanner, web UI & fetcher"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a normalized Medium+ CVE & writeups SQLite FTS5 DB from local corpora
    Build {
        #[arg(long)]
        source_dir: PathBuf,
        #[arg(long)]
        trickest_dir: Option<PathBuf>,
        #[arg(long)]
        nuclei_dir: Option<PathBuf>,
        #[arg(long)]
        osv_dir: Option<PathBuf>,
        #[arg(long, default_value = "data/cve_kb_med_plus.sqlite")]
        out: PathBuf,
        #[arg(long, default_value_t = 4.0)]
        min_cvss: f64,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        skip_kev: bool,
        #[arg(long)]
        skip_epss: bool,
        #[arg(long)]
        compress: bool,
    },
    /// Stream-fetch the latest prebuilt Medium+ CVE DB from GitHub Releases (ETag + SHA-256 + atomic swap)
    Fetch {
        #[arg(long, env = "ARTEX_NEXUS_REPO", default_value = DEFAULT_REPO)]
        repo: String,
        #[arg(long, env = "ARTEX_NEXUS_DB_TAG", default_value = DEFAULT_TAG)]
        tag: String,
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        out: PathBuf,
        #[arg(long, help = "Bypass ETag cache and force re-download")]
        force: bool,
    },
    /// Build an instant local starter DB directly from live CISA KEV + FIRST EPSS
    SeedKev {
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        out: PathBuf,
    },
    /// Offline SBOM/lockfile vulnerability scan against local OSV/GHSA Medium+ CVE ranges
    Scan {
        #[arg(long, default_value = ".", help = "Target directory or lockfile (10 formats supported)")]
        path: PathBuf,
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        db: PathBuf,
        #[arg(long, help = "Output raw JSON instead of human-readable summary")]
        json: bool,
        #[arg(long, help = "Write SARIF 2.1.0 report to this file")]
        sarif: Option<PathBuf>,
        #[arg(long, value_enum, help = "Exit non-zero if findings meet or exceed severity")]
        fail_on: Option<SeverityThreshold>,
    },
    /// Run health, schema, integrity, and coverage diagnostics on the local ARTEX-Nexus DB
    Doctor {
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        db: PathBuf,
    },
    /// Generate ready-to-paste MCP client JSON config for Antigravity, ZCode, Freebuff, Claude, Cursor, or ARTEX
    InitMcp {
        #[arg(long, value_enum, default_value_t = McpClientKind::Antigravity)]
        client: McpClientKind,
        #[arg(long, default_value = ".")]
        repo_root: PathBuf,
    },
    /// Launch local offline Web Dashboard for browsing CVEs, writeups, SemVer checks, receipts, and playbooks
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 8088)]
        port: u16,
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        db: PathBuf,
        #[arg(long, env = "SCOPE_STATE_DIR", default_value = "data/receipts")]
        receipts_dir: PathBuf,
        #[arg(long, default_value = "knowledge")]
        knowledge_dir: PathBuf,
    },
    /// Auto-configure a running ARTEX instance with all 4 ARTEX-Nexus MCPs, 7 skills, role prompts, caps, and headers
    Bootstrap {
        #[arg(long, env = "ARTEX_URL", default_value = "http://127.0.0.1:8787")]
        artex_url: String,
        #[arg(long, env = "ARTEX_UI_PASSWORD", default_value = "")]
        password: String,
        #[arg(long, env = "ARTEX_SETUP_TOKEN")]
        setup_token: Option<String>,
        #[arg(long, default_value = "127.0.0.1")]
        mcp_host: String,
        #[arg(long, help = "Use Docker Compose service hostnames for MCP URLs")]
        docker_network: bool,
        #[arg(long, default_value = "/opt/artex-nexus-knowledge")]
        knowledge_dir: String,
        #[arg(long, default_value = "/data")]
        data_dir: String,
        #[arg(long, default_value = "/config")]
        config_dir: String,
        #[arg(long, default_value = "http://127.0.0.1:8788")]
        proxy_url: String,
        #[arg(long, help = "LLM profile ID to bind to planner and mainagent")]
        planner_profile_id: Option<i64>,
        #[arg(long, help = "LLM profile ID to bind to worker/goals/auto/pentest/reporter/retester and global default")]
        worker_profile_id: Option<i64>,
        #[arg(long, default_value_t = 15)]
        reporter_max_turns: i64,
        #[arg(long, default_value_t = 300)]
        reporter_run_seconds: i64,
        #[arg(long, default_value_t = 25)]
        retester_max_turns: i64,
        #[arg(long, default_value_t = 600)]
        retester_run_seconds: i64,
        #[arg(long, help = "Optional host matcher for capture-proxy rewrite rule (e.g. *.example.com)")]
        rewrite_host: Option<String>,
        #[arg(long, help = "Optional header to inject via capture proxy (e.g. X-Intigriti-Username: handle)")]
        rewrite_header: Option<String>,
        #[arg(long, help = "Print bootstrap plan without modifying ARTEX")]
        dry_run: bool,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct KevFeed {
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    vulnerability_name: String,
    #[serde(default)]
    date_added: String,
    #[serde(default)]
    short_description: String,
    #[serde(default)]
    due_date: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    cwes: Vec<String>,
}

fn patch_patterns() -> &'static [Regex] {
    static PATS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            Regex::new(r"(?i)^https?://github\.com/[^/]+/[^/]+/(commit|pull)/").unwrap(),
            Regex::new(r"(?i)^https?://gitlab\.com/.+/-/commit/").unwrap(),
            Regex::new(r"(?i)^https?://git\.kernel\.org/").unwrap(),
        ]
    })
}

fn cwe_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)CWE-\d+").unwrap())
}

fn cve_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)CVE-\d{4}-\d{4,}").unwrap())
}

fn url_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"https?://[^\s\)\]>\"']+"#).unwrap())
}

fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("artex-nexus-sync/0.2")
        .build()?)
}

fn fetch_kev_map(client: &Client) -> Result<HashMap<String, KevEntry>> {
    let feed: KevFeed = client
        .get(CISA_KEV_URL)
        .send()
        .context("fetching CISA KEV catalog")?
        .error_for_status()?
        .json()?;
    let mut map = HashMap::with_capacity(feed.vulnerabilities.len());
    for entry in feed.vulnerabilities {
        let cid = entry.cve_id.trim().to_uppercase();
        if !cid.is_empty() {
            map.insert(cid, entry);
        }
    }
    Ok(map)
}

fn fetch_epss_map(client: &Client) -> Result<HashMap<String, (f64, f64)>> {
    let resp = client
        .get(EPSS_CSV_GZ_URL)
        .send()
        .context("fetching FIRST EPSS feed")?
        .error_for_status()?;
    let mut decoder = GzDecoder::new(resp);
    let mut raw = String::new();
    decoder.read_to_string(&mut raw)?;

    let cleaned: String = raw
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");

    let mut reader = csv::Reader::from_reader(cleaned.as_bytes());
    let mut map = HashMap::with_capacity(280_000);
    for rec in reader.records().flatten() {
        if let (Some(cve), Some(epss), Some(pct)) = (rec.get(0), rec.get(1), rec.get(2))
            && let (Ok(e), Ok(p)) = (epss.parse::<f64>(), pct.parse::<f64>())
        {
            map.insert(cve.trim().to_uppercase(), (e, p));
        }
    }
    Ok(map)
}

fn extract_cvss(containers: &Value) -> (Option<f64>, String, String, String) {
    let mut metric_blocks: Vec<&Value> = Vec::new();
    if let Some(arr) = containers.pointer("/cna/metrics").and_then(Value::as_array) {
        metric_blocks.extend(arr.iter());
    }
    if let Some(adps) = containers.get("adp").and_then(Value::as_array) {
        for adp in adps {
            if let Some(arr) = adp.get("metrics").and_then(Value::as_array) {
                metric_blocks.extend(arr.iter());
            }
        }
    }

    let keys = [
        ("cvssV4_0", 4_u8),
        ("cvssV3_1", 3_u8),
        ("cvssV3_0", 2_u8),
        ("cvssV2_0", 1_u8),
    ];

    let mut best: Option<(u8, f64, String, String, String)> = None;
    for block in metric_blocks {
        for (key, rank) in keys {
            if let Some(cvss) = block.get(key).and_then(Value::as_object)
                && let Some(score) = cvss.get("baseScore").and_then(Value::as_f64)
            {
                let ver = cvss
                    .get("version")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| key.trim_start_matches("cvssV").replace('_', "."));
                let sev = cvss
                    .get("baseSeverity")
                    .and_then(Value::as_str)
                    .map(str::to_uppercase)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| severity_from_score(score).to_string());
                let vec_str = cvss
                    .get("vectorString")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let replace = match &best {
                    None => true,
                    Some((br, bs, _, _, _)) => rank > *br || (rank == *br && score > *bs),
                };
                if replace {
                    best = Some((rank, score, ver, sev, vec_str));
                }
            }
        }
    }

    match best {
        Some((_, score, ver, sev, vec_str)) => (Some(score), ver, sev, vec_str),
        None => (None, String::new(), "UNSCORED".to_string(), String::new()),
    }
}

fn classify_reference(url: &str, tags: &[String]) -> (&'static str, bool) {
    let lower_tags: HashSet<String> = tags.iter().map(|t| t.to_lowercase()).collect();
    let has_patch = lower_tags.contains("patch") || patch_patterns().iter().any(|p| p.is_match(url));
    if has_patch {
        return ("patch", true);
    }
    if lower_tags.contains("exploit") || lower_tags.contains("poc") {
        return ("poc", false);
    }
    if lower_tags.contains("vendor-advisory") || lower_tags.contains("third-party-advisory") {
        return ("advisory", false);
    }
    let low_url = url.to_lowercase();
    let writeup_domains = [
        "github.com",
        "blog.",
        "medium.com",
        "hackerone.com",
        "huntr.com",
        "projectzero",
        "zerodayinitiative.com",
        "portswigger.net",
        "assetnote.io",
        "watchtowr.com",
        "projectdiscovery.io",
        "exploit-db.com",
        "advisories",
    ];
    if lower_tags.contains("technical-description")
        || writeup_domains.iter().any(|d| low_url.contains(d))
    {
        return ("writeup", false);
    }
    ("reference", false)
}

fn parse_cve5_value(
    val: &Value,
    kev_map: &HashMap<String, KevEntry>,
    epss_map: &HashMap<String, (f64, f64)>,
    min_cvss: f64,
) -> Option<CveRecord> {
    let meta = val.get("cveMetadata")?;
    if meta.get("state").and_then(Value::as_str) == Some("REJECTED") {
        return None;
    }
    let cve_id = meta.get("cveId").and_then(Value::as_str)?.trim().to_uppercase();
    if !cve_id.starts_with("CVE-") {
        return None;
    }

    let containers = val.get("containers")?;
    let cna = containers.get("cna").unwrap_or(&Value::Null);
    let (mut score, ver, mut sev, vec_str) = extract_cvss(containers);
    let kev_entry = kev_map.get(&cve_id);
    let is_kev = kev_entry.is_some();

    // Strict truthfulness: never invent a fake CVSS score for unscored KEV entries.
    match score {
        Some(s) if s < min_cvss && !is_kev => return None,
        None if !is_kev => return None,
        None if is_kev => {
            score = None;
            sev = "KEV_UNSCORED".to_string();
        }
        _ => {}
    }

    let description = cna
        .get("descriptions")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .find(|d| {
                    d.get("lang")
                        .and_then(Value::as_str)
                        .is_some_and(|l| l.to_lowercase().starts_with("en"))
                })
                .or_else(|| arr.first())
                .and_then(|d| d.get("value"))
                .and_then(Value::as_str)
        })
        .unwrap_or("")
        .trim()
        .to_string();

    let title = cna
        .get("title")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| kev_entry.map(|k| k.vulnerability_name.as_str()).filter(|s| !s.is_empty()))
        .unwrap_or("")
        .to_string();

    // Exact CWE extraction
    let mut cwes = HashSet::new();
    let mut pt_blocks: Vec<&Value> = Vec::new();
    if let Some(arr) = cna.get("problemTypes").and_then(Value::as_array) {
        pt_blocks.extend(arr.iter());
    }
    if let Some(adps) = containers.get("adp").and_then(Value::as_array) {
        for adp in adps {
            if let Some(arr) = adp.get("problemTypes").and_then(Value::as_array) {
                pt_blocks.extend(arr.iter());
            }
        }
    }
    for pt in pt_blocks {
        if let Some(descs) = pt.get("descriptions").and_then(Value::as_array) {
            for d in descs {
                if let Some(cid) = d.get("cweId").and_then(Value::as_str)
                    && cid.to_uppercase().starts_with("CWE-")
                {
                    cwes.insert(cid.trim().to_uppercase());
                } else if let Some(txt) = d.get("description").and_then(Value::as_str) {
                    for m in cwe_regex().find_iter(txt) {
                        cwes.insert(m.as_str().to_uppercase());
                    }
                }
            }
        }
    }
    if let Some(k) = kev_entry {
        for c in &k.cwes {
            if c.to_uppercase().starts_with("CWE-") {
                cwes.insert(c.trim().to_uppercase());
            }
        }
    }
    let mut cwe_ids: Vec<String> = cwes.into_iter().collect();
    cwe_ids.sort();

    // Affected products
    let mut affected_products = Vec::new();
    if let Some(arr) = cna.get("affected").and_then(Value::as_array) {
        for item in arr.iter().take(25) {
            let vendor = item.get("vendor").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let product = item.get("product").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let versions: Vec<String> = item
                .get("versions")
                .and_then(Value::as_array)
                .map(|vs| {
                    vs.iter()
                        .filter_map(|v| {
                            v.get("version")
                                .or_else(|| v.get("lessThan"))
                                .or_else(|| v.get("lessThanOrEqual"))
                                .and_then(Value::as_str)
                                .map(str::trim)
                                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("n/a"))
                                .map(ToOwned::to_owned)
                        })
                        .take(10)
                        .collect()
                })
                .unwrap_or_default();
            if !vendor.is_empty() || !product.is_empty() {
                affected_products.push(AffectedProduct { vendor, product, versions });
            }
        }
    }

    // References & writeups
    let mut ref_objs: Vec<&Value> = Vec::new();
    if let Some(arr) = cna.get("references").and_then(Value::as_array) {
        ref_objs.extend(arr.iter());
    }
    if let Some(adps) = containers.get("adp").and_then(Value::as_array) {
        for adp in adps {
            if let Some(arr) = adp.get("references").and_then(Value::as_array) {
                ref_objs.extend(arr.iter());
            }
        }
    }

    let mut writeups = Vec::new();
    let mut seen_urls = HashSet::new();
    let mut has_poc = false;
    let mut has_patch_any = false;

    for r in ref_objs {
        let Some(url) = r.get("url").and_then(Value::as_str).map(str::trim) else {
            continue;
        };
        if url.is_empty() || !seen_urls.insert(url.to_string()) {
            continue;
        }
        let tags: Vec<String> = r
            .get("tags")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let (src, has_patch) = classify_reference(url, &tags);
        if src == "poc" {
            has_poc = true;
        }
        if has_patch {
            has_patch_any = true;
        }
        if matches!(src, "patch" | "poc" | "advisory" | "writeup") {
            let ref_title = r
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .chars()
                .take(240)
                .collect();
            writeups.push(WriteupRecord {
                cve_id: cve_id.clone(),
                source: src.to_string(),
                url: url.to_string(),
                title: ref_title,
                tags: tags.join(","),
                has_patch_diff: has_patch,
                content_excerpt: String::new(),
            });
        }
    }

    let exploit_maturity = if is_kev {
        "KEV_EXPLOITED"
    } else if has_poc {
        "POC_PUBLIC"
    } else if has_patch_any {
        "PATCH_ONLY"
    } else {
        "NONE"
    }
    .to_string();

    let (epss_score, epss_percentile) = epss_map
        .get(&cve_id)
        .map(|(e, p)| (Some(*e), Some(*p)))
        .unwrap_or((None, None));

    Some(CveRecord {
        cve_id,
        published_date: meta.get("datePublished").and_then(Value::as_str).unwrap_or("").to_string(),
        modified_date: meta.get("dateUpdated").and_then(Value::as_str).unwrap_or("").to_string(),
        cvss_score: score,
        cvss_version: ver,
        cvss_severity: sev,
        cvss_vector: vec_str,
        cwe_ids,
        epss_score,
        epss_percentile,
        is_kev,
        kev_date_added: kev_entry.map(|k| k.date_added.clone()),
        kev_due_date: kev_entry.map(|k| k.due_date.clone()),
        exploit_maturity,
        title,
        description,
        affected_products,
        writeups,
    })
}

fn ingest_trickest(conn: &mut Connection, trickest_dir: &Path, existing: &HashSet<String>) -> Result<usize> {
    let md_files: Vec<PathBuf> = WalkDir::new(trickest_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("CVE-") && n.ends_with(".md"))
        })
        .map(|e| e.into_path())
        .collect();

    let extracted: Vec<WriteupRecord> = md_files
        .par_iter()
        .flat_map(|path| {
            let cid = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_uppercase();
            if !existing.contains(&cid) {
                return Vec::new();
            }
            let Ok(text) = fs::read_to_string(path) else {
                return Vec::new();
            };
            let mut out = Vec::new();
            let mut seen = HashSet::new();
            for m in url_regex().find_iter(&text) {
                let url = m.as_str().trim_end_matches(&['.', ',', ';'][..]);
                if url.contains("nvd.nist.gov/vuln/detail") || url.contains("cve.mitre.org") {
                    continue;
                }
                if !seen.insert(url.to_string()) {
                    continue;
                }
                let src = if url.to_lowercase().contains("github.com") {
                    "trickest:poc"
                } else {
                    "trickest:writeup"
                };
                let has_patch = patch_patterns().iter().any(|p| p.is_match(url));
                out.push(WriteupRecord {
                    cve_id: cid.clone(),
                    source: src.to_string(),
                    url: url.to_string(),
                    title: String::new(),
                    tags: "trickest".to_string(),
                    has_patch_diff: has_patch,
                    content_excerpt: String::new(),
                });
            }
            out
        })
        .collect();

    let tx = conn.transaction()?;
    let mut inserted = 0usize;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO writeups (cve_id, source, url, title, tags, has_patch_diff, content_excerpt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        let mut upd = tx.prepare_cached(
            "UPDATE cves SET exploit_maturity = 'POC_PUBLIC'
             WHERE cve_id = ?1 AND exploit_maturity IN ('NONE', 'PATCH_ONLY')",
        )?;
        for w in &extracted {
            inserted += stmt.execute(params![
                w.cve_id,
                w.source,
                w.url,
                w.title,
                w.tags,
                w.has_patch_diff as i32,
                w.content_excerpt
            ])?;
            if w.source == "trickest:poc" {
                upd.execute(params![w.cve_id])?;
            }
        }
    }
    tx.commit()?;
    Ok(inserted)
}

fn ingest_nuclei(conn: &mut Connection, nuclei_dir: &Path, existing: &HashSet<String>) -> Result<usize> {
    let yaml_files: Vec<(String, String, String)> = WalkDir::new(nuclei_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("CVE-") && n.ends_with(".yaml"))
        })
        .filter_map(|e| {
            let p = e.into_path();
            let stem = p.file_stem()?.to_str()?.to_string();
            let cid = cve_regex().find(&stem)?.as_str().to_uppercase();
            if !existing.contains(&cid) {
                return None;
            }
            let rel = p.strip_prefix(nuclei_dir).ok()?.to_string_lossy().replace('\\', "/");
            let url = format!("https://github.com/projectdiscovery/nuclei-templates/blob/main/{rel}");
            Some((cid, stem, url))
        })
        .collect();

    let tx = conn.transaction()?;
    let mut inserted = 0usize;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO writeups (cve_id, source, url, title, tags, has_patch_diff, content_excerpt)
             VALUES (?1, 'nuclei', ?2, ?3, 'nuclei-template', 0, '')",
        )?;
        let mut upd = tx.prepare_cached(
            "UPDATE cves SET exploit_maturity = 'NUCLEI_VERIFIED'
             WHERE cve_id = ?1 AND exploit_maturity != 'KEV_EXPLOITED'",
        )?;
        for (cid, stem, url) in &yaml_files {
            inserted += stmt.execute(params![cid, url, stem])?;
            upd.execute(params![cid])?;
        }
    }
    tx.commit()?;
    Ok(inserted)
}

fn ingest_osv(conn: &mut Connection, osv_dir: &Path, existing: &HashSet<String>) -> Result<(usize, usize)> {
    let json_files: Vec<PathBuf> = WalkDir::new(osv_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && e.path().extension().and_then(|s| s.to_str()) == Some("json")
        })
        .map(|e| e.into_path())
        .collect();

    let parsed: Vec<(Vec<PackageRange>, Vec<WriteupRecord>)> = json_files
        .par_iter()
        .filter_map(|p| {
            let raw = fs::read_to_string(p).ok()?;
            let v: Value = serde_json::from_str(&raw).ok()?;
            let adv_id = v.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            let aliases: Vec<String> = v
                .get("aliases")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_uppercase)
                        .filter(|s| s.starts_with("CVE-") && existing.contains(s))
                        .collect()
                })
                .unwrap_or_default();
            if aliases.is_empty() {
                return None;
            }
            let summary = v.get("summary").and_then(Value::as_str).unwrap_or("").trim();
            let details = v.get("details").and_then(Value::as_str).unwrap_or("").trim();
            let excerpt: String = details.chars().take(2000).collect();

            let mut pkgs = Vec::new();
            let mut wus = Vec::new();

            for cid in &aliases {
                if !excerpt.is_empty() {
                    let url = if adv_id.starts_with("GHSA-") {
                        format!("https://github.com/advisories/{adv_id}")
                    } else {
                        format!("https://osv.dev/vulnerability/{adv_id}")
                    };
                    wus.push(WriteupRecord {
                        cve_id: cid.clone(),
                        source: "osv-advisory".to_string(),
                        url,
                        title: summary.chars().take(240).collect(),
                        tags: "osv,ghsa,writeup-text".to_string(),
                        has_patch_diff: false,
                        content_excerpt: excerpt.clone(),
                    });
                }
                if let Some(affs) = v.get("affected").and_then(Value::as_array) {
                    for aff in affs {
                        let ecosystem = aff
                            .pointer("/package/ecosystem")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        let pkg_name = aff
                            .pointer("/package/name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        if ecosystem.is_empty() || pkg_name.is_empty() {
                            continue;
                        }
                        if let Some(ranges) = aff.get("ranges").and_then(Value::as_array) {
                            for rng in ranges {
                                let mut intro = String::new();
                                let mut fixed = String::new();
                                if let Some(events) = rng.get("events").and_then(Value::as_array) {
                                    for ev in events {
                                        if let Some(i) = ev.get("introduced").and_then(Value::as_str) {
                                            if !intro.is_empty() && !fixed.is_empty() {
                                                pkgs.push(PackageRange {
                                                    cve_id: cid.clone(),
                                                    ecosystem: ecosystem.clone(),
                                                    package_name: pkg_name.clone(),
                                                    introduced_ver: intro.clone(),
                                                    fixed_ver: fixed.clone(),
                                                    advisory_id: adv_id.clone(),
                                                });
                                                fixed.clear();
                                            }
                                            intro = i.to_string();
                                        }
                                        if let Some(f) = ev.get("fixed").and_then(Value::as_str) {
                                            fixed = f.to_string();
                                        } else if let Some(la) = ev.get("last_affected").and_then(Value::as_str) {
                                            fixed = format!("<={la}");
                                        }
                                    }
                                }
                                if !intro.is_empty() || !fixed.is_empty() {
                                    pkgs.push(PackageRange {
                                        cve_id: cid.clone(),
                                        ecosystem: ecosystem.clone(),
                                        package_name: pkg_name.clone(),
                                        introduced_ver: intro,
                                        fixed_ver: fixed,
                                        advisory_id: adv_id.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Some((pkgs, wus))
        })
        .collect();

    let tx = conn.transaction()?;
    let mut pkg_count = 0usize;
    let mut wu_count = 0usize;
    {
        let mut p_stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO cve_packages (cve_id, ecosystem, package_name, introduced_ver, fixed_ver, advisory_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        let mut w_stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO writeups (cve_id, source, url, title, tags, has_patch_diff, content_excerpt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for (pkgs, wus) in parsed {
            for p in pkgs {
                pkg_count += p_stmt.execute(params![
                    p.cve_id,
                    p.ecosystem,
                    p.package_name,
                    p.introduced_ver,
                    p.fixed_ver,
                    p.advisory_id
                ])?;
            }
            for w in wus {
                wu_count += w_stmt.execute(params![
                    w.cve_id,
                    w.source,
                    w.url,
                    w.title,
                    w.tags,
                    w.has_patch_diff as i32,
                    w.content_excerpt
                ])?;
            }
        }
    }
    tx.commit()?;
    Ok((pkg_count, wu_count))
}

pub fn write_records_to_db(
    out: &Path,
    records: &[CveRecord],
    min_cvss: f64,
    trickest_dir: Option<&Path>,
    nuclei_dir: Option<&Path>,
    osv_dir: Option<&Path>,
) -> Result<Value> {
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = out.with_extension("sqlite.building");
    if tmp_path.exists() {
        fs::remove_file(&tmp_path)?;
    }

    let mut conn = Connection::open(&tmp_path)?;
    conn.execute_batch(
        "PRAGMA journal_mode = OFF;
         PRAGMA synchronous = OFF;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -128000;",
    )?;
    conn.execute_batch(SCHEMA_SQL)?;

    let mut existing = HashSet::with_capacity(records.len());
    {
        let tx = conn.transaction()?;
        {
            let mut cve_stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO cves (
                    cve_id, published_date, modified_date, cvss_score, cvss_version,
                    cvss_severity, cvss_vector, epss_score, epss_percentile,
                    is_kev, kev_date_added, kev_due_date, exploit_maturity,
                    title, description, affected_products
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            )?;
            let mut cwe_stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO cve_cwes (cve_id, cwe_id) VALUES (?1, ?2)",
            )?;
            let mut wu_stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO writeups (cve_id, source, url, title, tags, has_patch_diff, content_excerpt)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;

            for rec in records {
                existing.insert(rec.cve_id.clone());
                let aff_json = serde_json::to_string(&rec.affected_products)?;
                cve_stmt.execute(params![
                    rec.cve_id,
                    rec.published_date,
                    rec.modified_date,
                    rec.cvss_score,
                    rec.cvss_version,
                    rec.cvss_severity,
                    rec.cvss_vector,
                    rec.epss_score,
                    rec.epss_percentile,
                    rec.is_kev as i32,
                    rec.kev_date_added,
                    rec.kev_due_date,
                    rec.exploit_maturity,
                    rec.title,
                    rec.description,
                    aff_json
                ])?;
                for cwe in &rec.cwe_ids {
                    cwe_stmt.execute(params![rec.cve_id, cwe])?;
                }
                for w in &rec.writeups {
                    wu_stmt.execute(params![
                        w.cve_id,
                        w.source,
                        w.url,
                        w.title,
                        w.tags,
                        w.has_patch_diff as i32,
                        w.content_excerpt
                    ])?;
                }
            }
        }
        tx.commit()?;
    }

    if let Some(d) = trickest_dir
        && d.exists()
    {
        ingest_trickest(&mut conn, d, &existing)?;
    }
    if let Some(d) = nuclei_dir
        && d.exists()
    {
        ingest_nuclei(&mut conn, d, &existing)?;
    }
    if let Some(d) = osv_dir
        && d.exists()
    {
        ingest_osv(&mut conn, d, &existing)?;
    }

    // Build both FTS5 indexes
    conn.execute_batch(
        "INSERT INTO cves_fts(cves_fts) VALUES('rebuild');
         INSERT INTO writeups_fts(writeups_fts) VALUES('rebuild');",
    )?;

    let total_cves: i64 = conn.query_row("SELECT COUNT(*) FROM cves", [], |r| r.get(0))?;
    let total_writeups: i64 = conn.query_row("SELECT COUNT(*) FROM writeups", [], |r| r.get(0))?;
    let total_packages: i64 = conn.query_row("SELECT COUNT(*) FROM cve_packages", [], |r| r.get(0))?;
    let kev_count: i64 = conn.query_row("SELECT COUNT(*) FROM cves WHERE is_kev = 1", [], |r| r.get(0))?;
    let writeups_with_text: i64 = conn.query_row(
        "SELECT COUNT(*) FROM writeups WHERE length(content_excerpt) > 0",
        [],
        |r| r.get(0),
    )?;

    let meta = [
        ("schema_version", SCHEMA_VERSION.to_string()),
        ("built_at", Utc::now().to_rfc3339()),
        ("min_cvss", min_cvss.to_string()),
        ("total_cves", total_cves.to_string()),
        ("total_writeups", total_writeups.to_string()),
        ("writeups_with_text", writeups_with_text.to_string()),
        ("total_packages", total_packages.to_string()),
        ("kev_count", kev_count.to_string()),
    ];
    for (k, v) in meta {
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
            params![k, v],
        )?;
    }
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA optimize;")?;
    drop(conn);

    // Atomic swap into final destination
    if out.exists() {
        fs::remove_file(out)?;
    }
    fs::rename(&tmp_path, out)?;

    Ok(serde_json::json!({
        "db": out.display().to_string(),
        "schema_version": SCHEMA_VERSION,
        "total_cves": total_cves,
        "total_writeups": total_writeups,
        "writeups_with_text": writeups_with_text,
        "total_packages": total_packages,
        "kev_count": kev_count
    }))
}

fn compress_zstd(db_path: &Path) -> Result<(PathBuf, String)> {
    let out_path = db_path.with_extension("sqlite.zst");
    let src = BufReader::new(File::open(db_path)?);
    let dst = BufWriter::new(File::create(&out_path)?);
    let mut encoder = zstd::stream::Encoder::new(dst, 11)?;
    let mut reader = src;
    io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;

    let mut hasher = Sha256::new();
    let mut f = File::open(&out_path)?;
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hex::encode(hasher.finalize());
    let sums_path = out_path.parent().unwrap_or(Path::new(".")).join("SHA256SUMS.txt");
    fs::write(
        &sums_path,
        format!(
            "{}  {}\n",
            digest,
            out_path.file_name().unwrap().to_string_lossy()
        ),
    )?;
    Ok((out_path, digest))
}

fn cmd_fetch(repo: &str, tag: &str, out: &Path, force: bool) -> Result<()> {
    let start = Instant::now();
    let client = http_client()?;
    let cache_dir = out.parent().unwrap_or(Path::new("data")).join(".cache");
    fs::create_dir_all(&cache_dir)?;
    let etag_file = cache_dir.join("release.etag");

    let api_url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
    let mut req = client.get(&api_url).header(USER_AGENT, "artex-nexus-sync/0.2");
    if !force && out.exists() && etag_file.exists() {
        let etag = fs::read_to_string(&etag_file)?.trim().to_string();
        if !etag.is_empty() {
            req = req.header(IF_NONE_MATCH, etag);
        }
    }

    let resp = req.send().context("querying GitHub Release metadata")?;
    if resp.status().as_u16() == 304 && out.exists() {
        eprintln!(
            "[+] Local DB is already up to date (HTTP 304 Not Modified in {}ms): {}",
            start.elapsed().as_millis(),
            out.display()
        );
        return Ok(());
    }
    let resp = resp.error_for_status()?;
    let new_etag = resp
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let release: Value = resp.json()?;

    let mut asset_url: Option<(String, String)> = None;
    let mut sums_url: Option<String> = None;
    if let Some(assets) = release.get("assets").and_then(Value::as_array) {
        for a in assets {
            let name = a.get("name").and_then(Value::as_str).unwrap_or("");
            let dl = a
                .get("browser_download_url")
                .and_then(Value::as_str)
                .unwrap_or("");
            if name == "cve_kb_med_plus.sqlite.zst" || name == "cve_kb_med_plus.sqlite.gz" {
                asset_url = Some((name.to_string(), dl.to_string()));
            } else if name == "SHA256SUMS.txt" {
                sums_url = Some(dl.to_string());
            }
        }
    }

    let (asset_name, dl_url) =
        asset_url.ok_or_else(|| anyhow::anyhow!("No CVE DB archive asset found in {repo}@{tag}"))?;

    let expected_sha = if let Some(s_url) = sums_url {
        let text = client.get(&s_url).send()?.error_for_status()?.text()?;
        text.lines().find_map(|line| {
            let mut parts = line.split_whitespace();
            let h = parts.next()?;
            let n = parts.next()?;
            if n == asset_name {
                Some(h.to_lowercase())
            } else {
                None
            }
        })
    } else {
        None
    };

    // Stream download to cache while hashing on the fly
    let archive_path = cache_dir.join(&asset_name);
    let dl_start = Instant::now();
    let mut dl_resp = client.get(&dl_url).send()?.error_for_status()?;
    let mut out_file = BufWriter::new(File::create(&archive_path)?);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 256 * 1024];
    let mut total_bytes: u64 = 0;
    loop {
        let n = dl_resp.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out_file.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        total_bytes += n as u64;
    }
    out_file.flush()?;
    let actual_sha = hex::encode(hasher.finalize());
    let mb = total_bytes as f64 / (1024.0 * 1024.0);
    let mbps = mb / dl_start.elapsed().as_secs_f64().max(0.001);
    eprintln!(
        "[*] Downloaded {asset_name} ({mb:.2} MiB at {mbps:.1} MiB/s), sha256={}...",
        &actual_sha[..16]
    );

    if let Some(exp) = expected_sha
        && exp != actual_sha
    {
        fs::remove_file(&archive_path).ok();
        anyhow::bail!("SHA-256 verification FAILED: expected {exp}, got {actual_sha}");
    }

    // Stream decompress to temp file, verify SQLite integrity, and atomic swap
    let tmp_db = out.with_extension("sqlite.tmp");
    let dec_start = Instant::now();
    {
        let src = BufReader::new(File::open(&archive_path)?);
        let mut dst = BufWriter::new(File::create(&tmp_db)?);
        if asset_name.ends_with(".zst") {
            let mut decoder = zstd::stream::Decoder::new(src)?;
            io::copy(&mut decoder, &mut dst)?;
        } else {
            let mut decoder = GzDecoder::new(src);
            io::copy(&mut decoder, &mut dst)?;
        }
        dst.flush()?;
    }

    // Quick SQLite integrity check before swapping live DB
    {
        let conn = Connection::open(&tmp_db)?;
        let check: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if check != "ok" {
            fs::remove_file(&tmp_db).ok();
            anyhow::bail!("Decompressed SQLite quick_check failed: {check}");
        }
    }

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    if out.exists() {
        fs::remove_file(out)?;
    }
    fs::rename(&tmp_db, out)?;
    if let Some(et) = new_etag {
        fs::write(&etag_file, et)?;
    }

    eprintln!(
        "[+] Decompressed & verified in {}ms -> {} (total {}ms)",
        dec_start.elapsed().as_millis(),
        out.display(),
        start.elapsed().as_millis()
    );
    Ok(())
}

fn cmd_seed_kev(out: &Path) -> Result<()> {
    let client = http_client()?;
    let kev_map = fetch_kev_map(&client)?;
    let epss_map = fetch_epss_map(&client)?;
    let records: Vec<CveRecord> = kev_map
        .iter()
        .map(|(cid, item)| {
            let (epss_score, epss_percentile) = epss_map
                .get(cid)
                .map(|(e, p)| (Some(*e), Some(*p)))
                .unwrap_or((None, None));
            let writeups: Vec<WriteupRecord> = item
                .notes
                .split(';')
                .map(str::trim)
                .filter(|s| s.starts_with("http"))
                .map(|u| WriteupRecord {
                    cve_id: cid.clone(),
                    source: "advisory".to_string(),
                    url: u.to_string(),
                    title: item.vulnerability_name.clone(),
                    tags: "cisa-kev".to_string(),
                    has_patch_diff: false,
                    content_excerpt: item.short_description.clone(),
                })
                .collect();
            CveRecord {
                cve_id: cid.clone(),
                published_date: item.date_added.clone(),
                modified_date: item.due_date.clone(),
                cvss_score: None,
                cvss_version: String::new(),
                cvss_severity: "KEV_UNSCORED".to_string(),
                cvss_vector: String::new(),
                cwe_ids: item.cwes.iter().map(|c| c.to_uppercase()).collect(),
                epss_score,
                epss_percentile,
                is_kev: true,
                kev_date_added: Some(item.date_added.clone()),
                kev_due_date: Some(item.due_date.clone()),
                exploit_maturity: "KEV_EXPLOITED".to_string(),
                title: item.vulnerability_name.clone(),
                description: item.short_description.clone(),
                affected_products: vec![AffectedProduct {
                    vendor: item.vendor_project.clone(),
                    product: item.product.clone(),
                    versions: Vec::new(),
                }],
                writeups,
            }
        })
        .collect();

    let stats = write_records_to_db(out, &records, 4.0, None, None, None)?;
    println!("{}", serde_json::to_string_pretty(&stats)?);
    Ok(())
}

fn parse_dependencies_from_file(path: &Path) -> Vec<(String, String, String)> {
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut deps = Vec::new();
    match fname {
        "package-lock.json" => {
            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                if let Some(pkgs) = v.get("packages").and_then(Value::as_object) {
                    for (k, val) in pkgs {
                        if let Some(ver) = val.get("version").and_then(Value::as_str)
                            && let Some(name) = k.rsplit("node_modules/").next()
                            && !name.is_empty()
                        {
                            deps.push(("npm".to_string(), name.to_string(), ver.to_string()));
                        }
                    }
                } else if let Some(dmap) = v.get("dependencies").and_then(Value::as_object) {
                    for (name, val) in dmap {
                        if let Some(ver) = val.get("version").and_then(Value::as_str) {
                            deps.push(("npm".to_string(), name.clone(), ver.to_string()));
                        }
                    }
                }
            }
        }
        "package.json" => {
            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                for key in ["dependencies", "devDependencies"] {
                    if let Some(map) = v.get(key).and_then(Value::as_object) {
                        for (name, ver) in map {
                            if let Some(vs) = ver.as_str() {
                                deps.push(("npm".to_string(), name.clone(), vs.to_string()));
                            }
                        }
                    }
                }
            }
        }
        "requirements.txt" => {
            for line in raw.lines() {
                let l = line.split('#').next().unwrap_or("").trim();
                if l.is_empty() || l.starts_with('-') {
                    continue;
                }
                if let Some((pkg, ver)) = l.split_once("==") {
                    deps.push(("PyPI".to_string(), pkg.trim().to_string(), ver.trim().to_string()));
                }
            }
        }
        "go.mod" => {
            for line in raw.lines() {
                let l = line.split("//").next().unwrap_or("").trim();
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 2 && parts[1].starts_with('v') && !matches!(parts[0], "go" | "module" | "toolchain") {
                    let name = if parts[0] == "require" && parts.len() >= 3 {
                        parts[1]
                    } else {
                        parts[0]
                    };
                    let ver = if parts[0] == "require" && parts.len() >= 3 {
                        parts[2]
                    } else {
                        parts[1]
                    };
                    deps.push(("Go".to_string(), name.to_string(), ver.trim_start_matches('v').to_string()));
                }
            }
        }
        "Cargo.lock" => {
            let mut cur_name = String::new();
            for line in raw.lines() {
                let l = line.trim();
                if l == "[[package]]" {
                    cur_name.clear();
                } else if let Some(rest) = l.strip_prefix("name = \"") {
                    cur_name = rest.trim_end_matches('"').to_string();
                } else if let Some(rest) = l.strip_prefix("version = \"")
                    && !cur_name.is_empty()
                {
                    deps.push((
                        "crates.io".to_string(),
                        cur_name.clone(),
                        rest.trim_end_matches('"').to_string(),
                    ));
                }
            }
        }
        "poetry.lock" => {
            let mut cur_name = String::new();
            for line in raw.lines() {
                let l = line.trim();
                if l == "[[package]]" {
                    cur_name.clear();
                } else if let Some(rest) = l.strip_prefix("name = \"") {
                    cur_name = rest.trim_end_matches('"').to_string();
                } else if let Some(rest) = l.strip_prefix("version = \"")
                    && !cur_name.is_empty()
                {
                    deps.push((
                        "PyPI".to_string(),
                        cur_name.clone(),
                        rest.trim_end_matches('"').to_string(),
                    ));
                }
            }
        }
        "yarn.lock" => {
            let mut cur_names: Vec<String> = Vec::new();
            for line in raw.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
                    cur_names.clear();
                    for part in trimmed.trim_end_matches(':').split(',') {
                        let spec = part.trim().trim_matches('"').trim_matches('\'');
                        if spec.len() > 1
                            && let Some(at_pos) = spec[1..].find('@')
                        {
                            let pkg = spec[..1 + at_pos].to_string();
                            if !pkg.is_empty() && !cur_names.contains(&pkg) {
                                cur_names.push(pkg);
                            }
                        }
                    }
                } else if !cur_names.is_empty() {
                    let ver_opt = trimmed
                        .strip_prefix("version \"")
                        .map(|s| s.trim_end_matches('"'))
                        .or_else(|| trimmed.strip_prefix("version:").map(str::trim));
                    if let Some(ver) = ver_opt
                        && ver.chars().next().is_some_and(|c| c.is_ascii_digit())
                    {
                        for name in &cur_names {
                            deps.push(("npm".to_string(), name.clone(), ver.to_string()));
                        }
                        cur_names.clear();
                    }
                }
            }
        }
        "pnpm-lock.yaml" => {
            for line in raw.lines() {
                let t = line.trim();
                if !t.ends_with(':') {
                    continue;
                }
                let cleaned = t
                    .trim_end_matches(':')
                    .trim_matches('\'')
                    .trim_matches('"')
                    .trim_start_matches('/');
                let no_peers = cleaned.split('(').next().unwrap_or(cleaned);
                if no_peers.len() > 1
                    && let Some(at_pos) = no_peers[1..].find('@')
                {
                    let name = &no_peers[..1 + at_pos];
                    let ver = &no_peers[2 + at_pos..];
                    if !name.is_empty()
                        && ver.chars().next().is_some_and(|c| c.is_ascii_digit())
                        && !ver.contains('/')
                    {
                        deps.push(("npm".to_string(), name.to_string(), ver.to_string()));
                    }
                }
            }
        }
        "composer.lock" => {
            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                for key in ["packages", "packages-dev"] {
                    if let Some(arr) = v.get(key).and_then(Value::as_array) {
                        for pkg in arr {
                            if let (Some(name), Some(ver)) = (
                                pkg.get("name").and_then(Value::as_str),
                                pkg.get("version").and_then(Value::as_str),
                            ) {
                                deps.push((
                                    "Packagist".to_string(),
                                    name.to_string(),
                                    ver.trim_start_matches(['v', 'V']).to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }
        "pom.xml" => {
            let dep_re = Regex::new(r"(?s)<dependency>(.*?)</dependency>").unwrap();
            let gid_re = Regex::new(r"<groupId>\s*([^<\s]+)\s*</groupId>").unwrap();
            let aid_re = Regex::new(r"<artifactId>\s*([^<\s]+)\s*</artifactId>").unwrap();
            let ver_re = Regex::new(r"<version>\s*([^<\s]+)\s*</version>").unwrap();
            for cap in dep_re.captures_iter(&raw) {
                let block = &cap[1];
                if let (Some(g), Some(a), Some(v)) =
                    (gid_re.captures(block), aid_re.captures(block), ver_re.captures(block))
                {
                    let ver = v[1].trim();
                    if !ver.starts_with('$') && !ver.is_empty() {
                        deps.push((
                            "Maven".to_string(),
                            format!("{}:{}", g[1].trim(), a[1].trim()),
                            ver.to_string(),
                        ));
                    }
                }
            }
        }
        _ => {}
    }
    deps
}

fn build_sarif_report(findings: &[Value]) -> Value {
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let sev = f["severity"].as_str().unwrap_or("MEDIUM");
            let is_kev = f["is_kev"].as_bool().unwrap_or(false);
            let level = if sev == "CRITICAL" || sev == "HIGH" || sev == "KEV_UNSCORED" || is_kev {
                "error"
            } else {
                "warning"
            };
            let pkg = f["package"].as_str().unwrap_or("");
            let inst = f["installed"].as_str().unwrap_or("");
            let eco = f["ecosystem"].as_str().unwrap_or("");
            let fixed = f["fixed"].as_str().unwrap_or("none");
            let cve_id = f["cve_id"].as_str().unwrap_or("CVE-UNKNOWN");
            let title = f["title"].as_str().unwrap_or("");
            let manifest = f["file"].as_str().unwrap_or("lockfile");
            json!({
                "ruleId": cve_id,
                "level": level,
                "message": {
                    "text": format!("{pkg}@{inst} ({eco}) affected by {cve_id} (fix: {fixed}) — {title}")
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": manifest.replace('\\', "/") }
                    }
                }],
                "properties": {
                    "advisory_id": f["advisory_id"],
                    "ecosystem": eco,
                    "package": pkg,
                    "installed": inst,
                    "fixed": fixed,
                    "cvss_score": f["cvss_score"],
                    "severity": sev,
                    "is_kev": is_kev,
                    "epss_score": f["epss_score"]
                }
            })
        })
        .collect();

    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "artex-nexus-sbom-scanner",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/blah-blah-cell/artex-nexus"
                }
            },
            "results": results
        }]
    })
}

fn severity_rank(sev: &str, is_kev: bool) -> u8 {
    match sev {
        "CRITICAL" => 3,
        "HIGH" | "KEV_UNSCORED" => 2,
        "MEDIUM" => 1,
        _ => if is_kev { 2 } else { 0 },
    }
}

fn cmd_scan(
    path: &Path,
    db_path: &Path,
    as_json: bool,
    sarif_out: Option<&Path>,
    fail_on: Option<SeverityThreshold>,
) -> Result<()> {
    let start = Instant::now();
    let conn = open_readonly(db_path)?;
    if detect_schema_version(&conn) < 2 {
        anyhow::bail!("Scan requires v2 DB with OSV packages. Run `nexus-sync fetch` first.");
    }

    let targets: Vec<PathBuf> = if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        WalkDir::new(path)
            .max_depth(4)
            .into_iter()
            .filter_entry(|e| {
                !matches!(
                    e.file_name().to_str(),
                    Some(".git" | "node_modules" | "target" | "vendor" | ".venv")
                )
            })
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_type().is_file()
                    && matches!(
                        e.file_name().to_str(),
                        Some(
                            "package-lock.json"
                                | "package.json"
                                | "yarn.lock"
                                | "pnpm-lock.yaml"
                                | "requirements.txt"
                                | "poetry.lock"
                                | "go.mod"
                                | "Cargo.lock"
                                | "composer.lock"
                                | "pom.xml"
                        )
                    )
            })
            .map(|e| e.into_path())
            .collect()
    };

    let mut seen = HashSet::new();
    let mut findings = Vec::new();
    let mut deps_checked = 0usize;

    let mut stmt = conn.prepare(
        "SELECT p.cve_id, p.introduced_ver, p.fixed_ver, p.advisory_id,
                c.cvss_score, c.cvss_severity, c.is_kev, c.epss_score, c.title
         FROM cve_packages p
         JOIN cves c ON c.cve_id = p.cve_id
         WHERE LOWER(p.ecosystem) = LOWER(?1) AND LOWER(p.package_name) = LOWER(?2)",
    )?;

    for file in &targets {
        for (eco, name, ver) in parse_dependencies_from_file(file) {
            if !seen.insert((eco.clone(), name.clone(), ver.clone())) {
                continue;
            }
            deps_checked += 1;
            let rows = stmt.query_map(params![&eco, &name], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<f64>>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)? == 1,
                    r.get::<_, Option<f64>>(7)?,
                    r.get::<_, String>(8)?,
                ))
            })?;
            for (cve_id, intro, fixed, adv, score, sev, is_kev, epss, title) in rows.flatten() {
                if is_version_affected(&ver, &intro, &fixed) == Some(true) {
                    findings.push(serde_json::json!({
                        "file": file.display().to_string(),
                        "ecosystem": eco,
                        "package": name,
                        "installed": ver,
                        "fixed": fixed,
                        "cve_id": cve_id,
                        "advisory_id": adv,
                        "cvss_score": score,
                        "severity": sev,
                        "is_kev": is_kev,
                        "epss_score": epss,
                        "title": title
                    }));
                }
            }
        }
    }

    if let Some(sarif_path) = sarif_out {
        if let Some(parent) = sarif_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let sarif_doc = build_sarif_report(&findings);
        fs::write(sarif_path, serde_json::to_string_pretty(&sarif_doc)?)?;
        eprintln!("[+] SARIF 2.1.0 report written to {}", sarif_path.display());
    }

    let report = serde_json::json!({
        "manifests_scanned": targets.len(),
        "dependencies_checked": deps_checked,
        "vulnerabilities_found": findings.len(),
        "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0,
        "findings": findings
    });

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "ARTEX-Nexus Offline SBOM Scan: {} manifests, {} deps checked, {} Medium+ vulnerabilities found ({:.2} ms)",
            targets.len(),
            deps_checked,
            findings.len(),
            start.elapsed().as_secs_f64() * 1000.0
        );
        for f in &findings {
            println!(
                "  [{} | CVSS {} | KEV={}] {}@{} ({}) -> fix: {} | {} ({})",
                f["severity"].as_str().unwrap_or("?"),
                f["cvss_score"],
                f["is_kev"],
                f["package"].as_str().unwrap_or(""),
                f["installed"].as_str().unwrap_or(""),
                f["ecosystem"].as_str().unwrap_or(""),
                f["fixed"].as_str().unwrap_or("none"),
                f["cve_id"].as_str().unwrap_or(""),
                f["advisory_id"].as_str().unwrap_or("")
            );
        }
    }

    if let Some(threshold) = fail_on {
        let min_rank = match threshold {
            SeverityThreshold::Medium => 1,
            SeverityThreshold::High => 2,
            SeverityThreshold::Critical => 3,
        };
        let failing = findings
            .iter()
            .filter(|f| {
                severity_rank(
                    f["severity"].as_str().unwrap_or("NONE"),
                    f["is_kev"].as_bool().unwrap_or(false),
                ) >= min_rank
            })
            .count();
        if failing > 0 {
            anyhow::bail!("{failing} findings met or exceeded --fail-on threshold ({threshold:?})");
        }
    }
    Ok(())
}

fn cmd_doctor(db_path: &Path) -> Result<()> {
    let start = Instant::now();
    let conn = open_readonly(db_path)?;
    let schema = detect_schema_version(&conn);
    let check: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    let total_cves: i64 = conn.query_row("SELECT COUNT(*) FROM cves", [], |r| r.get(0))?;
    let total_writeups: i64 = conn.query_row("SELECT COUNT(*) FROM writeups", [], |r| r.get(0))?;
    let kev_count: i64 = conn.query_row("SELECT COUNT(*) FROM cves WHERE is_kev = 1", [], |r| r.get(0))?;
    let total_packages: i64 = if schema >= 2 {
        conn.query_row("SELECT COUNT(*) FROM cve_packages", [], |r| r.get(0))?
    } else {
        0
    };
    let writeups_with_text: i64 = if schema >= 2 {
        conn.query_row("SELECT COUNT(*) FROM writeups WHERE length(content_excerpt) > 0", [], |r| r.get(0))?
    } else {
        0
    };
    let built_at: String = conn
        .query_row("SELECT value FROM metadata WHERE key = 'built_at'", [], |r| r.get(0))
        .unwrap_or_else(|_| "unknown".to_string());

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": if check == "ok" { "healthy" } else { "corrupt" },
            "db_path": db_path.display().to_string(),
            "schema_version": schema,
            "quick_check": check,
            "built_at": built_at,
            "total_cves": total_cves,
            "kev_count": kev_count,
            "total_writeups": total_writeups,
            "writeups_with_text": writeups_with_text,
            "total_packages": total_packages,
            "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0
        }))?
    );
    Ok(())
}

fn clean_abs_path(p: &Path) -> PathBuf {
    let abs = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = abs.to_string_lossy();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
}

fn cmd_init_mcp(client: McpClientKind, repo_root: &Path) -> Result<()> {
    if client == McpClientKind::Artex {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "artexHttpServers": {
                    "cve-intel-mcp": "http://cve-intel-mcp:8901/mcp",
                    "patch-diff-mcp": "http://patch-diff-mcp:8902/mcp",
                    "scope-guard-mcp": "http://scope-guard-mcp:8903/mcp",
                    "attack-surface-mcp": "http://attack-surface-mcp:8904/mcp"
                }
            }))?
        );
        return Ok(());
    }

    let root = clean_abs_path(repo_root);
    let ext = if cfg!(windows) { ".exe" } else { "" };
    let cve_bin = root.join("target").join("release").join(format!("cve-intel-mcp{ext}"));
    let patch_bin = root.join("go").join("bin").join(format!("patch-diff-mcp{ext}"));
    let scope_bin = root.join("go").join("bin").join(format!("scope-guard-mcp{ext}"));
    let surface_bin = root.join("go").join("bin").join(format!("attack-surface-mcp{ext}"));
    let db_path = root.join("data").join("cve_kb_med_plus.sqlite");
    let cfg_dir = root.join("config");
    let state_dir = root.join("data").join("receipts");

    let output = if client == McpClientKind::Zcode {
        json!({
            "mcp": {
                "servers": {
                    "cve-intel-mcp": {
                        "type": "stdio",
                        "command": cve_bin,
                        "args": ["--transport", "stdio", "--db-path", db_path],
                        "timeoutMs": 30000
                    },
                    "patch-diff-mcp": {
                        "type": "stdio",
                        "command": patch_bin,
                        "args": ["--transport", "stdio"],
                        "timeoutMs": 30000
                    },
                    "scope-guard-mcp": {
                        "type": "stdio",
                        "command": scope_bin,
                        "args": ["--transport", "stdio", "--config-dir", cfg_dir, "--state-dir", state_dir],
                        "timeoutMs": 30000
                    },
                    "attack-surface-mcp": {
                        "type": "stdio",
                        "command": surface_bin,
                        "args": ["--transport", "stdio"],
                        "timeoutMs": 30000
                    }
                }
            }
        })
    } else {
        json!({
            "mcpServers": {
                "cve-intel-mcp": {
                    "command": cve_bin,
                    "args": ["--transport", "stdio", "--db-path", db_path]
                },
                "patch-diff-mcp": {
                    "command": patch_bin,
                    "args": ["--transport", "stdio"]
                },
                "scope-guard-mcp": {
                    "command": scope_bin,
                    "args": ["--transport", "stdio", "--config-dir", cfg_dir, "--state-dir", state_dir]
                },
                "attack-surface-mcp": {
                    "command": surface_bin,
                    "args": ["--transport", "stdio"]
                }
            }
        })
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3])
                    && let Ok(val) = u8::from_str_radix(hex_str, 16)
                {
                    out.push(val);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query_params(url: &str) -> (&str, HashMap<String, String>) {
    let Some((path, qs)) = url.split_once('?') else {
        return (url, HashMap::new());
    };
    let mut map = HashMap::new();
    for pair in qs.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(percent_decode(k), percent_decode(v));
    }
    (path, map)
}

fn api_stats(db_path: &Path) -> Result<Value> {
    let conn = open_readonly(db_path)?;
    let schema = detect_schema_version(&conn);
    let mut meta = serde_json::Map::new();
    let mut stmt = conn.prepare("SELECT key, value FROM metadata")?;
    for (k, v) in stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .flatten()
    {
        meta.insert(k, json!(v));
    }
    let mut by_sev = serde_json::Map::new();
    let mut sev_stmt = conn.prepare("SELECT cvss_severity, COUNT(*) FROM cves GROUP BY cvss_severity")?;
    for (k, v) in sev_stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .flatten()
    {
        by_sev.insert(k, json!(v));
    }
    let mut by_maturity = serde_json::Map::new();
    if schema >= 2 {
        let mut mat_stmt =
            conn.prepare("SELECT exploit_maturity, COUNT(*) FROM cves GROUP BY exploit_maturity")?;
        for (k, v) in mat_stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .flatten()
        {
            by_maturity.insert(k, json!(v));
        }
    }
    Ok(json!({
        "schema_version": schema,
        "metadata": meta,
        "by_severity": by_sev,
        "by_exploit_maturity": by_maturity
    }))
}

fn api_search(db_path: &Path, params: &HashMap<String, String>) -> Result<Value> {
    let start = Instant::now();
    let q = params.get("q").map(String::as_str).unwrap_or("");
    let mode = params.get("mode").map(String::as_str).unwrap_or("cves");
    let fts_q = sanitize_fts_query(q);
    if fts_q.is_empty() {
        return Ok(json!({"error": "Provide a non-empty search query."}));
    }
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(30)
        .clamp(1, 100);
    let conn = open_readonly(db_path)?;
    let schema = detect_schema_version(&conn);

    if mode == "writeups" {
        if schema < 2 {
            return Ok(json!({"error": "Writeup full-text search requires schema v2 DB."}));
        }
        let mut stmt = conn.prepare(
            "SELECT w.cve_id, c.cvss_score, c.cvss_severity, c.is_kev, w.source, w.url, w.title,
                    substr(w.content_excerpt, 1, 320)
             FROM writeups_fts wf
             JOIN writeups w ON w.id = wf.rowid
             JOIN cves c ON c.cve_id = w.cve_id
             WHERE writeups_fts MATCH ?1
             ORDER BY c.is_kev DESC, COALESCE(c.cvss_score, 8.0) DESC
             LIMIT ?2",
        )?;
        let rows: Vec<Value> = stmt
            .query_map(params![fts_q, limit], |r| {
                Ok(json!({
                    "cve_id": r.get::<_, String>(0)?,
                    "cvss_score": r.get::<_, Option<f64>>(1)?,
                    "cvss_severity": r.get::<_, String>(2)?,
                    "is_kev": r.get::<_, i64>(3)? == 1,
                    "source": r.get::<_, String>(4)?,
                    "url": r.get::<_, String>(5)?,
                    "title": r.get::<_, String>(6)?,
                    "excerpt": r.get::<_, String>(7)?
                }))
            })?
            .flatten()
            .collect();
        return Ok(json!({
            "query": q,
            "mode": "writeups",
            "count": rows.len(),
            "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0,
            "results": rows
        }));
    }

    let min_cvss = params
        .get("min_cvss")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(4.0)
        .max(4.0);
    let kev_only = params
        .get("kev")
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let cwe_opt = params
        .get("cwe")
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .map(|s| if s.starts_with("CWE-") { s } else { format!("CWE-{s}") });

    let maturity_col = if schema >= 2 {
        "c.exploit_maturity"
    } else {
        "CASE WHEN c.is_kev = 1 THEN 'KEV_EXPLOITED' ELSE 'NONE' END"
    };
    let mut sql = format!(
        "SELECT c.cve_id, c.title, c.cvss_score, c.cvss_severity, c.is_kev, {maturity_col},
                substr(c.description, 1, 260)
         FROM cves_fts f
         JOIN cves c ON c.rowid = f.rowid
         WHERE cves_fts MATCH ?
           AND (c.cvss_score >= ? OR (c.cvss_score IS NULL AND c.is_kev = 1))"
    );
    let mut sql_params: Vec<rusqlite::types::Value> = vec![fts_q.into(), min_cvss.into()];

    if let Some(cwe_id) = cwe_opt {
        if schema >= 2 {
            sql.push_str(" AND EXISTS (SELECT 1 FROM cve_cwes cc WHERE cc.cve_id = c.cve_id AND cc.cwe_id = ?)");
            sql_params.push(cwe_id.into());
        } else {
            sql.push_str(" AND (',' || UPPER(c.cwe_ids) || ',') LIKE ?");
            sql_params.push(format!("%,{cwe_id},%").into());
        }
    }
    if kev_only {
        sql.push_str(" AND c.is_kev = 1");
    }
    sql.push_str(" ORDER BY c.is_kev DESC, COALESCE(c.cvss_score, 8.0) DESC, COALESCE(c.epss_score, 0.0) DESC LIMIT ?");
    sql_params.push(limit.into());

    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<Value> = stmt
        .query_map(params_from_iter(sql_params.iter()), |r| {
            Ok(json!({
                "cve_id": r.get::<_, String>(0)?,
                "title": r.get::<_, String>(1)?,
                "cvss_score": r.get::<_, Option<f64>>(2)?,
                "cvss_severity": r.get::<_, String>(3)?,
                "is_kev": r.get::<_, i64>(4)? == 1,
                "exploit_maturity": r.get::<_, String>(5)?,
                "summary": r.get::<_, String>(6)?
            }))
        })?
        .flatten()
        .collect();

    Ok(json!({
        "query": q,
        "mode": "cves",
        "count": rows.len(),
        "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0,
        "results": rows
    }))
}

fn api_cve_detail(db_path: &Path, raw_id: &str) -> Result<Value> {
    let cid = percent_decode(raw_id).trim().to_uppercase();
    let conn = open_readonly(db_path)?;
    let schema = detect_schema_version(&conn);
    let maturity_col = if schema >= 2 {
        "exploit_maturity"
    } else {
        "CASE WHEN is_kev = 1 THEN 'KEV_EXPLOITED' ELSE 'NONE' END"
    };
    let sql = format!(
        "SELECT cve_id, published_date, modified_date, cvss_score, cvss_severity, cvss_vector,
                epss_score, is_kev, {maturity_col}, title, description
         FROM cves WHERE cve_id = ?1"
    );
    let mut record = match conn.query_row(&sql, [&cid], |r| {
        Ok(json!({
            "found": true,
            "cve_id": r.get::<_, String>(0)?,
            "published_date": r.get::<_, String>(1)?,
            "modified_date": r.get::<_, String>(2)?,
            "cvss_score": r.get::<_, Option<f64>>(3)?,
            "cvss_severity": r.get::<_, String>(4)?,
            "cvss_vector": r.get::<_, String>(5)?,
            "epss_score": r.get::<_, Option<f64>>(6)?,
            "is_kev": r.get::<_, i64>(7)? == 1,
            "exploit_maturity": r.get::<_, String>(8)?,
            "title": r.get::<_, String>(9)?,
            "description": r.get::<_, String>(10)?
        }))
    }) {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(json!({"found": false, "cve_id": cid})),
        Err(e) => return Err(e.into()),
    };

    if schema >= 2 {
        let mut cwe_stmt = conn.prepare("SELECT cwe_id FROM cve_cwes WHERE cve_id = ?1 ORDER BY cwe_id")?;
        let cwes: Vec<String> = cwe_stmt
            .query_map([&cid], |r| r.get::<_, String>(0))?
            .flatten()
            .collect();
        record["cwes"] = json!(cwes);

        let mut pkg_stmt = conn.prepare(
            "SELECT ecosystem, package_name, introduced_ver, fixed_ver, advisory_id
             FROM cve_packages WHERE cve_id = ?1 ORDER BY ecosystem, package_name",
        )?;
        let pkgs: Vec<Value> = pkg_stmt
            .query_map([&cid], |r| {
                Ok(json!({
                    "ecosystem": r.get::<_, String>(0)?,
                    "package_name": r.get::<_, String>(1)?,
                    "introduced_ver": r.get::<_, String>(2)?,
                    "fixed_ver": r.get::<_, String>(3)?,
                    "advisory_id": r.get::<_, String>(4)?
                }))
            })?
            .flatten()
            .collect();
        record["packages"] = json!(pkgs);
    }

    let excerpt_col = if schema >= 2 { "content_excerpt" } else { "''" };
    let wu_sql = format!(
        "SELECT source, url, title, has_patch_diff, {excerpt_col}
         FROM writeups WHERE cve_id = ?1
         ORDER BY length({excerpt_col}) DESC, has_patch_diff DESC LIMIT 50"
    );
    let mut wu_stmt = conn.prepare(&wu_sql)?;
    let writeups: Vec<Value> = wu_stmt
        .query_map([&cid], |r| {
            Ok(json!({
                "source": r.get::<_, String>(0)?,
                "url": r.get::<_, String>(1)?,
                "title": r.get::<_, String>(2)?,
                "has_patch_diff": r.get::<_, i64>(3)? == 1,
                "content_excerpt": r.get::<_, String>(4)?
            }))
        })?
        .flatten()
        .collect();
    record["writeups"] = json!(writeups);
    Ok(record)
}

fn api_package_check(db_path: &Path, params: &HashMap<String, String>) -> Result<Value> {
    let start = Instant::now();
    let eco = params.get("ecosystem").map(String::as_str).unwrap_or("").trim();
    let name = params.get("name").map(String::as_str).unwrap_or("").trim();
    let ver = params.get("version").map(String::as_str).unwrap_or("").trim();
    if eco.is_empty() || name.is_empty() || ver.is_empty() {
        return Ok(json!({"error": "ecosystem, name, and version are required."}));
    }
    let conn = open_readonly(db_path)?;
    if detect_schema_version(&conn) < 2 {
        return Ok(json!({"error": "Package checking requires schema v2 DB."}));
    }
    let mut stmt = conn.prepare(
        "SELECT p.cve_id, p.introduced_ver, p.fixed_ver, p.advisory_id,
                c.cvss_score, c.cvss_severity, c.is_kev, c.title
         FROM cve_packages p
         JOIN cves c ON c.cve_id = p.cve_id
         WHERE LOWER(p.ecosystem) = LOWER(?1) AND LOWER(p.package_name) = LOWER(?2)
         ORDER BY c.is_kev DESC, COALESCE(c.cvss_score, 8.0) DESC",
    )?;
    let rows = stmt.query_map(params![eco, name], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<f64>>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, i64>(6)? == 1,
            r.get::<_, String>(7)?,
        ))
    })?;
    let mut vulns = Vec::new();
    for (cve_id, intro, fixed, adv, score, sev, is_kev, title) in rows.flatten() {
        if is_version_affected(ver, &intro, &fixed) == Some(true) {
            vulns.push(json!({
                "cve_id": cve_id,
                "advisory_id": adv,
                "introduced_ver": intro,
                "fixed_ver": fixed,
                "cvss_score": score,
                "cvss_severity": sev,
                "is_kev": is_kev,
                "title": title
            }));
        }
    }
    Ok(json!({
        "ecosystem": eco,
        "package_name": name,
        "installed_version": ver,
        "vulnerable": !vulns.is_empty(),
        "count": vulns.len(),
        "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0,
        "vulnerabilities": vulns
    }))
}

fn json_response(status: u16, body: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let hdr = Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
    let cors = Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap();
    Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(hdr)
        .with_header(cors)
}

fn api_receipts(receipts_dir: &Path) -> Result<Value> {
    let ledger_path = receipts_dir.join("receipts.jsonl");
    if !ledger_path.exists() {
        return Ok(json!({"count": 0, "chain_valid": true, "receipts": []}));
    }
    let raw = fs::read_to_string(&ledger_path)?;
    let mut entries = Vec::new();
    let mut expected_prev = "GENESIS".to_string();
    let mut chain_valid = true;
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let val: Value = serde_json::from_str(trimmed)?;
        let prev = val.get("prev_sha256").and_then(|v| v.as_str()).unwrap_or("");
        let seq = val.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
        if seq != (idx as u64) + 1 || prev != expected_prev {
            chain_valid = false;
        }
        expected_prev = val
            .get("sha256")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        entries.push(val);
    }
    Ok(json!({
        "count": entries.len(),
        "chain_valid": chain_valid,
        "head_sha256": expected_prev,
        "receipts": entries,
    }))
}

fn api_playbooks(knowledge_dir: &Path) -> Result<Value> {
    let mut items = Vec::new();
    if knowledge_dir.exists() {
        for entry in WalkDir::new(knowledge_dir).max_depth(3).into_iter().flatten() {
            if entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("md"))
            {
                let rel = entry
                    .path()
                    .strip_prefix(knowledge_dir)
                    .unwrap_or(entry.path())
                    .display()
                    .to_string()
                    .replace('\\', "/");
                let text = fs::read_to_string(entry.path()).unwrap_or_default();
                let title = text
                    .lines()
                    .find(|l| l.starts_with('#'))
                    .map(|l| l.trim_start_matches('#').trim().to_string())
                    .unwrap_or_else(|| rel.clone());
                items.push(json!({
                    "path": rel,
                    "title": title,
                    "bytes": text.len(),
                    "preview": text.chars().take(600).collect::<String>(),
                }));
            }
        }
    }
    Ok(json!({"count": items.len(), "playbooks": items}))
}

fn serve_dashboard(
    server: Arc<Server>,
    db_path: PathBuf,
    receipts_dir: PathBuf,
    knowledge_dir: PathBuf,
) {
    for request in server.incoming_requests() {
        if *request.method() == Method::Options {
            let cors = Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap();
            let methods = Header::from_bytes("Access-Control-Allow-Methods", "GET, OPTIONS").unwrap();
            let _ = request.respond(
                Response::from_string("")
                    .with_status_code(204)
                    .with_header(cors)
                    .with_header(methods),
            );
            continue;
        }
        if *request.method() != Method::Get && *request.method() != Method::Head {
            let _ = request.respond(Response::from_string("Method Not Allowed").with_status_code(405));
            continue;
        }
        let full_url = request.url().to_string();
        let (path, qparams) = parse_query_params(&full_url);
        let resp = match path {
            "/" | "/index.html" => {
                let hdr = Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap();
                Response::from_string(DASHBOARD_HTML).with_header(hdr)
            }
            "/api/stats" => match api_stats(&db_path) {
                Ok(v) => json_response(200, v),
                Err(e) => json_response(500, json!({"error": e.to_string()})),
            },
            "/api/search" => match api_search(&db_path, &qparams) {
                Ok(v) => json_response(200, v),
                Err(e) => json_response(500, json!({"error": e.to_string()})),
            },
            "/api/package" => match api_package_check(&db_path, &qparams) {
                Ok(v) => json_response(200, v),
                Err(e) => json_response(500, json!({"error": e.to_string()})),
            },
            "/api/receipts" => match api_receipts(&receipts_dir) {
                Ok(v) => json_response(200, v),
                Err(e) => json_response(500, json!({"error": e.to_string()})),
            },
            "/api/playbooks" => match api_playbooks(&knowledge_dir) {
                Ok(v) => json_response(200, v),
                Err(e) => json_response(500, json!({"error": e.to_string()})),
            },
            p if p.starts_with("/api/cve/") => {
                let cid = p.trim_start_matches("/api/cve/");
                match api_cve_detail(&db_path, cid) {
                    Ok(v) => json_response(200, v),
                    Err(e) => json_response(500, json!({"error": e.to_string()})),
                }
            }
            _ => Response::from_string("Not Found").with_status_code(404),
        };
        let _ = request.respond(resp);
    }
}

fn cmd_serve(
    host: &str,
    port: u16,
    db_path: PathBuf,
    receipts_dir: PathBuf,
    knowledge_dir: PathBuf,
) -> Result<()> {
    let _ = open_readonly(&db_path)?;
    let addr = format!("{host}:{port}");
    let server = Arc::new(Server::http(&addr).map_err(|e| anyhow::anyhow!("binding {addr}: {e}"))?);
    eprintln!("[+] ARTEX-Nexus Offline Web Console listening on http://{addr}");
    serve_dashboard(server, db_path, receipts_dir, knowledge_dir);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Build {
            source_dir,
            trickest_dir,
            nuclei_dir,
            osv_dir,
            out,
            min_cvss,
            limit,
            skip_kev,
            skip_epss,
            compress,
        } => {
            let start = Instant::now();
            let client = http_client()?;
            let kev_map = if skip_kev {
                HashMap::new()
            } else {
                fetch_kev_map(&client)?
            };
            let epss_map = if skip_epss {
                HashMap::new()
            } else {
                fetch_epss_map(&client)?
            };

            let mut json_paths: Vec<PathBuf> = WalkDir::new(&source_dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_type().is_file()
                        && e.file_name()
                            .to_str()
                            .is_some_and(|n| n.starts_with("CVE-") && n.ends_with(".json"))
                })
                .map(|e| e.into_path())
                .collect();
            if let Some(lim) = limit {
                json_paths.truncate(lim);
            }

            let records: Vec<CveRecord> = json_paths
                .par_iter()
                .filter_map(|p| {
                    let bytes = fs::read(p).ok()?;
                    let val: Value = serde_json::from_slice(&bytes).ok()?;
                    parse_cve5_value(&val, &kev_map, &epss_map, min_cvss)
                })
                .collect();

            let mut stats = write_records_to_db(
                &out,
                &records,
                min_cvss,
                trickest_dir.as_deref(),
                nuclei_dir.as_deref(),
                osv_dir.as_deref(),
            )?;
            stats["elapsed_ms"] = serde_json::json!(start.elapsed().as_millis());
            println!("{}", serde_json::to_string_pretty(&stats)?);

            if compress {
                let (archive, sha256) = compress_zstd(&out)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "archive": archive.display().to_string(),
                        "sha256": sha256
                    }))?
                );
            }
        }
        Command::Fetch {
            repo,
            tag,
            out,
            force,
        } => cmd_fetch(&repo, &tag, &out, force)?,
        Command::SeedKev { out } => cmd_seed_kev(&out)?,
        Command::Scan {
            path,
            db,
            json,
            sarif,
            fail_on,
        } => cmd_scan(&path, &db, json, sarif.as_deref(), fail_on)?,
        Command::Doctor { db } => cmd_doctor(&db)?,
        Command::InitMcp { client, repo_root } => cmd_init_mcp(client, &repo_root)?,
        Command::Serve {
            host,
            port,
            db,
            receipts_dir,
            knowledge_dir,
        } => cmd_serve(&host, port, db, receipts_dir, knowledge_dir)?,
        Command::Bootstrap {
            artex_url,
            password,
            setup_token,
            mcp_host,
            docker_network,
            knowledge_dir,
            data_dir,
            config_dir,
            proxy_url,
            planner_profile_id,
            worker_profile_id,
            reporter_max_turns,
            reporter_run_seconds,
            retester_max_turns,
            retester_run_seconds,
            rewrite_host,
            rewrite_header,
            dry_run,
        } => {
            let out = bootstrap::cmd_bootstrap(&bootstrap::BootstrapConfig {
                artex_url,
                password,
                setup_token,
                mcp_host,
                docker_network,
                knowledge_dir,
                data_dir,
                config_dir,
                proxy_url,
                planner_profile_id,
                worker_profile_id,
                reporter_max_turns,
                reporter_run_seconds,
                retester_max_turns,
                retester_run_seconds,
                rewrite_host,
                rewrite_header,
                dry_run,
            })?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn sample_cve(id: &str, score: Option<f64>, cwe: &str, state: &str) -> Value {
        let metrics = match score {
            Some(s) => serde_json::json!([{"cvssV3_1": {"version": "3.1", "baseScore": s, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]),
            None => serde_json::json!([]),
        };
        serde_json::json!({
            "cveMetadata": {"cveId": id, "state": state, "datePublished": "2026-01-10T00:00:00Z", "dateUpdated": "2026-01-12T00:00:00Z"},
            "containers": {
                "cna": {
                    "title": format!("Test {id} in AcmeProxy"),
                    "descriptions": [{"lang": "en", "value": "SSRF via unvalidated upstream redirect"}],
                    "affected": [{"vendor": "Acme", "product": "AcmeProxy", "versions": [{"version": "< 2.0"}]}],
                    "problemTypes": [{"descriptions": [{"cweId": cwe}]}],
                    "metrics": metrics,
                    "references": [
                        {"url": "https://github.com/acme/proxy/commit/1234567", "tags": ["patch"]},
                        {"url": "https://blog.acme.test/writeup", "tags": ["technical-description"]}
                    ]
                }
            }
        })
    }

    #[test]
    fn unscored_kev_has_null_cvss_not_fabricated() {
        let mut kev = HashMap::new();
        kev.insert(
            "CVE-2026-0001".to_string(),
            KevEntry {
                cve_id: "CVE-2026-0001".to_string(),
                vendor_project: "Acme".to_string(),
                product: "AcmeProxy".to_string(),
                vulnerability_name: "Unscored KEV".to_string(),
                date_added: "2026-01-11".to_string(),
                short_description: "Exploited in wild".to_string(),
                due_date: "2026-02-01".to_string(),
                notes: String::new(),
                cwes: vec!["CWE-79".to_string()],
            },
        );
        let rec = parse_cve5_value(&sample_cve("CVE-2026-0001", None, "CWE-79", "PUBLISHED"), &kev, &HashMap::new(), 4.0)
            .expect("unscored KEV must be kept");
        assert!(rec.cvss_score.is_none(), "must NOT invent fake CVSS score");
        assert_eq!(rec.cvss_severity, "KEV_UNSCORED");
        assert_eq!(rec.exploit_maturity, "KEV_EXPLOITED");

        // Low score non-KEV rejected
        assert!(parse_cve5_value(&sample_cve("CVE-2026-0002", Some(3.1), "CWE-79", "PUBLISHED"), &kev, &HashMap::new(), 4.0).is_none());
        // REJECTED state dropped
        assert!(parse_cve5_value(&sample_cve("CVE-2026-0003", Some(9.8), "CWE-79", "REJECTED"), &kev, &HashMap::new(), 4.0).is_none());
    }

    #[test]
    fn exact_cwe_table_and_osv_ingestion() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("test.sqlite");
        let osv_dir = dir.path().join("osv");
        fs::create_dir_all(&osv_dir).unwrap();
        fs::write(
            osv_dir.join("GHSA-test-1234.json"),
            serde_json::json!({
                "id": "GHSA-test-1234",
                "aliases": ["CVE-2026-1000"],
                "summary": "Prototype pollution in lodash-demo",
                "details": "Detailed root cause writeup explaining merge() prototype pollution.",
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "lodash-demo"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
                }]
            })
            .to_string(),
        )
        .unwrap();

        let r1 = parse_cve5_value(&sample_cve("CVE-2026-1000", Some(9.1), "CWE-79", "PUBLISHED"), &HashMap::new(), &HashMap::new(), 4.0).unwrap();
        let r2 = parse_cve5_value(&sample_cve("CVE-2026-1001", Some(8.2), "CWE-798", "PUBLISHED"), &HashMap::new(), &HashMap::new(), 4.0).unwrap();
        write_records_to_db(&db, &[r1, r2], 4.0, None, None, Some(&osv_dir)).unwrap();

        let conn = Connection::open(&db).unwrap();
        let cwe79: Vec<String> = conn
            .prepare("SELECT cve_id FROM cve_cwes WHERE cwe_id = 'CWE-79'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(cwe79, vec!["CVE-2026-1000"]); // Does NOT match CWE-798!

        let pkg_fixed: String = conn
            .query_row(
                "SELECT fixed_ver FROM cve_packages WHERE package_name = 'lodash-demo' AND ecosystem = 'npm'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pkg_fixed, "4.17.21");

        let wu_hit: String = conn
            .query_row(
                "SELECT cve_id FROM writeups_fts WHERE writeups_fts MATCH '\"prototype\"'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(wu_hit, "CVE-2026-1000");
    }

    #[test]
    fn parses_new_lockfile_formats_and_builds_sarif() {
        let dir = tempdir().unwrap();

        let yarn = dir.path().join("yarn.lock");
        fs::write(
            &yarn,
            "\"@babel/core@^7.0.0\":\n  version \"7.24.0\"\n\n\"lodash@^4.17.15\", lodash@^4.17.20:\n  version \"4.17.15\"\n",
        )
        .unwrap();
        let yarn_deps = parse_dependencies_from_file(&yarn);
        assert!(yarn_deps.contains(&("npm".to_string(), "@babel/core".to_string(), "7.24.0".to_string())));
        assert!(yarn_deps.contains(&("npm".to_string(), "lodash".to_string(), "4.17.15".to_string())));

        let pnpm = dir.path().join("pnpm-lock.yaml");
        fs::write(&pnpm, "packages:\n  '/lodash@4.17.15':\n  '@scope/pkg@1.2.3(react@18.0.0)':\n").unwrap();
        let pnpm_deps = parse_dependencies_from_file(&pnpm);
        assert!(pnpm_deps.contains(&("npm".to_string(), "lodash".to_string(), "4.17.15".to_string())));
        assert!(pnpm_deps.contains(&("npm".to_string(), "@scope/pkg".to_string(), "1.2.3".to_string())));

        let poetry = dir.path().join("poetry.lock");
        fs::write(&poetry, "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n").unwrap();
        assert_eq!(
            parse_dependencies_from_file(&poetry),
            vec![("PyPI".to_string(), "requests".to_string(), "2.31.0".to_string())]
        );

        let composer = dir.path().join("composer.lock");
        fs::write(&composer, r#"{"packages":[{"name":"symfony/http-kernel","version":"v6.4.0"}]}"#).unwrap();
        assert_eq!(
            parse_dependencies_from_file(&composer),
            vec![("Packagist".to_string(), "symfony/http-kernel".to_string(), "6.4.0".to_string())]
        );

        let pom = dir.path().join("pom.xml");
        fs::write(
            &pom,
            "<dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies>",
        )
        .unwrap();
        assert_eq!(
            parse_dependencies_from_file(&pom),
            vec![("Maven".to_string(), "org.apache.logging.log4j:log4j-core".to_string(), "2.14.1".to_string())]
        );

        let sarif = build_sarif_report(&[json!({
            "file": "package-lock.json",
            "ecosystem": "npm",
            "package": "lodash",
            "installed": "4.17.15",
            "fixed": "4.17.21",
            "cve_id": "CVE-2021-23337",
            "advisory_id": "GHSA-35jh-r3h4-6jhm",
            "cvss_score": 7.2,
            "severity": "HIGH",
            "is_kev": false,
            "epss_score": 0.2,
            "title": "Command Injection"
        })]);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "CVE-2021-23337");
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn dashboard_http_endpoints_work() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("dash.sqlite");
        let osv_dir = dir.path().join("osv");
        fs::create_dir_all(&osv_dir).unwrap();
        fs::write(
            osv_dir.join("GHSA-dash-0001.json"),
            serde_json::json!({
                "id": "GHSA-dash-0001",
                "aliases": ["CVE-2026-2000"],
                "summary": "Demo SSRF in lodash-demo",
                "details": "Detailed SSRF writeup body.",
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "lodash-demo"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
                }]
            })
            .to_string(),
        )
        .unwrap();
        let r1 = parse_cve5_value(
            &sample_cve("CVE-2026-2000", Some(9.1), "CWE-79", "PUBLISHED"),
            &HashMap::new(),
            &HashMap::new(),
            4.0,
        )
        .unwrap();
        write_records_to_db(&db, &[r1], 4.0, None, None, Some(&osv_dir)).unwrap();

        let server = Arc::new(Server::http("127.0.0.1:0").unwrap());
        let addr = server.server_addr().to_ip().unwrap();
        let srv_clone = Arc::clone(&server);
        let db_clone = db.clone();
        let receipts_dir = dir.path().join("receipts");
        let knowledge_dir = dir.path().join("knowledge");
        fs::create_dir_all(&receipts_dir).unwrap();
        fs::create_dir_all(&knowledge_dir).unwrap();
        fs::write(knowledge_dir.join("demo-playbook.md"), "# Demo Playbook\nCheck BOLA.\n").unwrap();
        std::thread::spawn(move || serve_dashboard(srv_clone, db_clone, receipts_dir, knowledge_dir));

        let client = Client::new();
        let html = client.get(format!("http://{addr}/")).send().unwrap().text().unwrap();
        assert!(html.contains("ARTEX-"));

        let stats: Value = client.get(format!("http://{addr}/api/stats")).send().unwrap().json().unwrap();
        assert_eq!(stats["metadata"]["total_cves"], "1");

        let search: Value = client
            .get(format!("http://{addr}/api/search?q=AcmeProxy%20SSRF&cwe=CWE-79"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(search["count"], 1);
        assert_eq!(search["results"][0]["cve_id"], "CVE-2026-2000");

        let detail: Value = client
            .get(format!("http://{addr}/api/cve/CVE-2026-2000"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(detail["found"], true);

        let pkg: Value = client
            .get(format!("http://{addr}/api/package?ecosystem=npm&name=lodash-demo&version=4.17.15"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(pkg["vulnerable"], true);
        assert_eq!(pkg["count"], 1);

        let receipts: Value = client
            .get(format!("http://{addr}/api/receipts"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(receipts["chain_valid"], true);

        let playbooks: Value = client
            .get(format!("http://{addr}/api/playbooks"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(playbooks["count"], 1);

        server.unblock();
    }

    #[test]
    fn bootstrap_prompt_merge_is_idempotent_and_dry_run_works() {
        let cfg = bootstrap::BootstrapConfig {
            artex_url: "http://127.0.0.1:8787".to_string(),
            password: "test".to_string(),
            setup_token: None,
            mcp_host: "127.0.0.1".to_string(),
            docker_network: false,
            knowledge_dir: "/opt/knowledge".to_string(),
            data_dir: "/data".to_string(),
            config_dir: "/config".to_string(),
            proxy_url: "http://127.0.0.1:8788".to_string(),
            planner_profile_id: Some(3),
            worker_profile_id: Some(2),
            reporter_max_turns: 15,
            reporter_run_seconds: 300,
            retester_max_turns: 25,
            retester_run_seconds: 600,
            rewrite_host: None,
            rewrite_header: None,
            dry_run: true,
        };
        let dry = bootstrap::cmd_bootstrap(&cfg).unwrap();
        assert_eq!(dry["dry_run"], true);
        let block = bootstrap::build_role_context("planner", &cfg).unwrap();
        assert!(block.contains("extract_js_endpoints"));
        assert!(block.contains("2–3 non-overlapping intents"));
        let once = bootstrap::merge_prompt("Base prompt.", &block);
        let twice = bootstrap::merge_prompt(&once, &block);
        assert_eq!(once, twice);
    }
}
