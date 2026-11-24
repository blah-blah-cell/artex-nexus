use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use flate2::read::GzDecoder;
use nexus_common::version::is_version_affected;
use nexus_common::{
    AffectedProduct, CveRecord, PackageRange, SCHEMA_SQL, SCHEMA_VERSION, WriteupRecord,
    detect_schema_version, open_readonly, severity_from_score,
};
use rayon::prelude::*;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{ETAG, IF_NONE_MATCH, USER_AGENT};
use rusqlite::{Connection, params};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_CSV_GZ_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const DEFAULT_REPO: &str = "blah-blah-cell/artex-nexus";
const DEFAULT_TAG: &str = "cve-db-latest";

#[derive(Parser)]
#[command(
    name = "nexus-sync",
    about = "High-throughput Rust CVE, OSV, KEV, EPSS & writeups DB builder and streaming fetcher"
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
        #[arg(long, default_value = ".", help = "Target directory or lockfile (package-lock.json, package.json, requirements.txt, go.mod, Cargo.lock)")]
        path: PathBuf,
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        db: PathBuf,
        #[arg(long, help = "Output raw JSON instead of human-readable summary")]
        json: bool,
    },
    /// Run health, schema, integrity, and coverage diagnostics on the local ARTEX-Nexus DB
    Doctor {
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        db: PathBuf,
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
        _ => {}
    }
    deps
}

fn cmd_scan(path: &Path, db_path: &Path, as_json: bool) -> Result<()> {
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
                        Some("package-lock.json" | "package.json" | "requirements.txt" | "go.mod" | "Cargo.lock")
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
        Command::Scan { path, db, json } => cmd_scan(&path, &db, json)?,
        Command::Doctor { db } => cmd_doctor(&db)?,
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
}
