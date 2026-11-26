use anyhow::{Context, Result};
use chrono::Utc;
use flate2::read::GzDecoder;
use nexus_common::{
    AffectedProduct, CveRecord, PackageRange, SCHEMA_SQL, SCHEMA_VERSION, WriteupRecord,
    atomic_replace, severity_from_score,
};
use rayon::prelude::*;
use regex::Regex;
use reqwest::blocking::Client;
use rusqlite::{Connection, params};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use walkdir::WalkDir;

const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_CSV_GZ_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

pub const SYNC_USER_AGENT: &str = concat!("artex-nexus-sync/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Deserialize)]
struct KevFeed {
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevEntry {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(default)]
    pub vendor_project: String,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub vulnerability_name: String,
    #[serde(default)]
    pub date_added: String,
    #[serde(default)]
    pub short_description: String,
    #[serde(default)]
    pub due_date: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub cwes: Vec<String>,
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

pub fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent(SYNC_USER_AGENT)
        .build()?)
}

pub fn fetch_kev_map(client: &Client) -> Result<HashMap<String, KevEntry>> {
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

pub fn parse_epss_reader<R: Read>(reader: R) -> Result<HashMap<String, (f64, f64)>> {
    let mut csv_reader = csv::ReaderBuilder::new()
        .comment(Some(b'#'))
        .has_headers(true)
        .from_reader(BufReader::new(reader));
    let mut map = HashMap::with_capacity(280_000);
    let mut rec = csv::StringRecord::new();
    while csv_reader.read_record(&mut rec)? {
        if let (Some(cve), Some(epss), Some(pct)) = (rec.get(0), rec.get(1), rec.get(2))
            && let (Ok(e), Ok(p)) = (epss.trim().parse::<f64>(), pct.trim().parse::<f64>())
        {
            map.insert(cve.trim().to_uppercase(), (e, p));
        }
    }
    Ok(map)
}

pub fn fetch_epss_map(client: &Client) -> Result<HashMap<String, (f64, f64)>> {
    let resp = client
        .get(EPSS_CSV_GZ_URL)
        .send()
        .context("fetching FIRST EPSS feed")?
        .error_for_status()?;
    parse_epss_reader(GzDecoder::new(resp))
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
                && (0.0..=10.0).contains(&score)
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

fn host_matches(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

pub fn classify_reference(url: &str, tags: &[String]) -> (&'static str, bool) {
    let lower_tags: HashSet<String> = tags.iter().map(|t| t.to_lowercase()).collect();
    let has_patch =
        lower_tags.contains("patch") || patch_patterns().iter().any(|p| p.is_match(url));
    if has_patch {
        return ("patch", true);
    }
    if lower_tags.contains("exploit") || lower_tags.contains("poc") {
        return ("poc", false);
    }
    if lower_tags.contains("vendor-advisory") || lower_tags.contains("third-party-advisory") {
        return ("advisory", false);
    }
    if lower_tags.contains("technical-description") {
        return ("writeup", false);
    }
    if let Ok(parsed) = reqwest::Url::parse(url)
        && let Some(raw_host) = parsed.host_str()
    {
        let host = raw_host.to_ascii_lowercase();
        let path = parsed.path().to_ascii_lowercase();
        if host == "github.com" || host == "www.github.com" {
            if path.starts_with("/advisories/") || path.contains("/security/advisories/") {
                return ("advisory", false);
            }
            return ("reference", false);
        }
        let writeup_hosts = [
            "medium.com",
            "hackerone.com",
            "huntr.com",
            "googleprojectzero.blogspot.com",
            "bugs.chromium.org",
            "zerodayinitiative.com",
            "portswigger.net",
            "assetnote.io",
            "watchtowr.com",
            "projectdiscovery.io",
            "exploit-db.com",
        ];
        if host.starts_with("blog.") || writeup_hosts.iter().any(|d| host_matches(&host, d)) {
            return ("writeup", false);
        }
    }
    ("reference", false)
}

pub fn parse_cve5_value(
    val: &Value,
    kev_map: &HashMap<String, KevEntry>,
    epss_map: &HashMap<String, (f64, f64)>,
    min_cvss: f64,
) -> Option<CveRecord> {
    let meta = val.get("cveMetadata")?;
    if meta.get("state").and_then(Value::as_str) == Some("REJECTED") {
        return None;
    }
    let cve_id = meta
        .get("cveId")
        .and_then(Value::as_str)?
        .trim()
        .to_uppercase();
    if !cve_id.starts_with("CVE-") {
        return None;
    }

    let containers = val.get("containers")?;
    let cna = containers.get("cna").unwrap_or(&Value::Null);
    let (mut score, ver, mut sev, vec_str) = extract_cvss(containers);
    let kev_entry = kev_map.get(&cve_id);
    let is_kev = kev_entry.is_some();

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
        .or_else(|| {
            kev_entry
                .map(|k| k.vulnerability_name.as_str())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("")
        .to_string();

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

    let mut affected_products = Vec::new();
    if let Some(arr) = cna.get("affected").and_then(Value::as_array) {
        for item in arr.iter().take(25) {
            let vendor = item
                .get("vendor")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            let product = item
                .get("product")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            let versions: Vec<String> = item
                .get("versions")
                .and_then(Value::as_array)
                .map(|vs| {
                    vs.iter()
                        .filter_map(|v| {
                            let clean_ver = |key: &str| {
                                v.get(key)
                                    .and_then(Value::as_str)
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("n/a"))
                            };
                            let start = clean_ver("version");
                            let upper = clean_ver("lessThan")
                                .filter(|s| *s != "*")
                                .map(|u| format!("< {u}"))
                                .or_else(|| {
                                    clean_ver("lessThanOrEqual")
                                        .filter(|s| *s != "*")
                                        .map(|u| format!("<= {u}"))
                                });
                            match (start, upper) {
                                (Some(s), Some(u))
                                    if s == "0"
                                        || s == "*"
                                        || s.eq_ignore_ascii_case("unspecified") =>
                                {
                                    Some(u)
                                }
                                (Some(s), Some(u)) => Some(format!(">= {s}, {u}")),
                                (None, Some(u)) => Some(u),
                                (Some(s), None) => Some(s.to_string()),
                                (None, None) => None,
                            }
                        })
                        .take(10)
                        .collect()
                })
                .unwrap_or_default();
            if !vendor.is_empty() || !product.is_empty() {
                affected_products.push(AffectedProduct {
                    vendor,
                    product,
                    versions,
                });
            }
        }
    }

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
        published_date: meta
            .get("datePublished")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        modified_date: meta
            .get("dateUpdated")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
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

fn is_github_poc_url(url: &str, in_github_section: bool) -> bool {
    if !in_github_section {
        return false;
    }
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    if host != "github.com" && host != "www.github.com" {
        return false;
    }
    let path = parsed.path().to_ascii_lowercase();
    let non_poc_markers = [
        "/commit/",
        "/pull/",
        "/issues/",
        "/releases/",
        "/security/advisories/",
        "/discussions/",
        "/wiki/",
    ];
    if path.starts_with("/advisories/")
        || path.starts_with("/cveproject/")
        || non_poc_markers.iter().any(|m| path.contains(m))
    {
        return false;
    }
    let segs: Vec<&str> = parsed
        .path()
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    segs.len() >= 2
}

pub fn parse_trickest_markdown(cid: &str, text: &str) -> Vec<WriteupRecord> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut in_github_section = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            let heading = trimmed.trim_start_matches('#').trim().to_ascii_lowercase();
            in_github_section = heading == "github" || heading.starts_with("github ");
            continue;
        }
        for m in url_regex().find_iter(trimmed) {
            let url = m.as_str().trim_end_matches(&['.', ',', ';'][..]);
            if url.contains("nvd.nist.gov/vuln/detail") || url.contains("cve.mitre.org") {
                continue;
            }
            if !seen.insert(url.to_string()) {
                continue;
            }
            let has_patch = patch_patterns().iter().any(|p| p.is_match(url));
            let src = if has_patch {
                "trickest:patch"
            } else if is_github_poc_url(url, in_github_section) {
                "trickest:poc"
            } else {
                "trickest:writeup"
            };
            out.push(WriteupRecord {
                cve_id: cid.to_string(),
                source: src.to_string(),
                url: url.to_string(),
                title: String::new(),
                tags: "trickest".to_string(),
                has_patch_diff: has_patch,
                content_excerpt: String::new(),
            });
        }
    }
    out
}

fn ingest_trickest(
    conn: &mut Connection,
    trickest_dir: &Path,
    existing: &HashSet<String>,
) -> Result<usize> {
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
            parse_trickest_markdown(&cid, &text)
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

fn ingest_nuclei(
    conn: &mut Connection,
    nuclei_dir: &Path,
    existing: &HashSet<String>,
) -> Result<usize> {
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
            let rel = p
                .strip_prefix(nuclei_dir)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            let url =
                format!("https://github.com/projectdiscovery/nuclei-templates/blob/main/{rel}");
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
            "UPDATE cves SET exploit_maturity = 'NUCLEI_TEMPLATE'
             WHERE cve_id = ?1 AND exploit_maturity IN ('NONE', 'PATCH_ONLY')",
        )?;
        for (cid, stem, url) in &yaml_files {
            inserted += stmt.execute(params![cid, url, stem])?;
            upd.execute(params![cid])?;
        }
    }
    tx.commit()?;
    Ok(inserted)
}

fn ingest_osv(
    conn: &mut Connection,
    osv_dir: &Path,
    existing: &HashSet<String>,
) -> Result<(usize, usize)> {
    let json_files: Vec<PathBuf> = WalkDir::new(osv_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file() && e.path().extension().and_then(|s| s.to_str()) == Some("json")
        })
        .map(|e| e.into_path())
        .collect();

    let parsed: Vec<(Vec<PackageRange>, Vec<WriteupRecord>)> = json_files
        .par_iter()
        .filter_map(|p| {
            let raw = fs::read_to_string(p).ok()?;
            let v: Value = serde_json::from_str(&raw).ok()?;
            let adv_id = v
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
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
            let summary = v
                .get("summary")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let details = v
                .get("details")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
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
                                if rng
                                    .get("type")
                                    .and_then(Value::as_str)
                                    .is_some_and(|t| t.eq_ignore_ascii_case("GIT"))
                                {
                                    continue;
                                }
                                let mut intro: Option<String> = None;
                                if let Some(events) = rng.get("events").and_then(Value::as_array) {
                                    for ev in events {
                                        if let Some(i) =
                                            ev.get("introduced").and_then(Value::as_str)
                                        {
                                            if let Some(prev_intro) = intro.take() {
                                                pkgs.push(PackageRange {
                                                    cve_id: cid.clone(),
                                                    ecosystem: ecosystem.clone(),
                                                    package_name: pkg_name.clone(),
                                                    introduced_ver: prev_intro,
                                                    fixed_ver: String::new(),
                                                    advisory_id: adv_id.clone(),
                                                });
                                            }
                                            intro = Some(i.to_string());
                                        }
                                        let close_ver = ev
                                            .get("fixed")
                                            .or_else(|| ev.get("limit"))
                                            .and_then(Value::as_str)
                                            .map(ToOwned::to_owned)
                                            .or_else(|| {
                                                ev.get("last_affected")
                                                    .and_then(Value::as_str)
                                                    .map(|la| format!("<={la}"))
                                            });
                                        if let Some(fixed) = close_ver {
                                            let start_ver =
                                                intro.take().unwrap_or_else(|| "0".to_string());
                                            pkgs.push(PackageRange {
                                                cve_id: cid.clone(),
                                                ecosystem: ecosystem.clone(),
                                                package_name: pkg_name.clone(),
                                                introduced_ver: start_ver,
                                                fixed_ver: fixed,
                                                advisory_id: adv_id.clone(),
                                            });
                                        }
                                    }
                                }
                                if let Some(open_intro) = intro {
                                    pkgs.push(PackageRange {
                                        cve_id: cid.clone(),
                                        ecosystem: ecosystem.clone(),
                                        package_name: pkg_name.clone(),
                                        introduced_ver: open_intro,
                                        fixed_ver: String::new(),
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
            "INSERT INTO writeups (cve_id, source, url, title, tags, has_patch_diff, content_excerpt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(cve_id, source, url) DO UPDATE SET
               title = CASE WHEN length(excluded.title) > length(writeups.title) THEN excluded.title ELSE writeups.title END,
               tags = excluded.tags,
               has_patch_diff = MAX(writeups.has_patch_diff, excluded.has_patch_diff),
               content_excerpt = CASE WHEN length(excluded.content_excerpt) > length(writeups.content_excerpt) THEN excluded.content_excerpt ELSE writeups.content_excerpt END",
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

    conn.execute_batch(
        "INSERT INTO cves_fts(cves_fts) VALUES('rebuild');
         INSERT INTO writeups_fts(writeups_fts) VALUES('rebuild');",
    )?;

    let total_cves: i64 = conn.query_row("SELECT COUNT(*) FROM cves", [], |r| r.get(0))?;
    let total_writeups: i64 = conn.query_row("SELECT COUNT(*) FROM writeups", [], |r| r.get(0))?;
    let total_packages: i64 =
        conn.query_row("SELECT COUNT(*) FROM cve_packages", [], |r| r.get(0))?;
    let kev_count: i64 = conn.query_row("SELECT COUNT(*) FROM cves WHERE is_kev = 1", [], |r| {
        r.get(0)
    })?;
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
    conn.execute_batch("PRAGMA journal_mode = DELETE; PRAGMA optimize;")?;
    drop(conn);

    atomic_replace(&tmp_path, out)?;

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

pub fn compress_zstd(db_path: &Path) -> Result<(PathBuf, String)> {
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
    let sums_path = out_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("SHA256SUMS.txt");
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

pub fn cmd_seed_kev(out: &Path) -> Result<()> {
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
