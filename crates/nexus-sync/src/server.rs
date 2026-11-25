use anyhow::Result;
use http::{HeaderValue, Method, header};
use nexus_common::http_srv::{
    HttpRequest, HttpResponse, ServerConfig, serve_http_blocking,
};
#[cfg(test)]
use nexus_common::http_srv::{RunningServer, spawn_http_server};
use nexus_common::open_readonly;
use nexus_common::queries::{
    CachedDb, SearchCveOpts, norm_cwe, query_cve_details, query_kb_stats, query_package_vulns,
    query_search_cves, query_search_writeups, with_cached_db,
};
use serde::{Deserialize, Serialize};
use serde_json::ser::{CharEscape, CompactFormatter, Formatter};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use walkdir::WalkDir;

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Field order matches Go's `scope-guard-mcp` LedgerEntry so JSON serialization
/// produces identical bytes for SHA-256 verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub seq: u64,
    pub scope_id: String,
    pub finding_id: String,
    pub program: String,
    pub title: String,
    pub target: String,
    pub cwe: String,
    pub severity: String,
    pub cvss_vector: String,
    pub verification_command: String,
    pub observed_output_summary: String,
    pub remediation: String,
    pub recorded_at: String,
    pub prev_sha256: String,
    pub sha256: String,
}

/// Formatter matching Go's `encoding/json.Marshal` escaping (`\u0008`, `\u000c`,
/// `\u0026`, `\u003c`, `\u003e`, `\u2028`, `\u2029`).
struct GoJsonFormatter;

impl Formatter for GoJsonFormatter {
    fn write_char_escape<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        char_escape: CharEscape,
    ) -> io::Result<()> {
        match char_escape {
            CharEscape::Backspace => writer.write_all(b"\\u0008"),
            CharEscape::FormFeed => writer.write_all(b"\\u000c"),
            other => CompactFormatter.write_char_escape(writer, other),
        }
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        for ch in fragment.chars() {
            match ch {
                '&' => writer.write_all(b"\\u0026")?,
                '<' => writer.write_all(b"\\u003c")?,
                '>' => writer.write_all(b"\\u003e")?,
                '\u{2028}' => writer.write_all(b"\\u2028")?,
                '\u{2029}' => writer.write_all(b"\\u2029")?,
                _ => {
                    let mut buf = [0u8; 4];
                    writer.write_all(ch.encode_utf8(&mut buf).as_bytes())?;
                }
            }
        }
        Ok(())
    }
}

fn go_canonical_json(entry: &LedgerEntry) -> Result<Vec<u8>> {
    let mut clone = entry.clone();
    clone.sha256.clear();
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut out, GoJsonFormatter);
    clone.serialize(&mut ser)?;
    Ok(out)
}

pub fn compute_ledger_hash(entry: &LedgerEntry) -> Result<String> {
    let canonical = go_canonical_json(entry)?;
    let mut hasher = Sha256::new();
    hasher.update(entry.prev_sha256.as_bytes());
    hasher.update(b"|");
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize()))
}

pub fn default_cors_origins() -> Vec<String> {
    vec![
        "http://127.0.0.1:8787".to_string(),
        "http://localhost:8787".to_string(),
        "http://127.0.0.1:8088".to_string(),
        "http://localhost:8088".to_string(),
    ]
}

fn extract_origin_host(origin: &str) -> Option<String> {
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))?;
    let host_port = rest.split('/').next()?;
    if let Some(b) = host_port.strip_prefix('[') {
        let host = b.split(']').next()?;
        return Some(host.to_lowercase());
    }
    Some(host_port.split(':').next()?.to_lowercase())
}

fn extract_host_header(req: &HttpRequest) -> Option<String> {
    let raw = req.headers.get(header::HOST)?.to_str().ok()?.trim();
    if let Some(b) = raw.strip_prefix('[') {
        return b.split(']').next().map(str::to_lowercase);
    }
    raw.split(':').next().map(str::to_lowercase)
}

fn build_allowed_hosts(allowed_origins: &[String]) -> HashSet<String> {
    let mut hosts: HashSet<String> = ["127.0.0.1", "localhost", "::1"]
        .into_iter()
        .map(String::from)
        .collect();
    for o in allowed_origins {
        if let Some(h) = extract_origin_host(o) {
            hosts.insert(h);
        }
    }
    hosts
}

enum OriginCheck<'a> {
    None,
    Allowed(&'a str),
    Forbidden,
}

fn check_origin<'a>(req: &HttpRequest, allowed: &'a [String]) -> OriginCheck<'a> {
    let mut origins = Vec::new();
    for val in req.headers.get_all(header::ORIGIN) {
        let Ok(s) = val.to_str() else {
            return OriginCheck::Forbidden;
        };
        origins.push(s.trim());
    }
    if origins.is_empty() {
        return OriginCheck::None;
    }
    if origins.len() > 1 {
        return OriginCheck::Forbidden;
    }
    if origins[0].is_empty() {
        return OriginCheck::None;
    }
    match allowed
        .iter()
        .find(|o| o.eq_ignore_ascii_case(origins[0]))
        .map(String::as_str)
    {
        Some(matched) => OriginCheck::Allowed(matched),
        None => OriginCheck::Forbidden,
    }
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

fn api_search(db: &mut CachedDb, params: &HashMap<String, String>) -> Result<Value> {
    let q = params.get("q").map(String::as_str).unwrap_or("");
    let mode = params.get("mode").map(String::as_str).unwrap_or("cves");
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(30)
        .clamp(1, 100);
    let (conn, schema) = db.connection()?;

    if mode == "writeups" {
        return query_search_writeups(conn, schema, q, false, limit);
    }

    let min_cvss = params
        .get("min_cvss")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(4.0);
    let kev_only = params
        .get("kev")
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let cwe = params
        .get("cwe")
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(norm_cwe);

    query_search_cves(
        conn,
        schema,
        &SearchCveOpts {
            query: q,
            min_cvss,
            severity: None,
            cwe,
            kev_only,
            has_writeup: false,
            limit,
        },
    )
}

fn api_package_check(db: &mut CachedDb, params: &HashMap<String, String>) -> Result<Value> {
    let start = Instant::now();
    let eco = params.get("ecosystem").map(String::as_str).unwrap_or("").trim();
    let name = params.get("name").map(String::as_str).unwrap_or("").trim();
    let ver = params.get("version").map(String::as_str).unwrap_or("").trim();
    if eco.is_empty() || name.is_empty() || ver.is_empty() {
        return Ok(json!({"error": "ecosystem, name, and version are required."}));
    }
    let (conn, schema) = db.connection()?;
    if schema < 2 {
        return Ok(json!({"error": "Package checking requires schema v2 DB."}));
    }
    let vulns = query_package_vulns(conn, eco, name, ver)?;
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

pub fn api_receipts(receipts_dir: &Path) -> Result<Value> {
    let ledger_path = receipts_dir.join("receipts.jsonl");
    if !ledger_path.exists() {
        return Ok(json!({"count": 0, "chain_valid": true, "head_sha256": "GENESIS", "receipts": []}));
    }
    let raw = fs::read_to_string(&ledger_path)?;
    let mut entries = Vec::new();
    let mut expected_prev = "GENESIS".to_string();
    let mut chain_valid = true;
    let mut entry_num: u64 = 0;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        entry_num += 1;
        let entry: LedgerEntry = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => {
                chain_valid = false;
                continue;
            }
        };
        let recomputed = compute_ledger_hash(&entry).unwrap_or_default();
        if entry.seq != entry_num || entry.prev_sha256 != expected_prev || entry.sha256 != recomputed {
            chain_valid = false;
        }
        expected_prev = entry.sha256.clone();
        entries.push(serde_json::to_value(&entry)?);
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

fn json_response(status: u16, body: Value, cors_origin: Option<&str>) -> HttpResponse {
    let mut resp = HttpResponse::json(status, &body);
    if let Some(origin) = cors_origin {
        resp = resp
            .with_header("Access-Control-Allow-Origin", origin)
            .with_header("Vary", "Origin");
    }
    resp
}

fn handle_dashboard_request(
    req: HttpRequest,
    db_path: &Path,
    receipts_dir: &Path,
    knowledge_dir: &Path,
    allowed_origins: &[String],
    allowed_hosts: &HashSet<String>,
) -> HttpResponse {
    // Reject DNS-rebinding requests carrying an unknown Host header.
    if let Some(host) = extract_host_header(&req)
        && !allowed_hosts.contains(&host)
    {
        return HttpResponse::text(403, "Forbidden host");
    }

    let origin_check = check_origin(&req, allowed_origins);
    let cors = match origin_check {
        OriginCheck::Allowed(o) => Some(o),
        OriginCheck::None => None,
        OriginCheck::Forbidden => {
            if req.method == Method::OPTIONS || req.uri.starts_with("/api/") {
                return HttpResponse::text(403, "Forbidden origin");
            }
            None
        }
    };

    if req.method == Method::OPTIONS {
        let mut resp = HttpResponse::empty(204)
            .with_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
        if let Some(origin) = cors {
            resp = resp
                .with_header("Access-Control-Allow-Origin", origin)
                .with_header("Vary", "Origin");
        }
        return resp;
    }
    if req.method != Method::GET && req.method != Method::HEAD {
        return HttpResponse::text(405, "Method Not Allowed");
    }

    let full_url = req.uri.clone();
    let (path, qparams) = parse_query_params(&full_url);
    match path {
        "/" | "/index.html" => HttpResponse::html(200, DASHBOARD_HTML),
        "/api/stats" => match with_cached_db(db_path, |db| {
            let (c, s) = db.connection()?;
            query_kb_stats(c, s)
        }) {
            Ok(v) => json_response(200, v, cors),
            Err(e) => json_response(500, json!({"error": e.to_string()}), cors),
        },
        "/api/search" => match with_cached_db(db_path, |db| api_search(db, &qparams)) {
            Ok(v) => json_response(200, v, cors),
            Err(e) => json_response(500, json!({"error": e.to_string()}), cors),
        },
        "/api/package" => match with_cached_db(db_path, |db| api_package_check(db, &qparams)) {
            Ok(v) => json_response(200, v, cors),
            Err(e) => json_response(500, json!({"error": e.to_string()}), cors),
        },
        "/api/receipts" => match api_receipts(receipts_dir) {
            Ok(v) => json_response(200, v, cors),
            Err(e) => json_response(500, json!({"error": e.to_string()}), cors),
        },
        "/api/playbooks" => match api_playbooks(knowledge_dir) {
            Ok(v) => json_response(200, v, cors),
            Err(e) => json_response(500, json!({"error": e.to_string()}), cors),
        },
        p if p.starts_with("/api/cve/") => {
            let cid = percent_decode(p.trim_start_matches("/api/cve/"));
            match with_cached_db(db_path, |db| {
                let (c, s) = db.connection()?;
                query_cve_details(c, s, &cid)
            }) {
                Ok(v) => json_response(200, v, cors),
                Err(e) => json_response(500, json!({"error": e.to_string()}), cors),
            }
        }
        _ => HttpResponse::text(404, "Not Found"),
    }
}

fn filter_valid_origins(allowed_origins: Vec<String>) -> Vec<String> {
    allowed_origins
        .into_iter()
        .filter(|o| HeaderValue::from_str(o).is_ok())
        .collect()
}

#[cfg(test)]
pub fn spawn_dashboard(
    bind_addr: &str,
    db_path: PathBuf,
    receipts_dir: PathBuf,
    knowledge_dir: PathBuf,
    allowed_origins: Vec<String>,
) -> Result<RunningServer> {
    let origins = Arc::new(filter_valid_origins(allowed_origins));
    let hosts = Arc::new(build_allowed_hosts(&origins));
    let db_path = Arc::new(db_path);
    let receipts_dir = Arc::new(receipts_dir);
    let knowledge_dir = Arc::new(knowledge_dir);

    spawn_http_server(bind_addr, ServerConfig::default(), move |req| {
        handle_dashboard_request(req, &db_path, &receipts_dir, &knowledge_dir, &origins, &hosts)
    })
}

pub fn cmd_serve(
    host: &str,
    port: u16,
    db_path: PathBuf,
    receipts_dir: PathBuf,
    knowledge_dir: PathBuf,
    cors_origins: Vec<String>,
) -> Result<()> {
    let _ = open_readonly(&db_path)?;
    let addr = format!("{host}:{port}");
    let mut origins = if cors_origins.is_empty() {
        default_cors_origins()
    } else {
        cors_origins
    };
    // If bound to an explicit non-wildcard host (e.g. a LAN IP), allow same-origin console access.
    if host != "0.0.0.0" && host != "::" {
        let self_origin = format!("http://{host}:{port}");
        if !origins.iter().any(|o| o.eq_ignore_ascii_case(&self_origin)) {
            origins.push(self_origin);
        }
    }
    let origins = Arc::new(filter_valid_origins(origins));
    let hosts = Arc::new(build_allowed_hosts(&origins));
    let db_path = Arc::new(db_path);
    let receipts_dir = Arc::new(receipts_dir);
    let knowledge_dir = Arc::new(knowledge_dir);

    eprintln!("[+] ARTEX-Nexus Web Console listening on http://{addr}");
    serve_http_blocking(&addr, ServerConfig::default(), move |req| {
        handle_dashboard_request(req, &db_path, &receipts_dir, &knowledge_dir, &origins, &hosts)
    })
}
