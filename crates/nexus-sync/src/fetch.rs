use crate::ingest::{SYNC_USER_AGENT, http_client};
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use nexus_common::atomic_replace;
use reqwest::header::{ETAG, IF_NONE_MATCH, USER_AGENT};
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::time::Instant;

pub fn cmd_fetch(
    repo: &str,
    tag: &str,
    out: &Path,
    force: bool,
    allow_unverified: bool,
) -> Result<()> {
    let start = Instant::now();
    let client = http_client()?;
    let cache_dir = out.parent().unwrap_or(Path::new("data")).join(".cache");
    fs::create_dir_all(&cache_dir)?;
    let etag_file = cache_dir.join("release.etag");

    let api_url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
    let mut req = client.get(&api_url).header(USER_AGENT, SYNC_USER_AGENT);
    if !force && out.exists() && etag_file.exists() {
        let etag = fs::read_to_string(&etag_file)?.trim().to_string();
        if !etag.is_empty() {
            req = req.header(IF_NONE_MATCH, etag);
        }
    }

    let resp = req.send().context("querying GitHub Release metadata")?;
    if resp.status().as_u16() == 304 && out.exists() {
        eprintln!(
            "[+] Local DB is already up to date (HTTP 304 in {}ms): {}",
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

    if expected_sha.is_none() && !allow_unverified {
        anyhow::bail!(
            "SHA256SUMS.txt missing or has no entry for {asset_name} in {repo}@{tag} (pass --allow-unverified to override)"
        );
    }

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
        anyhow::bail!("SHA-256 verification failed: expected {exp}, got {actual_sha}");
    }

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

    {
        let conn = Connection::open(&tmp_db)?;
        let check: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        drop(conn);
        if check != "ok" {
            fs::remove_file(&tmp_db).ok();
            anyhow::bail!("Decompressed SQLite quick_check failed: {check}");
        }
    }

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    atomic_replace(&tmp_db, out)?;
    if let Some(et) = new_etag {
        fs::write(&etag_file, et)?;
    }

    eprintln!(
        "[+] Decompressed and verified in {}ms -> {} (total {}ms)",
        dec_start.elapsed().as_millis(),
        out.display(),
        start.elapsed().as_millis()
    );
    Ok(())
}
