pub mod http_srv;
pub mod queries;
pub mod version;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const SCHEMA_SQL: &str = include_str!("schema.sql");
pub const SCHEMA_VERSION: &str = "2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedProduct {
    pub vendor: String,
    pub product: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteupRecord {
    pub cve_id: String,
    pub source: String,
    pub url: String,
    pub title: String,
    pub tags: String,
    pub has_patch_diff: bool,
    pub content_excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRange {
    pub cve_id: String,
    pub ecosystem: String,
    pub package_name: String,
    pub introduced_ver: String,
    pub fixed_ver: String,
    pub advisory_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveRecord {
    pub cve_id: String,
    pub published_date: String,
    pub modified_date: String,
    pub cvss_score: Option<f64>,
    pub cvss_version: String,
    pub cvss_severity: String,
    pub cvss_vector: String,
    pub cwe_ids: Vec<String>,
    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub is_kev: bool,
    pub kev_date_added: Option<String>,
    pub kev_due_date: Option<String>,
    pub exploit_maturity: String,
    pub title: String,
    pub description: String,
    pub affected_products: Vec<AffectedProduct>,
    pub writeups: Vec<WriteupRecord>,
}

pub fn severity_from_score(score: f64) -> &'static str {
    if score >= 9.0 {
        "CRITICAL"
    } else if score >= 7.0 {
        "HIGH"
    } else if score >= 4.0 {
        "MEDIUM"
    } else if score > 0.0 {
        "LOW"
    } else {
        "NONE"
    }
}

const FTS_STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "into", "is", "it", "of",
    "on", "or", "that", "the", "this", "to", "via", "when", "with",
];

pub fn sanitize_fts_query(raw: &str) -> String {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
            if tokens.len() >= 32 {
                break;
            }
        }
    }
    if !current.is_empty() && tokens.len() < 32 {
        tokens.push(current);
    }
    if tokens.len() > 4 {
        let filtered: Vec<String> = tokens
            .iter()
            .filter(|t| !FTS_STOPWORDS.contains(&t.to_ascii_lowercase().as_str()))
            .cloned()
            .collect();
        if !filtered.is_empty() {
            tokens = filtered;
        }
    }
    let mut seen = std::collections::HashSet::new();
    tokens.retain(|t| seen.insert(t.to_ascii_lowercase()));

    let joiner = if tokens.len() <= 4 { " AND " } else { " OR " };
    tokens
        .into_iter()
        .map(|t| format!("\"{}\"", t.replace('"', "")))
        .collect::<Vec<_>>()
        .join(joiner)
}

pub fn escape_like(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

pub fn normalize_pypi_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.trim().chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !prev_dash && !out.is_empty() {
                out.push('-');
                prev_dash = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        }
    }
    out.trim_end_matches('-').to_string()
}

pub fn open_readonly(path: &Path) -> Result<Connection> {
    if !path.exists() {
        anyhow::bail!(
            "CVE database not found at '{}'. Run `nexus-sync fetch` or `nexus-sync seed-kev` first.",
            path.display()
        );
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening SQLite DB at {}", path.display()))?;
    conn.execute_batch(
        "PRAGMA query_only = ON; PRAGMA mmap_size = 268435456; PRAGMA cache_size = -64000;",
    )?;
    Ok(conn)
}

pub fn detect_schema_version(conn: &Connection) -> Result<u32> {
    let has_cve_cwes: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='cve_cwes')",
            [],
            |r| r.get(0),
        )
        .context("detecting SQLite schema version")?;
    Ok(if has_cve_cwes { 2 } else { 1 })
}

/// Replaces `dst` with `src` without deleting `dst` first.
/// Uses POSIX `rename` on Unix and `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` on Windows.
pub fn atomic_replace(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::rename(src, dst)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
        unsafe extern "system" {
            fn MoveFileExW(src: *const u16, dst: *const u16, flags: u32) -> i32;
        }
        let src_w: Vec<u16> = src.as_os_str().encode_wide().chain(Some(0)).collect();
        let dst_w: Vec<u16> = dst.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: Both pointers are valid null-terminated UTF-16 buffers for the duration of the call.
        let ok = unsafe {
            MoveFileExW(
                src_w.as_ptr(),
                dst_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::rename(src, dst)
    }
}
