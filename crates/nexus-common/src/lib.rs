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

pub fn sanitize_fts_query(raw: &str) -> String {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
            if tokens.len() >= 12 {
                break;
            }
        }
    }
    if !current.is_empty() && tokens.len() < 12 {
        tokens.push(current);
    }
    tokens
        .into_iter()
        .map(|t| format!("\"{}\"", t.replace('"', "")))
        .collect::<Vec<_>>()
        .join(" AND ")
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
    conn.execute_batch("PRAGMA query_only = ON; PRAGMA mmap_size = 268435456; PRAGMA cache_size = -64000;")?;
    Ok(conn)
}

pub fn detect_schema_version(conn: &Connection) -> u32 {
    let has_cve_cwes: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='cve_cwes')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if has_cve_cwes { 2 } else { 1 }
}

/// Replaces `dst` with `src` atomically on Unix (POSIX rename overwrites in place).
pub fn atomic_replace(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::rename(src, dst)
    }
    #[cfg(not(unix))]
    {
        if dst.exists() {
            std::fs::remove_file(dst)?;
        }
        std::fs::rename(src, dst)
    }
}
