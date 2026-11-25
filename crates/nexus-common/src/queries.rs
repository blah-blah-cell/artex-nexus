use crate::version::is_version_affected;
use crate::{detect_schema_version, open_readonly, sanitize_fts_query};
use anyhow::Result;
use rusqlite::{Connection, params, params_from_iter};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

#[derive(Debug, Clone, Eq, PartialEq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    ino: u64,
}

fn read_file_stamp(path: &Path) -> Option<FileStamp> {
    let meta = fs::metadata(path).ok()?;
    #[cfg(unix)]
    let ino = {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    };
    Some(FileStamp {
        len: meta.len(),
        modified: meta.modified().ok(),
        #[cfg(unix)]
        ino,
    })
}

/// Per-thread read-only SQLite handle that reopens automatically when the DB file is swapped.
pub struct CachedDb {
    path: PathBuf,
    conn: Option<Connection>,
    schema: u32,
    stamp: Option<FileStamp>,
}

impl CachedDb {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            conn: None,
            schema: 0,
            stamp: None,
        }
    }

    pub fn connection(&mut self) -> Result<(&Connection, u32)> {
        let cur_stamp = read_file_stamp(&self.path);
        let stale = self.conn.is_none() || self.stamp != cur_stamp;
        if stale {
            let conn = open_readonly(&self.path)?;
            let schema = detect_schema_version(&conn);
            self.conn = Some(conn);
            self.schema = schema;
            self.stamp = cur_stamp;
        }
        Ok((self.conn.as_ref().expect("connection opened"), self.schema))
    }
}

thread_local! {
    static THREAD_DBS: RefCell<HashMap<PathBuf, CachedDb>> = RefCell::new(HashMap::new());
}

/// Runs `f` with a thread-local `CachedDb` for `path`, reopening automatically if the file changes.
pub fn with_cached_db<T>(path: &Path, f: impl FnOnce(&mut CachedDb) -> Result<T>) -> Result<T> {
    THREAD_DBS.with(|cell| {
        let mut map = cell.borrow_mut();
        let entry = map
            .entry(path.to_path_buf())
            .or_insert_with(|| CachedDb::new(path.to_path_buf()));
        f(entry)
    })
}

pub fn norm_cwe(raw: &str) -> String {
    let s = raw.trim().to_uppercase();
    if s.starts_with("CWE-") {
        s
    } else {
        format!("CWE-{s}")
    }
}

pub fn cwes_for_cve(conn: &Connection, schema: u32, cve_id: &str) -> Result<Vec<String>> {
    if schema >= 2 {
        let mut stmt =
            conn.prepare_cached("SELECT cwe_id FROM cve_cwes WHERE cve_id = ?1 ORDER BY cwe_id")?;
        let rows = stmt
            .query_map([cve_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    } else {
        match conn.query_row("SELECT cwe_ids FROM cves WHERE cve_id = ?1", [cve_id], |r| {
            r.get::<_, String>(0)
        }) {
            Ok(raw) => Ok(raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect()),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }
}

pub struct SearchCveOpts<'a> {
    pub query: &'a str,
    pub min_cvss: f64,
    pub severity: Option<String>,
    pub cwe: Option<String>,
    pub kev_only: bool,
    pub has_writeup: bool,
    pub limit: i64,
}

pub fn query_search_cves(conn: &Connection, schema: u32, opts: &SearchCveOpts<'_>) -> Result<Value> {
    let start = Instant::now();
    let fts_q = sanitize_fts_query(opts.query);
    if fts_q.is_empty() {
        return Ok(json!({"error": "Provide a non-empty search query."}));
    }
    let min_cvss = opts.min_cvss.max(4.0);
    let limit = opts.limit.clamp(1, 100);
    let maturity_col = if schema >= 2 {
        "c.exploit_maturity"
    } else {
        "CASE WHEN c.is_kev = 1 THEN 'KEV_EXPLOITED' ELSE 'NONE' END"
    };

    let mut sql = format!(
        "SELECT c.cve_id, c.title, c.cvss_score, c.cvss_severity, c.epss_score, c.is_kev,
                {maturity_col} AS exploit_maturity, c.published_date,
                substr(c.description, 1, 280) AS summary,
                (SELECT COUNT(*) FROM writeups w WHERE w.cve_id = c.cve_id) AS writeup_count
         FROM cves_fts f
         JOIN cves c ON c.rowid = f.rowid
         WHERE cves_fts MATCH ?
           AND (c.cvss_score >= ? OR c.is_kev = 1)"
    );
    let mut sql_params: Vec<rusqlite::types::Value> = vec![fts_q.into(), min_cvss.into()];

    if let Some(ref sev) = opts.severity {
        sql.push_str(" AND UPPER(c.cvss_severity) = ?");
        sql_params.push(sev.clone().into());
    }
    if let Some(ref cwe_id) = opts.cwe {
        if schema >= 2 {
            sql.push_str(" AND EXISTS (SELECT 1 FROM cve_cwes cc WHERE cc.cve_id = c.cve_id AND cc.cwe_id = ?)");
            sql_params.push(cwe_id.clone().into());
        } else {
            sql.push_str(" AND (',' || UPPER(c.cwe_ids) || ',') LIKE ?");
            sql_params.push(format!("%,{cwe_id},%").into());
        }
    }
    if opts.kev_only {
        sql.push_str(" AND c.is_kev = 1");
    }
    if opts.has_writeup {
        sql.push_str(" AND EXISTS (SELECT 1 FROM writeups w WHERE w.cve_id = c.cve_id)");
    }

    sql.push_str(
        " ORDER BY c.is_kev DESC, COALESCE(c.cvss_score, 8.0) DESC, COALESCE(c.epss_score, 0.0) DESC
          LIMIT ?",
    );
    sql_params.push(limit.into());

    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<Value> = stmt
        .query_map(params_from_iter(sql_params.iter()), |r| {
            Ok(json!({
                "cve_id": r.get::<_, String>(0)?,
                "title": r.get::<_, String>(1)?,
                "cvss_score": r.get::<_, Option<f64>>(2)?,
                "cvss_severity": r.get::<_, String>(3)?,
                "epss_score": r.get::<_, Option<f64>>(4)?,
                "is_kev": r.get::<_, i64>(5)? == 1,
                "exploit_maturity": r.get::<_, String>(6)?,
                "published_date": r.get::<_, String>(7)?,
                "summary": r.get::<_, String>(8)?,
                "writeup_count": r.get::<_, i64>(9)?
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(json!({
        "query": opts.query,
        "mode": "cves",
        "count": rows.len(),
        "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0,
        "results": rows
    }))
}

pub fn query_search_writeups(
    conn: &Connection,
    schema: u32,
    query: &str,
    patch_only: bool,
    limit: i64,
) -> Result<Value> {
    let start = Instant::now();
    let fts_q = sanitize_fts_query(query);
    if fts_q.is_empty() {
        return Ok(json!({"error": "Provide a non-empty search query."}));
    }
    if schema < 2 {
        return Ok(json!({
            "error": "Loaded DB is schema v1 (no writeups_fts). Run `nexus-sync fetch` for the v2 DB."
        }));
    }
    let limit = limit.clamp(1, 100);
    let patch_clause = if patch_only {
        "AND w.has_patch_diff = 1"
    } else {
        ""
    };
    let sql = format!(
        "SELECT w.cve_id, c.cvss_score, c.cvss_severity, c.is_kev, w.source, w.url, w.title,
                w.tags, w.has_patch_diff, substr(w.content_excerpt, 1, 400) AS excerpt
         FROM writeups_fts wf
         JOIN writeups w ON w.id = wf.rowid
         JOIN cves c ON c.cve_id = w.cve_id
         WHERE writeups_fts MATCH ?1 {patch_clause}
         ORDER BY c.is_kev DESC, COALESCE(c.cvss_score, 8.0) DESC, w.has_patch_diff DESC
         LIMIT ?2"
    );
    let mut stmt = conn.prepare(&sql)?;
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
                "tags": r.get::<_, String>(7)?,
                "has_patch_diff": r.get::<_, i64>(8)? == 1,
                "excerpt": r.get::<_, String>(9)?
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(json!({
        "query": query,
        "mode": "writeups",
        "count": rows.len(),
        "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0,
        "results": rows
    }))
}

pub fn query_cve_details(conn: &Connection, schema: u32, raw_cve_id: &str) -> Result<Value> {
    let cid = raw_cve_id.trim().to_uppercase();
    let maturity_col = if schema >= 2 {
        "exploit_maturity"
    } else {
        "CASE WHEN is_kev = 1 THEN 'KEV_EXPLOITED' ELSE 'NONE' END"
    };

    let sql = format!(
        "SELECT cve_id, published_date, modified_date, cvss_score, cvss_version, cvss_severity,
                cvss_vector, epss_score, epss_percentile, is_kev, kev_date_added, kev_due_date,
                {maturity_col}, title, description, affected_products
         FROM cves WHERE cve_id = ?1"
    );
    let row_opt = conn.query_row(&sql, [&cid], |r| {
        let aff_str: String = r.get(15)?;
        let aff: Value = serde_json::from_str(&aff_str).unwrap_or(json!([]));
        Ok(json!({
            "found": true,
            "cve_id": r.get::<_, String>(0)?,
            "published_date": r.get::<_, String>(1)?,
            "modified_date": r.get::<_, String>(2)?,
            "cvss_score": r.get::<_, Option<f64>>(3)?,
            "cvss_version": r.get::<_, String>(4)?,
            "cvss_severity": r.get::<_, String>(5)?,
            "cvss_vector": r.get::<_, String>(6)?,
            "epss_score": r.get::<_, Option<f64>>(7)?,
            "epss_percentile": r.get::<_, Option<f64>>(8)?,
            "is_kev": r.get::<_, i64>(9)? == 1,
            "kev_date_added": r.get::<_, Option<String>>(10)?,
            "kev_due_date": r.get::<_, Option<String>>(11)?,
            "exploit_maturity": r.get::<_, String>(12)?,
            "title": r.get::<_, String>(13)?,
            "description": r.get::<_, String>(14)?,
            "affected_products": aff
        }))
    });

    let mut record = match row_opt {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok(json!({"found": false, "cve_id": cid}));
        }
        Err(e) => return Err(e.into()),
    };

    record["cwes"] = json!(cwes_for_cve(conn, schema, &cid)?);

    let excerpt_col = if schema >= 2 { "content_excerpt" } else { "''" };
    let wu_sql = format!(
        "SELECT source, url, title, tags, has_patch_diff, {excerpt_col}
         FROM writeups WHERE cve_id = ?1
         ORDER BY length({excerpt_col}) DESC, has_patch_diff DESC, source ASC LIMIT 50"
    );
    let mut wu_stmt = conn.prepare(&wu_sql)?;
    let writeups: Vec<Value> = wu_stmt
        .query_map([&cid], |r| {
            Ok(json!({
                "source": r.get::<_, String>(0)?,
                "url": r.get::<_, String>(1)?,
                "title": r.get::<_, String>(2)?,
                "tags": r.get::<_, String>(3)?,
                "has_patch_diff": r.get::<_, i64>(4)? == 1,
                "content_excerpt": r.get::<_, String>(5)?
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    record["writeups"] = json!(writeups);

    if schema >= 2 {
        let mut pkg_stmt = conn.prepare_cached(
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
            .collect::<rusqlite::Result<Vec<_>>>()?;
        record["packages"] = json!(pkgs);
    }

    Ok(record)
}

pub fn query_package_vulns(
    conn: &Connection,
    ecosystem: &str,
    package_name: &str,
    version: &str,
) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare_cached(
        "SELECT p.cve_id, p.ecosystem, p.package_name, p.introduced_ver, p.fixed_ver, p.advisory_id,
                c.cvss_score, c.cvss_severity, c.is_kev, c.epss_score, c.exploit_maturity, c.title
         FROM cve_packages p
         JOIN cves c ON c.cve_id = p.cve_id
         WHERE p.package_name = ?1 COLLATE NOCASE AND p.ecosystem = ?2 COLLATE NOCASE
         ORDER BY c.is_kev DESC, COALESCE(c.cvss_score, 8.0) DESC",
    )?;
    let mut findings = Vec::new();
    let rows = stmt.query_map(params![package_name, ecosystem], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, Option<f64>>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, i64>(8)? == 1,
            r.get::<_, Option<f64>>(9)?,
            r.get::<_, String>(10)?,
            r.get::<_, String>(11)?,
        ))
    })?;
    for row in rows {
        let (cve_id, eco, pkg, intro, fixed, adv, score, sev, is_kev, epss, mat, title) = row?;
        if is_version_affected(version, &intro, &fixed) == Some(true) {
            findings.push(json!({
                "cve_id": cve_id,
                "advisory_id": adv,
                "ecosystem": eco,
                "package_name": pkg,
                "installed_version": version,
                "introduced_ver": intro,
                "fixed_ver": fixed,
                "cvss_score": score,
                "cvss_severity": sev,
                "is_kev": is_kev,
                "epss_score": epss,
                "exploit_maturity": mat,
                "title": title
            }));
        }
    }
    Ok(findings)
}

pub fn query_kb_stats(conn: &Connection, schema: u32) -> Result<Value> {
    let mut meta = serde_json::Map::new();
    let mut stmt = conn.prepare_cached("SELECT key, value FROM metadata")?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (k, v) = row?;
        meta.insert(k, json!(v));
    }
    let mut by_sev = serde_json::Map::new();
    let mut sev_stmt = conn.prepare_cached("SELECT cvss_severity, COUNT(*) FROM cves GROUP BY cvss_severity")?;
    for row in sev_stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
        let (k, v) = row?;
        by_sev.insert(k, json!(v));
    }
    let mut by_maturity = serde_json::Map::new();
    if schema >= 2 {
        let mut mat_stmt =
            conn.prepare_cached("SELECT exploit_maturity, COUNT(*) FROM cves GROUP BY exploit_maturity")?;
        for row in mat_stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (k, v) = row?;
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
