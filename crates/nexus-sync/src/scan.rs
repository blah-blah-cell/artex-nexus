use crate::SeverityThreshold;
use anyhow::Result;
use nexus_common::version::{ParsedVersion, is_version_affected};
use nexus_common::{detect_schema_version, open_readonly};
use regex::Regex;
use rusqlite::params;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

fn collect_v1_npm_deps(map: &serde_json::Map<String, Value>, out: &mut Vec<(String, String, String)>) {
    for (name, val) in map {
        if let Some(ver) = val.get("version").and_then(Value::as_str) {
            out.push(("npm".to_string(), name.clone(), ver.to_string()));
        }
        if let Some(nested) = val.get("dependencies").and_then(Value::as_object) {
            collect_v1_npm_deps(nested, out);
        }
    }
}

pub fn parse_dependencies_from_file(path: &Path) -> Vec<(String, String, String)> {
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let raw = raw.strip_prefix('\u{FEFF}').unwrap_or(&raw);
    let mut deps = Vec::new();
    match fname {
        "package-lock.json" => {
            if let Ok(v) = serde_json::from_str::<Value>(raw) {
                if let Some(pkgs) = v.get("packages").and_then(Value::as_object) {
                    for (k, val) in pkgs {
                        if let Some(ver) = val.get("version").and_then(Value::as_str)
                            && let Some((_, tail)) = k.rsplit_once("node_modules/")
                            && !tail.is_empty()
                        {
                            let pkg_name = val
                                .get("name")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                                .unwrap_or(tail);
                            deps.push(("npm".to_string(), pkg_name.to_string(), ver.to_string()));
                        }
                    }
                } else if let Some(dmap) = v.get("dependencies").and_then(Value::as_object) {
                    collect_v1_npm_deps(dmap, &mut deps);
                }
            }
        }
        "package.json" => {
            if let Ok(v) = serde_json::from_str::<Value>(raw) {
                for key in ["dependencies", "devDependencies"] {
                    if let Some(map) = v.get(key).and_then(Value::as_object) {
                        for (name, ver) in map {
                            if let Some(vs) = ver.as_str()
                                && ParsedVersion::parse(vs).is_some()
                            {
                                // Only scan exact pinned versions; ranges (^, ~, >=) need a lockfile.
                                deps.push(("npm".to_string(), name.clone(), vs.trim().to_string()));
                            }
                        }
                    }
                }
            }
        }
        "requirements.txt" => {
            for line in raw.lines() {
                let no_comment = line.split('#').next().unwrap_or("");
                let no_marker = no_comment.split(';').next().unwrap_or("").trim();
                if no_marker.is_empty() || no_marker.starts_with('-') {
                    continue;
                }
                if let Some((pkg_part, ver_part)) = no_marker.split_once("==") {
                    let pkg = pkg_part.split('[').next().unwrap_or(pkg_part).trim();
                    let ver = ver_part
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim_end_matches('\\')
                        .trim();
                    if !pkg.is_empty() && !ver.is_empty() {
                        deps.push(("PyPI".to_string(), pkg.to_string(), ver.to_string()));
                    }
                }
            }
        }
        "go.mod" => {
            let mut in_require_block = false;
            let mut in_ignored_block = false;
            for line in raw.lines() {
                let l = line.split("//").next().unwrap_or("").trim();
                if l.is_empty() {
                    continue;
                }
                if l == ")" {
                    in_require_block = false;
                    in_ignored_block = false;
                    continue;
                }
                if l.starts_with("require (") || l == "require(" {
                    in_require_block = true;
                    continue;
                }
                if (l.starts_with("exclude") || l.starts_with("replace") || l.starts_with("retract"))
                    && l.ends_with('(')
                {
                    in_ignored_block = true;
                    continue;
                }
                if in_ignored_block {
                    continue;
                }
                let mut parts: Vec<&str> = l.split_whitespace().collect();
                let is_single_require = parts.first() == Some(&"require");
                if is_single_require {
                    parts.remove(0);
                } else if !in_require_block {
                    continue;
                }
                if parts.len() >= 2 && parts[1].starts_with('v') {
                    deps.push((
                        "Go".to_string(),
                        parts[0].to_string(),
                        parts[1].trim_start_matches('v').to_string(),
                    ));
                }
            }
        }
        "Cargo.lock" => {
            let mut cur_name = String::new();
            for line in raw.lines() {
                let l = line.trim();
                if l.starts_with('[') {
                    cur_name.clear();
                } else if let Some(rest) = l.strip_prefix("name = \"") {
                    cur_name = rest.trim_end_matches('"').to_string();
                } else if let Some(rest) = l.strip_prefix("version = \"")
                    && !cur_name.is_empty()
                {
                    deps.push((
                        "crates.io".to_string(),
                        std::mem::take(&mut cur_name),
                        rest.trim_end_matches('"').to_string(),
                    ));
                }
            }
        }
        "poetry.lock" => {
            let mut cur_name = String::new();
            for line in raw.lines() {
                let l = line.trim();
                if l.starts_with('[') {
                    cur_name.clear();
                } else if let Some(rest) = l.strip_prefix("name = \"") {
                    cur_name = rest.trim_end_matches('"').to_string();
                } else if let Some(rest) = l.strip_prefix("version = \"")
                    && !cur_name.is_empty()
                {
                    deps.push((
                        "PyPI".to_string(),
                        std::mem::take(&mut cur_name),
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
                        let off = usize::from(spec.starts_with('@'));
                        if spec.len() > off
                            && let Some(at_pos) = spec[off..].find('@')
                        {
                            let pkg = spec[..off + at_pos].to_string();
                            if !pkg.is_empty() && !cur_names.contains(&pkg) {
                                cur_names.push(pkg);
                            }
                        }
                    }
                } else if !cur_names.is_empty() {
                    let ver_opt = trimmed
                        .strip_prefix("version \"")
                        .map(|s| s.trim_end_matches('"'))
                        .or_else(|| {
                            trimmed
                                .strip_prefix("version:")
                                .map(|s| s.trim().trim_matches('"').trim_matches('\''))
                        });
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
                let off = usize::from(no_peers.starts_with('@'));
                if no_peers.len() > off
                    && let Some(at_pos) = no_peers[off..].find('@')
                {
                    let name = &no_peers[..off + at_pos];
                    let ver = &no_peers[off + at_pos + 1..];
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
            if let Ok(v) = serde_json::from_str::<Value>(raw) {
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
            for cap in dep_re.captures_iter(raw) {
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

pub fn build_sarif_report(findings: &[Value]) -> Value {
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
                    "text": format!("{pkg}@{inst} ({eco}) affected by {cve_id} (fix: {fixed}) - {title}")
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

pub fn cmd_scan(
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
         WHERE p.package_name = ?1 COLLATE NOCASE AND p.ecosystem = ?2 COLLATE NOCASE",
    )?;

    for file in &targets {
        for (eco, name, ver) in parse_dependencies_from_file(file) {
            if !seen.insert((eco.clone(), name.clone(), ver.clone())) {
                continue;
            }
            deps_checked += 1;
            let rows = stmt.query_map(params![&name, &eco], |r| {
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
                    findings.push(json!({
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

    let report = json!({
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
            "Offline SBOM scan: {} manifests, {} deps checked, {} Medium+ vulnerabilities ({:.2} ms)",
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
