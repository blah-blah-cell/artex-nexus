use crate::SeverityThreshold;
use anyhow::Result;
use nexus_common::queries::{PackageCheckReport, query_package_vulns_detailed};
use nexus_common::version::ParsedVersion;
use nexus_common::{detect_schema_version, normalize_pypi_name, open_readonly};
use regex::Regex;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

#[derive(Debug, Default)]
pub struct ParsedManifest {
    pub deps: Vec<(String, String, String)>,
    pub skipped_unpinned: usize,
}

fn collect_v1_npm_deps(
    map: &serde_json::Map<String, Value>,
    out: &mut Vec<(String, String, String)>,
) {
    for (name, val) in map {
        if let Some(ver) = val.get("version").and_then(Value::as_str) {
            out.push(("npm".to_string(), name.clone(), ver.to_string()));
        }
        if let Some(nested) = val.get("dependencies").and_then(Value::as_object) {
            collect_v1_npm_deps(nested, out);
        }
    }
}

fn parse_pom_properties(raw: &str) -> HashMap<String, String> {
    let mut props = HashMap::new();
    let props_block_re = Regex::new(r"(?s)<properties>(.*?)</properties>").unwrap();
    let tag_re = Regex::new(r"<([A-Za-z0-9._-]+)>\s*([^<]+?)\s*</([A-Za-z0-9._-]+)>").unwrap();
    if let Some(cap) = props_block_re.captures(raw) {
        for m in tag_re.captures_iter(&cap[1]) {
            if m[1] == m[3] {
                props.insert(m[1].to_string(), m[2].trim().to_string());
            }
        }
    }
    // Extract top-level <project><version> if present (ignoring nested dependency versions).
    let no_deps = Regex::new(r"(?s)<dependencies>.*?</dependencies>")
        .unwrap()
        .replace_all(raw, "");
    let ver_re = Regex::new(r"<version>\s*([^<\s]+)\s*</version>").unwrap();
    if let Some(cap) = ver_re.captures(&no_deps) {
        props.insert("project.version".to_string(), cap[1].trim().to_string());
    }
    props
}

fn resolve_pom_prop(val: &str, props: &HashMap<String, String>) -> Option<String> {
    let mut cur = val.trim().to_string();
    for _ in 0..4 {
        if let Some(inner) = cur.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
            cur = props.get(inner)?.clone();
        } else {
            break;
        }
    }
    if cur.contains("${") || cur.is_empty() {
        None
    } else {
        Some(cur)
    }
}

pub fn parse_manifest_file(path: &Path) -> ParsedManifest {
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let Ok(raw) = fs::read_to_string(path) else {
        return ParsedManifest::default();
    };
    let raw = raw.strip_prefix('\u{FEFF}').unwrap_or(&raw);
    let mut out = ParsedManifest::default();

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
                            out.deps.push((
                                "npm".to_string(),
                                pkg_name.to_string(),
                                ver.to_string(),
                            ));
                        }
                    }
                } else if let Some(dmap) = v.get("dependencies").and_then(Value::as_object) {
                    collect_v1_npm_deps(dmap, &mut out.deps);
                }
            }
        }
        "package.json" => {
            if let Ok(v) = serde_json::from_str::<Value>(raw) {
                for key in ["dependencies", "devDependencies"] {
                    if let Some(map) = v.get(key).and_then(Value::as_object) {
                        for (name, ver) in map {
                            if let Some(vs) = ver.as_str() {
                                if ParsedVersion::parse(vs).is_some() {
                                    out.deps.push((
                                        "npm".to_string(),
                                        name.clone(),
                                        vs.trim().to_string(),
                                    ));
                                } else {
                                    out.skipped_unpinned += 1;
                                }
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
                    let pkg = normalize_pypi_name(pkg_part.split('[').next().unwrap_or(pkg_part));
                    let ver = ver_part
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim_end_matches('\\')
                        .trim();
                    if !pkg.is_empty() && !ver.is_empty() {
                        out.deps.push(("PyPI".to_string(), pkg, ver.to_string()));
                    }
                } else {
                    out.skipped_unpinned += 1;
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
                if (l.starts_with("exclude")
                    || l.starts_with("replace")
                    || l.starts_with("retract"))
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
                    out.deps.push((
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
                    out.deps.push((
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
                    cur_name = normalize_pypi_name(rest.trim_end_matches('"'));
                } else if let Some(rest) = l.strip_prefix("version = \"")
                    && !cur_name.is_empty()
                {
                    out.deps.push((
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
                            out.deps
                                .push(("npm".to_string(), name.clone(), ver.to_string()));
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
                        out.deps
                            .push(("npm".to_string(), name.to_string(), ver.to_string()));
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
                                out.deps.push((
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
            let props = parse_pom_properties(raw);
            let dep_re = Regex::new(r"(?s)<dependency>(.*?)</dependency>").unwrap();
            let gid_re = Regex::new(r"<groupId>\s*([^<\s]+)\s*</groupId>").unwrap();
            let aid_re = Regex::new(r"<artifactId>\s*([^<\s]+)\s*</artifactId>").unwrap();
            let ver_re = Regex::new(r"<version>\s*([^<\s]+)\s*</version>").unwrap();
            for cap in dep_re.captures_iter(raw) {
                let block = &cap[1];
                if let (Some(g), Some(a), Some(v)) = (
                    gid_re.captures(block),
                    aid_re.captures(block),
                    ver_re.captures(block),
                ) {
                    if let Some(resolved) = resolve_pom_prop(&v[1], &props) {
                        out.deps.push((
                            "Maven".to_string(),
                            format!("{}:{}", g[1].trim(), a[1].trim()),
                            resolved,
                        ));
                    } else {
                        out.skipped_unpinned += 1;
                    }
                }
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
pub fn parse_dependencies_from_file(path: &Path) -> Vec<(String, String, String)> {
    parse_manifest_file(path).deps
}

pub fn build_sarif_report(findings: &[Value]) -> Value {
    let mut rules_map: BTreeMap<String, Value> = BTreeMap::new();
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
            let fixed = f["fixed"].as_str().unwrap_or("");
            let last_aff = f["last_affected"].as_str().unwrap_or("");
            let range_note = if !fixed.is_empty() {
                format!("fix: {fixed}")
            } else if !last_aff.is_empty() {
                format!("no fix (last affected: {last_aff})")
            } else {
                "no fix recorded".to_string()
            };
            let cve_id = f["cve_id"].as_str().unwrap_or("CVE-UNKNOWN");
            let title = f["title"].as_str().unwrap_or("");
            let manifest = f["file"].as_str().unwrap_or("lockfile");

            rules_map.entry(cve_id.to_string()).or_insert_with(|| {
                json!({
                    "id": cve_id,
                    "shortDescription": { "text": if title.is_empty() { cve_id } else { title } }
                })
            });

            json!({
                "ruleId": cve_id,
                "level": level,
                "message": {
                    "text": format!("{pkg}@{inst} ({eco}) affected by {cve_id} ({range_note}) - {title}")
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
                    "last_affected": last_aff,
                    "cvss_score": f["cvss_score"],
                    "severity": sev,
                    "is_kev": is_kev,
                    "epss_score": f["epss_score"]
                }
            })
        })
        .collect();

    let rules: Vec<Value> = rules_map.into_values().collect();
    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "artex-nexus-sbom-scanner",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/blah-blah-cell/artex-nexus",
                    "rules": rules
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
        _ => {
            if is_kev {
                2
            } else {
                0
            }
        }
    }
}

fn rel_manifest_uri(scan_root: &Path, file: &Path) -> String {
    let base = if scan_root.is_file() {
        scan_root.parent().unwrap_or(Path::new("."))
    } else {
        scan_root
    };
    let rel = file.strip_prefix(base).unwrap_or(file);
    rel.display().to_string().replace('\\', "/")
}

pub fn cmd_scan(
    path: &Path,
    db_path: &Path,
    as_json: bool,
    sarif_out: Option<&Path>,
    fail_on: Option<SeverityThreshold>,
    max_depth: usize,
) -> Result<()> {
    let start = Instant::now();
    let conn = open_readonly(db_path)?;
    if detect_schema_version(&conn)? < 2 {
        anyhow::bail!("Scan requires v2 DB with OSV packages. Run `nexus-sync fetch` first.");
    }

    let depth_limit = max_depth.max(1);
    let targets: Vec<PathBuf> = if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        WalkDir::new(path)
            .max_depth(depth_limit)
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

    let mut cache: HashMap<(String, String, String), PackageCheckReport> = HashMap::new();
    let mut findings = Vec::new();
    let mut deps_checked = 0usize;
    let mut skipped_unpinned = 0usize;
    let mut unparseable_deps = 0usize;
    let mut unverifiable_ranges = 0usize;

    for file in &targets {
        let rel_file = rel_manifest_uri(path, file);
        let parsed = parse_manifest_file(file);
        skipped_unpinned += parsed.skipped_unpinned;
        let mut seen_in_file = HashSet::new();

        for (eco, name, ver) in parsed.deps {
            if !seen_in_file.insert((eco.clone(), name.clone(), ver.clone())) {
                continue;
            }
            deps_checked += 1;
            let key = (eco.clone(), name.clone(), ver.clone());
            if !cache.contains_key(&key) {
                let rep = query_package_vulns_detailed(&conn, &eco, &name, &ver)?;
                cache.insert(key.clone(), rep);
            }
            let rep = &cache[&key];
            if rep.installed_unparseable {
                unparseable_deps += 1;
            }
            unverifiable_ranges += rep.unverifiable_ranges;
            for v in &rep.vulnerabilities {
                findings.push(json!({
                    "file": rel_file,
                    "ecosystem": eco,
                    "package": name,
                    "installed": ver,
                    "fixed": v["fixed_ver"],
                    "last_affected": v["last_affected"],
                    "cve_id": v["cve_id"],
                    "advisory_id": v["advisory_id"],
                    "cvss_score": v["cvss_score"],
                    "severity": v["cvss_severity"],
                    "is_kev": v["is_kev"],
                    "epss_score": v["epss_score"],
                    "title": v["title"]
                }));
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
        "max_depth": depth_limit,
        "dependencies_checked": deps_checked,
        "skipped_unpinned_or_unresolved": skipped_unpinned,
        "unparseable_dependencies": unparseable_deps,
        "unverifiable_ranges": unverifiable_ranges,
        "vulnerabilities_found": findings.len(),
        "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0,
        "findings": findings
    });

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "Offline SBOM scan: {} manifests (max_depth={}), {} deps checked, {} Medium+ vulns, {} skipped unpinned/unresolved, {} unparseable deps, {} unverifiable ranges ({:.2} ms)",
            targets.len(),
            depth_limit,
            deps_checked,
            findings.len(),
            skipped_unpinned,
            unparseable_deps,
            unverifiable_ranges,
            start.elapsed().as_secs_f64() * 1000.0
        );
        for f in &findings {
            let fixed = f["fixed"].as_str().unwrap_or("");
            let last_aff = f["last_affected"].as_str().unwrap_or("");
            let fix_label = if !fixed.is_empty() {
                format!("fix: {fixed}")
            } else if !last_aff.is_empty() {
                format!("no fix (<= {last_aff})")
            } else {
                "no fix".to_string()
            };
            println!(
                "  [{} | CVSS {} | KEV={}] {} {}@{} ({}) -> {} | {} ({})",
                f["severity"].as_str().unwrap_or("?"),
                f["cvss_score"],
                f["is_kev"],
                f["file"].as_str().unwrap_or(""),
                f["package"].as_str().unwrap_or(""),
                f["installed"].as_str().unwrap_or(""),
                f["ecosystem"].as_str().unwrap_or(""),
                fix_label,
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
