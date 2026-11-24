mod bootstrap;
mod fetch;
mod ingest;
mod scan;
mod server;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use nexus_common::{CveRecord, detect_schema_version, open_readonly};
use rayon::prelude::*;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

const DEFAULT_REPO: &str = "blah-blah-cell/artex-nexus";
const DEFAULT_TAG: &str = "cve-db-latest";

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum SeverityThreshold {
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
    about = "CVE/OSV/KEV/EPSS SQLite builder, release fetcher, lockfile scanner, web console, and ARTEX bootstrapper"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a Medium+ CVE and writeups SQLite FTS5 DB from local corpora
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
    /// Download the prebuilt Medium+ CVE DB from GitHub Releases (ETag + SHA-256 + atomic swap)
    Fetch {
        #[arg(long, env = "ARTEX_NEXUS_REPO", default_value = DEFAULT_REPO)]
        repo: String,
        #[arg(long, env = "ARTEX_NEXUS_DB_TAG", default_value = DEFAULT_TAG)]
        tag: String,
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        out: PathBuf,
        #[arg(long, help = "Bypass ETag cache and force re-download")]
        force: bool,
        #[arg(long, help = "Allow installing an archive when SHA256SUMS.txt is absent")]
        allow_unverified: bool,
    },
    /// Build a small starter DB directly from live CISA KEV + FIRST EPSS
    SeedKev {
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        out: PathBuf,
    },
    /// Scan lockfiles and manifests offline against OSV/GHSA Medium+ CVE ranges
    Scan {
        #[arg(long, default_value = ".", help = "Target directory or lockfile (10 formats)")]
        path: PathBuf,
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        db: PathBuf,
        #[arg(long, help = "Output raw JSON instead of text summary")]
        json: bool,
        #[arg(long, help = "Write SARIF 2.1.0 report to this file")]
        sarif: Option<PathBuf>,
        #[arg(long, value_enum, help = "Exit non-zero if findings meet or exceed severity")]
        fail_on: Option<SeverityThreshold>,
    },
    /// Check local DB integrity, schema version, and row counts
    Doctor {
        #[arg(long, env = "CVE_DB_PATH", default_value = "data/cve_kb_med_plus.sqlite")]
        db: PathBuf,
    },
    /// Print MCP client JSON config for Antigravity, ZCode, Freebuff, Claude, Cursor, or ARTEX
    InitMcp {
        #[arg(long, value_enum, default_value_t = McpClientKind::Antigravity)]
        client: McpClientKind,
        #[arg(long, default_value = ".")]
        repo_root: PathBuf,
    },
    /// Run the local offline web console for CVEs, SemVer checks, receipts, and playbooks
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
        #[arg(
            long = "cors-origin",
            env = "NEXUS_CORS_ORIGINS",
            value_delimiter = ',',
            help = "Allowed CORS origin(s); defaults to loopback :8787 and :8088"
        )]
        cors_origins: Vec<String>,
    },
    /// Configure a running ARTEX instance with the 4 MCPs, 8 skills, prompts, traffic binding, and caps
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
        #[arg(long, help = "Optional request header to inject via capture proxy (e.g. X-Researcher-Id: handle)")]
        rewrite_header: Option<String>,
        #[arg(long, help = "Print bootstrap plan without modifying ARTEX")]
        dry_run: bool,
    },
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
        serde_json::to_string_pretty(&json!({
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
                        "args": ["--transport", "stdio", "--workspace-dir", root],
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
                    "args": ["--transport", "stdio", "--workspace-dir", root]
                }
            }
        })
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
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
            let client = ingest::http_client()?;
            let kev_map = if skip_kev {
                HashMap::new()
            } else {
                ingest::fetch_kev_map(&client)?
            };
            let epss_map = if skip_epss {
                HashMap::new()
            } else {
                ingest::fetch_epss_map(&client)?
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
                    ingest::parse_cve5_value(&val, &kev_map, &epss_map, min_cvss)
                })
                .collect();

            let mut stats = ingest::write_records_to_db(
                &out,
                &records,
                min_cvss,
                trickest_dir.as_deref(),
                nuclei_dir.as_deref(),
                osv_dir.as_deref(),
            )?;
            stats["elapsed_ms"] = json!(start.elapsed().as_millis());
            println!("{}", serde_json::to_string_pretty(&stats)?);

            if compress {
                let (archive, sha256) = ingest::compress_zstd(&out)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
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
            allow_unverified,
        } => fetch::cmd_fetch(&repo, &tag, &out, force, allow_unverified)?,
        Command::SeedKev { out } => ingest::cmd_seed_kev(&out)?,
        Command::Scan {
            path,
            db,
            json,
            sarif,
            fail_on,
        } => scan::cmd_scan(&path, &db, json, sarif.as_deref(), fail_on)?,
        Command::Doctor { db } => cmd_doctor(&db)?,
        Command::InitMcp { client, repo_root } => cmd_init_mcp(client, &repo_root)?,
        Command::Serve {
            host,
            port,
            db,
            receipts_dir,
            knowledge_dir,
            cors_origins,
        } => server::cmd_serve(&host, port, db, receipts_dir, knowledge_dir, cors_origins)?,
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
    use crate::ingest::{KevEntry, parse_cve5_value, write_records_to_db};
    use crate::scan::{build_sarif_report, parse_dependencies_from_file};
    use crate::server::{LedgerEntry, api_receipts, compute_ledger_hash, default_cors_origins, serve_dashboard};
    use reqwest::blocking::Client;
    use rusqlite::Connection;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tiny_http::Server;

    fn sample_cve(id: &str, score: Option<f64>, cwe: &str, state: &str) -> Value {
        let metrics = match score {
            Some(s) => json!([{"cvssV3_1": {"version": "3.1", "baseScore": s, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]),
            None => json!([]),
        };
        json!({
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
        assert!(rec.cvss_score.is_none());
        assert_eq!(rec.cvss_severity, "KEV_UNSCORED");
        assert_eq!(rec.exploit_maturity, "KEV_EXPLOITED");

        assert!(parse_cve5_value(&sample_cve("CVE-2026-0002", Some(3.1), "CWE-79", "PUBLISHED"), &kev, &HashMap::new(), 4.0).is_none());
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
            json!({
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
        assert_eq!(cwe79, vec!["CVE-2026-1000"]);

        let pkg_fixed: String = conn
            .query_row(
                "SELECT fixed_ver FROM cve_packages WHERE package_name = 'LODASH-DEMO' COLLATE NOCASE AND ecosystem = 'NPM' COLLATE NOCASE",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pkg_fixed, "4.17.21");
    }

    #[test]
    fn parses_lockfiles_single_line_gomod_and_skips_package_json_ranges() {
        let dir = tempdir().unwrap();

        let gomod = dir.path().join("go.mod");
        fs::write(
            &gomod,
            "module example.com/app\ngo 1.24\nrequire github.com/foo/bar v1.2.3\nrequire (\n\tgolang.org/x/net v0.20.0\n)\nexclude (\n\tgithub.com/old/excluded v0.1.0\n)\nreplace (\n\tgithub.com/old/replaced v0.2.0 => github.com/new/fork v0.3.0\n)\n",
        )
        .unwrap();
        let go_deps = parse_dependencies_from_file(&gomod);
        assert!(go_deps.contains(&("Go".to_string(), "github.com/foo/bar".to_string(), "1.2.3".to_string())));
        assert!(go_deps.contains(&("Go".to_string(), "golang.org/x/net".to_string(), "0.20.0".to_string())));
        assert!(!go_deps.iter().any(|(_, n, _)| n.contains("excluded") || n.contains("replaced")));

        let reqs = dir.path().join("requirements.txt");
        fs::write(
            &reqs,
            "\u{FEFF}requests[security]==2.28.0 ; python_version >= \"3.8\"\nurllib3==1.26.5 \\\n  --hash=sha256:abc\n",
        )
        .unwrap();
        let py_deps = parse_dependencies_from_file(&reqs);
        assert!(py_deps.contains(&("PyPI".to_string(), "requests".to_string(), "2.28.0".to_string())));
        assert!(py_deps.contains(&("PyPI".to_string(), "urllib3".to_string(), "1.26.5".to_string())));

        let pkgjson = dir.path().join("package.json");
        fs::write(
            &pkgjson,
            r#"{"dependencies":{"lodash":"4.17.15","axios":">=1.6.0","express":"^4.18.0"}}"#,
        )
        .unwrap();
        let npm_deps = parse_dependencies_from_file(&pkgjson);
        assert_eq!(npm_deps, vec![("npm".to_string(), "lodash".to_string(), "4.17.15".to_string())]);

        let yarn = dir.path().join("yarn.lock");
        fs::write(
            &yarn,
            "\"@babel/core@^7.0.0\":\n  version \"7.24.0\"\n\n\"lodash@^4.17.15\", lodash@^4.17.20:\n  version \"4.17.15\"\n",
        )
        .unwrap();
        let yarn_deps = parse_dependencies_from_file(&yarn);
        assert!(yarn_deps.contains(&("npm".to_string(), "@babel/core".to_string(), "7.24.0".to_string())));
        assert!(yarn_deps.contains(&("npm".to_string(), "lodash".to_string(), "4.17.15".to_string())));

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
    }

    #[test]
    fn receipts_recompute_sha256_and_handle_blank_lines() {
        let dir = tempdir().unwrap();
        let mut e1 = LedgerEntry {
            seq: 1,
            scope_id: "default".to_string(),
            finding_id: "F-1".to_string(),
            program: "demo".to_string(),
            title: "Original <title> & test".to_string(),
            target: "api.example.test".to_string(),
            cwe: "CWE-639".to_string(),
            severity: "HIGH".to_string(),
            cvss_vector: String::new(),
            verification_command: "curl https://api.example.test/1".to_string(),
            observed_output_summary: "200 OK".to_string(),
            remediation: "Enforce authz".to_string(),
            recorded_at: "2026-11-25T00:00:00Z".to_string(),
            prev_sha256: "GENESIS".to_string(),
            sha256: String::new(),
        };
        e1.sha256 = compute_ledger_hash(&e1).unwrap();
        let mut e2 = e1.clone();
        e2.seq = 2;
        e2.finding_id = "F-2".to_string();
        e2.prev_sha256 = e1.sha256.clone();
        e2.sha256 = compute_ledger_hash(&e2).unwrap();

        // Blank lines between valid entries must still verify as valid.
        let content = format!(
            "\n{}\n\n{}\n",
            serde_json::to_string(&e1).unwrap(),
            serde_json::to_string(&e2).unwrap()
        );
        fs::write(dir.path().join("receipts.jsonl"), &content).unwrap();
        let ok = api_receipts(dir.path()).unwrap();
        assert_eq!(ok["chain_valid"], true);
        assert_eq!(ok["count"], 2);

        // Editing title without changing sha256 must fail hash verification.
        let tampered = content.replace("Original <title>", "Edited <title>");
        fs::write(dir.path().join("receipts.jsonl"), tampered).unwrap();
        let bad = api_receipts(dir.path()).unwrap();
        assert_eq!(bad["chain_valid"], false);
    }

    #[test]
    fn dashboard_http_endpoints_and_cors_allowlist_work() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("dash.sqlite");
        let osv_dir = dir.path().join("osv");
        fs::create_dir_all(&osv_dir).unwrap();
        fs::write(
            osv_dir.join("GHSA-dash-0001.json"),
            json!({
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
        std::thread::spawn(move || {
            serve_dashboard(srv_clone, db_clone, receipts_dir, knowledge_dir, default_cors_origins())
        });

        let client = Client::new();

        // Untrusted origin on /api/* must be rejected with 403.
        let evil_resp = client
            .get(format!("http://{addr}/api/receipts"))
            .header("Origin", "https://evil.example")
            .send()
            .unwrap();
        assert_eq!(evil_resp.status().as_u16(), 403);
        assert!(evil_resp.headers().get("access-control-allow-origin").is_none());

        // DNS-rebinding unknown Host header must be rejected with 403.
        let rebind_resp = client
            .get(format!("http://{addr}/api/receipts"))
            .header("Host", "rebind.attacker.example:8088")
            .send()
            .unwrap();
        assert_eq!(rebind_resp.status().as_u16(), 403);

        // Allowed loopback origin receives exact echoed origin (never '*').
        let ok_resp = client
            .get(format!("http://{addr}/api/stats"))
            .header("Origin", "http://127.0.0.1:8787")
            .send()
            .unwrap();
        assert_eq!(
            ok_resp.headers().get("access-control-allow-origin").unwrap().to_str().unwrap(),
            "http://127.0.0.1:8787"
        );
        let stats: Value = ok_resp.json().unwrap();
        assert_eq!(stats["metadata"]["total_cves"], "1");

        let pkg: Value = client
            .get(format!("http://{addr}/api/package?ecosystem=npm&name=lodash-demo&version=4.17.15"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(pkg["vulnerable"], true);
        assert_eq!(pkg["count"], 1);

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
        let once = bootstrap::merge_prompt("Base prompt.", &block);
        let twice = bootstrap::merge_prompt(&once, &block);
        assert_eq!(once, twice);
    }
}
