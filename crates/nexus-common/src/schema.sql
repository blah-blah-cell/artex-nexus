-- Normalized Medium+ CVE, OSV, and writeup schema (SQLite 3 + Dual FTS5)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    published_date TEXT NOT NULL DEFAULT '',
    modified_date TEXT NOT NULL DEFAULT '',
    cvss_score REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0.0 AND cvss_score <= 10.0)),
    cvss_version TEXT NOT NULL DEFAULT '',
    cvss_severity TEXT NOT NULL,
    cvss_vector TEXT NOT NULL DEFAULT '',
    epss_score REAL,
    epss_percentile REAL,
    is_kev INTEGER NOT NULL DEFAULT 0,
    kev_date_added TEXT,
    kev_due_date TEXT,
    exploit_maturity TEXT NOT NULL DEFAULT 'NONE',
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    affected_products TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS cve_cwes (
    cve_id TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, cwe_id),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL COLLATE NOCASE,
    package_name TEXT NOT NULL COLLATE NOCASE,
    introduced_ver TEXT NOT NULL DEFAULT '',
    fixed_ver TEXT NOT NULL DEFAULT '',
    advisory_id TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
    UNIQUE (cve_id, ecosystem, package_name, introduced_ver, fixed_ver)
);

CREATE TABLE IF NOT EXISTS writeups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    source TEXT NOT NULL,
    url TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    has_patch_diff INTEGER NOT NULL DEFAULT 0,
    content_excerpt TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
    UNIQUE (cve_id, source, url)
);

CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(is_kev DESC);
CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_maturity ON cves(exploit_maturity);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date DESC);
CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves(modified_date DESC);
CREATE INDEX IF NOT EXISTS idx_cve_cwes_cwe ON cve_cwes(cwe_id);
CREATE INDEX IF NOT EXISTS idx_cve_packages_pkg ON cve_packages(package_name COLLATE NOCASE, ecosystem COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_cve_packages_cve ON cve_packages(cve_id);
CREATE INDEX IF NOT EXISTS idx_writeups_cve ON writeups(cve_id);
CREATE INDEX IF NOT EXISTS idx_writeups_source ON writeups(source);
CREATE INDEX IF NOT EXISTS idx_writeups_patch ON writeups(has_patch_diff);

CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
    cve_id,
    title,
    description,
    affected_products,
    content='cves',
    content_rowid='rowid',
    tokenize='porter unicode61'
);

CREATE VIRTUAL TABLE IF NOT EXISTS writeups_fts USING fts5(
    cve_id,
    title,
    content_excerpt,
    tags,
    url,
    content='writeups',
    content_rowid='id',
    tokenize='porter unicode61'
);
