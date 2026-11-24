-- ARTEX-Nexus Medium+ CVE & Writeups Knowledge Base Schema (SQLite 3 + FTS5)
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    published_date TEXT,
    modified_date TEXT,
    cvss_score REAL NOT NULL CHECK (cvss_score >= 0.0 AND cvss_score <= 10.0),
    cvss_version TEXT,
    cvss_severity TEXT NOT NULL,
    cvss_vector TEXT,
    cwe_ids TEXT DEFAULT '',
    epss_score REAL,
    epss_percentile REAL,
    is_kev INTEGER NOT NULL DEFAULT 0,
    kev_date_added TEXT,
    kev_due_date TEXT,
    title TEXT DEFAULT '',
    description TEXT DEFAULT '',
    affected_products TEXT DEFAULT '[]',
    raw_references TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS writeups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    source TEXT NOT NULL,
    url TEXT NOT NULL,
    title TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    has_patch_diff INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
    UNIQUE (cve_id, url)
);

CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(is_kev);
CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date DESC);
CREATE INDEX IF NOT EXISTS idx_writeups_cve ON writeups(cve_id);
CREATE INDEX IF NOT EXISTS idx_writeups_source ON writeups(source);
CREATE INDEX IF NOT EXISTS idx_writeups_patch ON writeups(has_patch_diff);

CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
    cve_id,
    title,
    description,
    cwe_ids,
    affected_products,
    content='cves',
    content_rowid='rowid',
    tokenize='porter unicode61'
);
