#!/usr/bin/env python3
"""
ARTEX-Nexus Medium+ CVE & Public Writeups Ingestion Pipeline.

Aggregates:
  1. Official CVE JSON 5.0 records (CVEProject/cvelistV5)
  2. CISA Known Exploited Vulnerabilities (KEV) catalog
  3. FIRST.org EPSS probability scores
  4. Public writeups, advisories, PoC references, and patch links
     (CVE JSON 5.0 references + optional trickest/cve, PoC-in-GitHub, nuclei-templates)

Filters strictly to Medium and above (CVSS >= 4.0, or listed in CISA KEV) and
builds a fast, portable SQLite + FTS5 database.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import re
import sqlite3
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_CSV_GZ_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

PATCH_URL_PATTERNS = (
    re.compile(r"https?://github\.com/[^/]+/[^/]+/(commit|pull)/", re.I),
    re.compile(r"https?://gitlab\.com/.+/-/commit/", re.I),
    re.compile(r"https?://git\.kernel\.org/", re.I),
)

WRITEUP_DOMAINS = (
    "github.com",
    "blog.",
    "medium.com",
    "hackerone.com",
    "huntr.com",
    "projectzero",
    "zerodayinitiative.com",
    "portswigger.net",
    "assetnote.io",
    "watchtowr.com",
    "projectdiscovery.io",
    "packetstormsecurity.com",
    "exploit-db.com",
    "nvd.nist.gov",
    "advisories",
)

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def extract_cvss(containers: dict[str, Any]) -> tuple[float | None, str, str, str]:
    """Extract highest CVSS score (v4.0 > v3.1 > v3.0 > v2.0) from CVE 5.0 containers."""
    candidates: list[tuple[int, float, str, str, str]] = []
    metric_blocks: list[dict[str, Any]] = []

    cna = containers.get("cna") or {}
    metric_blocks.extend(cna.get("metrics") or [])
    for adp in containers.get("adp") or []:
        if isinstance(adp, dict):
            metric_blocks.extend(adp.get("metrics") or [])

    version_rank = {"cvssV4_0": 4, "cvssV3_1": 3, "cvssV3_0": 2, "cvssV2_0": 1}
    for block in metric_blocks:
        if not isinstance(block, dict):
            continue
        for key, rank in version_rank.items():
            cvss = block.get(key)
            if not isinstance(cvss, dict):
                continue
            raw_score = cvss.get("baseScore")
            if raw_score is None:
                continue
            try:
                score = float(raw_score)
            except (TypeError, ValueError):
                continue
            ver = str(cvss.get("version") or key.replace("cvssV", "").replace("_", "."))
            sev = str(cvss.get("baseSeverity") or severity_from_score(score)).upper()
            vec = str(cvss.get("vectorString") or "")
            candidates.append((rank, score, ver, sev, vec))

    if not candidates:
        return None, "", "UNKNOWN", ""

    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    _, score, ver, sev, vec = candidates[0]
    return score, ver, sev, vec


def extract_cwes(containers: dict[str, Any]) -> list[str]:
    cwes: set[str] = set()
    blocks: list[dict[str, Any]] = []
    cna = containers.get("cna") or {}
    blocks.extend(cna.get("problemTypes") or [])
    for adp in containers.get("adp") or []:
        if isinstance(adp, dict):
            blocks.extend(adp.get("problemTypes") or [])

    for pt in blocks:
        for desc in pt.get("descriptions") or []:
            cwe_id = desc.get("cweId")
            if isinstance(cwe_id, str) and cwe_id.upper().startswith("CWE-"):
                cwes.add(cwe_id.upper())
            else:
                text = str(desc.get("description") or "")
                for match in re.findall(r"CWE-\d+", text, re.I):
                    cwes.add(match.upper())
    return sorted(cwes)


def extract_affected(cna: dict[str, Any]) -> list[dict[str, Any]]:
    affected_out: list[dict[str, Any]] = []
    for item in cna.get("affected") or []:
        if not isinstance(item, dict):
            continue
        vendor = str(item.get("vendor") or "").strip()
        product = str(item.get("product") or "").strip()
        versions = [
            str(v.get("version") or v.get("lessThan") or v.get("lessThanOrEqual") or "").strip()
            for v in (item.get("versions") or [])
            if isinstance(v, dict)
        ]
        versions = [v for v in versions if v and v.lower() != "n/a"][:10]
        if vendor or product:
            affected_out.append({"vendor": vendor, "product": product, "versions": versions})
    return affected_out[:25]


def classify_reference(url: str, tags: list[str]) -> tuple[str, int]:
    lower_tags = {t.lower() for t in tags}
    has_patch = int(
        "patch" in lower_tags or any(pat.search(url) for pat in PATCH_URL_PATTERNS)
    )
    if has_patch:
        return "patch", 1
    if "exploit" in lower_tags or "poc" in lower_tags:
        return "poc", 0
    if "vendor-advisory" in lower_tags or "third-party-advisory" in lower_tags:
        return "advisory", 0
    if "technical-description" in lower_tags or any(dom in url.lower() for dom in WRITEUP_DOMAINS):
        return "writeup", 0
    return "reference", 0


def parse_cve5_record(
    record: dict[str, Any],
    kev_map: dict[str, dict[str, Any]],
    epss_map: dict[str, tuple[float, float]],
    min_cvss: float = 4.0,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Parse a CVE JSON 5.0 dict into normalized (cve_row, writeup_rows)."""
    meta = record.get("cveMetadata") or {}
    if meta.get("state") == "REJECTED":
        return None, []
    cve_id = str(meta.get("cveId") or "").upper().strip()
    if not cve_id.startswith("CVE-"):
        return None, []

    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    score, ver, sev, vec = extract_cvss(containers)
    kev_info = kev_map.get(cve_id)
    is_kev = 1 if kev_info else 0

    if score is None:
        if not is_kev:
            return None, []
        score = 7.5
        sev = "HIGH"
        ver = "KEV-ESTIMATED"
    elif score < min_cvss and not is_kev:
        return None, []

    descriptions = cna.get("descriptions") or []
    desc_text = ""
    for d in descriptions:
        if isinstance(d, dict) and str(d.get("lang", "")).lower().startswith("en"):
            desc_text = str(d.get("value") or "").strip()
            break
    if not desc_text and descriptions and isinstance(descriptions[0], dict):
        desc_text = str(descriptions[0].get("value") or "").strip()

    title = str(cna.get("title") or (kev_info.get("vulnerabilityName") if kev_info else "") or "").strip()
    cwes = extract_cwes(containers)
    affected = extract_affected(cna)
    epss_score, epss_pct = epss_map.get(cve_id, (None, None))

    refs_raw: list[dict[str, Any]] = []
    refs_raw.extend(cna.get("references") or [])
    for adp in containers.get("adp") or []:
        if isinstance(adp, dict):
            refs_raw.extend(adp.get("references") or [])

    writeups: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    ref_urls: list[str] = []

    for ref in refs_raw:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url") or "").strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        ref_urls.append(url)
        tags = [str(t) for t in (ref.get("tags") or []) if isinstance(t, str)]
        source, has_patch = classify_reference(url, tags)
        if source in ("patch", "poc", "advisory", "writeup"):
            writeups.append(
                {
                    "cve_id": cve_id,
                    "source": source,
                    "url": url,
                    "title": str(ref.get("name") or "")[:240],
                    "tags": ",".join(tags),
                    "has_patch_diff": has_patch,
                }
            )

    cve_row = {
        "cve_id": cve_id,
        "published_date": str(meta.get("datePublished") or ""),
        "modified_date": str(meta.get("dateUpdated") or ""),
        "cvss_score": score,
        "cvss_version": ver,
        "cvss_severity": sev,
        "cvss_vector": vec,
        "cwe_ids": ",".join(cwes),
        "epss_score": epss_score,
        "epss_percentile": epss_pct,
        "is_kev": is_kev,
        "kev_date_added": str(kev_info.get("dateAdded") or "") if kev_info else None,
        "kev_due_date": str(kev_info.get("dueDate") or "") if kev_info else None,
        "title": title,
        "description": desc_text,
        "affected_products": json.dumps(affected, ensure_ascii=False),
        "raw_references": json.dumps(ref_urls[:40], ensure_ascii=False),
    }
    return cve_row, writeups


def fetch_kev_catalog(url: str = CISA_KEV_URL, timeout: int = 30) -> dict[str, dict[str, Any]]:
    req = urllib.request.Request(url, headers={"User-Agent": "artex-nexus-sync/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    out: dict[str, dict[str, Any]] = {}
    for vuln in payload.get("vulnerabilities") or []:
        cid = str(vuln.get("cveID") or "").upper().strip()
        if cid:
            out[cid] = vuln
    return out


def fetch_epss_scores(url: str = EPSS_CSV_GZ_URL, timeout: int = 45) -> dict[str, tuple[float, float]]:
    req = urllib.request.Request(url, headers={"User-Agent": "artex-nexus-sync/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        compressed = resp.read()
    text = gzip.decompress(compressed).decode("utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    out: dict[str, tuple[float, float]] = {}
    for row in reader:
        cid = str(row.get("cve") or "").upper().strip()
        if not cid:
            continue
        try:
            out[cid] = (float(row["epss"]), float(row["percentile"]))
        except (KeyError, ValueError, TypeError):
            continue
    return out


def iter_cve5_json_files(source_dir: Path) -> Iterable[dict[str, Any]]:
    for path in source_dir.rglob("CVE-*.json"):
        try:
            with path.open("r", encoding="utf-8") as fh:
                yield json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue


def iter_cve5_zip(zip_path: Path) -> Iterable[dict[str, Any]]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if not name.endswith(".json") or "/CVE-" not in name and not name.startswith("CVE-"):
                continue
            try:
                with zf.open(name) as fh:
                    yield json.loads(fh.read().decode("utf-8"))
            except (KeyError, json.JSONDecodeError, UnicodeDecodeError):
                continue


def ingest_trickest_markdown(conn: sqlite3.Connection, trickest_dir: Path) -> int:
    """Ingest external writeup/PoC links from a cloned trickest/cve repo."""
    url_re = re.compile(r"https?://[^\s\)\]>\"']+")
    added = 0
    existing = {row[0] for row in conn.execute("SELECT cve_id FROM cves")}
    batch: list[tuple[str, str, str, str, str, int]] = []

    for md_path in trickest_dir.rglob("CVE-*.md"):
        cid = md_path.stem.upper()
        if cid not in existing:
            continue
        try:
            content = md_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for url in set(url_re.findall(content)):
            if "nvd.nist.gov/vuln/detail" in url or "cve.mitre.org" in url:
                continue
            src = "poc" if "github.com" in url.lower() else "writeup"
            has_patch = int(any(p.search(url) for p in PATCH_URL_PATTERNS))
            batch.append((cid, f"trickest:{src}", url.rstrip(".,;"), "", "trickest", has_patch))
            if len(batch) >= 2000:
                conn.executemany(
                    "INSERT OR IGNORE INTO writeups (cve_id, source, url, title, tags, has_patch_diff) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    batch,
                )
                added += len(batch)
                batch.clear()

    if batch:
        conn.executemany(
            "INSERT OR IGNORE INTO writeups (cve_id, source, url, title, tags, has_patch_diff) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            batch,
        )
        added += len(batch)
    conn.commit()
    return added


def ingest_nuclei_templates(conn: sqlite3.Connection, nuclei_dir: Path) -> int:
    """Map CVE IDs to public Nuclei template verification paths."""
    existing = {row[0] for row in conn.execute("SELECT cve_id FROM cves")}
    batch: list[tuple[str, str, str, str, str, int]] = []
    added = 0
    for yml_path in nuclei_dir.rglob("CVE-*.yaml"):
        match = CVE_ID_RE.search(yml_path.stem)
        if not match:
            continue
        cid = match.group(0).upper()
        if cid not in existing:
            continue
        rel = yml_path.relative_to(nuclei_dir).as_posix()
        url = f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{rel}"
        batch.append((cid, "nuclei", url, yml_path.stem, "nuclei-template", 0))
        if len(batch) >= 1000:
            conn.executemany(
                "INSERT OR IGNORE INTO writeups (cve_id, source, url, title, tags, has_patch_diff) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                batch,
            )
            added += len(batch)
            batch.clear()
    if batch:
        conn.executemany(
            "INSERT OR IGNORE INTO writeups (cve_id, source, url, title, tags, has_patch_diff) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            batch,
        )
        added += len(batch)
    conn.commit()
    return added


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def build_database(
    db_path: Path,
    records: Iterable[dict[str, Any]],
    kev_map: dict[str, dict[str, Any]],
    epss_map: dict[str, tuple[float, float]],
    min_cvss: float = 4.0,
    limit: int | None = None,
    trickest_dir: Path | None = None,
    nuclei_dir: Path | None = None,
) -> dict[str, int]:
    conn = init_db(db_path)
    cve_batch: list[tuple[Any, ...]] = []
    wu_batch: list[tuple[Any, ...]] = []
    inserted = 0

    def flush() -> None:
        if cve_batch:
            conn.executemany(
                """
                INSERT OR REPLACE INTO cves (
                    cve_id, published_date, modified_date, cvss_score, cvss_version,
                    cvss_severity, cvss_vector, cwe_ids, epss_score, epss_percentile,
                    is_kev, kev_date_added, kev_due_date, title, description,
                    affected_products, raw_references
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                cve_batch,
            )
            cve_batch.clear()
        if wu_batch:
            conn.executemany(
                """
                INSERT OR IGNORE INTO writeups (
                    cve_id, source, url, title, tags, has_patch_diff
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                wu_batch,
            )
            wu_batch.clear()
        conn.commit()

    for rec in records:
        cve_row, writeups = parse_cve5_record(rec, kev_map, epss_map, min_cvss=min_cvss)
        if not cve_row:
            continue
        cve_batch.append(
            (
                cve_row["cve_id"],
                cve_row["published_date"],
                cve_row["modified_date"],
                cve_row["cvss_score"],
                cve_row["cvss_version"],
                cve_row["cvss_severity"],
                cve_row["cvss_vector"],
                cve_row["cwe_ids"],
                cve_row["epss_score"],
                cve_row["epss_percentile"],
                cve_row["is_kev"],
                cve_row["kev_date_added"],
                cve_row["kev_due_date"],
                cve_row["title"],
                cve_row["description"],
                cve_row["affected_products"],
                cve_row["raw_references"],
            )
        )
        for wu in writeups:
            wu_batch.append(
                (wu["cve_id"], wu["source"], wu["url"], wu["title"], wu["tags"], wu["has_patch_diff"])
            )
        inserted += 1
        if len(cve_batch) >= 2000:
            flush()
        if limit and inserted >= limit:
            break

    flush()

    if trickest_dir and trickest_dir.exists():
        ingest_trickest_markdown(conn, trickest_dir)
    if nuclei_dir and nuclei_dir.exists():
        ingest_nuclei_templates(conn, nuclei_dir)

    # Populate FTS5 index
    conn.execute("INSERT INTO cves_fts(cves_fts) VALUES('rebuild')")

    total_cves = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    total_writeups = conn.execute("SELECT COUNT(*) FROM writeups").fetchone()[0]
    kev_count = conn.execute("SELECT COUNT(*) FROM cves WHERE is_kev = 1").fetchone()[0]

    meta_rows = [
        ("built_at", datetime.now(timezone.utc).isoformat()),
        ("min_cvss", str(min_cvss)),
        ("total_cves", str(total_cves)),
        ("total_writeups", str(total_writeups)),
        ("kev_count", str(kev_count)),
    ]
    conn.executemany("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)", meta_rows)
    conn.commit()
    conn.execute("PRAGMA optimize")
    conn.close()

    return {
        "total_cves": total_cves,
        "total_writeups": total_writeups,
        "kev_count": kev_count,
    }


def compress_db(db_path: Path) -> tuple[Path, str]:
    """Compress SQLite DB using zstd if available, else gzip, and compute SHA-256."""
    try:
        import zstandard as zstd  # type: ignore

        out_path = db_path.with_suffix(".sqlite.zst")
        cctx = zstd.ZstdCompressor(level=10)
        with db_path.open("rb") as src, out_path.open("wb") as dst:
            cctx.copy_stream(src, dst)
    except ImportError:
        out_path = db_path.with_suffix(".sqlite.gz")
        with db_path.open("rb") as src, gzip.open(out_path, "wb", compresslevel=6) as dst:
            while chunk := src.read(1024 * 1024):
                dst.write(chunk)

    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()
    (out_path.parent / "SHA256SUMS.txt").write_text(
        f"{digest}  {out_path.name}\n", encoding="utf-8"
    )
    return out_path, digest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build ARTEX-Nexus Medium+ CVE & Writeups SQLite DB")
    parser.add_argument("--source-dir", type=Path, help="Path to cloned CVEProject/cvelistV5/cves directory")
    parser.add_argument("--source-zip", type=Path, help="Path to CVEProject/cvelistV5 zip archive")
    parser.add_argument("--trickest-dir", type=Path, help="Optional path to cloned trickest/cve repo")
    parser.add_argument("--nuclei-dir", type=Path, help="Optional path to cloned projectdiscovery/nuclei-templates")
    parser.add_argument("--out", type=Path, default=Path("data/cve_kb_med_plus.sqlite"))
    parser.add_argument("--min-cvss", type=float, default=4.0)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--skip-kev", action="store_true")
    parser.add_argument("--skip-epss", action="store_true")
    parser.add_argument("--compress", action="store_true")
    args = parser.parse_args()

    if not args.source_dir and not args.source_zip:
        parser.error("Provide either --source-dir or --source-zip")

    kev_map = {} if args.skip_kev else fetch_kev_catalog()
    epss_map = {} if args.skip_epss else fetch_epss_scores()
    records = (
        iter_cve5_json_files(args.source_dir)
        if args.source_dir
        else iter_cve5_zip(args.source_zip)
    )

    stats = build_database(
        db_path=args.out,
        records=records,
        kev_map=kev_map,
        epss_map=epss_map,
        min_cvss=args.min_cvss,
        limit=args.limit,
        trickest_dir=args.trickest_dir,
        nuclei_dir=args.nuclei_dir,
    )
    print(json.dumps({"db": str(args.out), **stats}, indent=2))

    if args.compress:
        archive_path, digest = compress_db(args.out)
        print(json.dumps({"archive": str(archive_path), "sha256": digest}, indent=2))


if __name__ == "__main__":
    main()
