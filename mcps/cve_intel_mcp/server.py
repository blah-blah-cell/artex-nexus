#!/usr/bin/env python3
"""
cve-intel-mcp: Dual-transport (stdio + Streamable HTTP / SSE) MCP server for
querying all public Medium+ CVEs (CVSS >= 4.0), CISA KEV, EPSS, and public writeups.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from mcps.compat import create_mcp_server, run_mcp_server

DEFAULT_DB = Path(os.environ.get("CVE_DB_PATH", "data/cve_kb_med_plus.sqlite"))
mcp = create_mcp_server("cve-intel-mcp")


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or Path(os.environ.get("CVE_DB_PATH", str(DEFAULT_DB)))
    if not path.exists():
        raise FileNotFoundError(
            f"CVE database not found at '{path}'. Run `python -m pipeline.bootstrap` "
            "or `python -m pipeline.bootstrap --kev-seed` first."
        )
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _sanitize_fts_query(raw: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_.\-]+", raw)
    if not tokens:
        return ""
    return " AND ".join(f'"{t}"' for t in tokens[:12])


@mcp.tool()
def search_cves(
    query: str,
    min_cvss: float = 4.0,
    severity: str | None = None,
    cwe: str | None = None,
    kev_only: bool = False,
    has_writeup: bool = False,
    limit: int = 20,
) -> dict[str, Any]:
    """Full-text search across all Medium+ CVEs (CVSS >= 4.0) and public writeups."""
    limit = max(1, min(limit, 100))
    fts_q = _sanitize_fts_query(query)
    if not fts_q:
        return {"error": "Provide a non-empty search query."}

    sql = [
        "SELECT c.cve_id, c.title, c.cvss_score, c.cvss_severity, c.cwe_ids,",
        "       c.epss_score, c.is_kev, c.published_date,",
        "       substr(c.description, 1, 280) AS summary,",
        "       (SELECT COUNT(*) FROM writeups w WHERE w.cve_id = c.cve_id) AS writeup_count",
        "FROM cves_fts f",
        "JOIN cves c ON c.rowid = f.rowid",
        "WHERE cves_fts MATCH ?",
        "  AND c.cvss_score >= ?",
    ]
    params: list[Any] = [fts_q, max(4.0, float(min_cvss))]

    if severity:
        sql.append("  AND UPPER(c.cvss_severity) = ?")
        params.append(severity.upper().strip())
    if cwe:
        sql.append("  AND UPPER(c.cwe_ids) LIKE ?")
        params.append(f"%{cwe.upper().strip()}%")
    if kev_only:
        sql.append("  AND c.is_kev = 1")
    if has_writeup:
        sql.append("  AND EXISTS (SELECT 1 FROM writeups w WHERE w.cve_id = c.cve_id)")

    sql.append("ORDER BY c.is_kev DESC, c.cvss_score DESC, COALESCE(c.epss_score, 0) DESC")
    sql.append("LIMIT ?")
    params.append(limit)

    with _connect() as conn:
        rows = [dict(r) for r in conn.execute("\n".join(sql), params).fetchall()]
    return {"query": query, "count": len(rows), "results": rows}


@mcp.tool()
def get_cve_details(cve_id: str) -> dict[str, Any]:
    """Return full metadata, CVSS vector, KEV/EPSS status, affected products, and all public writeup/patch links for a CVE."""
    cid = cve_id.upper().strip()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (cid,)).fetchone()
        if not row:
            return {"found": False, "cve_id": cid}
        writeups = [
            dict(w)
            for w in conn.execute(
                "SELECT source, url, title, tags, has_patch_diff FROM writeups WHERE cve_id = ? "
                "ORDER BY has_patch_diff DESC, source ASC",
                (cid,),
            ).fetchall()
        ]

    data = dict(row)
    data["affected_products"] = json.loads(data.get("affected_products") or "[]")
    data["raw_references"] = json.loads(data.get("raw_references") or "[]")
    data["writeups"] = writeups
    data["found"] = True
    return data


@mcp.tool()
def match_product_cves(
    product: str,
    vendor: str | None = None,
    min_cvss: float = 4.0,
    limit: int = 25,
) -> dict[str, Any]:
    """Find Medium+ CVEs affecting a given product (and optional vendor) ordered by KEV & CVSS."""
    limit = max(1, min(limit, 100))
    terms = f"{vendor} {product}".strip() if vendor else product.strip()
    fts_q = _sanitize_fts_query(terms)
    if not fts_q:
        return {"error": "Provide a product name."}

    with _connect() as conn:
        rows = [
            dict(r)
            for r in conn.execute(
                """
                SELECT c.cve_id, c.title, c.cvss_score, c.cvss_severity, c.cwe_ids,
                       c.is_kev, c.epss_score, c.published_date, c.affected_products,
                       (SELECT COUNT(*) FROM writeups w WHERE w.cve_id = c.cve_id) AS writeup_count
                FROM cves_fts f
                JOIN cves c ON c.rowid = f.rowid
                WHERE cves_fts MATCH ?
                  AND c.cvss_score >= ?
                ORDER BY c.is_kev DESC, c.cvss_score DESC, c.published_date DESC
                LIMIT ?
                """,
                (fts_q, max(4.0, float(min_cvss)), limit),
            ).fetchall()
        ]
    for r in rows:
        r["affected_products"] = json.loads(r.get("affected_products") or "[]")
    return {"vendor": vendor, "product": product, "count": len(rows), "results": rows}


@mcp.tool()
def list_cwe_writeups(
    cwe_id: str,
    min_cvss: float = 7.0,
    patch_only: bool = False,
    limit: int = 20,
) -> dict[str, Any]:
    """List high-signal CVE writeups and patch references for a specific CWE class (ideal for variant analysis)."""
    limit = max(1, min(limit, 100))
    cwe_norm = cwe_id.upper().strip()
    if not cwe_norm.startswith("CWE-"):
        cwe_norm = f"CWE-{cwe_norm}"

    patch_clause = "AND w.has_patch_diff = 1" if patch_only else ""
    with _connect() as conn:
        rows = [
            dict(r)
            for r in conn.execute(
                f"""
                SELECT c.cve_id, c.cvss_score, c.cvss_severity, c.is_kev, c.title,
                       w.source, w.url, w.tags, w.has_patch_diff
                FROM writeups w
                JOIN cves c ON c.cve_id = w.cve_id
                WHERE UPPER(c.cwe_ids) LIKE ?
                  AND c.cvss_score >= ?
                  {patch_clause}
                ORDER BY c.is_kev DESC, c.cvss_score DESC, w.has_patch_diff DESC
                LIMIT ?
                """,
                (f"%{cwe_norm}%", max(4.0, float(min_cvss)), limit),
            ).fetchall()
        ]
    return {"cwe_id": cwe_norm, "count": len(rows), "writeups": rows}


@mcp.tool()
def get_kb_stats() -> dict[str, Any]:
    """Return freshness and coverage statistics for the loaded Medium+ CVE knowledge base."""
    with _connect() as conn:
        meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM metadata").fetchall()}
        by_sev = {
            r["cvss_severity"]: r["cnt"]
            for r in conn.execute(
                "SELECT cvss_severity, COUNT(*) AS cnt FROM cves GROUP BY cvss_severity"
            ).fetchall()
        }
    return {"metadata": meta, "by_severity": by_sev}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run cve-intel-mcp server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
    )
    parser.add_argument("--host", default=os.environ.get("MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT", "8901")))
    args = parser.parse_args()

    run_mcp_server(mcp, transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
