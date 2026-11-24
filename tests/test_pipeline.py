from __future__ import annotations

import sqlite3
from pathlib import Path

from pipeline.sync_cves import build_database, parse_cve5_record


def _sample_record(
    cve_id: str,
    score: float,
    cwe: str = "CWE-918",
    state: str = "PUBLISHED",
    refs: list[dict] | None = None,
) -> dict:
    return {
        "cveMetadata": {
            "cveId": cve_id,
            "state": state,
            "datePublished": "2025-05-01T00:00:00Z",
            "dateUpdated": "2025-05-02T00:00:00Z",
        },
        "containers": {
            "cna": {
                "title": f"Sample {cve_id} SSRF in ExampleProxy",
                "descriptions": [{"lang": "en", "value": "Server-side request forgery via unvalidated redirect."}],
                "affected": [{"vendor": "ExampleCorp", "product": "ExampleProxy", "versions": [{"version": "< 2.1.0"}]}],
                "problemTypes": [{"descriptions": [{"cweId": cwe}]}],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseScore": score,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }
                ],
                "references": refs
                or [
                    {"url": "https://github.com/example/proxy/commit/abcdef1234", "tags": ["patch"]},
                    {"url": "https://blog.example.org/cve-writeup", "tags": ["technical-description"]},
                ],
            }
        },
    }


def test_filters_low_and_rejected_cves():
    low_rec = _sample_record("CVE-2025-0001", score=3.1)
    rejected_rec = _sample_record("CVE-2025-0002", score=9.8, state="REJECTED")
    med_rec = _sample_record("CVE-2025-0003", score=5.4)

    assert parse_cve5_record(low_rec, {}, {}, min_cvss=4.0)[0] is None
    assert parse_cve5_record(rejected_rec, {}, {}, min_cvss=4.0)[0] is None
    row, writeups = parse_cve5_record(med_rec, {}, {"CVE-2025-0003": (0.42, 0.91)}, min_cvss=4.0)
    assert row is not None
    assert row["cvss_severity"] == "MEDIUM"
    assert row["epss_score"] == 0.42
    assert any(w["has_patch_diff"] == 1 for w in writeups)


def test_build_database_and_fts_and_enrichers(tmp_path: Path):
    db_path = tmp_path / "test_cve.sqlite"
    trickest_dir = tmp_path / "trickest"
    trickest_dir.mkdir()
    (trickest_dir / "CVE-2025-1000.md").write_text(
        "PoC: https://github.com/researcher/cve-2025-1000-poc\n", encoding="utf-8"
    )

    nuclei_dir = tmp_path / "nuclei" / "http" / "cves"
    nuclei_dir.mkdir(parents=True)
    (nuclei_dir / "CVE-2025-1000.yaml").write_text("id: CVE-2025-1000\n", encoding="utf-8")

    records = [
        _sample_record("CVE-2025-1000", score=9.8, cwe="CWE-918"),
        _sample_record("CVE-2025-1001", score=2.5, cwe="CWE-79"),  # excluded
    ]
    kev = {"CVE-2025-1000": {"cveID": "CVE-2025-1000", "dateAdded": "2025-05-03", "dueDate": "2025-05-24"}}
    stats = build_database(
        db_path=db_path,
        records=records,
        kev_map=kev,
        epss_map={"CVE-2025-1000": (0.95, 0.99)},
        min_cvss=4.0,
        trickest_dir=trickest_dir,
        nuclei_dir=tmp_path / "nuclei",
    )
    assert stats["total_cves"] == 1
    assert stats["kev_count"] == 1
    assert stats["total_writeups"] >= 4  # patch + blog + trickest + nuclei

    with sqlite3.connect(db_path) as conn:
        hits = conn.execute("SELECT cve_id FROM cves_fts WHERE cves_fts MATCH '\"ExampleProxy\"'").fetchall()
        assert hits == [("CVE-2025-1000",)]
