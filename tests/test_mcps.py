from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcps.cve_intel_mcp import server as cve_mcp
from mcps.patch_diff_mcp import server as patch_mcp
from mcps.scope_guard_mcp import server as scope_mcp
from pipeline.sync_cves import build_database


@pytest.fixture()
def seeded_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "cve_kb.sqlite"
    records = [
        {
            "cveMetadata": {"cveId": "CVE-2025-9001", "state": "PUBLISHED", "datePublished": "2025-06-01"},
            "containers": {
                "cna": {
                    "title": "Auth bypass in AcmeGateway",
                    "descriptions": [{"lang": "en", "value": "Path normalization bypass allows unauthenticated admin access."}],
                    "affected": [{"vendor": "Acme", "product": "AcmeGateway", "versions": [{"version": "< 4.2"}]}],
                    "problemTypes": [{"descriptions": [{"cweId": "CWE-287"}]}],
                    "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.1, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}}],
                    "references": [
                        {"url": "https://github.com/acme/gateway/commit/deadbeef", "tags": ["patch"]},
                        {"url": "https://research.example.com/acme-gateway-writeup", "tags": ["technical-description"]},
                    ],
                }
            },
        }
    ]
    build_database(
        db_path=db_path,
        records=records,
        kev_map={"CVE-2025-9001": {"cveID": "CVE-2025-9001", "dateAdded": "2025-06-05", "dueDate": "2025-06-26"}},
        epss_map={"CVE-2025-9001": (0.88, 0.98)},
        min_cvss=4.0,
    )
    monkeypatch.setenv("CVE_DB_PATH", str(db_path))
    return db_path


def test_cve_intel_mcp_tools(seeded_db: Path):
    res = cve_mcp.search_cves("AcmeGateway", kev_only=True)
    assert res["count"] == 1
    assert res["results"][0]["cve_id"] == "CVE-2025-9001"

    detail = cve_mcp.get_cve_details("CVE-2025-9001")
    assert detail["found"] is True
    assert detail["is_kev"] == 1
    assert len(detail["writeups"]) == 2

    prod = cve_mcp.match_product_cves(product="AcmeGateway", vendor="Acme")
    assert prod["count"] == 1

    cwe_wu = cve_mcp.list_cwe_writeups("CWE-287", patch_only=True)
    assert cwe_wu["count"] == 1
    assert cwe_wu["writeups"][0]["has_patch_diff"] == 1

    stats = cve_mcp.get_kb_stats()
    assert stats["metadata"]["total_cves"] == "1"


def test_patch_diff_mcp_allowlist_and_hunks(seeded_db: Path):
    links = patch_mcp.find_patch_links_for_cve("CVE-2025-9001")
    assert links["count"] == 1

    # SSRF protection: reject non-allowlisted hosts
    blocked = patch_mcp.fetch_cve_patch_diff("http://169.254.169.254/latest/meta-data/")
    assert "error" in blocked

    sample_diff = """diff --git a/auth/middleware.py b/auth/middleware.py
@@ -10,4 +10,6 @@ def check_access(path):
-    if path.startswith("/admin"):
+    norm = os.path.normpath(path)
+    if norm.startswith("/admin"):
+        verify_auth_token()
"""
    parsed = patch_mcp.extract_diff_hunks(sample_diff)
    assert parsed["files_changed"] == 1
    assert any("verify" in s["hints"] or "auth" in s["hints"] for s in parsed["security_signals"])


def test_scope_guard_mcp_enforcement_and_receipts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    policy = tmp_path / "scope.yaml"
    policy.write_text(
        "program: acme-bounty\n"
        "in_scope:\n"
        "  - '*.staging.acme.test'\n"
        "  - '10.20.0.0/16'\n"
        "out_of_scope:\n"
        "  - 'payments.staging.acme.test'\n",
        encoding="utf-8",
    )
    receipt_dir = tmp_path / "receipts"
    monkeypatch.setenv("SCOPE_RECEIPT_DIR", str(receipt_dir))

    loaded = scope_mcp.load_scope_policy(str(policy))
    assert loaded["loaded"] is True

    assert scope_mcp.check_target_in_scope("https://api.staging.acme.test/v1")["allowed"] is True
    assert scope_mcp.check_target_in_scope("10.20.5.12")["allowed"] is True
    assert scope_mcp.check_target_in_scope("https://payments.staging.acme.test/pay")["allowed"] is False
    assert scope_mcp.check_target_in_scope("https://evil.other.test")["allowed"] is False

    rec = scope_mcp.record_evidence_receipt(
        finding_id="FIND-001",
        title="Path normalization auth bypass",
        target="https://api.staging.acme.test",
        cwe="CWE-287",
        severity="HIGH",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        verification_command="pytest tests/test_auth_norm.py",
        observed_output_summary="Returned 200 on unnormalized /admin/.. path",
        remediation="Canonicalize request path before RBAC middleware",
    )
    assert rec["recorded"] is True
    assert len(rec["sha256"]) == 64

    md = scope_mcp.export_report("markdown")
    assert "FIND-001" in md["content"]

    sarif = scope_mcp.export_report("sarif")
    parsed_sarif = json.loads(sarif["content"])
    assert parsed_sarif["version"] == "2.1.0"
    assert len(parsed_sarif["runs"][0]["results"]) == 1
