#!/usr/bin/env python3
"""
One-command bootstrap for the ARTEX-Nexus Medium+ CVE & Writeups SQLite DB.

Downloads the latest nightly prebuilt database from GitHub Releases and verifies
its SHA-256 checksum, or builds a fast KEV-backed starter DB with --kev-seed.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import urllib.request
from pathlib import Path

from pipeline.sync_cves import build_database, fetch_epss_scores, fetch_kev_catalog

DEFAULT_REPO = os.environ.get("ARTEX_NEXUS_REPO", "blah-blah-cell/artex-nexus")
RELEASE_TAG = os.environ.get("ARTEX_NEXUS_DB_TAG", "cve-db-latest")


def download_file(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "artex-nexus-bootstrap/0.1"})
    with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as fh:
        while chunk := resp.read(1024 * 1024):
            fh.write(chunk)


def decompress_archive(archive_path: Path, out_db: Path) -> None:
    if archive_path.suffix == ".zst":
        import zstandard as zstd  # type: ignore

        dctx = zstd.ZstdDecompressor()
        with archive_path.open("rb") as src, out_db.open("wb") as dst:
            dctx.copy_stream(src, dst)
    elif archive_path.suffix == ".gz":
        with gzip.open(archive_path, "rb") as src, out_db.open("wb") as dst:
            while chunk := src.read(1024 * 1024):
                dst.write(chunk)
    else:
        raise ValueError(f"Unsupported archive format: {archive_path.name}")


def bootstrap_from_release(repo: str, tag: str, out_db: Path) -> None:
    api_url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    req = urllib.request.Request(api_url, headers={"User-Agent": "artex-nexus-bootstrap/0.1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        release = json.loads(resp.read().decode("utf-8"))

    assets = {a["name"]: a["browser_download_url"] for a in release.get("assets") or []}
    archive_name = next(
        (n for n in ("cve_kb_med_plus.sqlite.zst", "cve_kb_med_plus.sqlite.gz") if n in assets),
        None,
    )
    if not archive_name:
        raise RuntimeError(f"No CVE DB asset found in release {repo}@{tag}")

    cache_dir = out_db.parent / "cache"
    archive_path = cache_dir / archive_name
    print(f"[*] Downloading {archive_name} from {repo}@{tag}...")
    download_file(assets[archive_name], archive_path)

    if "SHA256SUMS.txt" in assets:
        sums_path = cache_dir / "SHA256SUMS.txt"
        download_file(assets["SHA256SUMS.txt"], sums_path)
        expected = None
        for line in sums_path.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == archive_name:
                expected = parts[0].lower()
                break
        if expected:
            actual = hashlib.sha256(archive_path.read_bytes()).hexdigest().lower()
            if actual != expected:
                raise RuntimeError(f"Checksum mismatch for {archive_name}: {actual} != {expected}")
            print(f"[+] SHA-256 verified: {actual[:16]}...")

    print(f"[*] Decompressing to {out_db}...")
    decompress_archive(archive_path, out_db)
    print(f"[+] Ready: {out_db}")


def bootstrap_kev_seed(out_db: Path) -> None:
    """Fast 5-second starter DB built directly from CISA KEV + FIRST EPSS."""
    print("[*] Fetching CISA KEV catalog & FIRST EPSS scores...")
    kev_map = fetch_kev_catalog()
    epss_map = fetch_epss_scores()
    records = []
    for cid, item in kev_map.items():
        records.append(
            {
                "cveMetadata": {
                    "cveId": cid,
                    "state": "PUBLISHED",
                    "datePublished": item.get("dateAdded", ""),
                    "dateUpdated": item.get("dueDate", ""),
                },
                "containers": {
                    "cna": {
                        "title": item.get("vulnerabilityName", ""),
                        "descriptions": [{"lang": "en", "value": item.get("shortDescription", "")}],
                        "affected": [
                            {
                                "vendor": item.get("vendorProject", ""),
                                "product": item.get("product", ""),
                                "versions": [],
                            }
                        ],
                        "problemTypes": [
                            {"descriptions": [{"cweId": cwe} for cwe in (item.get("cwes") or [])]}
                        ],
                        "references": [
                            {"url": u.strip(), "tags": ["advisory"]}
                            for u in str(item.get("notes") or "").split(";")
                            if u.strip().startswith("http")
                        ],
                    }
                },
            }
        )
    stats = build_database(out_db, records, kev_map, epss_map, min_cvss=4.0)
    print(f"[+] KEV starter DB built at {out_db}: {stats}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap ARTEX-Nexus CVE Knowledge Base")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--tag", default=RELEASE_TAG)
    parser.add_argument("--out", type=Path, default=Path("data/cve_kb_med_plus.sqlite"))
    parser.add_argument("--kev-seed", action="store_true", help="Build instant local starter DB from CISA KEV + EPSS")
    args = parser.parse_args()

    if args.kev_seed:
        bootstrap_kev_seed(args.out)
    else:
        bootstrap_from_release(args.repo, args.tag, args.out)


if __name__ == "__main__":
    main()
