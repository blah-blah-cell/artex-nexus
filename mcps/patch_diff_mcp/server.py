"""
patch-diff-mcp: Dual-transport (stdio + Streamable HTTP / SSE) MCP server for
fetching public CVE patch diffs from allowlisted code hosts and extracting
security-relevant hunks for root-cause and variant analysis.
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from mcps.compat import create_mcp_server, run_mcp_server

DEFAULT_DB = Path(os.environ.get("CVE_DB_PATH", "data/cve_kb_med_plus.sqlite"))
ALLOWED_HOSTS = {"github.com", "api.github.com", "gitlab.com"}
MAX_PATCH_BYTES = 256 * 1024

SECURITY_HINTS = (
    "auth",
    "token",
    "sanitize",
    "escape",
    "validate",
    "verify",
    "permission",
    "check",
    "allowlist",
    "denylist",
    "csrf",
    "ssrf",
    "path",
    "traversal",
    "sql",
    "exec",
    "eval",
    "deserialize",
    "bounds",
    "overflow",
)

mcp = create_mcp_server("patch-diff-mcp")


def _normalize_patch_url(raw_url: str) -> str:
    parsed = urlparse(raw_url.strip())
    if parsed.scheme not in ("https",):
        raise ValueError("Only HTTPS URLs on allowlisted public code hosts are permitted.")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Host '{host}' is not in allowlist {sorted(ALLOWED_HOSTS)}.")

    path = parsed.path.rstrip("/")
    if host == "github.com" and re.match(r"^/[^/]+/[^/]+/(commit|pull)/[^/]+$", path):
        return f"https://github.com{path}.diff"
    if host == "gitlab.com" and "/-/commit/" in path and not path.endswith(".diff"):
        return f"https://gitlab.com{path}.diff"
    return raw_url.strip()


@mcp.tool()
def find_patch_links_for_cve(cve_id: str) -> dict[str, Any]:
    """Look up public patch/commit/PR URLs for a CVE in the local Medium+ CVE knowledge base."""
    cid = cve_id.upper().strip()
    db_path = Path(os.environ.get("CVE_DB_PATH", str(DEFAULT_DB)))
    if not db_path.exists():
        return {"error": f"CVE DB not found at '{db_path}'."}

    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        rows = [
            dict(r)
            for r in conn.execute(
                "SELECT source, url, title, tags FROM writeups "
                "WHERE cve_id = ? AND has_patch_diff = 1",
                (cid,),
            ).fetchall()
        ]
    return {"cve_id": cid, "patch_links": rows, "count": len(rows)}


@mcp.tool()
def fetch_cve_patch_diff(commit_or_pr_url: str) -> dict[str, Any]:
    """Fetch a public commit or PR unified diff from GitHub/GitLab (allowlisted hosts only)."""
    try:
        diff_url = _normalize_patch_url(commit_or_pr_url)
    except ValueError as exc:
        return {"error": str(exc)}

    headers = {"User-Agent": "artex-nexus-patch-diff/0.1", "Accept": "text/plain"}
    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token and "github.com" in diff_url:
        headers["Authorization"] = f"Bearer {gh_token}"

    try:
        with httpx.Client(follow_redirects=True, timeout=20.0) as client:
            resp = client.get(diff_url, headers=headers)
            resp.raise_for_status()
            content = resp.text
    except httpx.HTTPError as exc:
        return {"error": f"Failed to fetch diff: {exc}", "url": diff_url}

    truncated = len(content.encode("utf-8", errors="ignore")) > MAX_PATCH_BYTES
    if truncated:
        content = content[:MAX_PATCH_BYTES]

    return {
        "url": diff_url,
        "truncated": truncated,
        "patch": content,
        "analysis": extract_diff_hunks(content),
    }


@mcp.tool()
def extract_diff_hunks(patch_text: str) -> dict[str, Any]:
    """Parse a unified diff into per-file hunks and highlight security-relevant added/removed lines."""
    files: list[dict[str, Any]] = []
    current_file: dict[str, Any] | None = None
    security_signals: list[dict[str, Any]] = []

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            if current_file:
                files.append(current_file)
            parts = line.split()
            fname = parts[-1].removeprefix("b/") if len(parts) >= 4 else line
            current_file = {"file": fname, "added": 0, "removed": 0, "hunks": []}
        elif line.startswith("@@ ") and current_file is not None:
            current_file["hunks"].append(line)
        elif current_file is not None and line.startswith("+") and not line.startswith("+++"):
            current_file["added"] += 1
            lower = line.lower()
            matched = [h for h in SECURITY_HINTS if h in lower]
            if matched and len(security_signals) < 60:
                security_signals.append(
                    {"file": current_file["file"], "op": "added", "hints": matched, "line": line[1:].strip()[:200]}
                )
        elif current_file is not None and line.startswith("-") and not line.startswith("---"):
            current_file["removed"] += 1
            lower = line.lower()
            matched = [h for h in SECURITY_HINTS if h in lower]
            if matched and len(security_signals) < 60:
                security_signals.append(
                    {"file": current_file["file"], "op": "removed", "hints": matched, "line": line[1:].strip()[:200]}
                )

    if current_file:
        files.append(current_file)

    return {
        "files_changed": len(files),
        "files": files,
        "security_signals": security_signals,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run patch-diff-mcp server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
    )
    parser.add_argument("--host", default=os.environ.get("MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT", "8902")))
    args = parser.parse_args()

    run_mcp_server(mcp, transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
